// Package migrations implements OWASAKA's BoltDB schema-versioning
// framework. Migrations are Go functions registered in init() and
// applied in monotonically-increasing ID order. The highest applied
// ID is persisted in a schema_version bucket; a gap means "boot
// refuses unless --auto-migrate". A downgrade (applied > available)
// is always a fatal refusal — operator must use the matching binary.
//
// See ADR-0064 §"Migrations" for design rationale.
package migrations

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// BucketSchema is the BoltDB bucket holding the highest applied
// migration ID under the key "applied".
const (
	BucketSchema    = "schema_version"
	keyAppliedID    = "applied"
	keyAppliedAt    = "applied_at"
)

// Migration is one schema change. The framework guarantees Up runs
// inside a write transaction; the migration body just operates on
// buckets within that tx. Down is optional and discouraged — BoltDB
// data evolution is rarely reversible at the schema level.
type Migration struct {
	ID          uint32
	Description string
	Up          func(tx *bolt.Tx) error
	Down        func(tx *bolt.Tx) error // optional; nil means "irreversible"
}

// registry is the package-level set of registered migrations. Tests
// can swap it for an isolated set via swapRegistry.
var (
	registryMu sync.Mutex
	registry   []Migration
)

// Register adds a migration to the package registry. Typical call
// site is inside an init() function in a per-migration file:
//
//	func init() {
//	    migrations.Register(migrations.Migration{ID: 1, ...})
//	}
//
// Duplicate IDs cause a panic at startup — the package refuses to
// run with an ambiguous migration tree.
func Register(m Migration) {
	registryMu.Lock()
	defer registryMu.Unlock()
	for _, existing := range registry {
		if existing.ID == m.ID {
			panic(fmt.Sprintf("migrations: duplicate ID %d (%q vs %q)",
				m.ID, existing.Description, m.Description))
		}
	}
	registry = append(registry, m)
}

// All returns a copy of the registered migrations sorted by ID. Tests
// and the runner use this to enumerate available migrations.
func All() []Migration {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Migration, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// swapRegistry is a test-only helper that replaces the registry and
// returns a restore function. Useful for unit tests that need to
// exercise the framework without depending on whatever the binary
// has registered globally.
func swapRegistry(replacement []Migration) func() {
	registryMu.Lock()
	defer registryMu.Unlock()
	prev := registry
	registry = append([]Migration{}, replacement...)
	return func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		registry = prev
	}
}

// Status describes the current state of the schema relative to the
// available migrations. Returned by Status() for the CLI and the
// boot-time gate.
type Status struct {
	Applied   uint32      // highest applied migration ID
	Available uint32      // highest available migration ID
	Pending   []Migration // migrations with ID > Applied
}

// AppliedID returns the highest migration ID applied to the DB, or
// 0 when the schema_version bucket is absent or empty (fresh deploy).
func AppliedID(db *bolt.DB) (uint32, error) {
	if db == nil {
		return 0, errors.New("migrations: nil db")
	}
	var applied uint32
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketSchema))
		if b == nil {
			return nil
		}
		raw := b.Get([]byte(keyAppliedID))
		if raw == nil {
			return nil
		}
		if len(raw) != 4 {
			return fmt.Errorf("migrations: applied id has wrong length %d", len(raw))
		}
		applied = binary.BigEndian.Uint32(raw)
		return nil
	})
	return applied, err
}

// AvailableID returns the highest migration ID known to the package.
// Zero when no migrations are registered.
func AvailableID() uint32 {
	all := All()
	if len(all) == 0 {
		return 0
	}
	return all[len(all)-1].ID
}

// CurrentStatus snapshots Applied + Available + Pending.
func CurrentStatus(db *bolt.DB) (Status, error) {
	applied, err := AppliedID(db)
	if err != nil {
		return Status{}, err
	}
	all := All()
	var pending []Migration
	for _, m := range all {
		if m.ID > applied {
			pending = append(pending, m)
		}
	}
	return Status{
		Applied:   applied,
		Available: AvailableID(),
		Pending:   pending,
	}, nil
}

// Sentinel errors returned by Run / RunUp / RunDown and the boot gate.
var (
	ErrPendingMigrations = errors.New("migrations: pending migrations require explicit apply (run `oswaka migrate up` or set --auto-migrate)")
	ErrDowngradeDetected = errors.New("migrations: applied id exceeds highest available; binary is older than the database — refuse to run")
	ErrDuplicateID       = errors.New("migrations: duplicate migration ID registered")
	ErrUnknownMigration  = errors.New("migrations: requested migration ID is not registered")
)

// EnsureBucket creates the schema_version bucket if it does not yet
// exist. Idempotent. Always run before invoking the runner.
func EnsureBucket(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketSchema))
		return err
	})
}

func writeAppliedID(tx *bolt.Tx, id uint32) error {
	b := tx.Bucket([]byte(BucketSchema))
	if b == nil {
		var err error
		b, err = tx.CreateBucket([]byte(BucketSchema))
		if err != nil {
			return err
		}
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	_ = b.Put([]byte(keyAppliedAt), nil)
	return b.Put([]byte(keyAppliedID), buf)
}
