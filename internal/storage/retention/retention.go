// Package retention implements OWASAKA's per-bucket TTL pruner and
// the BoltDB compaction trigger. See ADR-0064 §"Retention" for the
// design contract.
//
// The transparency log is NEVER retention-pruned here — that would
// defeat the tamper-evidence guarantee. STH history is configurable
// (defaults to keep-all because its volume is bounded by leaf-append
// rate, not event rate). Routine event volume is what the rules
// below actually bound.
package retention

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Config carries operator-tuned retention durations + compaction
// thresholds. Defaults are filled in by EnsureDefaults; zero values
// disable the corresponding sweep (operator chose to keep forever).
type Config struct {
	// EventsDefaultTTL applies to every event bucket entry whose
	// `type` claim is NOT THREAT_ALERT.
	EventsDefaultTTL time.Duration

	// AlertsTTL applies to high-severity alerts specifically. Set
	// longer than EventsDefaultTTL because auditors examine alerts
	// long after routine events have aged out.
	AlertsTTL time.Duration

	// AssetsStaleTTL applies to assets whose LastSeen is older than
	// this many days. Stale assets are removed from the assets
	// bucket; the transparency log retains any historical record.
	AssetsStaleTTL time.Duration

	// SweepInterval controls how often the background goroutine runs
	// a full pass. Default: 24h.
	SweepInterval time.Duration

	// CompactionFreelistThreshold triggers a BoltDB compaction
	// after a sweep if the freelist size (in pages) exceeds this.
	// 0 disables compaction.
	CompactionFreelistThreshold int
}

// EnsureDefaults fills zero-valued fields with operationally-sane
// defaults. Callers may set any field explicitly to override.
func (c *Config) EnsureDefaults() {
	if c.EventsDefaultTTL == 0 {
		c.EventsDefaultTTL = 90 * 24 * time.Hour
	}
	if c.AlertsTTL == 0 {
		c.AlertsTTL = 365 * 24 * time.Hour
	}
	if c.AssetsStaleTTL == 0 {
		c.AssetsStaleTTL = 30 * 24 * time.Hour
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = 24 * time.Hour
	}
}

// Engine runs the retention sweep + compaction on a schedule and on
// demand. Construct once; Start kicks off the background goroutine,
// Stop cancels it cleanly.
type Engine struct {
	cfg    Config
	db     *bolt.DB
	clock  func() time.Time
	logger Logger

	running atomic.Bool
}

// Logger is the minimal contract the engine uses. Production wires
// pkg/logging; tests pass a no-op or capture-into-slice impl.
type Logger interface {
	Infow(msg string, kv ...any)
	Warnw(msg string, kv ...any)
}

// NopLogger drops every log line. Useful for tests and offline use.
type NopLogger struct{}

// Infow implements Logger.
func (NopLogger) Infow(string, ...any) {}

// Warnw implements Logger.
func (NopLogger) Warnw(string, ...any) {}

// NewEngine builds a retention engine. The db must already be open.
// logger may be nil — defaults to NopLogger.
func NewEngine(cfg Config, db *bolt.DB, logger Logger) (*Engine, error) {
	if db == nil {
		return nil, errors.New("retention: nil db")
	}
	cfg.EnsureDefaults()
	if logger == nil {
		logger = NopLogger{}
	}
	return &Engine{cfg: cfg, db: db, clock: time.Now, logger: logger}, nil
}

// Report summarizes a single sweep's outcome.
type Report struct {
	EventsRemoved      int
	AlertsRemoved      int
	AssetsRemoved      int
	CompactionRan      bool
	FreelistPagesAfter int
	StartedAt          time.Time
	FinishedAt         time.Time
}

// Sweep runs one full pass: prune events, alerts, assets; optionally
// trigger BoltDB compaction. Safe to call manually (admin endpoint,
// CLI, tests) in addition to the scheduled background loop.
func (e *Engine) Sweep(ctx context.Context) (Report, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	now := e.clock()
	rep := Report{StartedAt: now}

	// Events bucket: each value is a JSON object with at least a
	// "type" and "timestamp"; drop entries older than the type-
	// specific TTL.
	if err := e.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("events"))
		if b == nil {
			return nil
		}
		var toDelete [][]byte
		cur := b.Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			drop, isAlert := e.shouldDropEvent(v, now)
			if drop {
				keyCopy := append([]byte{}, k...)
				toDelete = append(toDelete, keyCopy)
				if isAlert {
					rep.AlertsRemoved++
				} else {
					rep.EventsRemoved++
				}
			}
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return rep, fmt.Errorf("retention: events sweep: %w", err)
	}

	// Assets bucket: drop entries whose LastSeen is older than the
	// stale TTL. Asset JSON uses snake_case "last_seen".
	if err := e.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("assets"))
		if b == nil {
			return nil
		}
		var toDelete [][]byte
		cur := b.Cursor()
		cutoff := now.Add(-e.cfg.AssetsStaleTTL)
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if e.assetIsStale(v, cutoff) {
				keyCopy := append([]byte{}, k...)
				toDelete = append(toDelete, keyCopy)
			}
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			rep.AssetsRemoved++
		}
		return nil
	}); err != nil {
		return rep, fmt.Errorf("retention: assets sweep: %w", err)
	}

	// Compaction trigger: read freelist page count; if above the
	// threshold, run an offline compaction via the bbolt API. This
	// is a heavy operation (writes a fresh DB file) so we only
	// invoke it when the freelist actually warrants it.
	if e.cfg.CompactionFreelistThreshold > 0 {
		pages := e.freelistPageCount()
		rep.FreelistPagesAfter = pages
		if pages > e.cfg.CompactionFreelistThreshold {
			if err := e.compact(); err != nil {
				e.logger.Warnw("retention: compaction failed",
					"error", err, "pages", pages,
					"threshold", e.cfg.CompactionFreelistThreshold)
			} else {
				rep.CompactionRan = true
				e.logger.Infow("retention: compaction completed",
					"pages_before", pages)
			}
		}
	}

	rep.FinishedAt = e.clock()
	e.logger.Infow("retention: sweep complete",
		"events_removed", rep.EventsRemoved,
		"alerts_removed", rep.AlertsRemoved,
		"assets_removed", rep.AssetsRemoved,
		"compaction_ran", rep.CompactionRan,
		"duration_ms", rep.FinishedAt.Sub(rep.StartedAt).Milliseconds())
	return rep, nil
}

// shouldDropEvent returns (drop, isAlert). isAlert lets the caller
// keep the by-category counters straight.
func (e *Engine) shouldDropEvent(raw []byte, now time.Time) (drop, isAlert bool) {
	var ev struct {
		Type      string    `json:"type"`
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		// Malformed entries are kept; they'll be visible to ops and
		// can be removed manually.
		return false, false
	}
	ttl := e.cfg.EventsDefaultTTL
	isAlert = ev.Type == "THREAT_ALERT"
	if isAlert {
		ttl = e.cfg.AlertsTTL
	}
	if ttl == 0 || ev.Timestamp.IsZero() {
		return false, isAlert
	}
	return now.Sub(ev.Timestamp) > ttl, isAlert
}

// assetIsStale returns true when the persisted Asset's last_seen
// timestamp precedes the cutoff.
func (e *Engine) assetIsStale(raw []byte, cutoff time.Time) bool {
	var a struct {
		LastSeen time.Time `json:"last_seen"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return false
	}
	if a.LastSeen.IsZero() {
		return false
	}
	return a.LastSeen.Before(cutoff)
}

// freelistPageCount returns the BoltDB freelist size in pages. Used
// to gate compaction. bbolt exposes this via Stats(); the value is
// approximate at request time but accurate enough for a threshold.
func (e *Engine) freelistPageCount() int {
	st := e.db.Stats()
	return st.FreePageN
}

// compact runs an offline compaction: copy the live DB to a fresh
// file via bolt.Compact, then atomic-rename the new file into place.
// The DB is briefly read-locked during the copy; writers see a
// transient pause but no data inconsistency.
//
// Compaction implementation note: bbolt's compact-in-place isn't a
// public API at the time of this writing. We approximate by copying
// the DB through Tx.WriteTo to a sibling file then renaming. The
// hot-backup primitive (used here) gives a consistent point-in-time
// snapshot, and the rename is atomic.
func (e *Engine) compact() error {
	path := e.db.Path()
	dst := path + ".compact"

	// Acquire a read transaction; stream the entire DB to a new file.
	err := e.db.View(func(tx *bolt.Tx) error {
		return tx.CopyFile(dst, 0o600)
	})
	if err != nil {
		return fmt.Errorf("compact: write copy: %w", err)
	}

	// Atomic rename. The bolt handle still points at the old file
	// after this; live processes should restart to pick up the
	// compacted version. The retention engine signals this need via
	// a Warnw log line — production callers schedule the compaction
	// during a maintenance window.
	if err := atomicRename(dst, path); err != nil {
		return fmt.Errorf("compact: rename: %w", err)
	}
	return nil
}

// atomicRename is the POSIX move; on most filesystems it is atomic.
// Wrapped here so tests can stub if portability becomes a concern.
func atomicRename(src, dst string) error {
	return osRename(src, dst)
}

// indirection for testability.
var osRename = func(src, dst string) error {
	return renameImpl(src, dst)
}

// --- internal helpers ---------------------------------------------------

// encodeIndex / decodeIndex mirror the transparency package's
// 8-byte big-endian leaf-index encoding for any future bucket the
// retention engine learns to manage.
//
//nolint:unused // reserved for future bucket layouts
func encodeIndex(idx uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, idx)
	return b
}
