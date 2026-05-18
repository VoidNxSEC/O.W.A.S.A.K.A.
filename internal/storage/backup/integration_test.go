//go:build integration

// Sprint 4 / ADR-0064 task B13. End-to-end backup→wipe→restore cycle
// guarded by build tag `integration` so it runs in CI on every PR
// that touches storage but stays out of the fast `go test ./...`
// loop. Failure here means the on-disk format silently drifted; the
// breakage surfaces at the storage boundary, not weeks later in
// production restore drills.
package backup

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
)

func TestIntegration_BackupWipeRestoreCycle(t *testing.T) {
	ctx := context.Background()
	workDir := t.TempDir()
	dbPath := filepath.Join(workDir, "owasaka.db")

	// ── Phase 1: seed a live DB with events + a transparency leaf ──
	live, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("open live db: %v", err)
	}
	tree, err := transparency.Open(live)
	if err != nil {
		t.Fatalf("open tree: %v", err)
	}

	// Seed a deterministic events bucket so we can assert round-trip.
	mustUpdate(t, live, func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("events"))
		if e != nil {
			return e
		}
		return b.Put([]byte("evt-1"), []byte(`{"src":"10.0.0.5","sig":"…"}`))
	})

	for i := 0; i < 3; i++ {
		if _, e := tree.Append(ctx, transparency.Leaf{
			Kind:      transparency.LeafPolicyReload,
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Payload:   []byte{byte('a' + i)},
		}); e != nil {
			t.Fatalf("append: %v", e)
		}
	}
	preSize := tree.Size()
	preRoot := tree.Root()
	t.Logf("seeded: tree size=%d root=%s", preSize, hex.EncodeToString(preRoot[:8]))

	// ── Phase 2: backup ──
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen age: %v", err)
	}
	sinkDir := filepath.Join(workDir, "backups")
	sink, err := NewLocalSink(sinkDir, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	engine, err := NewEngine(NewBoltSource(live, tree), []Sink{sink}, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	art, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("backup run: %v", err)
	}
	t.Logf("backup written: %s (tree size=%d)", art.Filename, art.TreeSize)

	// Sign the live STH so we can journal-record-compare during restore.
	authority := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := authority.GenerateKeyPair(ctx, pki.PurposeTransparencyLogSTH, time.Hour); err != nil {
		t.Fatalf("sth key: %v", err)
	}
	signer := transparency.NewSTHSigner(authority)
	expectedSTH, err := signer.SignSTH(ctx, preSize, preRoot)
	if err != nil {
		t.Fatalf("sign STH: %v", err)
	}

	// ── Phase 3: wipe ──
	if err := live.Close(); err != nil {
		t.Fatalf("close live: %v", err)
	}
	if err := os.Remove(dbPath); err != nil {
		t.Fatalf("wipe: %v", err)
	}

	// ── Phase 4: restore ──
	report, err := Restore(ctx, RestoreInput{
		EncryptedPath: filepath.Join(sinkDir, art.Filename),
		Identities:    []age.Identity{id},
		TargetPath:    dbPath,
		ExpectedSTH:   &expectedSTH,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !report.STHMatch {
		t.Fatalf("STH mismatch on restore: %s", report.STHMismatchNote)
	}
	if report.BackupTreeSize != uint64(preSize) {
		t.Fatalf("restored tree size %d != original %d", report.BackupTreeSize, preSize)
	}
	t.Logf("restore report: tree size=%d match=%v", report.BackupTreeSize, report.STHMatch)

	// ── Phase 5: re-open and verify ──
	restored, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer restored.Close()

	tree2, err := transparency.Open(restored)
	if err != nil {
		t.Fatalf("re-open tree: %v", err)
	}
	if tree2.Size() != preSize {
		t.Fatalf("post-restore size %d != pre %d", tree2.Size(), preSize)
	}
	if tree2.Root() != preRoot {
		t.Fatalf("post-restore root diverges")
	}

	// Seeded event must read back identical.
	mustView(t, restored, func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("events"))
		if b == nil {
			t.Fatal("events bucket missing post-restore")
		}
		got := b.Get([]byte("evt-1"))
		if string(got) != `{"src":"10.0.0.5","sig":"…"}` {
			t.Fatalf("event payload diverged: %q", got)
		}
		return nil
	})

	// STH signed by the original signer must still verify against the
	// restored authority (same key material is in-memory). This is the
	// real reason the cycle test exists: after a restore, downstream
	// verifiers must continue to trust historical events.
	if err := transparency.VerifySTH(ctx, authority, expectedSTH, time.Now()); err != nil {
		t.Fatalf("STH verification post-restore: %v", err)
	}
}

func TestIntegration_RestoreRefusesSTHMismatch(t *testing.T) {
	ctx := context.Background()
	workDir := t.TempDir()
	dbPath := filepath.Join(workDir, "owasaka.db")

	live, _ := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	tree, _ := transparency.Open(live)
	_, _ = tree.Append(ctx, transparency.Leaf{Kind: transparency.LeafAlertHigh, Payload: []byte("x")})

	id, _ := age.GenerateX25519Identity()
	sink, _ := NewLocalSink(filepath.Join(workDir, "b"), 0)
	engine, _ := NewEngine(NewBoltSource(live, tree), []Sink{sink}, []age.Recipient{id.Recipient()})
	art, _ := engine.Run(ctx)
	_ = live.Close()
	_ = os.Remove(dbPath)

	// Forged "journal" with wrong size — restore must refuse.
	var fakeRoot [32]byte
	for i := range fakeRoot {
		fakeRoot[i] = 0x99
	}
	bogus := transparency.STH{TreeSize: 999, RootHash: fakeRoot[:]}

	_, err := Restore(ctx, RestoreInput{
		EncryptedPath: filepath.Join(workDir, "b", art.Filename),
		Identities:    []age.Identity{id},
		TargetPath:    dbPath,
		ExpectedSTH:   &bogus,
	})
	if !errors.Is(err, ErrSTHMismatch) {
		t.Fatalf("expected ErrSTHMismatch, got %v", err)
	}
	if _, statErr := os.Stat(dbPath); statErr == nil {
		t.Fatal("STH mismatch must NOT have swapped the file in")
	}
}

func TestIntegration_RestoreAllowsSTHMismatchExplicitly(t *testing.T) {
	ctx := context.Background()
	workDir := t.TempDir()
	dbPath := filepath.Join(workDir, "owasaka.db")

	live, _ := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	tree, _ := transparency.Open(live)
	_, _ = tree.Append(ctx, transparency.Leaf{Kind: transparency.LeafAlertHigh, Payload: []byte("x")})

	id, _ := age.GenerateX25519Identity()
	sink, _ := NewLocalSink(filepath.Join(workDir, "b"), 0)
	engine, _ := NewEngine(NewBoltSource(live, tree), []Sink{sink}, []age.Recipient{id.Recipient()})
	art, _ := engine.Run(ctx)
	_ = live.Close()
	_ = os.Remove(dbPath)

	var fakeRoot [32]byte
	bogus := transparency.STH{TreeSize: 999, RootHash: fakeRoot[:]}

	rep, err := Restore(ctx, RestoreInput{
		EncryptedPath:    filepath.Join(workDir, "b", art.Filename),
		Identities:       []age.Identity{id},
		TargetPath:       dbPath,
		ExpectedSTH:      &bogus,
		AllowSTHMismatch: true,
	})
	if err != nil {
		t.Fatalf("expected success with AllowSTHMismatch, got %v", err)
	}
	if rep.STHMatch {
		t.Fatal("report must record the mismatch even when allowed")
	}
	if rep.STHMismatchNote == "" {
		t.Fatal("report must explain the mismatch")
	}
	if _, statErr := os.Stat(dbPath); statErr != nil {
		t.Fatal("AllowSTHMismatch must still complete the swap")
	}
}

// --- helpers --------------------------------------------------------------

func mustUpdate(t *testing.T, db *bolt.DB, fn func(*bolt.Tx) error) {
	t.Helper()
	if err := db.Update(fn); err != nil {
		t.Fatalf("bolt update: %v", err)
	}
}

func mustView(t *testing.T, db *bolt.DB, fn func(*bolt.Tx) error) {
	t.Helper()
	if err := db.View(fn); err != nil {
		t.Fatalf("bolt view: %v", err)
	}
}
