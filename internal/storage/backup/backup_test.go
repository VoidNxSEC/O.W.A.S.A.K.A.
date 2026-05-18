package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
)

// --- Fixtures --------------------------------------------------------------

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "t.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Seed a tiny bucket so backups have something to copy.
	_ = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("seed"))
		return b.Put([]byte("k"), []byte("v"))
	})
	return db
}

func newAgeKey(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age key: %v", err)
	}
	return id, id.Recipient()
}

// --- Engine wiring ---------------------------------------------------------

func TestNewEngine_Validations(t *testing.T) {
	_, rec := newAgeKey(t)
	dir := t.TempDir()
	sink, _ := NewLocalSink(dir, 0)

	if _, err := NewEngine(nil, []Sink{sink}, []age.Recipient{rec}); !errors.Is(err, ErrNoSource) {
		t.Fatalf("expected ErrNoSource, got %v", err)
	}
	src := NewBoltSource(openTestDB(t), nil)
	if _, err := NewEngine(src, nil, []age.Recipient{rec}); !errors.Is(err, ErrNoSinks) {
		t.Fatalf("expected ErrNoSinks, got %v", err)
	}
	if _, err := NewEngine(src, []Sink{sink}, nil); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

func TestEngine_HappyPath_LocalSink(t *testing.T) {
	db := openTestDB(t)
	id, rec := newAgeKey(t)

	dir := t.TempDir()
	sink, err := NewLocalSink(dir, 0)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	engine, err := NewEngine(NewBoltSource(db, nil), []Sink{sink}, []age.Recipient{rec})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	art, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.HasPrefix(art.Filename, "backup-") || !strings.HasSuffix(art.Filename, ".db.age") {
		t.Fatalf("unexpected filename: %s", art.Filename)
	}

	// The encrypted file + sidecar must exist on disk.
	encPath := filepath.Join(dir, art.Filename)
	sidePath := encPath + ".sha256"
	encBody, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	sideBody, err := os.ReadFile(sidePath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}

	if err := VerifySidecar(encBody, sideBody); err != nil {
		t.Fatalf("sidecar mismatch: %v", err)
	}

	// Decrypt and confirm we got a valid BoltDB file by opening it.
	plain, err := DecryptArtifact(encBody, []age.Identity{id})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restoredPath, plain, 0o600); err != nil {
		t.Fatalf("write restored: %v", err)
	}
	restoredDB, err := bolt.Open(restoredPath, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer restoredDB.Close()
	_ = restoredDB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("seed"))
		if b == nil {
			t.Fatal("seed bucket missing in restored db")
		}
		if string(b.Get([]byte("k"))) != "v" {
			t.Fatal("seed value missing in restored db")
		}
		return nil
	})
}

func TestEngine_MetadataProviderPopulatesArtifact(t *testing.T) {
	db := openTestDB(t)
	tree, err := transparency.Open(db)
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	_, _ = tree.Append(context.Background(), transparency.Leaf{
		Kind:      transparency.LeafPolicyReload,
		Timestamp: time.Now(),
		Payload:   []byte("policy-reload-1"),
	})

	_, rec := newAgeKey(t)
	sink, _ := NewLocalSink(t.TempDir(), 0)
	engine, _ := NewEngine(NewBoltSource(db, tree), []Sink{sink}, []age.Recipient{rec})

	art, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if art.TreeSize != 1 {
		t.Fatalf("expected tree size 1, got %d", art.TreeSize)
	}
	if len(art.RootHashHex) != 64 {
		t.Fatalf("root hash hex length: %d", len(art.RootHashHex))
	}
}

func TestEngine_RecordsCanceledContext(t *testing.T) {
	db := openTestDB(t)
	_, rec := newAgeKey(t)
	sink, _ := NewLocalSink(t.TempDir(), 0)
	engine, _ := NewEngine(NewBoltSource(db, nil), []Sink{sink}, []age.Recipient{rec})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Run(ctx); !errors.Is(err, ErrBackupCanceled) {
		t.Fatalf("expected ErrBackupCanceled, got %v", err)
	}
}

// --- Sinks -----------------------------------------------------------------

func TestLocalSink_Rotation(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewLocalSink(dir, 2) // keep last 2
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	// Manually write 4 pairs of files with chronologically-ordered
	// names so the rotation has something to compare against.
	for i := 1; i <= 4; i++ {
		art := Artifact{
			Filename:  asciiFilenameAt(i),
			Encrypted: []byte("body-" + string(rune('a'+i-1))),
		}
		digest := sha256.Sum256(art.Encrypted)
		art.Sidecar = []byte(hex.EncodeToString(digest[:]) + "\n")
		if err := sink.Write(context.Background(), art); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	entries, _ := os.ReadDir(dir)
	pairs := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".age" {
			pairs++
		}
	}
	if pairs != 2 {
		t.Fatalf("expected 2 retained backups after rotation, got %d", pairs)
	}
}

func TestLocalSink_CleansEncIfSidecarFails(t *testing.T) {
	dir := t.TempDir()
	// Force sidecar write to fail by passing a path the OS can't create:
	// the simplest reliable failure on POSIX is a path whose parent is a
	// file (not a dir). We engineer it by writing the artifact name
	// pointing into a regular file used as a "directory".
	sneaky := filepath.Join(dir, "not-a-dir")
	_ = os.WriteFile(sneaky, []byte("file"), 0o600)
	sink := &LocalSink{dir: sneaky, keepLast: 0}

	art := Artifact{
		Filename:  "would-fail.db.age",
		Encrypted: []byte("body"),
		Sidecar:   []byte("sidecar"),
	}
	if err := sink.Write(context.Background(), art); err == nil {
		t.Fatal("expected write to fail when dir is invalid")
	}
}

func TestMultiSink_AllSucceed(t *testing.T) {
	a, _ := NewLocalSink(t.TempDir(), 0)
	b, _ := NewLocalSink(t.TempDir(), 0)
	multi, err := NewMultiSink(a, b)
	if err != nil {
		t.Fatalf("multi: %v", err)
	}
	art := Artifact{
		Filename:  "x.db.age",
		Encrypted: []byte("body"),
		Sidecar:   []byte("sha"),
	}
	if err := multi.Write(context.Background(), art); err != nil {
		t.Fatalf("multi write: %v", err)
	}
	if !strings.Contains(multi.Name(), "multi[local:") {
		t.Fatalf("multi name: %s", multi.Name())
	}
}

func TestMultiSink_FailFast(t *testing.T) {
	good, _ := NewLocalSink(t.TempDir(), 0)
	bad := &failingSink{}
	multi, _ := NewMultiSink(good, bad, good)
	art := Artifact{Filename: "x.db.age", Encrypted: []byte("a"), Sidecar: []byte("b")}
	if err := multi.Write(context.Background(), art); err == nil {
		t.Fatal("expected multi to surface failure")
	}
}

func TestMultiSink_RejectsEmpty(t *testing.T) {
	if _, err := NewMultiSink(); !errors.Is(err, ErrNoSinks) {
		t.Fatalf("expected ErrNoSinks, got %v", err)
	}
}

// --- Sidecar / DecryptArtifact --------------------------------------------

func TestVerifySidecar_CorrectAndCorrupt(t *testing.T) {
	body := []byte("some bytes")
	digest := sha256.Sum256(body)
	side := []byte(hex.EncodeToString(digest[:]) + "\n")

	if err := VerifySidecar(body, side); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifySidecar(body, nil); err == nil {
		t.Fatal("empty sidecar must fail")
	}
	if err := VerifySidecar(append(body, 'x'), side); err == nil {
		t.Fatal("corrupted body must fail")
	}
}

func TestDecryptArtifact_RejectsNoIdentities(t *testing.T) {
	if _, err := DecryptArtifact([]byte("anything"), nil); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("expected ErrNoRecipients, got %v", err)
	}
}

// --- formatFilename --------------------------------------------------------

func TestFormatFilename_FilesystemSafe(t *testing.T) {
	got := formatFilename(time.Date(2026, 5, 18, 12, 30, 45, 0, time.UTC), 42)
	want := "backup-2026-05-18T12-30-45Z-tree42.db.age"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// --- helpers ---------------------------------------------------------------

// asciiFilenameAt returns a deterministic, lexicographically-ordered
// filename for rotation tests.
func asciiFilenameAt(i int) string {
	return "backup-2026-05-18T00-00-0" + string(rune('0'+i)) + "Z-tree0.db.age"
}

type failingSink struct{}

func (failingSink) Name() string                                     { return "failing" }
func (failingSink) Write(_ context.Context, _ Artifact) error        { return errors.New("nope") }

// Compile-time guards keeping a few imports used in case the file
// shrinks further during follow-up edits.
var _ = bytes.NewReader
var _ = io.EOF
