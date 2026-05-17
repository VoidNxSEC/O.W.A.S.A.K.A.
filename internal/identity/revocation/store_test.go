package revocation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "test.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOpen_NilDB(t *testing.T) {
	if _, err := Open(nil); err == nil {
		t.Fatal("expected error for nil db")
	}
}

func TestRevoke_AndQuery(t *testing.T) {
	s, err := Open(openTestDB(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()

	if revoked, _ := s.IsRevoked(ctx, "j1"); revoked {
		t.Fatal("unknown jti should not be revoked")
	}
	if revoked, _ := s.IsRevoked(ctx, ""); revoked {
		t.Fatal("empty jti must never be revoked")
	}

	err = s.Revoke(ctx, Entry{JTI: "j1", Reason: "test"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revoked, _ := s.IsRevoked(ctx, "j1")
	if !revoked {
		t.Fatal("j1 should be revoked")
	}

	// Idempotent
	if err := s.Revoke(ctx, Entry{JTI: "j1", Reason: "twice"}); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}

	// Rejects empty JTI
	if err := s.Revoke(ctx, Entry{}); err == nil {
		t.Fatal("expected error for empty jti")
	}
}

func TestRevoke_DefaultsRevokedAt(t *testing.T) {
	s, _ := Open(openTestDB(t))
	ctx := context.Background()
	if err := s.Revoke(ctx, Entry{JTI: "j1"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 || list[0].RevokedAt.IsZero() {
		t.Fatalf("revoked_at not set: %+v", list)
	}
}

func TestList(t *testing.T) {
	s, _ := Open(openTestDB(t))
	ctx := context.Background()
	_ = s.Revoke(ctx, Entry{JTI: "j1", Reason: "a"})
	_ = s.Revoke(ctx, Entry{JTI: "j2", Reason: "b"})
	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boltie.db")

	db1, _ := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	s1, _ := Open(db1)
	_ = s1.Revoke(context.Background(), Entry{JTI: "survives"})
	_ = db1.Close()

	db2, _ := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	defer db2.Close()
	s2, err := Open(db2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	revoked, _ := s2.IsRevoked(context.Background(), "survives")
	if !revoked {
		t.Fatal("revocation did not survive reopen")
	}
}

func TestGC(t *testing.T) {
	s, _ := Open(openTestDB(t))
	ctx := context.Background()
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	_ = s.Revoke(ctx, Entry{JTI: "expired", ExpiresAt: past})
	_ = s.Revoke(ctx, Entry{JTI: "future", ExpiresAt: future})
	_ = s.Revoke(ctx, Entry{JTI: "no-expiry"}) // kept indefinitely

	n, err := s.GC(ctx, time.Now())
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 GC'd, got %d", n)
	}

	revoked, _ := s.IsRevoked(ctx, "expired")
	if revoked {
		t.Fatal("expired entry should be GC'd")
	}
	revoked, _ = s.IsRevoked(ctx, "future")
	if !revoked {
		t.Fatal("future entry should remain")
	}
	revoked, _ = s.IsRevoked(ctx, "no-expiry")
	if !revoked {
		t.Fatal("no-expiry entry should remain")
	}

	// Idempotent: second call removes nothing.
	n2, _ := s.GC(ctx, time.Now())
	if n2 != 0 {
		t.Fatalf("second gc should be noop, got %d", n2)
	}
}

func TestConcurrent(t *testing.T) {
	s, _ := Open(openTestDB(t))
	ctx := context.Background()
	const n = 200
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			jti := "jti-" + string(rune('a'+(i%26))) + string(rune('a'+(i/26%26)))
			_ = s.Revoke(ctx, Entry{JTI: jti})
			_, _ = s.IsRevoked(ctx, jti)
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
}
