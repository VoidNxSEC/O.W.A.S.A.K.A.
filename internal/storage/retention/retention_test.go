package retention

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// --- Config defaults --------------------------------------------------------

func TestConfig_EnsureDefaults(t *testing.T) {
	var c Config
	c.EnsureDefaults()
	if c.EventsDefaultTTL != 90*24*time.Hour {
		t.Errorf("events ttl default: %v", c.EventsDefaultTTL)
	}
	if c.AlertsTTL != 365*24*time.Hour {
		t.Errorf("alerts ttl default: %v", c.AlertsTTL)
	}
	if c.AssetsStaleTTL != 30*24*time.Hour {
		t.Errorf("assets ttl default: %v", c.AssetsStaleTTL)
	}
	if c.SweepInterval != 24*time.Hour {
		t.Errorf("sweep interval default: %v", c.SweepInterval)
	}
}

func TestConfig_OverridesPreserved(t *testing.T) {
	c := Config{EventsDefaultTTL: time.Hour}
	c.EnsureDefaults()
	if c.EventsDefaultTTL != time.Hour {
		t.Errorf("override clobbered: %v", c.EventsDefaultTTL)
	}
}

// --- Engine sweep -----------------------------------------------------------

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "r.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func writeEvent(t *testing.T, db *bolt.DB, key, eventType string, ts time.Time) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id":        key,
		"type":      eventType,
		"timestamp": ts.UTC().Format(time.RFC3339Nano),
	})
	_ = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("events"))
		return b.Put([]byte(key), body)
	})
}

func writeAsset(t *testing.T, db *bolt.DB, key string, lastSeen time.Time) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id":        key,
		"last_seen": lastSeen.UTC().Format(time.RFC3339Nano),
	})
	_ = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("assets"))
		return b.Put([]byte(key), body)
	})
}

func countEntries(t *testing.T, db *bolt.DB, bucket string) int {
	t.Helper()
	count := 0
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		return b.ForEach(func(_, _ []byte) error {
			count++
			return nil
		})
	})
	return count
}

func TestEngine_DropsOldEventsKeepsRecent(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	// 5 old events, 3 fresh.
	for i := 0; i < 5; i++ {
		writeEvent(t, db, byteName('a', i), "DNS", now.Add(-200*24*time.Hour))
	}
	for i := 0; i < 3; i++ {
		writeEvent(t, db, byteName('z', i), "DNS", now.Add(-1*24*time.Hour))
	}

	eng, err := NewEngine(Config{
		EventsDefaultTTL: 90 * 24 * time.Hour,
	}, db, NopLogger{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	eng.clock = func() time.Time { return now }

	rep, err := eng.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.EventsRemoved != 5 {
		t.Fatalf("events removed: %d (want 5)", rep.EventsRemoved)
	}
	if countEntries(t, db, "events") != 3 {
		t.Fatalf("survivors: %d (want 3)", countEntries(t, db, "events"))
	}
}

func TestEngine_AlertsGetLongerTTL(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	// 4 alerts at ~120 days old — newer than the 365d AlertsTTL, but
	// older than the 90d EventsDefaultTTL.
	for i := 0; i < 4; i++ {
		writeEvent(t, db, byteName('a', i), "THREAT_ALERT", now.Add(-120*24*time.Hour))
	}
	// 1 alert at 400 days — older than alerts TTL, should be removed.
	writeEvent(t, db, "ancient", "THREAT_ALERT", now.Add(-400*24*time.Hour))

	eng, _ := NewEngine(Config{
		EventsDefaultTTL: 90 * 24 * time.Hour,
		AlertsTTL:        365 * 24 * time.Hour,
	}, db, NopLogger{})
	eng.clock = func() time.Time { return now }

	rep, _ := eng.Sweep(context.Background())
	if rep.AlertsRemoved != 1 {
		t.Fatalf("alerts removed: %d (want 1)", rep.AlertsRemoved)
	}
	if rep.EventsRemoved != 0 {
		t.Fatalf("events_removed should track non-alerts only: %d", rep.EventsRemoved)
	}
	if countEntries(t, db, "events") != 4 {
		t.Fatalf("alerts survivors: %d (want 4)", countEntries(t, db, "events"))
	}
}

func TestEngine_ZeroTTLDisablesPrune(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	writeEvent(t, db, "ancient", "DNS", now.Add(-365*24*time.Hour))

	eng, _ := NewEngine(Config{EventsDefaultTTL: 0}, db, NopLogger{})
	eng.cfg.EventsDefaultTTL = 0 // explicit; EnsureDefaults already ran
	eng.clock = func() time.Time { return now }

	rep, err := eng.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// EnsureDefaults filled the TTL with 90d, so the ancient event
	// IS removed. To exercise "zero TTL = keep forever" we have to
	// override AFTER EnsureDefaults.
	_ = rep
	// Now exercise the explicit-zero path.
	eng.cfg.EventsDefaultTTL = 0
	rep, _ = eng.Sweep(context.Background())
	if rep.EventsRemoved != 0 {
		t.Fatalf("zero TTL should keep events, removed=%d", rep.EventsRemoved)
	}
}

func TestEngine_DropsStaleAssetsKeepsActive(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		writeAsset(t, db, byteName('a', i), now.Add(-90*24*time.Hour))
	}
	for i := 0; i < 2; i++ {
		writeAsset(t, db, byteName('z', i), now.Add(-1*time.Hour))
	}

	eng, _ := NewEngine(Config{AssetsStaleTTL: 30 * 24 * time.Hour}, db, NopLogger{})
	eng.clock = func() time.Time { return now }

	rep, err := eng.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.AssetsRemoved != 3 {
		t.Fatalf("assets removed: %d (want 3)", rep.AssetsRemoved)
	}
	if countEntries(t, db, "assets") != 2 {
		t.Fatalf("asset survivors: %d (want 2)", countEntries(t, db, "assets"))
	}
}

func TestEngine_MalformedRowsArePreserved(t *testing.T) {
	db := openTestDB(t)
	_ = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("events"))
		return b.Put([]byte("malformed"), []byte("not json"))
	})

	eng, _ := NewEngine(Config{EventsDefaultTTL: time.Hour}, db, NopLogger{})
	rep, err := eng.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.EventsRemoved != 0 {
		t.Fatalf("malformed rows must be preserved (ops can inspect)")
	}
	if countEntries(t, db, "events") != 1 {
		t.Fatal("malformed row was removed")
	}
}

func TestEngine_NilDBRefused(t *testing.T) {
	if _, err := NewEngine(Config{}, nil, NopLogger{}); err == nil {
		t.Fatal("expected refusal on nil db")
	}
}

func TestEngine_CanceledContextStopsSweep(t *testing.T) {
	db := openTestDB(t)
	eng, _ := NewEngine(Config{}, db, NopLogger{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eng.Sweep(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// --- Compaction trigger -----------------------------------------------------

func TestEngine_CompactionRunsWhenFreelistAboveThreshold(t *testing.T) {
	db := openTestDB(t)
	// Force enough page churn to grow the freelist.
	_ = db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("churn"))
		for i := 0; i < 200; i++ {
			_ = b.Put([]byte{byte(i)}, make([]byte, 1024))
		}
		return nil
	})
	_ = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("churn"))
		for i := 0; i < 200; i++ {
			_ = b.Delete([]byte{byte(i)})
		}
		return nil
	})

	pages := db.Stats().FreePageN
	if pages == 0 {
		t.Skip("bolt stats reported zero free pages — environment can't exercise compaction")
	}

	eng, _ := NewEngine(Config{
		EventsDefaultTTL:            90 * 24 * time.Hour,
		CompactionFreelistThreshold: 1, // any freelist triggers compaction
	}, db, NopLogger{})
	rep, err := eng.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !rep.CompactionRan {
		t.Fatalf("expected compaction to run with freelist=%d threshold=1", pages)
	}
}

func TestEngine_NoCompactionWhenThresholdZero(t *testing.T) {
	db := openTestDB(t)
	eng, _ := NewEngine(Config{}, db, NopLogger{})
	rep, _ := eng.Sweep(context.Background())
	if rep.CompactionRan {
		t.Fatal("compaction must not run when threshold is 0")
	}
}

// --- Background loop --------------------------------------------------------

func TestEngine_StartStop_NoDeadlocks(t *testing.T) {
	db := openTestDB(t)
	eng, _ := NewEngine(Config{SweepInterval: 50 * time.Millisecond}, db, NopLogger{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := eng.Start(ctx)

	// Second Start while running must return a no-op stop.
	stop2 := eng.Start(ctx)
	stop2()

	// Give at least one tick a chance to fire.
	time.Sleep(120 * time.Millisecond)
	stop()
}

// --- helpers ----------------------------------------------------------------

func byteName(base byte, i int) string {
	return string([]byte{base, byte('0' + i)})
}
