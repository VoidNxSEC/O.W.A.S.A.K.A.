package migrations

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "test.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAppliedID_FreshDB(t *testing.T) {
	db := openTestDB(t)
	id, err := AppliedID(db)
	if err != nil {
		t.Fatalf("applied id: %v", err)
	}
	if id != 0 {
		t.Fatalf("fresh DB applied id should be 0, got %d", id)
	}
}

func TestAvailableID_ReflectsRegistry(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "first", Up: noopUp},
		{ID: 7, Description: "seventh", Up: noopUp},
		{ID: 3, Description: "third", Up: noopUp},
	})
	defer restore()
	if got := AvailableID(); got != 7 {
		t.Fatalf("expected 7, got %d", got)
	}
}

func TestRegister_DuplicateIDPanics(t *testing.T) {
	restore := swapRegistry(nil)
	defer restore()

	Register(Migration{ID: 1, Up: noopUp, Description: "first"})
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate ID")
		}
	}()
	Register(Migration{ID: 1, Up: noopUp, Description: "first-dup"})
}

func TestRunUp_AppliesPendingInOrder(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "create alpha", Up: createBucket("alpha")},
		{ID: 2, Description: "create beta", Up: createBucket("beta")},
		{ID: 3, Description: "create gamma", Up: createBucket("gamma")},
	})
	defer restore()

	db := openTestDB(t)
	applied, err := RunUp(db)
	if err != nil {
		t.Fatalf("run up: %v", err)
	}
	if applied != 3 {
		t.Fatalf("expected applied=3, got %d", applied)
	}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if !bucketExists(db, name) {
			t.Errorf("bucket %s missing after RunUp", name)
		}
	}
}

func TestRunUp_NoPendingIsNoop(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Up: noopUp, Description: "first"},
	})
	defer restore()

	db := openTestDB(t)
	_, _ = RunUp(db) // bring to applied=1
	applied, err := RunUp(db)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if applied != 1 {
		t.Fatalf("expected applied=1 (no new), got %d", applied)
	}
}

func TestRunUp_DowngradeRefused(t *testing.T) {
	// Apply with extended registry...
	extended := []Migration{
		{ID: 1, Up: noopUp, Description: "first"},
		{ID: 2, Up: noopUp, Description: "second"},
	}
	restore := swapRegistry(extended)
	db := openTestDB(t)
	_, _ = RunUp(db)
	restore()

	// ...then "downgrade" the binary to only know about migration 1.
	restore = swapRegistry([]Migration{{ID: 1, Up: noopUp, Description: "first"}})
	defer restore()

	if _, err := RunUp(db); !errors.Is(err, ErrDowngradeDetected) {
		t.Fatalf("expected ErrDowngradeDetected, got %v", err)
	}
}

func TestRunUp_FailingMigrationRollsBack(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "create alpha", Up: createBucket("alpha")},
		{ID: 2, Description: "failing", Up: func(tx *bolt.Tx) error {
			_, _ = tx.CreateBucketIfNotExists([]byte("uncommitted"))
			return errors.New("intentional")
		}},
	})
	defer restore()

	db := openTestDB(t)
	_, err := RunUp(db)
	if err == nil {
		t.Fatal("expected error from failing migration")
	}
	if !bucketExists(db, "alpha") {
		t.Fatal("migration 1 should have committed")
	}
	if bucketExists(db, "uncommitted") {
		t.Fatal("failing migration 2 must not leave its work behind")
	}
	id, _ := AppliedID(db)
	if id != 1 {
		t.Fatalf("applied id should rest at 1 after failure, got %d", id)
	}
}

func TestRunUp_MigrationWithoutUpFunctionRefused(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "no up", Up: nil},
	})
	defer restore()
	db := openTestDB(t)
	if _, err := RunUp(db); err == nil {
		t.Fatal("expected error for nil Up")
	}
}

func TestRunDown_ReversesHighestApplied(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "first", Up: createBucket("alpha"), Down: deleteBucket("alpha")},
		{ID: 2, Description: "second", Up: createBucket("beta"), Down: deleteBucket("beta")},
	})
	defer restore()

	db := openTestDB(t)
	_, _ = RunUp(db)

	newApplied, err := RunDown(db)
	if err != nil {
		t.Fatalf("run down: %v", err)
	}
	if newApplied != 1 {
		t.Fatalf("expected applied=1 after down, got %d", newApplied)
	}
	if bucketExists(db, "beta") {
		t.Fatal("down should have removed beta")
	}
	if !bucketExists(db, "alpha") {
		t.Fatal("down must not touch lower migrations")
	}
}

func TestRunDown_IrreversibleRefused(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "irreversible", Up: createBucket("alpha"), Down: nil},
	})
	defer restore()

	db := openTestDB(t)
	_, _ = RunUp(db)

	_, err := RunDown(db)
	if err == nil || !strings.Contains(err.Error(), "irreversible") {
		t.Fatalf("expected irreversible error, got %v", err)
	}
}

func TestRunDown_NothingApplied(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "first", Up: noopUp},
	})
	defer restore()

	db := openTestDB(t)
	if _, err := RunDown(db); err == nil {
		t.Fatal("expected error on RunDown with nothing applied")
	}
}

func TestCheckBoot_AutoMigrateApplies(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "create alpha", Up: createBucket("alpha")},
	})
	defer restore()

	db := openTestDB(t)
	if err := CheckBoot(db, true); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	if !bucketExists(db, "alpha") {
		t.Fatal("auto-migrate didn't run the migration")
	}
}

func TestCheckBoot_PendingRefusedWithoutAuto(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "create alpha", Up: createBucket("alpha")},
	})
	defer restore()

	db := openTestDB(t)
	err := CheckBoot(db, false)
	if !errors.Is(err, ErrPendingMigrations) {
		t.Fatalf("expected ErrPendingMigrations, got %v", err)
	}
	if bucketExists(db, "alpha") {
		t.Fatal("CheckBoot must not apply migrations when auto is false")
	}
}

func TestCheckBoot_NoPendingNoop(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Description: "first", Up: noopUp},
	})
	defer restore()
	db := openTestDB(t)
	_, _ = RunUp(db)
	if err := CheckBoot(db, false); err != nil {
		t.Fatalf("no pending should not error, got %v", err)
	}
}

func TestCheckBoot_EmptyRegistryNoop(t *testing.T) {
	restore := swapRegistry(nil)
	defer restore()
	db := openTestDB(t)
	if err := CheckBoot(db, false); err != nil {
		t.Fatalf("empty registry should pass, got %v", err)
	}
}

func TestCurrentStatus_ReportsPending(t *testing.T) {
	restore := swapRegistry([]Migration{
		{ID: 1, Up: noopUp, Description: "first"},
		{ID: 2, Up: noopUp, Description: "second"},
		{ID: 3, Up: noopUp, Description: "third"},
	})
	defer restore()

	db := openTestDB(t)
	_, _ = RunUp(db)
	// "Reset" the applied id artificially to simulate a partially-
	// applied state then check Status.

	// Manually rewind applied id to 1 to mimic a partial application.
	_ = db.Update(func(tx *bolt.Tx) error {
		return writeAppliedID(tx, 1)
	})

	status, err := CurrentStatus(db)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Applied != 1 || status.Available != 3 || len(status.Pending) != 2 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestInitialMigration_Registered(t *testing.T) {
	// The shipped 0001_initial migration must be registered when the
	// package is imported normally. swapRegistry is reset.
	all := All()
	var found bool
	for _, m := range all {
		if m.ID == 1 && strings.Contains(m.Description, "initial schema") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("0001_initial migration must be in the registry")
	}
}

func TestInitialMigration_CreatesAllBuckets(t *testing.T) {
	db := openTestDB(t)
	if err := CheckBoot(db, true); err != nil {
		t.Fatalf("auto-migrate: %v", err)
	}
	for _, name := range initialBuckets {
		if !bucketExists(db, name) {
			t.Errorf("initial migration must create bucket %s", name)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func noopUp(_ *bolt.Tx) error { return nil }

func createBucket(name string) func(*bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(name))
		return err
	}
}

func deleteBucket(name string) func(*bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte(name))
	}
}

func bucketExists(db *bolt.DB, name string) bool {
	var exists bool
	_ = db.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket([]byte(name)) != nil
		return nil
	})
	return exists
}
