package migrations

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// RunUp applies every pending migration in monotonically-increasing
// ID order. Each migration runs inside its own bolt.Update tx so
// failures roll back cleanly. The applied-ID is persisted in the
// same tx as the migration body, so a partial run leaves the DB
// at a consistent intermediate state.
//
// Returns the highest ID applied during this call (0 if no
// migrations ran).
func RunUp(db *bolt.DB) (uint32, error) {
	if db == nil {
		return 0, errors.New("migrations: nil db")
	}
	if err := EnsureBucket(db); err != nil {
		return 0, err
	}

	status, err := CurrentStatus(db)
	if err != nil {
		return 0, err
	}
	if status.Applied > status.Available {
		return 0, ErrDowngradeDetected
	}
	if len(status.Pending) == 0 {
		return status.Applied, nil
	}

	var lastApplied uint32
	for _, m := range status.Pending {
		if m.Up == nil {
			return lastApplied, fmt.Errorf("migrations: ID %d (%q) has no Up function", m.ID, m.Description)
		}
		err := db.Update(func(tx *bolt.Tx) error {
			if err := m.Up(tx); err != nil {
				return fmt.Errorf("migrations: ID %d up: %w", m.ID, err)
			}
			return writeAppliedID(tx, m.ID)
		})
		if err != nil {
			return lastApplied, err
		}
		lastApplied = m.ID
	}
	return lastApplied, nil
}

// RunDown reverts the highest-applied migration. Operators run this
// explicitly with --force; routine ops never invoke it. Returns the
// new applied-ID after the revert.
//
// Migrations without a Down function refuse to revert (returns
// "irreversible migration").
func RunDown(db *bolt.DB) (uint32, error) {
	if db == nil {
		return 0, errors.New("migrations: nil db")
	}

	status, err := CurrentStatus(db)
	if err != nil {
		return 0, err
	}
	if status.Applied == 0 {
		return 0, errors.New("migrations: no applied migration to revert")
	}

	all := All()
	var target *Migration
	for i := range all {
		if all[i].ID == status.Applied {
			target = &all[i]
			break
		}
	}
	if target == nil {
		return status.Applied, fmt.Errorf("%w: applied id %d", ErrUnknownMigration, status.Applied)
	}
	if target.Down == nil {
		return status.Applied, fmt.Errorf("migrations: ID %d (%q) is irreversible", target.ID, target.Description)
	}

	var newApplied uint32
	for _, m := range all {
		if m.ID < target.ID && m.ID > newApplied {
			newApplied = m.ID
		}
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if err := target.Down(tx); err != nil {
			return fmt.Errorf("migrations: ID %d down: %w", target.ID, err)
		}
		return writeAppliedID(tx, newApplied)
	})
	if err != nil {
		return status.Applied, err
	}
	return newApplied, nil
}

// CheckBoot is the gate called at app startup. Returns:
//
//   - nil + no migrations needed (Applied == Available or registry empty)
//   - ErrPendingMigrations if Applied < Available and autoMigrate is false
//   - ErrDowngradeDetected if Applied > Available (always fatal)
//
// When autoMigrate is true and migrations are pending, the function
// applies them via RunUp and returns nil. Callers wire `--auto-migrate`
// CLI flag (or `OSWAKA_AUTO_MIGRATE=1` env) to true; production
// deployments leave it false so operators run migrations deliberately.
func CheckBoot(db *bolt.DB, autoMigrate bool) error {
	if db == nil {
		return errors.New("migrations: nil db")
	}
	if err := EnsureBucket(db); err != nil {
		return err
	}
	status, err := CurrentStatus(db)
	if err != nil {
		return err
	}
	if status.Applied > status.Available {
		return ErrDowngradeDetected
	}
	if len(status.Pending) == 0 {
		return nil
	}
	if !autoMigrate {
		return fmt.Errorf("%w (have %d pending: %s)",
			ErrPendingMigrations, len(status.Pending), describePending(status.Pending))
	}
	_, err = RunUp(db)
	return err
}

func describePending(pending []Migration) string {
	if len(pending) == 0 {
		return ""
	}
	if len(pending) == 1 {
		return fmt.Sprintf("ID %d %q", pending[0].ID, pending[0].Description)
	}
	return fmt.Sprintf("ID %d through %d", pending[0].ID, pending[len(pending)-1].ID)
}
