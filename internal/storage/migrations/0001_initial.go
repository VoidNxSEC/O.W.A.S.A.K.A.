package migrations

import (
	bolt "go.etcd.io/bbolt"
)

// initialBuckets is the canonical list of top-level buckets the
// OWASAKA binary expects after the foundation sprints (1-3). It is
// the codification of what Sprints 1-3 created implicitly inside
// CreateBucketIfNotExists calls scattered across packages.
//
// Future migrations append-only this list; never remove a name once
// shipped (the migration history is immutable).
var initialBuckets = []string{
	// Sprint 0 / pre-existing (db.go)
	"assets",
	"events",

	// Sprint 1 — identity / authorization
	"auth.revoked",     // internal/identity/revocation
	"audit.api.access", // RBAC audit log groundwork (Sprint 5 expands)

	// Sprint 3 — transparency log
	"transparency.leaves",
	"transparency.nodes",
	"transparency.sth",
	"transparency.sth.history",
}

func init() {
	Register(Migration{
		ID:          1,
		Description: "initial schema — events, assets, identity, transparency log",
		Up: func(tx *bolt.Tx) error {
			for _, name := range initialBuckets {
				if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
					return err
				}
			}
			return nil
		},
		// Migration 1 is the foundation; reverting it would empty the
		// database. Refuse explicitly so operators don't accidentally
		// wipe state with `oswaka migrate down --force` from a
		// freshly-initialized DB.
		Down: nil,
	})
}
