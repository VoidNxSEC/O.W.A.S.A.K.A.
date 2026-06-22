package db

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
	bolt "go.etcd.io/bbolt"
)

const (
	// BucketAssets holds our parsed physical and network assets
	BucketAssets = "assets"
	// BucketEvents holds a stream of observational data
	BucketEvents = "events"
	// BucketCanaryTokens holds planted DNS/HTTP decoy tokens
	BucketCanaryTokens = "canary_tokens"
)

// Database wraps the boltdb subsystem
type Database struct {
	db     *bolt.DB
	logger *logging.Logger
}

// New constructs, opens, and ensures bucket initialization
func New(cfg *config.LocalStorageConfig, logger *logging.Logger) (*Database, error) {
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "owasaka.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open boltdb at %s: %w", dbPath, err)
	}

	// Initialize buckets safely in one write transaction
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(BucketAssets)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(BucketEvents)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(BucketCanaryTokens)); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to verify initial buckets: %w", err)
	}

	logger.Infow("BoltDB Persistence Engine Initialized", "path", dbPath)
	return &Database{db: db, logger: logger}, nil
}

// Close strictly releases the file lock
func (d *Database) Close() error {
	d.logger.Info("Closing BoltDB Engine")
	return d.db.Close()
}

// DB returns the underlying *bolt.DB. Exposed for subsystems that
// need direct access (migrations, transparency tree, backup engine,
// retention sweeps, health probes). Callers must not Close it — the
// Database owns the lifetime.
func (d *Database) DB() *bolt.DB {
	return d.db
}

// Healthy reports whether the database can service a read transaction.
// Used by the health probe; runs a no-op view tx to confirm the file
// lock is still held and the file is not corrupted.
func (d *Database) Healthy() error {
	if d == nil || d.db == nil {
		return fmt.Errorf("database not initialized")
	}
	return d.db.View(func(tx *bolt.Tx) error {
		_ = tx.Bucket([]byte(BucketEvents))
		return nil
	})
}
