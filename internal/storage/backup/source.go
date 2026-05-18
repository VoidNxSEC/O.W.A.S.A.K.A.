package backup

import (
	"context"
	"encoding/hex"
	"fmt"

	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
)

// BoltSource adapts a *bbolt.DB to the Source interface. The backup
// runs inside a read transaction (Tx.WriteTo), so writers see a
// short read-lock pause but no data inconsistency.
//
// If a non-nil Tree is supplied, BackupMetadata exposes the
// transparency log's current state at backup time, so restore-side
// operators can compare against their journal record.
type BoltSource struct {
	DB   *bolt.DB
	Tree *transparency.Tree // optional
}

// NewBoltSource builds a BoltSource. Tree may be nil if the
// deployment hasn't yet wired the transparency log.
func NewBoltSource(db *bolt.DB, tree *transparency.Tree) *BoltSource {
	return &BoltSource{DB: db, Tree: tree}
}

// WriteTo implements Source. Streams the entire database file
// through `write` (typically appending to a bytes.Buffer for
// in-process encryption).
func (s *BoltSource) WriteTo(ctx context.Context, write func(p []byte) (int, error)) (int64, error) {
	if s.DB == nil {
		return 0, fmt.Errorf("backup: bolt source has no DB")
	}
	var total int64
	err := s.DB.View(func(tx *bolt.Tx) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		n, err := tx.WriteTo(writerFunc(write))
		total = n
		return err
	})
	return total, err
}

// BackupMetadata exposes the transparency log's tree size + root at
// the moment of backup. If Tree is nil, returns zeros silently —
// not an error, just "no transparency state to snapshot".
func (s *BoltSource) BackupMetadata(_ context.Context) (uint64, string, error) {
	if s.Tree == nil {
		return 0, "", nil
	}
	size := s.Tree.Size()
	root := s.Tree.Root()
	return uint64(size), hex.EncodeToString(root[:]), nil
}

// writerFunc adapts a func(p []byte) (int, error) into io.Writer so
// callers can pass closures (e.g., bytes.Buffer.Write) without
// converting back and forth.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
