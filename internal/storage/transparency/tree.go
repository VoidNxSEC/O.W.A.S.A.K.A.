package transparency

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"
)

// Tree is the transparency log's append-only Merkle tree backed by
// BoltDB. Safe for concurrent reads; writes are serialized by an
// internal mutex (BoltDB itself serializes Update txns, but we hold
// the mutex over the full append + cache update path).
//
// Storage model:
//   - leaves bucket: leafIndex (8-byte BE) → JSON-serialized Leaf
//   - leaf hashes are computed on Append and cached in memory; the
//     full slice is rehydrated on Open for fast root + proof computation
//     up to operationally-relevant tree sizes (10^4–10^6 leaves).
//   - sth bucket: the latest STH; per-size history in sthHistory bucket.
//
// At the scale of a SIEM's critical events (single-digit per minute
// peak), keeping leaf hashes in memory is O(megabytes). For deployments
// that exceed memory budgets the implementation can be swapped for a
// compact-range cache without changing the public API.
type Tree struct {
	db *bolt.DB

	mu     sync.RWMutex
	hashes []RootHash // index = leaf index
}

// Open attaches a Tree to an already-open BoltDB handle. Creates the
// transparency buckets if needed and primes the in-memory leaf hash
// cache from disk. Idempotent: Open can be called multiple times
// against the same DB.
func Open(db *bolt.DB) (*Tree, error) {
	if db == nil {
		return nil, errors.New("transparency: nil bolt db")
	}
	t := &Tree{db: db}

	err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{BucketLeaves, BucketNodes, BucketSTH, BucketSTHHistory} {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("transparency: bootstrap: %w", err)
	}

	if err := t.rehydrate(); err != nil {
		return nil, err
	}
	return t, nil
}

// rehydrate scans the leaves bucket and rebuilds the in-memory hash
// slice. Run on Open and on demand for diagnostics.
func (t *Tree) rehydrate() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hashes = t.hashes[:0]

	return t.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketLeaves))
		// Bolt's ForEach iterates keys in sorted byte order; with
		// 8-byte big-endian indices that's the leaf order we want.
		return b.ForEach(func(_, v []byte) error {
			var leaf Leaf
			if err := json.Unmarshal(v, &leaf); err != nil {
				return fmt.Errorf("%w: leaf decode: %v", ErrCorruptedTree, err)
			}
			t.hashes = append(t.hashes, HashLeaf(leaf.Payload))
			return nil
		})
	})
}

// Append writes a new leaf and returns its 0-based index. The leaf's
// payload feeds the leaf hash; metadata (Kind, Timestamp) is persisted
// alongside but not hashed.
//
// Callers typically follow up with ComputeSTH to produce a fresh STH.
func (t *Tree) Append(ctx context.Context, leaf Leaf) (LeafIndex, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	idx := uint64(len(t.hashes))

	key := encodeIndex(idx)
	payload, err := json.Marshal(leaf)
	if err != nil {
		return 0, fmt.Errorf("transparency: marshal leaf: %w", err)
	}
	err = t.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketLeaves))
		return b.Put(key, payload)
	})
	if err != nil {
		return 0, err
	}
	t.hashes = append(t.hashes, HashLeaf(leaf.Payload))
	return LeafIndex(idx), nil
}

// Size returns the current tree size (count of leaves appended).
func (t *Tree) Size() TreeSize {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return TreeSize(len(t.hashes))
}

// Root returns the Merkle root for the current tree size. Empty tree
// returns the canonical RFC 6962 empty root.
func (t *Tree) Root() RootHash {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.hashes) == 0 {
		return EmptyRoot()
	}
	return MerkleTreeHash(t.hashes)
}

// RootAt returns the Merkle root for the tree as it would have been
// at `size`. Used by STH history queries and consistency proofs.
//
// Returns ErrTreeSizeMismatch if size > current.
func (t *Tree) RootAt(size TreeSize) (RootHash, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if uint64(size) > uint64(len(t.hashes)) {
		return RootHash{}, ErrTreeSizeMismatch
	}
	if size == 0 {
		return EmptyRoot(), nil
	}
	return MerkleTreeHash(t.hashes[:size]), nil
}

// LeafAt returns the persisted Leaf for an index. Useful for the
// HTTP /leaf?index endpoint and the demo's tamper-detection step.
func (t *Tree) LeafAt(idx LeafIndex) (Leaf, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if uint64(idx) >= uint64(len(t.hashes)) {
		return Leaf{}, ErrLeafIndexOutOfRange
	}
	var out Leaf
	err := t.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketLeaves))
		raw := b.Get(encodeIndex(uint64(idx)))
		if raw == nil {
			return ErrLeafIndexOutOfRange
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

// InclusionProof returns the audit path proving leaf m is in the tree
// of size n. Both indices are validated; the proof verifies against
// the root at size n.
func (t *Tree) InclusionProof(m LeafIndex, n TreeSize) (Proof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if uint64(n) > uint64(len(t.hashes)) {
		return nil, ErrTreeSizeMismatch
	}
	if uint64(m) >= uint64(n) {
		return nil, ErrLeafIndexOutOfRange
	}
	return InclusionProof(uint64(m), t.hashes[:n]), nil
}

// ConsistencyProof returns the audit nodes proving that the tree at
// size `second` is a consistent extension of the tree at size `first`.
func (t *Tree) ConsistencyProof(first, second TreeSize) (Proof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if uint64(second) > uint64(len(t.hashes)) || first > second || first == 0 {
		return nil, ErrConsistencyRange
	}
	return ConsistencyProof(uint64(first), uint64(second), t.hashes[:second]), nil
}

// encodeIndex serializes a leaf index as big-endian 8 bytes so BoltDB
// sorts keys in leaf order naturally.
func encodeIndex(idx uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, idx)
	return b
}
