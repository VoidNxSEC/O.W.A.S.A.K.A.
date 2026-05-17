// Package revocation maintains the OWASAKA token revocation denylist.
//
// Per ADR-0059, JWT tokens are revoked by JTI. The denylist is
// persistent (survives restart) and audit-trail bearing. Reads are
// O(1) via an in-memory hash cache; writes are durably persisted
// before the call returns.
package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket is the BoltDB bucket name where revoked-JTI records live.
const Bucket = "auth.revoked"

// Entry describes a single revocation event.
type Entry struct {
	JTI       string    `json:"jti"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
	RevokedBy string    `json:"revoked_by,omitempty"` // principal id of the revoker
	ExpiresAt time.Time `json:"expires_at,omitempty"` // original token expiry — after this we can GC
}

// Store is the public interface for the revocation denylist.
type Store interface {
	Revoke(ctx context.Context, entry Entry) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	List(ctx context.Context) ([]Entry, error)
	GC(ctx context.Context, now time.Time) (int, error)
}

// BoltStore persists revocations in BoltDB with an in-memory hash cache.
//
// The cache mirrors the on-disk denylist; it is loaded on Open and
// updated synchronously on each Revoke. IsRevoked never touches BoltDB
// after startup, keeping the hot path allocation-free.
type BoltStore struct {
	db    *bolt.DB
	mu    sync.RWMutex
	cache map[string]struct{}
}

// Open attaches a BoltStore to an already-open BoltDB handle. Creates
// the revocation bucket if it does not exist and primes the in-memory
// cache from the persisted contents.
func Open(db *bolt.DB) (*BoltStore, error) {
	if db == nil {
		return nil, errors.New("revocation: nil bolt db")
	}
	s := &BoltStore{db: db, cache: make(map[string]struct{})}
	err := db.Update(func(tx *bolt.Tx) error {
		bkt, err := tx.CreateBucketIfNotExists([]byte(Bucket))
		if err != nil {
			return err
		}
		return bkt.ForEach(func(k, _ []byte) error {
			s.cache[string(k)] = struct{}{}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("revocation: bootstrap cache: %w", err)
	}
	return s, nil
}

// Revoke marks a JTI as revoked, persisting durably and updating cache.
//
// Idempotent: revoking an already-revoked JTI is a no-op and returns
// nil. The first revocation is kept (we don't overwrite with later
// reasons) so audit history remains stable.
func (s *BoltStore) Revoke(_ context.Context, entry Entry) error {
	if entry.JTI == "" {
		return errors.New("revocation: jti required")
	}
	if entry.RevokedAt.IsZero() {
		entry.RevokedAt = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[entry.JTI]; ok {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("revocation: marshal: %w", err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(Bucket))
		// Don't overwrite an existing entry — keep first-revoke audit.
		if existing := bkt.Get([]byte(entry.JTI)); existing != nil {
			return nil
		}
		return bkt.Put([]byte(entry.JTI), data)
	})
	if err != nil {
		return fmt.Errorf("revocation: persist: %w", err)
	}
	s.cache[entry.JTI] = struct{}{}
	return nil
}

// IsRevoked checks the in-memory cache. O(1) and lock-only.
func (s *BoltStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, nil
	}
	s.mu.RLock()
	_, ok := s.cache[jti]
	s.mu.RUnlock()
	return ok, nil
}

// List returns all current revocations in arbitrary order. Used for
// audit and GC.
func (s *BoltStore) List(_ context.Context) ([]Entry, error) {
	var out []Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(Bucket))
		return bkt.ForEach(func(_, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GC removes revocation entries whose ExpiresAt has passed. Returns the
// number of entries dropped. Safe to call periodically.
//
// Entries without ExpiresAt are kept indefinitely — useful for long-term
// audit of compromised credentials.
func (s *BoltStore) GC(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []string
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(Bucket))
		return bkt.ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
				toDelete = append(toDelete, string(k))
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	if len(toDelete) == 0 {
		return 0, nil
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(Bucket))
		for _, k := range toDelete {
			if err := bkt.Delete([]byte(k)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, k := range toDelete {
		delete(s.cache, k)
	}
	return len(toDelete), nil
}
