package pki

import (
	"context"
	"sync"
)

// KeyStore persists KeyPairs and their lifecycle transitions.
//
// Implementations must be safe for concurrent use. The default
// MemoryKeyStore is fine for tests and short-lived processes; production
// deployments wrap a BoltDB-backed store (delivered in T8).
type KeyStore interface {
	Get(ctx context.Context, id string) (*KeyPair, error)

	// FindByPurpose returns all keys for a given purpose, regardless of
	// status. Callers filter by Status as needed.
	FindByPurpose(ctx context.Context, purpose Purpose) ([]*KeyPair, error)

	// ActiveByPurpose returns the single active key for a purpose, or
	// ErrNoActiveKey if none is active.
	ActiveByPurpose(ctx context.Context, purpose Purpose) (*KeyPair, error)

	Save(ctx context.Context, kp *KeyPair) error
	UpdateStatus(ctx context.Context, id string, status KeyStatus) error
}

// MemoryKeyStore is an in-process KeyStore. Safe for concurrent use.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*KeyPair
}

// NewMemoryKeyStore returns an empty in-memory store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{keys: make(map[string]*KeyPair)}
}

func (s *MemoryKeyStore) Get(_ context.Context, id string) (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kp, ok := s.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return kp, nil
}

func (s *MemoryKeyStore) FindByPurpose(_ context.Context, purpose Purpose) ([]*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*KeyPair
	for _, kp := range s.keys {
		if kp.Purpose == purpose {
			out = append(out, kp)
		}
	}
	return out, nil
}

func (s *MemoryKeyStore) ActiveByPurpose(_ context.Context, purpose Purpose) (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, kp := range s.keys {
		if kp.Purpose == purpose && kp.Status == StatusKeyActive {
			return kp, nil
		}
	}
	return nil, ErrNoActiveKey
}

func (s *MemoryKeyStore) Save(_ context.Context, kp *KeyPair) error {
	if kp == nil || kp.ID == "" {
		return ErrKeyNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[kp.ID] = kp
	return nil
}

func (s *MemoryKeyStore) UpdateStatus(_ context.Context, id string, status KeyStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kp, ok := s.keys[id]
	if !ok {
		return ErrKeyNotFound
	}
	kp.Status = status
	return nil
}
