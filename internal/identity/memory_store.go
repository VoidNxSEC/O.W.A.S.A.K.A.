package identity

import (
	"context"
	"sync"
	"time"
)

// MemoryPrincipalStore is an in-process PrincipalStore.
//
// Suitable for tests and dev mode. Production deployments swap in a
// BoltDB-backed implementation (Sprint 1 T8 lays the groundwork; the
// dedicated store lands as part of the data-layer hardening in Sprint 4).
type MemoryPrincipalStore struct {
	mu        sync.RWMutex
	byID      map[string]*Principal
	bySubject map[string]string // subject → id
}

// NewMemoryPrincipalStore returns an empty in-memory PrincipalStore.
func NewMemoryPrincipalStore() *MemoryPrincipalStore {
	return &MemoryPrincipalStore{
		byID:      make(map[string]*Principal),
		bySubject: make(map[string]string),
	}
}

func (s *MemoryPrincipalStore) Get(_ context.Context, id string) (*Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.byID[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return p, nil
}

func (s *MemoryPrincipalStore) FindBySubject(_ context.Context, subject string) (*Principal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.bySubject[subject]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return s.byID[id], nil
}

func (s *MemoryPrincipalStore) Save(_ context.Context, p *Principal) error {
	if p == nil || p.ID == "" {
		return ErrPrincipalNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[p.ID] = p
	if p.Subject != "" {
		s.bySubject[p.Subject] = p.ID
	}
	return nil
}

func (s *MemoryPrincipalStore) UpdateStatus(_ context.Context, id string, status PrincipalStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return ErrPrincipalNotFound
	}
	p.Status = status
	return nil
}

func (s *MemoryPrincipalStore) UpdateLastSeen(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byID[id]
	if !ok {
		return ErrPrincipalNotFound
	}
	p.LastSeenAt = &at
	return nil
}

// credentialKey indexes credentials by kind+subject for FindBySubject.
type credentialKey struct {
	kind    CredentialKind
	subject string
}

// MemoryCredentialStore is an in-process CredentialStore.
type MemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[credentialKey]Credential
	byPrincipal map[string][]credentialKey
}

// NewMemoryCredentialStore returns an empty in-memory CredentialStore.
func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		credentials: make(map[credentialKey]Credential),
		byPrincipal: make(map[string][]credentialKey),
	}
}

func (s *MemoryCredentialStore) Lookup(_ context.Context, principalID string) ([]Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := s.byPrincipal[principalID]
	out := make([]Credential, 0, len(keys))
	for _, k := range keys {
		if c, ok := s.credentials[k]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *MemoryCredentialStore) FindBySubject(_ context.Context, kind CredentialKind, subject string) (Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.credentials[credentialKey{kind: kind, subject: subject}]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return c, nil
}

// subjectCarrier lets a credential expose the subject it indexes under.
// All concrete credentials in this package implement it; tests can mock.
type subjectCarrier interface {
	Credential
	Subject() string
}

func (s *MemoryCredentialStore) Save(_ context.Context, c Credential) error {
	sc, ok := c.(subjectCarrier)
	if !ok {
		return ErrUnsupportedFactor
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credentialKey{kind: c.Kind(), subject: sc.Subject()}
	s.credentials[key] = c
	s.byPrincipal[c.PrincipalID()] = appendUnique(s.byPrincipal[c.PrincipalID()], key)
	return nil
}

func (s *MemoryCredentialStore) Revoke(_ context.Context, kind CredentialKind, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := credentialKey{kind: kind, subject: subject}
	c, ok := s.credentials[key]
	if !ok {
		return ErrCredentialNotFound
	}
	delete(s.credentials, key)
	if pid := c.PrincipalID(); pid != "" {
		s.byPrincipal[pid] = removeKey(s.byPrincipal[pid], key)
	}
	return nil
}

func appendUnique(slice []credentialKey, k credentialKey) []credentialKey {
	for _, existing := range slice {
		if existing == k {
			return slice
		}
	}
	return append(slice, k)
}

func removeKey(slice []credentialKey, k credentialKey) []credentialKey {
	out := slice[:0]
	for _, existing := range slice {
		if existing != k {
			out = append(out, existing)
		}
	}
	return out
}
