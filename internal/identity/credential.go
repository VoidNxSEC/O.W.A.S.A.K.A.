package identity

import (
	"context"
	"errors"
	"time"
)

// CredentialKind identifies the proof method a Principal uses to authenticate.
type CredentialKind string

const (
	CredentialPassword CredentialKind = "password" // password + TOTP (always combined)
	CredentialWebAuthn CredentialKind = "webauthn" // FIDO2 / WebAuthn (opt-in upgrade)
	CredentialAPIKey   CredentialKind = "apikey"   // long-lived agent key
	CredentialMTLS     CredentialKind = "mtls"     // client certificate
	CredentialOIDC     CredentialKind = "oidc"     // upstream IdP (Zitadel) token
)

// AuthFactor is one factor in a multi-factor authentication attempt.
//
// Implementations carry the raw proof material (password, OTP code,
// cert chain, signed challenge, etc.). The Authenticator inspects the
// Kind and dispatches to the appropriate Credential implementation.
type AuthFactor struct {
	Kind    CredentialKind
	Subject string         // username, key id, cert fingerprint, etc.
	Proof   []byte         // password bytes, signed assertion, etc.
	Extra   map[string]any // TOTP code, challenge nonce, etc.
}

// Credential is one verifiable proof method bound to a Principal.
//
// Implementations are stateless verifiers. Persistent material (hashed
// passwords, TOTP secrets, key fingerprints, etc.) is loaded through
// the CredentialStore.
type Credential interface {
	Kind() CredentialKind
	PrincipalID() string
	Verify(ctx context.Context, factor AuthFactor) error
}

// CredentialStore loads credentials and persists their state.
//
// Implementations must be safe for concurrent use.
type CredentialStore interface {
	// Lookup returns all credentials bound to a Principal.
	Lookup(ctx context.Context, principalID string) ([]Credential, error)

	// FindBySubject locates a credential by its public subject (username,
	// API-key id, certificate fingerprint, etc.) and kind. Returns
	// ErrCredentialNotFound when no match exists.
	FindBySubject(ctx context.Context, kind CredentialKind, subject string) (Credential, error)

	// Save persists a new or rotated credential.
	Save(ctx context.Context, cred Credential) error

	// Revoke removes a credential permanently. The associated Principal
	// remains, but the credential can no longer be used to authenticate.
	Revoke(ctx context.Context, kind CredentialKind, subject string) error
}

// PrincipalStore persists Principal lifecycle state.
//
// Implementations must be safe for concurrent use.
type PrincipalStore interface {
	Get(ctx context.Context, id string) (*Principal, error)
	FindBySubject(ctx context.Context, subject string) (*Principal, error)
	Save(ctx context.Context, p *Principal) error
	UpdateStatus(ctx context.Context, id string, status PrincipalStatus) error
	UpdateLastSeen(ctx context.Context, id string, at time.Time) error
}

// Authenticator verifies a set of AuthFactors and returns the resolved
// Principal on success.
//
// The default implementation enforces:
//
//   - PrincipalHuman: at least password + TOTP, or WebAuthn alone.
//   - PrincipalAgent: API key (one factor) or mTLS (one factor).
//   - PrincipalService: mTLS only.
//
// Returns one of the Err* sentinels below on failure.
type Authenticator interface {
	Authenticate(ctx context.Context, factors []AuthFactor) (*Principal, error)
}

// Sentinel errors returned by Authenticator and the stores.
var (
	ErrPrincipalNotFound  = errors.New("identity: principal not found")
	ErrPrincipalInactive  = errors.New("identity: principal not active")
	ErrCredentialNotFound = errors.New("identity: credential not found")
	ErrCredentialInvalid  = errors.New("identity: credential verification failed")
	ErrInsufficientFactor = errors.New("identity: insufficient authentication factors")
	ErrUnsupportedFactor  = errors.New("identity: unsupported authentication factor")
)
