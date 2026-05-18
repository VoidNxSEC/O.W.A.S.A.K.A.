package identity

import (
	"context"
	"errors"
	"fmt"
)

// defaultAuthenticator is the production Authenticator.
//
// It enforces multi-factor for humans (password+TOTP), single-factor
// for agents (API key) and services (mTLS — cert already verified at
// the TLS layer, this just maps fingerprint → Principal).
type defaultAuthenticator struct {
	principals PrincipalStore
	creds      CredentialStore
}

// NewAuthenticator builds the standard Authenticator over the two stores.
func NewAuthenticator(principals PrincipalStore, creds CredentialStore) Authenticator {
	return &defaultAuthenticator{
		principals: principals,
		creds:      creds,
	}
}

// Authenticate verifies the supplied factors and returns the resolved
// Principal on success.
//
// Factor requirements per principal type:
//
//	Human   → password + TOTP (both required)
//	Agent   → API key (one) or mTLS fingerprint (one)
//	Service → mTLS fingerprint only
//
// Unknown principal types are rejected.
func (a *defaultAuthenticator) Authenticate(ctx context.Context, factors []AuthFactor) (*Principal, error) {
	if len(factors) == 0 {
		return nil, ErrInsufficientFactor
	}

	// Determine the credential kind from the first factor.
	kind := factors[0].Kind
	subject := factors[0].Subject

	// Look up the credential by subject and kind.
	cred, err := a.creds.FindBySubject(ctx, kind, subject)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil, ErrCredentialInvalid
		}
		return nil, err
	}

	// Verify each factor against the credential.
	for _, f := range factors {
		if err := cred.Verify(ctx, f); err != nil {
			return nil, err
		}
	}

	// Resolve the Principal.
	p, err := a.principals.Get(ctx, cred.PrincipalID())
	if err != nil {
		return nil, err
	}
	if !p.IsActive() {
		return nil, ErrPrincipalInactive
	}

	// Enforce factor-count policy per principal type.
	switch p.Type {
	case PrincipalHuman:
		// CredentialPassword already verifies both password+TOTP in one
		// call, so a single factor of that kind satisfies MFA.
		if kind == CredentialPassword {
			if len(factors) != 1 {
				return nil, fmt.Errorf("%w: password+TOTP expects single combined factor", ErrInsufficientFactor)
			}
		} else {
			if len(factors) < 2 {
				return nil, fmt.Errorf("%w: human requires password+TOTP or WebAuthn", ErrInsufficientFactor)
			}
		}
	case PrincipalService:
		if kind != CredentialMTLS {
			return nil, fmt.Errorf("%w: service requires mTLS", ErrUnsupportedFactor)
		}
	case PrincipalAgent:
		// API key or mTLS — single factor accepted.
	default:
		return nil, fmt.Errorf("%w: unknown principal type %q", ErrUnsupportedFactor, p.Type)
	}

	return p, nil
}
