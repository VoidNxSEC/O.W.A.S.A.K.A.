package jwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// RevocationChecker reports whether a token JTI has been revoked.
//
// Implementations are queried on the hot path; the default
// implementation in T8 (Sprint 1) is a persistent denylist with a
// bloom-filter cache. A nil checker is treated as "nothing revoked".
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// Verifier validates JWT tokens issued by an OWASAKA Issuer.
type Verifier struct {
	authority   *pki.Authority
	revocations RevocationChecker
	clock       func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithRevocationChecker attaches a denylist to the verifier. Without
// one, tokens are accepted purely on signature+expiration.
func WithRevocationChecker(r RevocationChecker) VerifierOption {
	return func(v *Verifier) { v.revocations = r }
}

// WithVerifierClock overrides the time source.
func WithVerifierClock(c func() time.Time) VerifierOption {
	return func(v *Verifier) { v.clock = c }
}

// NewVerifier builds a Verifier over a PKI authority. Pass
// WithRevocationChecker once T8's denylist lands.
func NewVerifier(authority *pki.Authority, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		authority: authority,
		clock:     time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify parses, signature-checks, and validates a token. On success it
// returns the parsed claims.
//
// Rotating keys are accepted (they verify but no longer sign). Retired
// keys are rejected. Expired tokens are rejected.
//
// expectedType ensures the token is the right kind (access vs refresh)
// for the consumer. Pass empty string to accept either.
func (v *Verifier) Verify(ctx context.Context, raw string, expectedType TokenType) (*Claims, error) {
	claims := &Claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(v.clock),
	)
	parsed, err := parser.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "EdDSA" {
			return nil, ErrInvalidSignature
		}
		kidRaw, ok := token.Header["kid"]
		if !ok {
			return nil, ErrUnknownKey
		}
		kid, ok := kidRaw.(string)
		if !ok || kid == "" {
			return nil, ErrUnknownKey
		}
		kp, err := v.authority.GetKey(ctx, kid)
		if err != nil {
			return nil, ErrUnknownKey
		}
		if !kp.IsVerifyable(v.clock()) {
			return nil, ErrKeyExpired
		}
		return ed25519.PublicKey(kp.Public), nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return nil, ErrInvalidSignature
		case errors.Is(err, jwt.ErrTokenMalformed):
			return nil, ErrTokenMalformed
		}
		// Custom callback errors propagate as-is when not wrapped.
		if errors.Is(err, ErrUnknownKey) || errors.Is(err, ErrKeyExpired) || errors.Is(err, ErrInvalidSignature) {
			return nil, err
		}
		return nil, ErrTokenMalformed
	}
	if !parsed.Valid {
		return nil, ErrInvalidSignature
	}

	// Token-type gating.
	if expectedType != "" && claims.TokenType != expectedType {
		return nil, ErrWrongTokenType
	}

	// Audience sanity check matching the token type.
	if err := assertAudience(claims, expectedType); err != nil {
		return nil, err
	}

	// Revocation hot-path check (skipped if no checker wired).
	if v.revocations != nil {
		revoked, err := v.revocations.IsRevoked(ctx, claims.ID)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrInvalidSignature
		}
	}

	return claims, nil
}

func assertAudience(claims *Claims, tt TokenType) error {
	if tt == "" {
		return nil
	}
	want := AudienceAccess
	if tt == TypeRefresh {
		want = AudienceRefresh
	}
	for _, aud := range claims.Audience {
		if aud == want {
			return nil
		}
	}
	return ErrWrongAudience
}

// Re-export of the PKI sentinel so callers don't need both imports for
// common error checks.
var ErrKeyExpired = pki.ErrKeyExpired
