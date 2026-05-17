// Package jwt issues and verifies JWT access and refresh tokens for
// OWASAKA principals. Tokens are signed with Ed25519 keys managed by the
// PKI authority. See ADR-0059, Section "Token model".
package jwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

const (
	// IssuerName is the string embedded in every token's `iss` claim.
	// Downstream verifiers (Spectre, Cerebro) check this exactly.
	IssuerName = "owasaka"

	// AudienceAccess is set on access tokens authorizing API/WS calls.
	AudienceAccess = "owasaka-api"

	// AudienceRefresh is set on refresh tokens used only at /auth/refresh.
	AudienceRefresh = "owasaka-refresh"

	// DefaultAccessTTL: 15 minutes. See ADR-0059.
	DefaultAccessTTL = 15 * time.Minute

	// DefaultRefreshTTL: 24 hours. See ADR-0059.
	DefaultRefreshTTL = 24 * time.Hour
)

// TokenType distinguishes access tokens (used on every request) from
// refresh tokens (used only to mint new access tokens).
type TokenType string

const (
	TypeAccess  TokenType = "access"
	TypeRefresh TokenType = "refresh"
)

// Claims is the JWT claim payload OWASAKA issues. Embeds RegisteredClaims
// for iss/sub/aud/exp/iat/nbf/jti and adds principal context.
type Claims struct {
	jwt.RegisteredClaims

	PrincipalType    identity.PrincipalType `json:"ptype"`
	PrincipalSubject string                 `json:"psub,omitempty"`
	TokenType        TokenType              `json:"ttype"`
}

// TokenPair carries an access + refresh token freshly minted for a
// Principal. The caller persists the JTI of each so revocation works.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	AccessJTI    string
	RefreshJTI   string
	AccessExp    time.Time
	RefreshExp   time.Time
	SigningKeyID string
}

// Issuer mints access + refresh tokens.
//
// Always uses the current PurposeJWTSigning active key. Callers rotate
// keys via the Authority; the Issuer picks up the new key on the next
// Issue call.
type Issuer struct {
	authority  *pki.Authority
	clock      func() time.Time
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// IssuerOption configures an Issuer.
type IssuerOption func(*Issuer)

// WithClock overrides the time source.
func WithClock(c func() time.Time) IssuerOption {
	return func(i *Issuer) { i.clock = c }
}

// WithAccessTTL overrides the default access token TTL.
func WithAccessTTL(d time.Duration) IssuerOption {
	return func(i *Issuer) { i.accessTTL = d }
}

// WithRefreshTTL overrides the default refresh token TTL.
func WithRefreshTTL(d time.Duration) IssuerOption {
	return func(i *Issuer) { i.refreshTTL = d }
}

// NewIssuer wires an Issuer over a PKI authority.
func NewIssuer(authority *pki.Authority, opts ...IssuerOption) *Issuer {
	i := &Issuer{
		authority:  authority,
		clock:      time.Now,
		accessTTL:  DefaultAccessTTL,
		refreshTTL: DefaultRefreshTTL,
	}
	for _, o := range opts {
		o(i)
	}
	return i
}

// Issue mints a fresh access+refresh pair for a Principal.
//
// Returns identity.ErrPrincipalInactive if the Principal is not active.
// Returns pki.ErrNoActiveKey if no JWT signing key has been provisioned;
// callers typically pair Issuer with an Authority that ensures a signing
// key exists at boot.
func (i *Issuer) Issue(ctx context.Context, p *identity.Principal) (*TokenPair, error) {
	if p == nil {
		return nil, identity.ErrPrincipalNotFound
	}
	if !p.IsActive() {
		return nil, identity.ErrPrincipalInactive
	}

	signingKey, err := i.authority.ActiveKey(ctx, pki.PurposeJWTSigning)
	if err != nil {
		return nil, err
	}

	now := i.clock()
	accessJTI := uuid.NewString()
	refreshJTI := uuid.NewString()
	accessExp := now.Add(i.accessTTL)
	refreshExp := now.Add(i.refreshTTL)

	access, err := i.signClaims(buildClaims(p, accessJTI, now, accessExp, AudienceAccess, TypeAccess), signingKey)
	if err != nil {
		return nil, fmt.Errorf("jwt: sign access token: %w", err)
	}
	refresh, err := i.signClaims(buildClaims(p, refreshJTI, now, refreshExp, AudienceRefresh, TypeRefresh), signingKey)
	if err != nil {
		return nil, fmt.Errorf("jwt: sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		AccessJTI:    accessJTI,
		RefreshJTI:   refreshJTI,
		AccessExp:    accessExp,
		RefreshExp:   refreshExp,
		SigningKeyID: signingKey.ID,
	}, nil
}

func buildClaims(p *identity.Principal, jti string, now, exp time.Time, audience string, tt TokenType) *Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    IssuerName,
			Subject:   p.ID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
		PrincipalType:    p.Type,
		PrincipalSubject: p.Subject,
		TokenType:        tt,
	}
}

func (i *Issuer) signClaims(claims *Claims, kp *pki.KeyPair) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kp.ID
	tok.Header["alg"] = "EdDSA"
	return tok.SignedString(ed25519.PrivateKey(kp.Private))
}

// Sentinel errors specific to the JWT layer.
var (
	ErrInvalidSignature = errors.New("jwt: invalid signature")
	ErrTokenExpired     = errors.New("jwt: token expired")
	ErrTokenMalformed   = errors.New("jwt: token malformed")
	ErrUnknownKey       = errors.New("jwt: signing key unknown")
	ErrWrongAudience    = errors.New("jwt: wrong audience")
	ErrWrongTokenType   = errors.New("jwt: wrong token type")
)
