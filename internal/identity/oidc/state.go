package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// stateClaims is the payload embedded in the OAuth2 `state` parameter.
//
// We sign+encode it rather than storing per-request state server-side:
// the IdP echoes it back to /callback, we verify the signature, and
// reject if the contents look tampered with. CSRF protection comes
// from binding to a nonce that only the originating client knows.
type stateClaims struct {
	Nonce       string `json:"n"`
	RedirectURL string `json:"r,omitempty"`
	IssuedAt    int64  `json:"i"`
	ExpiresAt   int64  `json:"e"`
}

// stateCodec signs + verifies state tokens.
type stateCodec struct {
	key []byte
	ttl time.Duration
}

// newStateCodec builds a codec using `key` as the HMAC secret.
// The key should rotate with the JWT signing key (Sprint 1: same TTL,
// 24h). Empty key panics — misconfiguration we should not run with.
func newStateCodec(key []byte, ttl time.Duration) *stateCodec {
	if len(key) == 0 {
		panic("oidc: state codec key must not be empty")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &stateCodec{key: key, ttl: ttl}
}

// Encode produces a tamper-evident state token with the given nonce
// and post-login redirect.
func (c *stateCodec) Encode(now time.Time, nonce, redirect string) (string, error) {
	claims := stateClaims{
		Nonce:       nonce,
		RedirectURL: redirect,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(c.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, c.key)
	mac.Write(payload)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// Decode verifies a state token and returns its claims. Returns
// ErrInvalidState if the signature is bad or the token has expired.
func (c *stateCodec) Decode(now time.Time, token string) (stateClaims, error) {
	var zero stateClaims
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			payload, err := base64.RawURLEncoding.DecodeString(token[:i])
			if err != nil {
				return zero, ErrInvalidState
			}
			sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
			if err != nil {
				return zero, ErrInvalidState
			}
			mac := hmac.New(sha256.New, c.key)
			mac.Write(payload)
			expected := mac.Sum(nil)
			if !hmac.Equal(expected, sig) {
				return zero, ErrInvalidState
			}
			var claims stateClaims
			if err := json.Unmarshal(payload, &claims); err != nil {
				return zero, ErrInvalidState
			}
			if now.Unix() > claims.ExpiresAt {
				return zero, ErrInvalidState
			}
			return claims, nil
		}
	}
	return zero, fmt.Errorf("%w: missing separator", ErrInvalidState)
}
