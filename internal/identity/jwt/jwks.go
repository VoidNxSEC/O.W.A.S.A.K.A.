package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// JWK is a single JSON Web Key in the JWKS response. Only the fields
// Spectre/Cerebro need to verify Ed25519 OKP keys are emitted.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// JWKS is the public set of keys served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublishKeys returns the JWKS of all signing keys currently considered
// verifyable (active + rotating). Retired and expired keys are excluded.
func PublishKeys(ctx context.Context, authority *pki.Authority, now time.Time) (JWKS, error) {
	keys, err := authority.KeysForPurpose(ctx, pki.PurposeJWTSigning)
	if err != nil {
		return JWKS{}, err
	}
	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, kp := range keys {
		if !kp.IsVerifyable(now) {
			continue
		}
		out.Keys = append(out.Keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(kp.Public),
			Use: "sig",
			Alg: "EdDSA",
			Kid: kp.ID,
		})
	}
	return out, nil
}

// Handler returns an http.Handler that serves the JWKS as JSON at the
// well-known endpoint. Mount at "/.well-known/jwks.json".
//
// Caches at the HTTP layer should respect Cache-Control: max-age=60 to
// keep rotated keys available to verifiers within the 1-hour overlap.
func Handler(authority *pki.Authority, clock func() time.Time) http.Handler {
	if clock == nil {
		clock = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks, err := PublishKeys(r.Context(), authority, clock())
		if err != nil {
			http.Error(w, "jwks unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}
