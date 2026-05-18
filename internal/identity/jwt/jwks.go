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
// Spectre/Cerebro need to verify Ed25519 OKP keys are emitted. A custom
// `owasaka_purpose` field disambiguates the OWASAKA-internal purpose
// (jwt-signing vs event-signing vs transparency-sth) for verifiers that
// must dispatch on purpose; standard OIDC/JWKS consumers ignore it.
type JWK struct {
	Kty     string `json:"kty"`
	Crv     string `json:"crv"`
	X       string `json:"x"`
	Use     string `json:"use"`
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	Purpose string `json:"owasaka_purpose,omitempty"`
}

// JWKS is the public set of keys served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// publishedPurposes is the set of PKI purposes that get exported on
// the JWKS endpoint. PurposeCA and PurposeServiceCert are intentionally
// excluded: the root CA's public certificate is distributed separately
// (boot banner + ops record), and service-cert public keys belong in
// the cert itself, not in a JWKS.
var publishedPurposes = []pki.Purpose{
	pki.PurposeJWTSigning,
	pki.PurposeEventSigning,
}

// PublishKeys returns the JWKS of all signing keys currently considered
// verifyable (active + rotating) across every published purpose. Retired
// and expired keys are excluded. Per ADR-0062 §"JWKS extension" the same
// endpoint serves both JWT and event signing keys; downstream services
// disambiguate by the `owasaka_purpose` field.
func PublishKeys(ctx context.Context, authority *pki.Authority, now time.Time) (JWKS, error) {
	out := JWKS{Keys: make([]JWK, 0, 4)}
	for _, purpose := range publishedPurposes {
		keys, err := authority.KeysForPurpose(ctx, purpose)
		if err != nil {
			return JWKS{}, err
		}
		for _, kp := range keys {
			if !kp.IsVerifyable(now) {
				continue
			}
			out.Keys = append(out.Keys, JWK{
				Kty:     "OKP",
				Crv:     "Ed25519",
				X:       base64.RawURLEncoding.EncodeToString(kp.Public),
				Use:     "sig",
				Alg:     "EdDSA",
				Kid:     kp.ID,
				Purpose: string(purpose),
			})
		}
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
