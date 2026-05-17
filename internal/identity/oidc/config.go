// Package oidc implements the OWASAKA OpenID Connect client.
//
// The OIDC integration is feature-flagged and optional. Default
// deployments authenticate humans via password+TOTP (see
// internal/identity); the OIDC client adds federated SSO via an
// external provider — Zitadel is the supported/tested target per
// ADR-0059, but any OIDC-spec-compliant issuer should work.
//
// The flow is standard authorization-code with PKCE recommended for
// public clients and optional (still good practice) for confidential
// clients. ID tokens are verified against the provider's JWKS;
// verified claims are mapped to an OWASAKA Principal via the
// configured ClaimMapper.
package oidc

import (
	"errors"
	"time"
)

// Config carries OIDC client configuration. Sourced from
// sops-encrypted secrets at runtime (see docs/secrets/BOOTSTRAP.md).
//
// A zero-value Config disables OIDC; the constructor refuses to
// build a Client without Enabled=true.
type Config struct {
	// Enabled is the feature flag. When false, the application's
	// `NewClient` returns ErrDisabled and the OIDC endpoints are
	// not mounted on the API router.
	Enabled bool

	// IssuerURL is the OIDC issuer (Zitadel instance root). The
	// client performs OIDC Discovery against
	// `<IssuerURL>/.well-known/openid-configuration` at construction.
	IssuerURL string

	// ClientID and ClientSecret identify this application to the
	// IdP. ClientSecret comes from the encrypted secrets file.
	ClientID     string
	ClientSecret string

	// RedirectURL is the absolute URL the IdP redirects back to.
	// Must exactly match the value registered with the IdP.
	RedirectURL string

	// Scopes requested at login. "openid" is always added.
	Scopes []string

	// AutoProvision controls whether unknown subjects (verified by
	// the IdP but missing from the local PrincipalStore) get a new
	// Principal created on first login.
	AutoProvision bool

	// LoginStateTTL bounds how long a /login → /callback round-trip
	// may take. Defaults to 5 minutes if zero.
	LoginStateTTL time.Duration
}

// Validate enforces the minimum field set required to build a Client.
func (c Config) Validate() error {
	if !c.Enabled {
		return ErrDisabled
	}
	if c.IssuerURL == "" {
		return errors.New("oidc: IssuerURL required")
	}
	if c.ClientID == "" {
		return errors.New("oidc: ClientID required")
	}
	if c.ClientSecret == "" {
		return errors.New("oidc: ClientSecret required")
	}
	if c.RedirectURL == "" {
		return errors.New("oidc: RedirectURL required")
	}
	return nil
}

// Sentinel errors.
var (
	ErrDisabled         = errors.New("oidc: integration disabled by config")
	ErrInvalidState     = errors.New("oidc: state token invalid or expired")
	ErrInvalidIDToken   = errors.New("oidc: id token verification failed")
	ErrPrincipalUnknown = errors.New("oidc: principal not provisioned and auto-provision disabled")
)
