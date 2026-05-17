package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Client wraps OIDC discovery, token exchange, and ID-token verification.
//
// Built once at application startup against a configured issuer; safe
// for concurrent use afterward. Disabled OIDC (Config.Enabled=false)
// produces ErrDisabled from NewClient so the wiring path never holds
// a nil pointer.
type Client struct {
	cfg          Config
	provider     *gooidc.Provider
	oauth        *oauth2.Config
	idVerifier   *gooidc.IDTokenVerifier
	state        *stateCodec
	clock        func() time.Time
	randomReader io.Reader
}

// Option customizes the Client. Mostly for test injection.
type Option func(*Client)

// WithClock injects a time source. Default: time.Now.
func WithClock(c func() time.Time) Option { return func(cl *Client) { cl.clock = c } }

// WithRandom injects an entropy source. Default: crypto/rand.Reader.
func WithRandom(r io.Reader) Option { return func(cl *Client) { cl.randomReader = r } }

// withProvider lets tests inject a pre-built provider (avoids real
// network calls during construction). Not exported.
func withProvider(p *gooidc.Provider) Option { return func(cl *Client) { cl.provider = p } }

// NewClient performs OIDC Discovery against the configured issuer and
// returns a ready-to-use Client. Returns ErrDisabled if Config.Enabled
// is false.
//
// stateKey is the HMAC secret used to sign authorization-request state
// tokens; it should rotate with the JWT signing key (24h cadence per
// ADR-0059). Tests pass a fixed key.
func NewClient(ctx context.Context, cfg Config, stateKey []byte, opts ...Option) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	c := &Client{
		cfg:          cfg,
		state:        newStateCodec(stateKey, cfg.LoginStateTTL),
		clock:        time.Now,
		randomReader: rand.Reader,
	}
	for _, o := range opts {
		o(c)
	}

	if c.provider == nil {
		provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("oidc: discovery: %w", err)
		}
		c.provider = provider
	}

	c.oauth = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     c.provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       mergeScopes(cfg.Scopes),
	}
	c.idVerifier = c.provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})

	return c, nil
}

// AuthURL builds an authorization-endpoint URL and returns the state
// token that must be echoed back to Callback. The caller stores the
// state in a short-lived cookie or hidden form field; Callback verifies
// the round-trip.
//
// redirectAfter is the relative path the application should navigate
// to after successful login (e.g. "/dashboard"); empty means default.
func (c *Client) AuthURL(redirectAfter string) (authURL, state string, err error) {
	nonce, err := c.randomNonce()
	if err != nil {
		return "", "", err
	}
	state, err = c.state.Encode(c.clock(), nonce, redirectAfter)
	if err != nil {
		return "", "", err
	}
	return c.oauth.AuthCodeURL(state), state, nil
}

// VerifyState verifies a state token returned by the IdP without
// performing the code exchange. Exposed so handlers can reject malformed
// callbacks fast.
func (c *Client) VerifyState(state string) (RedirectInfo, error) {
	claims, err := c.state.Decode(c.clock(), state)
	if err != nil {
		return RedirectInfo{}, err
	}
	return RedirectInfo{Nonce: claims.Nonce, RedirectURL: claims.RedirectURL}, nil
}

// RedirectInfo carries claims extracted from a verified state token.
type RedirectInfo struct {
	Nonce       string
	RedirectURL string
}

// Exchange exchanges an authorization code for tokens and verifies the
// ID token signature + issuer + audience. Returns the parsed ID token
// and its verified claims.
func (c *Client) Exchange(ctx context.Context, code string) (*VerifiedToken, error) {
	tok, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("%w: no id_token in response", ErrInvalidIDToken)
	}
	idToken, err := c.idVerifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIDToken, err)
	}
	claims := IDClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: parse claims: %v", ErrInvalidIDToken, err)
	}
	return &VerifiedToken{
		IDToken:     idToken,
		IDClaims:    claims,
		AccessToken: tok.AccessToken,
		Expiry:      tok.Expiry,
	}, nil
}

// VerifiedToken is the result of a successful Exchange.
type VerifiedToken struct {
	IDToken     *gooidc.IDToken
	IDClaims    IDClaims
	AccessToken string
	Expiry      time.Time
}

// IDClaims captures the subset of OIDC standard + Zitadel custom claims
// relevant to OWASAKA. Unknown claims pass through go-oidc's Claims()
// method if a caller needs them — but the mapped Principal builds from
// these typed fields.
type IDClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Issuer            string   `json:"iss"`
}

func (c *Client) randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(c.randomReader, b); err != nil {
		return "", fmt.Errorf("oidc: random nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mergeScopes guarantees "openid" is present, deduplicating without
// reshuffling caller-provided ordering.
func mergeScopes(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in)+1)
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if !seen[gooidc.ScopeOpenID] {
		out = append([]string{gooidc.ScopeOpenID}, out...)
	}
	return out
}
