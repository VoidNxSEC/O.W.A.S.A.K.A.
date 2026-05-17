package oidc

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
)

// SessionIssuer is the subset of jwt.Issuer used by the OIDC callback
// — keeps this package's coupling minimal and lets tests stub it.
type SessionIssuer interface {
	Issue(ctx context.Context, p *identity.Principal) (*owjwt.TokenPair, error)
}

// Handlers wires OIDC HTTP endpoints onto the OWASAKA API.
type Handlers struct {
	client  *Client
	mapper  ClaimMapper
	issuer  SessionIssuer
	cookie  string // name of the cookie holding state for CSRF binding
	clock   func() time.Time
}

// NewHandlers builds the HTTP handler set.
//
// stateCookieName must be unique to OIDC flows (default
// `owasaka_oidc_state`) so unrelated requests don't clobber it.
func NewHandlers(client *Client, mapper ClaimMapper, issuer SessionIssuer) *Handlers {
	return &Handlers{
		client: client,
		mapper: mapper,
		issuer: issuer,
		cookie: "owasaka_oidc_state",
		clock:  time.Now,
	}
}

// Login is the entry point: GET /auth/oidc/login [?return=<path>].
// Generates a state token, sets it in a short-lived cookie, and
// redirects the user to the IdP's authorization endpoint.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return")
	authURL, state, err := h.client.AuthURL(returnTo)
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  h.clock().Add(10 * time.Minute),
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles the IdP redirect-back:
// GET /auth/oidc/callback?code=...&state=...
//
// Validates state against the cookie, exchanges the code, verifies the
// ID token, maps claims to a Principal, mints OWASAKA's own
// access+refresh JWTs, and redirects the user to the original return
// URL with tokens set as HttpOnly cookies (or via the configured
// session flow).
func (h *Handlers) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		http.Error(w, "idp error: "+errParam, http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// Bind state cookie to the state query param. Defeats CSRF: an
	// attacker controlling the query string cannot also forge the cookie.
	cookie, err := r.Cookie(h.cookie)
	if err != nil || cookie.Value != state {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	info, err := h.client.VerifyState(state)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	tok, err := h.client.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "exchange failed", http.StatusUnauthorized)
		return
	}
	// Bind the IdP-issued issuer back into the claims so the mapper
	// (which keys on iss+sub) can index correctly even if the IdP
	// omits `iss` from id_token claims (it shouldn't, but defense
	// in depth).
	tok.IDClaims.Issuer = h.coerceIssuer(tok.IDClaims.Issuer)

	principal, err := h.mapper.Map(r.Context(), tok.IDClaims)
	if err != nil {
		switch {
		case errors.Is(err, ErrPrincipalUnknown):
			http.Error(w, "user not provisioned", http.StatusForbidden)
		case errors.Is(err, identity.ErrPrincipalInactive):
			http.Error(w, "user inactive", http.StatusForbidden)
		default:
			http.Error(w, "principal mapping failed", http.StatusInternalServerError)
		}
		return
	}

	pair, err := h.issuer.Issue(r.Context(), principal)
	if err != nil {
		http.Error(w, "session issuance failed", http.StatusInternalServerError)
		return
	}

	// Clear the one-use state cookie now that we've consumed it.
	http.SetCookie(w, &http.Cookie{
		Name: h.cookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true,
	})

	// Hand the OWASAKA session back via HttpOnly cookies. The frontend
	// (T-Sprint-9) will swap this for a more deliberate flow; for now,
	// cookies keep the SSO loop functional without exposing JWTs to JS.
	h.setSessionCookies(w, pair)

	redirect := info.RedirectURL
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (h *Handlers) setSessionCookies(w http.ResponseWriter, pair *owjwt.TokenPair) {
	common := http.Cookie{Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}

	access := common
	access.Name = "owasaka_access"
	access.Value = pair.AccessToken
	access.Expires = pair.AccessExp
	http.SetCookie(w, &access)

	refresh := common
	refresh.Name = "owasaka_refresh"
	refresh.Value = pair.RefreshToken
	refresh.Expires = pair.RefreshExp
	http.SetCookie(w, &refresh)
}

// coerceIssuer returns the supplied issuer unchanged when non-empty;
// otherwise falls back to the client's configured issuer.
func (h *Handlers) coerceIssuer(iss string) string {
	if iss != "" {
		return iss
	}
	return h.client.cfg.IssuerURL
}

// Mount registers the Login and Callback handlers on a mux.
//
// Mount(mux, "/auth/oidc") yields:
//   GET /auth/oidc/login
//   GET /auth/oidc/callback
func (h *Handlers) Mount(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/login", h.Login)
	mux.HandleFunc(prefix+"/callback", h.Callback)
}
