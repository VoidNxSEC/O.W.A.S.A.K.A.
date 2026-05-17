// Package middleware wires JWT-based authentication into the OWASAKA
// HTTP API and WebSocket upgrade path. See ADR-0059 Section "AuthN
// middleware" and Section "Dev-mode escape hatch".
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

type contextKey int

const principalContextKey contextKey = iota

// Middleware authenticates incoming HTTP and WebSocket requests.
//
// A request is authenticated by carrying a Bearer JWT in the
// Authorization header. The token is validated against the JWT verifier;
// on success the resolved Principal is injected into the request context
// for downstream handlers.
//
// Dev mode: if a non-empty DevToken is configured and the OSWAKA_ENV
// environment is "development", requests carrying that exact token
// authenticate as the configured DevPrincipal. A loud warning is logged
// each minute the mode is active.
type Middleware struct {
	verifier       *owjwt.Verifier
	principals     identity.PrincipalStore
	logger         *logging.Logger
	devToken       string
	devPrincipal   *identity.Principal
	devWarned      atomic.Int64 // unix-second of last warning
	devWarningRate time.Duration
}

// Option configures a Middleware.
type Option func(*Middleware)

// WithDevMode enables the development escape hatch.
//
// When token is non-empty AND the surrounding application has confirmed
// it is in development (the caller is responsible — the middleware does
// not consult env vars directly), the static token authenticates as
// principal. Production builds MUST NOT call this option.
func WithDevMode(token string, principal *identity.Principal) Option {
	return func(m *Middleware) {
		m.devToken = token
		m.devPrincipal = principal
	}
}

// WithDevWarningInterval overrides the cadence of dev-mode warnings.
func WithDevWarningInterval(d time.Duration) Option {
	return func(m *Middleware) { m.devWarningRate = d }
}

// New builds a Middleware over a verifier and principal store.
func New(verifier *owjwt.Verifier, principals identity.PrincipalStore, logger *logging.Logger, opts ...Option) *Middleware {
	m := &Middleware{
		verifier:       verifier,
		principals:     principals,
		logger:         logger,
		devWarningRate: time.Minute,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Authenticate parses, verifies, and resolves a request's identity.
//
// Returns the resolved Principal on success. Returns identity.* sentinel
// errors on failure so callers can map to HTTP status codes.
func (m *Middleware) Authenticate(ctx context.Context, r *http.Request) (*identity.Principal, error) {
	raw, err := extractBearer(r)
	if err != nil {
		return nil, err
	}

	// Dev-mode short-circuit. The token must match exactly; partial or
	// prefix matches do not count.
	if m.devToken != "" && raw == m.devToken {
		m.maybeWarnDevMode()
		if m.devPrincipal == nil || !m.devPrincipal.IsActive() {
			return nil, identity.ErrPrincipalInactive
		}
		return m.devPrincipal, nil
	}

	claims, err := m.verifier.Verify(ctx, raw, owjwt.TypeAccess)
	if err != nil {
		return nil, err
	}

	p, err := m.principals.Get(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if !p.IsActive() {
		return nil, identity.ErrPrincipalInactive
	}
	return p, nil
}

// RequireAuth wraps an http.Handler so it only fires when authentication
// succeeds. Failed authentication produces 401 with a brief reason.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := m.Authenticate(r.Context(), r)
		if err != nil {
			writeAuthError(w, r, m.logger, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// AuthorizeWS authenticates a WebSocket upgrade request. The handshake
// is HTTP, so this is a thin wrapper around Authenticate returning the
// Principal for the WS connection state machine to remember.
func (m *Middleware) AuthorizeWS(ctx context.Context, r *http.Request) (*identity.Principal, error) {
	return m.Authenticate(ctx, r)
}

// WithPrincipal returns a derived context carrying the resolved Principal.
func WithPrincipal(parent context.Context, p *identity.Principal) context.Context {
	return context.WithValue(parent, principalContextKey, p)
}

// PrincipalFromContext returns the Principal placed by RequireAuth.
// Returns nil if no Principal is present.
func PrincipalFromContext(ctx context.Context) *identity.Principal {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(principalContextKey).(*identity.Principal)
	return p
}

// extractBearer parses the Authorization header.
// Accepts "Bearer <token>"; rejects everything else (including
// empty header or other schemes).
func extractBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		// Tolerate WebSocket clients that pass tokens via the
		// `Sec-WebSocket-Protocol` sub-protocol field. The token is
		// expected as the *second* protocol entry, prefixed by
		// "bearer." so the first slot stays free for any future
		// protocol negotiation.
		if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
			for _, part := range strings.Split(proto, ",") {
				p := strings.TrimSpace(part)
				if strings.HasPrefix(p, "bearer.") {
					return p[len("bearer."):], nil
				}
			}
		}
		return "", ErrMissingAuthHeader
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrMalformedAuthHeader
	}
	return parts[1], nil
}

// writeAuthError translates an Authenticate error into an HTTP response.
// Bodies are intentionally terse — they leak no info about which step
// failed beyond "authentication required" / "authentication failed".
func writeAuthError(w http.ResponseWriter, r *http.Request, logger *logging.Logger, err error) {
	status := http.StatusUnauthorized
	msg := "authentication required"
	switch {
	case errors.Is(err, identity.ErrPrincipalInactive):
		status = http.StatusForbidden
		msg = "principal inactive"
	case errors.Is(err, ErrMissingAuthHeader):
		// keep default 401
	case errors.Is(err, ErrMalformedAuthHeader):
		// keep default 401
	}
	if logger != nil {
		logger.Debugw("auth rejected",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"reason", err.Error(),
		)
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="owasaka"`)
	http.Error(w, msg, status)
}

func (m *Middleware) maybeWarnDevMode() {
	now := time.Now().Unix()
	last := m.devWarned.Load()
	cadence := int64(m.devWarningRate / time.Second)
	if cadence < 1 {
		cadence = 1
	}
	if now-last < cadence {
		return
	}
	if m.devWarned.CompareAndSwap(last, now) && m.logger != nil {
		m.logger.Warn("DEV MODE: static auth token is active — DO NOT USE IN PRODUCTION")
	}
}

// Errors returned by Authenticate and extractBearer.
var (
	ErrMissingAuthHeader   = errors.New("middleware: missing Authorization header")
	ErrMalformedAuthHeader = errors.New("middleware: malformed Authorization header")
)
