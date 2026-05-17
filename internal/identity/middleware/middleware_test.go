package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

func wire(t *testing.T) (*Middleware, *identity.MemoryPrincipalStore, *pki.Authority, *identity.Principal, *owjwt.Issuer) {
	t.Helper()
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	verifier := owjwt.NewVerifier(auth)
	issuer := owjwt.NewIssuer(auth)
	ps := identity.NewMemoryPrincipalStore()
	p := &identity.Principal{ID: "p1", Subject: "marcos", Type: identity.PrincipalHuman, Status: identity.StatusActive}
	_ = ps.Save(context.Background(), p)
	m := New(verifier, ps, nil)
	return m, ps, auth, p, issuer
}

func TestAuthenticate_HappyPath(t *testing.T) {
	m, _, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	got, err := m.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ID != p.ID {
		t.Fatalf("principal mismatch: %s", got.ID)
	}
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	m, _, _, _, _ := wire(t)
	req := httptest.NewRequest("GET", "/", nil)
	if _, err := m.Authenticate(req.Context(), req); !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected missing header, got %v", err)
	}
}

func TestAuthenticate_MalformedHeader(t *testing.T) {
	m, _, _, _, _ := wire(t)
	cases := []string{
		"NotBearer xyz",
		"Bearer",
		"Bearer ",
		"  ",
	}
	for _, h := range cases {
		t.Run(h, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", h)
			_, err := m.Authenticate(req.Context(), req)
			if err == nil {
				t.Fatalf("expected error for %q", h)
			}
		})
	}
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	m, _, _, _, _ := wire(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	if _, err := m.Authenticate(req.Context(), req); err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestAuthenticate_PrincipalNotFound(t *testing.T) {
	m, ps, _, _, iss := wire(t)
	// Issue a token for a principal we then delete by re-creating the store.
	stranger := &identity.Principal{ID: "ghost", Subject: "ghost", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), stranger)
	_ = ps

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	_, err := m.Authenticate(req.Context(), req)
	if !errors.Is(err, identity.ErrPrincipalNotFound) {
		t.Fatalf("expected ErrPrincipalNotFound, got %v", err)
	}
}

func TestAuthenticate_InactivePrincipal(t *testing.T) {
	m, ps, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)
	_ = ps.UpdateStatus(context.Background(), p.ID, identity.StatusSuspended)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	_, err := m.Authenticate(req.Context(), req)
	if !errors.Is(err, identity.ErrPrincipalInactive) {
		t.Fatalf("expected ErrPrincipalInactive, got %v", err)
	}
}

func TestRequireAuth_AllowsAuthenticated(t *testing.T) {
	m, _, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)

	called := false
	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if PrincipalFromContext(r.Context()) == nil {
			t.Fatal("principal not in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Fatal("handler not invoked")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code: %d", rr.Code)
	}
}

func TestRequireAuth_Rejects401(t *testing.T) {
	m, _, _, _, _ := wire(t)
	handler := m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler should not run")
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestRequireAuth_RejectsInactiveWith403(t *testing.T) {
	m, ps, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)
	_ = ps.UpdateStatus(context.Background(), p.ID, identity.StatusSuspended)

	handler := m.RequireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler should not run")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestDevMode_Authenticates(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, time.Hour)
	verifier := owjwt.NewVerifier(auth)
	ps := identity.NewMemoryPrincipalStore()
	dev := &identity.Principal{ID: "dev", Subject: "dev", Status: identity.StatusActive}

	m := New(verifier, ps, nil,
		WithDevMode("DEV-TOKEN", dev),
		WithDevWarningInterval(time.Hour),
	)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer DEV-TOKEN")
	p, err := m.Authenticate(req.Context(), req)
	if err != nil || p.ID != "dev" {
		t.Fatalf("dev auth: %v %v", p, err)
	}
}

func TestDevMode_InactivePrincipalRejected(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, time.Hour)
	verifier := owjwt.NewVerifier(auth)
	ps := identity.NewMemoryPrincipalStore()
	dev := &identity.Principal{ID: "dev", Status: identity.StatusSuspended}

	m := New(verifier, ps, nil, WithDevMode("DEV-TOKEN", dev))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer DEV-TOKEN")
	if _, err := m.Authenticate(req.Context(), req); !errors.Is(err, identity.ErrPrincipalInactive) {
		t.Fatalf("expected inactive, got %v", err)
	}
}

func TestDevMode_NotShortCircuitedForDifferentToken(t *testing.T) {
	m, _, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)

	// Wrap with dev mode but client uses a real token, not dev token.
	dev := &identity.Principal{ID: "dev", Status: identity.StatusActive}
	m2 := New(m.verifier, m.principals, nil, WithDevMode("DEV-TOKEN", dev))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	got, err := m2.Authenticate(req.Context(), req)
	if err != nil {
		t.Fatalf("real token should still work alongside dev mode: %v", err)
	}
	if got.ID != p.ID {
		t.Fatalf("dev mode swallowed real auth: %v", got)
	}
}

func TestWebSocketSubprotocolBearer(t *testing.T) {
	m, _, _, p, iss := wire(t)
	pair, _ := iss.Issue(context.Background(), p)

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "owasaka.v1, bearer."+pair.AccessToken)
	got, err := m.AuthorizeWS(req.Context(), req)
	if err != nil {
		t.Fatalf("ws auth: %v", err)
	}
	if got.ID != p.ID {
		t.Fatalf("ws principal mismatch")
	}
}

func TestWebSocketSubprotocol_NoBearerEntry(t *testing.T) {
	m, _, _, _, _ := wire(t)
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Sec-WebSocket-Protocol", "owasaka.v1, other.protocol")
	if _, err := m.AuthorizeWS(req.Context(), req); !errors.Is(err, ErrMissingAuthHeader) {
		t.Fatalf("expected missing, got %v", err)
	}
}

func TestPrincipalFromContext_Empty(t *testing.T) {
	if PrincipalFromContext(nil) != nil {
		t.Fatal("nil ctx should yield nil principal")
	}
	if PrincipalFromContext(context.Background()) != nil {
		t.Fatal("empty ctx should yield nil principal")
	}
}

func TestWithPrincipal_RoundTrip(t *testing.T) {
	p := &identity.Principal{ID: "x"}
	ctx := WithPrincipal(context.Background(), p)
	got := PrincipalFromContext(ctx)
	if got == nil || got.ID != "x" {
		t.Fatalf("round trip failed: %v", got)
	}
}

func TestExtractBearer_CaseInsensitiveScheme(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "bearer abc")
	tok, err := extractBearer(req)
	if err != nil || tok != "abc" {
		t.Fatalf("case-insensitive Bearer: %v %q", err, tok)
	}
}

func TestWriteAuthError_LogsAtDebug(t *testing.T) {
	// Just exercise the path with a nil logger to confirm we don't panic.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	writeAuthError(rr, req, nil, ErrMissingAuthHeader)
	body := strings.TrimSpace(rr.Body.String())
	if body == "" {
		t.Fatal("expected body")
	}
}
