package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// --- Config & state ---------------------------------------------------------

func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		name string
		c    Config
		want error
	}{
		{"disabled", Config{Enabled: false}, ErrDisabled},
		{"missing issuer", Config{Enabled: true}, nil}, // err non-nil but not sentinel
		{"complete", Config{
			Enabled:      true,
			IssuerURL:    "https://idp.example",
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "https://app.example/cb",
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if tc.name == "complete" && err != nil {
				t.Fatalf("complete config should validate, got %v", err)
			}
			if tc.name == "missing issuer" && err == nil {
				t.Fatal("expected error for missing issuer")
			}
		})
	}
}

func TestStateCodec_RoundTrip(t *testing.T) {
	c := newStateCodec([]byte("key"), time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tok, err := c.Encode(now, "nonce-1", "/dashboard")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	claims, err := c.Decode(now, tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if claims.Nonce != "nonce-1" || claims.RedirectURL != "/dashboard" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestStateCodec_TamperedSignature(t *testing.T) {
	c := newStateCodec([]byte("key"), time.Minute)
	now := time.Now()
	tok, _ := c.Encode(now, "n", "")
	// Flip a character in the signature half.
	idx := strings.Index(tok, ".")
	if idx < 0 || idx == len(tok)-1 {
		t.Fatal("token shape unexpected")
	}
	tampered := tok[:idx+1] + flipFirst(tok[idx+1:])
	if _, err := c.Decode(now, tampered); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestStateCodec_Expired(t *testing.T) {
	c := newStateCodec([]byte("key"), time.Second)
	now := time.Now()
	tok, _ := c.Encode(now, "n", "")
	if _, err := c.Decode(now.Add(2*time.Second), tok); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState (expired), got %v", err)
	}
}

func TestStateCodec_MissingSeparator(t *testing.T) {
	c := newStateCodec([]byte("key"), time.Minute)
	if _, err := c.Decode(time.Now(), "no-separator-here"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState, got %v", err)
	}
}

func TestStateCodec_EmptyKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty key")
		}
	}()
	_ = newStateCodec(nil, time.Minute)
}

func flipFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

// --- Mapping ----------------------------------------------------------------

func TestDefaultMapper_AutoProvisionCreatesPrincipal(t *testing.T) {
	store := identity.NewMemoryPrincipalStore()
	m := NewDefaultMapper(store, true)

	got, err := m.Map(context.Background(), IDClaims{
		Subject:           "user-1",
		Issuer:            "https://idp.example",
		Email:             "marcos@voidnxlabs.dev",
		EmailVerified:     true,
		Name:              "Marcos",
		PreferredUsername: "marcos",
		Groups:            []string{"security"},
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if got.Type != identity.PrincipalHuman || !got.IsActive() {
		t.Fatalf("provisioned principal shape: %+v", got)
	}
	if got.Subject != "oidc:https://idp.example:user-1" {
		t.Fatalf("subject: %s", got.Subject)
	}
	if got.DisplayName != "Marcos" {
		t.Fatalf("display name: %s", got.DisplayName)
	}
	if got.Claims["email"] != "marcos@voidnxlabs.dev" {
		t.Fatalf("email claim missing")
	}
}

func TestDefaultMapper_FindsExistingPrincipal(t *testing.T) {
	store := identity.NewMemoryPrincipalStore()
	preexisting := &identity.Principal{
		ID:      "pre-1",
		Type:    identity.PrincipalHuman,
		Subject: "oidc:https://idp.example:user-1",
		Status:  identity.StatusActive,
	}
	_ = store.Save(context.Background(), preexisting)

	m := NewDefaultMapper(store, false)
	got, err := m.Map(context.Background(), IDClaims{
		Subject: "user-1",
		Issuer:  "https://idp.example",
		Email:   "fresh@voidnxlabs.dev", // upstream change
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if got.ID != "pre-1" {
		t.Fatalf("expected existing principal, got %s", got.ID)
	}
	if got.Claims["email"] != "fresh@voidnxlabs.dev" {
		t.Fatalf("claims should refresh on login, got %v", got.Claims["email"])
	}
}

func TestDefaultMapper_AutoProvisionDisabled(t *testing.T) {
	store := identity.NewMemoryPrincipalStore()
	m := NewDefaultMapper(store, false)
	_, err := m.Map(context.Background(), IDClaims{Subject: "ghost", Issuer: "https://idp.example"})
	if !errors.Is(err, ErrPrincipalUnknown) {
		t.Fatalf("expected ErrPrincipalUnknown, got %v", err)
	}
}

func TestDefaultMapper_InactivePrincipalRejected(t *testing.T) {
	store := identity.NewMemoryPrincipalStore()
	_ = store.Save(context.Background(), &identity.Principal{
		ID:      "p", Subject: "oidc:https://idp.example:u",
		Status: identity.StatusSuspended,
	})
	m := NewDefaultMapper(store, true)
	_, err := m.Map(context.Background(), IDClaims{Subject: "u", Issuer: "https://idp.example"})
	if !errors.Is(err, identity.ErrPrincipalInactive) {
		t.Fatalf("expected ErrPrincipalInactive, got %v", err)
	}
}

func TestDefaultMapper_RejectsEmptySubOrIss(t *testing.T) {
	m := NewDefaultMapper(identity.NewMemoryPrincipalStore(), true)
	if _, err := m.Map(context.Background(), IDClaims{Issuer: "x"}); err == nil {
		t.Fatal("expected error for empty sub")
	}
	if _, err := m.Map(context.Background(), IDClaims{Subject: "x"}); err == nil {
		t.Fatal("expected error for empty iss")
	}
}

// --- mergeScopes ------------------------------------------------------------

func TestMergeScopes_AlwaysIncludesOpenID(t *testing.T) {
	got := mergeScopes([]string{"email", "profile"})
	if got[0] != gooidc.ScopeOpenID {
		t.Fatalf("openid not first: %v", got)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 scopes, got %v", got)
	}
}

func TestMergeScopes_DedupesAndIgnoresEmpty(t *testing.T) {
	got := mergeScopes([]string{"openid", "", "profile", "profile"})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique, got %v", got)
	}
}

// --- Client construction (uses test OIDC server) ---------------------------

// fakeProvider stands up an httptest server that responds to OIDC
// Discovery and JWKS lookups so NewClient + Exchange can complete in
// tests without external dependencies.
type fakeProvider struct {
	server    *httptest.Server
	signer    jose.Signer
	signingKP *signKeyPair
	mux       *http.ServeMux
	t         *testing.T
}

type signKeyPair struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
	kid     string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kp := &signKeyPair{public: pub, private: priv, kid: "fake-kid-1"}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kp.kid))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	fp := &fakeProvider{signer: signer, signingKP: kp, t: t}
	fp.mux = http.NewServeMux()
	fp.server = httptest.NewServer(fp.mux)

	fp.mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 fp.server.URL,
			"authorization_endpoint": fp.server.URL + "/authorize",
			"token_endpoint":         fp.server.URL + "/token",
			"jwks_uri":               fp.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"EdDSA"},
		})
	})

	fp.mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: pub, KeyID: kp.kid, Algorithm: "EdDSA", Use: "sig"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	return fp
}

func (fp *fakeProvider) mintIDToken(t *testing.T, clientID, sub, email string) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":            fp.server.URL,
		"sub":            sub,
		"aud":            clientID,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          email,
		"email_verified": true,
		"name":           "Test User",
	}
	raw, err := jwt.Signed(fp.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return raw
}

func (fp *fakeProvider) wireToken(t *testing.T, clientID, accessToken, idToken string) {
	fp.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Form.Get("client_id") != clientID && getBasicUser(r) != clientID {
			http.Error(w, "wrong client_id", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
}

func (fp *fakeProvider) close() { fp.server.Close() }

func getBasicUser(r *http.Request) string {
	u, _, ok := r.BasicAuth()
	if !ok {
		return ""
	}
	return u
}

func TestClient_AuthURL_IncludesStateAndScopes(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()

	c, err := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: "client-1", ClientSecret: "secret-1",
		RedirectURL: "https://app.example/cb",
		Scopes:      []string{"profile", "email"},
	}, []byte("state-key"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	authURL, state, err := c.AuthURL("/dashboard")
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("client_id") != "client-1" {
		t.Fatalf("client_id missing")
	}
	if u.Query().Get("state") != state {
		t.Fatalf("state mismatch")
	}
	if !strings.Contains(u.Query().Get("scope"), "openid") {
		t.Fatalf("openid scope missing")
	}

	info, err := c.VerifyState(state)
	if err != nil {
		t.Fatalf("verify state: %v", err)
	}
	if info.RedirectURL != "/dashboard" {
		t.Fatalf("redirect: %s", info.RedirectURL)
	}
}

func TestClient_Exchange_HappyPath(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()

	clientID := "client-1"
	idToken := fp.mintIDToken(t, clientID, "user-42", "u@voidnxlabs.dev")
	fp.wireToken(t, clientID, "access-token-value", idToken)

	c, err := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: clientID, ClientSecret: "secret",
		RedirectURL: "https://app/cb",
	}, []byte("state-key"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	verified, err := c.Exchange(context.Background(), "auth-code-xyz")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if verified.IDClaims.Subject != "user-42" {
		t.Fatalf("sub: %s", verified.IDClaims.Subject)
	}
	if verified.IDClaims.Email != "u@voidnxlabs.dev" {
		t.Fatalf("email: %s", verified.IDClaims.Email)
	}
	if verified.AccessToken != "access-token-value" {
		t.Fatalf("access token: %s", verified.AccessToken)
	}
}

// --- Handlers (end-to-end with stubbed issuer) ------------------------------

type stubIssuer struct{ pair *owjwt.TokenPair }

func (s *stubIssuer) Issue(_ context.Context, _ *identity.Principal) (*owjwt.TokenPair, error) {
	return s.pair, nil
}

func realIssuer(t *testing.T) (*owjwt.Issuer, *pki.Authority) {
	t.Helper()
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, time.Hour); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	return owjwt.NewIssuer(auth), auth
}

func TestHandlers_LoginRedirectsToIdP(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()

	c, err := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: "client", ClientSecret: "secret",
		RedirectURL: "https://app/cb",
	}, []byte("state-key"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	iss, _ := realIssuer(t)
	h := NewHandlers(c, NewDefaultMapper(identity.NewMemoryPrincipalStore(), true), iss)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/auth/oidc/login?return=/dash", nil)
	h.Login(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status: %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), fp.server.URL+"/authorize") {
		t.Fatalf("redirect target: %s", rr.Header().Get("Location"))
	}
	cookies := rr.Result().Cookies()
	var found bool
	for _, ck := range cookies {
		if ck.Name == "owasaka_oidc_state" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("state cookie not set")
	}
}

func TestHandlers_CallbackHappyPath(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()

	clientID := "client"
	idToken := fp.mintIDToken(t, clientID, "user-7", "u@voidnxlabs.dev")
	fp.wireToken(t, clientID, "at", idToken)

	c, err := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: clientID, ClientSecret: "secret",
		RedirectURL: "https://app/cb",
	}, []byte("state-key"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	store := identity.NewMemoryPrincipalStore()
	mapper := NewDefaultMapper(store, true)
	pair := &owjwt.TokenPair{AccessToken: "ow-a", RefreshToken: "ow-r"}
	h := NewHandlers(c, mapper, &stubIssuer{pair: pair})

	// First: hit Login to get a valid state cookie.
	loginReq := httptest.NewRequest("GET", "/auth/oidc/login?return=/done", nil)
	loginRR := httptest.NewRecorder()
	h.Login(loginRR, loginReq)
	cookies := loginRR.Result().Cookies()
	var stateCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == "owasaka_oidc_state" {
			stateCookie = ck
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("no state cookie")
	}

	// Then: call Callback with the matching state.
	cbReq := httptest.NewRequest("GET", "/auth/oidc/callback?code=auth-1&state="+url.QueryEscape(stateCookie.Value), nil)
	cbReq.AddCookie(stateCookie)
	cbRR := httptest.NewRecorder()
	h.Callback(cbRR, cbReq)

	if cbRR.Code != http.StatusFound {
		t.Fatalf("status: %d body=%s", cbRR.Code, cbRR.Body.String())
	}
	if cbRR.Header().Get("Location") != "/done" {
		t.Fatalf("redirect: %s", cbRR.Header().Get("Location"))
	}

	// Principal should be auto-provisioned.
	if _, err := store.FindBySubject(context.Background(), "oidc:"+fp.server.URL+":user-7"); err != nil {
		t.Fatalf("principal not provisioned: %v", err)
	}

	// Session cookies set.
	bodyCookies := cbRR.Result().Cookies()
	var hasAccess, hasRefresh bool
	for _, ck := range bodyCookies {
		if ck.Name == "owasaka_access" {
			hasAccess = true
		}
		if ck.Name == "owasaka_refresh" {
			hasRefresh = true
		}
	}
	if !hasAccess || !hasRefresh {
		t.Fatalf("session cookies missing: access=%v refresh=%v", hasAccess, hasRefresh)
	}
}

func TestHandlers_CallbackRejectsStateMismatch(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()
	c, _ := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: "c", ClientSecret: "s", RedirectURL: "https://app/cb",
	}, []byte("state-key"))
	h := NewHandlers(c, NewDefaultMapper(identity.NewMemoryPrincipalStore(), true), &stubIssuer{pair: &owjwt.TokenPair{}})

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=x&state=forged", nil)
	req.AddCookie(&http.Cookie{Name: "owasaka_oidc_state", Value: "different"})
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandlers_CallbackForwardsIdPError(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()
	c, _ := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: "c", ClientSecret: "s", RedirectURL: "https://app/cb",
	}, []byte("state-key"))
	h := NewHandlers(c, NewDefaultMapper(identity.NewMemoryPrincipalStore(), true), &stubIssuer{pair: &owjwt.TokenPair{}})

	req := httptest.NewRequest("GET", "/auth/oidc/callback?error=access_denied", nil)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for idp error, got %d", rr.Code)
	}
}

func TestHandlers_CallbackUnknownPrincipal(t *testing.T) {
	fp := newFakeProvider(t)
	defer fp.close()
	clientID := "c"
	idToken := fp.mintIDToken(t, clientID, "u-unknown", "")
	fp.wireToken(t, clientID, "at", idToken)

	c, _ := NewClient(context.Background(), Config{
		Enabled: true, IssuerURL: fp.server.URL,
		ClientID: clientID, ClientSecret: "s", RedirectURL: "https://app/cb",
	}, []byte("state-key"))

	store := identity.NewMemoryPrincipalStore()
	mapper := NewDefaultMapper(store, false) // no auto-provision
	h := NewHandlers(c, mapper, &stubIssuer{pair: &owjwt.TokenPair{}})

	loginRR := httptest.NewRecorder()
	h.Login(loginRR, httptest.NewRequest("GET", "/auth/oidc/login", nil))
	state := loginRR.Result().Cookies()[0]

	req := httptest.NewRequest("GET", "/auth/oidc/callback?code=c&state="+url.QueryEscape(state.Value), nil)
	req.AddCookie(state)
	rr := httptest.NewRecorder()
	h.Callback(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown user, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPrincipalSubject_Format(t *testing.T) {
	got := PrincipalSubject(IDClaims{Subject: "abc", Issuer: "https://idp"})
	if got != "oidc:https://idp:abc" {
		t.Fatalf("format: %s", got)
	}
}

// Touch unused import guards so vet doesn't complain in slim builds.
var _ = base64.RawURLEncoding
var _ = (*url.URL)(nil)
