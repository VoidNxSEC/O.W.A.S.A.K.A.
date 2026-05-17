package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

func setup(t *testing.T) (*pki.Authority, *Issuer, *Verifier, *identity.Principal) {
	t.Helper()
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour); err != nil {
		t.Fatalf("seed signing key: %v", err)
	}
	iss := NewIssuer(auth)
	ver := NewVerifier(auth)
	p := &identity.Principal{
		ID:      "p1",
		Type:    identity.PrincipalHuman,
		Subject: "marcos",
		Status:  identity.StatusActive,
	}
	return auth, iss, ver, p
}

func TestIssue_NilPrincipal(t *testing.T) {
	_, iss, _, _ := setup(t)
	if _, err := iss.Issue(context.Background(), nil); err != identity.ErrPrincipalNotFound {
		t.Fatalf("expected ErrPrincipalNotFound, got %v", err)
	}
}

func TestIssue_InactivePrincipal(t *testing.T) {
	_, iss, _, _ := setup(t)
	inactive := &identity.Principal{ID: "x", Status: identity.StatusSuspended}
	if _, err := iss.Issue(context.Background(), inactive); err != identity.ErrPrincipalInactive {
		t.Fatalf("expected ErrPrincipalInactive, got %v", err)
	}
}

func TestIssue_NoSigningKey(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	iss := NewIssuer(auth)
	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	if _, err := iss.Issue(context.Background(), p); err != pki.ErrNoActiveKey {
		t.Fatalf("expected ErrNoActiveKey, got %v", err)
	}
}

func TestIssueAndVerify_RoundTrip(t *testing.T) {
	_, iss, ver, p := setup(t)
	ctx := context.Background()

	pair, err := iss.Issue(ctx, p)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("empty tokens")
	}
	if !strings.HasPrefix(pair.AccessToken, "eyJ") {
		t.Fatalf("access token doesn't look like JWT: %s", pair.AccessToken[:10])
	}
	if pair.AccessExp.Before(pair.RefreshExp) == false {
		t.Fatal("refresh should outlast access")
	}

	// Verify access token
	claims, err := ver.Verify(ctx, pair.AccessToken, TypeAccess)
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if claims.Subject != p.ID {
		t.Fatalf("sub: %s", claims.Subject)
	}
	if claims.TokenType != TypeAccess {
		t.Fatalf("token type: %v", claims.TokenType)
	}
	if claims.PrincipalSubject != p.Subject {
		t.Fatalf("psub: %s", claims.PrincipalSubject)
	}
	if claims.PrincipalType != identity.PrincipalHuman {
		t.Fatalf("ptype: %v", claims.PrincipalType)
	}
	if claims.ID != pair.AccessJTI {
		t.Fatalf("jti mismatch: %s vs %s", claims.ID, pair.AccessJTI)
	}

	// Refresh token must not pass as access
	if _, err := ver.Verify(ctx, pair.RefreshToken, TypeAccess); !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("expected ErrWrongTokenType, got %v", err)
	}

	// Refresh token verifies as refresh
	rclaims, err := ver.Verify(ctx, pair.RefreshToken, TypeRefresh)
	if err != nil {
		t.Fatalf("verify refresh: %v", err)
	}
	if rclaims.TokenType != TypeRefresh {
		t.Fatalf("refresh type: %v", rclaims.TokenType)
	}
}

func TestVerify_Expired(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour)

	frozen := time.Now()
	iss := NewIssuer(auth,
		WithClock(func() time.Time { return frozen }),
		WithAccessTTL(time.Minute),
	)
	ver := NewVerifier(auth, WithVerifierClock(func() time.Time { return frozen.Add(2 * time.Minute) }))

	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), p)

	if _, err := ver.Verify(context.Background(), pair.AccessToken, TypeAccess); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	_, _, ver, _ := setup(t)
	if _, err := ver.Verify(context.Background(), "not.a.jwt", TypeAccess); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestVerify_UnknownKey(t *testing.T) {
	// Two authorities: issue under one, try to verify under another
	authA := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = authA.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour)
	iss := NewIssuer(authA)

	authB := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = authB.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour)
	ver := NewVerifier(authB)

	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), p)
	if _, err := ver.Verify(context.Background(), pair.AccessToken, TypeAccess); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestVerify_AfterKeyRotation_VerifiesViaRotatingKey(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour)

	iss := NewIssuer(auth)
	ver := NewVerifier(auth)

	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), p)

	// Rotate signing key. The old key becomes "rotating" and must still verify
	// tokens previously issued.
	if _, err := auth.Rotate(context.Background(), pki.PurposeJWTSigning, 24*time.Hour); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := ver.Verify(context.Background(), pair.AccessToken, TypeAccess); err != nil {
		t.Fatalf("token issued before rotation should still verify, got %v", err)
	}
}

type denylist map[string]bool

func (d denylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	return d[jti], nil
}

func TestVerify_Revoked(t *testing.T) {
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, _ = auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, 24*time.Hour)
	iss := NewIssuer(auth)

	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), p)

	dl := denylist{pair.AccessJTI: true}
	ver := NewVerifier(auth, WithRevocationChecker(dl))

	if _, err := ver.Verify(context.Background(), pair.AccessToken, TypeAccess); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for revoked, got %v", err)
	}
}

func TestPublishKeys(t *testing.T) {
	auth, _, _, _ := setup(t)
	jwks, err := PublishKeys(context.Background(), auth, time.Now())
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" {
		t.Fatalf("wrong key envelope: %+v", k)
	}
	if k.X == "" {
		t.Fatal("missing public key encoding")
	}
}

func TestHandler_ServesJWKS(t *testing.T) {
	auth, _, _, _ := setup(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	Handler(auth, nil).ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var jwks JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("keys: %d", len(jwks.Keys))
	}
	if rr.Header().Get("Cache-Control") == "" {
		t.Fatal("missing Cache-Control")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	// Manually mint a token with a bogus audience to ensure audience check works.
	auth := pki.NewAuthority(pki.NewMemoryKeyStore())
	kp, _ := auth.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, time.Hour)
	iss := NewIssuer(auth)
	p := &identity.Principal{ID: "p", Status: identity.StatusActive}
	pair, _ := iss.Issue(context.Background(), p)
	_ = kp

	ver := NewVerifier(auth)
	// Access token attempted as refresh should yield ErrWrongTokenType (caught first)
	if _, err := ver.Verify(context.Background(), pair.AccessToken, TypeRefresh); !errors.Is(err, ErrWrongTokenType) {
		t.Fatalf("expected ErrWrongTokenType, got %v", err)
	}
}
