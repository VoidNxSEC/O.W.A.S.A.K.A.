package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// --- PasswordTOTPCredential -------------------------------------------------

func TestPasswordTOTP_HappyPath(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("OWASAKA", "marcos")
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	cred, err := NewPasswordTOTPCredential("p1", "marcos", "correct horse battery staple", secret, "OWASAKA")
	if err != nil {
		t.Fatalf("new cred: %v", err)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	err = cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialPassword,
		Proof: []byte("correct horse battery staple"),
		Extra: map[string]any{"totp": code},
	})
	if err != nil {
		t.Fatalf("verify happy path: %v", err)
	}
}

func TestPasswordTOTP_WrongPassword(t *testing.T) {
	secret, _, _ := GenerateTOTPSecret("OWASAKA", "marcos")
	cred, _ := NewPasswordTOTPCredential("p1", "marcos", "right", secret, "")

	code, _ := totp.GenerateCode(secret, time.Now())
	err := cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialPassword,
		Proof: []byte("wrong"),
		Extra: map[string]any{"totp": code},
	})
	if !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestPasswordTOTP_WrongTOTP(t *testing.T) {
	secret, _, _ := GenerateTOTPSecret("OWASAKA", "marcos")
	cred, _ := NewPasswordTOTPCredential("p1", "marcos", "right", secret, "")

	err := cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialPassword,
		Proof: []byte("right"),
		Extra: map[string]any{"totp": "000000"},
	})
	if !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestPasswordTOTP_MissingTOTP(t *testing.T) {
	secret, _, _ := GenerateTOTPSecret("OWASAKA", "marcos")
	cred, _ := NewPasswordTOTPCredential("p1", "marcos", "right", secret, "")

	err := cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialPassword,
		Proof: []byte("right"),
		Extra: nil,
	})
	if !errors.Is(err, ErrInsufficientFactor) {
		t.Fatalf("expected ErrInsufficientFactor, got %v", err)
	}
}

func TestPasswordTOTP_WrongFactorKind(t *testing.T) {
	secret, _, _ := GenerateTOTPSecret("OWASAKA", "marcos")
	cred, _ := NewPasswordTOTPCredential("p1", "marcos", "right", secret, "")

	err := cred.Verify(context.Background(), AuthFactor{Kind: CredentialAPIKey})
	if !errors.Is(err, ErrUnsupportedFactor) {
		t.Fatalf("expected ErrUnsupportedFactor, got %v", err)
	}
}

func TestPasswordTOTP_ConstructorValidation(t *testing.T) {
	cases := []struct {
		name                string
		pid, subj, pw, sec  string
	}{
		{"empty principal id", "", "u", "p", "s"},
		{"empty subject", "p1", "", "p", "s"},
		{"empty password", "p1", "u", "", "s"},
		{"empty secret", "p1", "u", "p", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPasswordTOTPCredential(tc.pid, tc.subj, tc.pw, tc.sec, ""); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPasswordTOTP_Accessors(t *testing.T) {
	secret, _, _ := GenerateTOTPSecret("OWASAKA", "marcos")
	cred, _ := NewPasswordTOTPCredential("p1", "marcos", "right", secret, "")

	if cred.Kind() != CredentialPassword {
		t.Fatalf("kind: %v", cred.Kind())
	}
	if cred.PrincipalID() != "p1" {
		t.Fatalf("pid: %s", cred.PrincipalID())
	}
	if cred.Subject() != "marcos" {
		t.Fatalf("subject: %s", cred.Subject())
	}
	if cred.TOTPSecret() != secret {
		t.Fatalf("totp secret mismatch")
	}
	if cred.Issuer() != "OWASAKA" {
		t.Fatalf("issuer: %s", cred.Issuer())
	}
}

func TestLoadPasswordTOTP_DefaultIssuer(t *testing.T) {
	cred := LoadPasswordTOTPCredential("p", "u", []byte("hash"), "secret", "")
	if cred.Issuer() != "OWASAKA" {
		t.Fatalf("default issuer: %s", cred.Issuer())
	}
}

// --- APIKeyCredential -------------------------------------------------------

func TestAPIKey_RoundTrip(t *testing.T) {
	cred, plaintext, err := NewAPIKey("p1", "ci-runner")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !strings.HasPrefix(plaintext, APIKeyPrefix) {
		t.Fatalf("plaintext missing prefix: %s", plaintext)
	}

	keyID, secret, err := ParseAPIKey(plaintext)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if keyID != cred.Subject() {
		t.Fatalf("key id mismatch: %s vs %s", keyID, cred.Subject())
	}

	err = cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialAPIKey,
		Proof: []byte(secret),
	})
	if err != nil {
		t.Fatalf("verify happy: %v", err)
	}

	err = cred.Verify(context.Background(), AuthFactor{
		Kind:  CredentialAPIKey,
		Proof: []byte("not-the-secret"),
	})
	if !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestAPIKey_ParseInvalid(t *testing.T) {
	cases := []string{
		"",
		"not-a-key",
		"oswk_",
		"oswk_keyid_",
		"oswk__secret",
		"prefix_wrong_key_value",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, _, err := ParseAPIKey(c); err == nil {
				t.Fatalf("expected error for %q", c)
			}
		})
	}
}

func TestAPIKey_ConstructorValidation(t *testing.T) {
	if _, _, err := NewAPIKey("", "label"); err == nil {
		t.Fatal("expected error for empty principal id")
	}
}

func TestAPIKey_WrongFactorKind(t *testing.T) {
	cred, _, _ := NewAPIKey("p1", "ci")
	err := cred.Verify(context.Background(), AuthFactor{Kind: CredentialPassword})
	if !errors.Is(err, ErrUnsupportedFactor) {
		t.Fatalf("expected ErrUnsupportedFactor, got %v", err)
	}
}

func TestAPIKey_Accessors(t *testing.T) {
	cred, _, _ := NewAPIKey("p1", "ci-runner")
	if cred.Kind() != CredentialAPIKey {
		t.Fatal("kind")
	}
	if cred.PrincipalID() != "p1" {
		t.Fatal("pid")
	}
	if cred.Label() != "ci-runner" {
		t.Fatal("label")
	}
	if cred.Subject() == "" {
		t.Fatal("subject empty")
	}
}

// --- MTLSCredential ---------------------------------------------------------

func generateLeaf(t *testing.T, cn string) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, pool
}

func TestMTLS_VerifyHappyPath(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	cred, err := NewMTLSCredential("p1", "spectre", leaf)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	err = cred.Verify(context.Background(), AuthFactor{
		Kind:    CredentialMTLS,
		Subject: cred.Fingerprint(),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestMTLS_VerifyMismatch(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	cred, _ := NewMTLSCredential("p1", "spectre", leaf)

	err := cred.Verify(context.Background(), AuthFactor{
		Kind:    CredentialMTLS,
		Subject: "00:00:00",
	})
	if !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestMTLS_VerifyEmpty(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	cred, _ := NewMTLSCredential("p1", "spectre", leaf)

	if err := cred.Verify(context.Background(), AuthFactor{Kind: CredentialMTLS, Subject: ""}); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid for empty, got %v", err)
	}
}

func TestMTLS_WrongFactorKind(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	cred, _ := NewMTLSCredential("p1", "spectre", leaf)

	if err := cred.Verify(context.Background(), AuthFactor{Kind: CredentialAPIKey}); !errors.Is(err, ErrUnsupportedFactor) {
		t.Fatalf("expected ErrUnsupportedFactor, got %v", err)
	}
}

func TestMTLS_ConstructorValidation(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	if _, err := NewMTLSCredential("", "spectre", leaf); err == nil {
		t.Fatal("expected error for empty principal id")
	}
	if _, err := NewMTLSCredential("p1", "", leaf); err == nil {
		t.Fatal("expected error for empty subject")
	}
	if _, err := NewMTLSCredential("p1", "spectre", nil); err == nil {
		t.Fatal("expected error for nil leaf")
	}
}

func TestMTLS_Accessors(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	cred, _ := NewMTLSCredential("p1", "spectre", leaf)

	if cred.Kind() != CredentialMTLS {
		t.Fatal("kind")
	}
	if cred.PrincipalID() != "p1" {
		t.Fatal("pid")
	}
	if cred.CommonName() != "spectre" {
		t.Fatal("cn")
	}
	if cred.Subject() != cred.Fingerprint() {
		t.Fatal("subject must equal fingerprint")
	}
}

func TestMTLSValidator_HappyPath(t *testing.T) {
	leaf, pool := generateLeaf(t, "spectre")
	val := NewMTLSValidator(pool)
	fp, err := val.Validate(leaf, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if fp != SPKIFingerprint(leaf) {
		t.Fatalf("fingerprint mismatch: %s vs %s", fp, SPKIFingerprint(leaf))
	}
}

func TestMTLSValidator_UntrustedRoot(t *testing.T) {
	leaf, _ := generateLeaf(t, "spectre")
	// Fresh empty pool — root not trusted.
	val := NewMTLSValidator(x509.NewCertPool())
	if _, err := val.Validate(leaf, nil); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestMTLSValidator_NilLeaf(t *testing.T) {
	val := NewMTLSValidator(x509.NewCertPool())
	if _, err := val.Validate(nil, nil); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected ErrCredentialInvalid, got %v", err)
	}
}

func TestMTLSValidator_ExpiredCert(t *testing.T) {
	leaf, pool := generateLeaf(t, "spectre")
	val := NewMTLSValidator(pool).WithClock(func() time.Time {
		return time.Now().Add(48 * time.Hour) // way past NotAfter
	})
	if _, err := val.Validate(leaf, nil); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expected expired -> ErrCredentialInvalid, got %v", err)
	}
}

func TestLoadMTLSCredential_NormalizesFingerprint(t *testing.T) {
	c := LoadMTLSCredential("p", "s", "  AB:cd:EF  ")
	if c.Fingerprint() != "ab:cd:ef" {
		t.Fatalf("not normalized: %q", c.Fingerprint())
	}
}

// --- MemoryStores -----------------------------------------------------------

func TestMemoryPrincipalStore(t *testing.T) {
	s := NewMemoryPrincipalStore()
	ctx := context.Background()

	if _, err := s.Get(ctx, "missing"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}
	if err := s.Save(ctx, nil); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("nil save: %v", err)
	}
	if err := s.Save(ctx, &Principal{}); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("empty id save: %v", err)
	}

	p := &Principal{ID: "p1", Subject: "marcos", Type: PrincipalHuman, Status: StatusActive}
	if err := s.Save(ctx, p); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, _ := s.Get(ctx, "p1")
	if got.Subject != "marcos" {
		t.Fatal("save/get mismatch")
	}
	bySub, _ := s.FindBySubject(ctx, "marcos")
	if bySub.ID != "p1" {
		t.Fatal("find-by-subject mismatch")
	}
	if _, err := s.FindBySubject(ctx, "ghost"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected not-found for unknown subject, got %v", err)
	}

	if err := s.UpdateStatus(ctx, "p1", StatusSuspended); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ = s.Get(ctx, "p1")
	if got.Status != StatusSuspended {
		t.Fatalf("status not updated: %v", got.Status)
	}
	if err := s.UpdateStatus(ctx, "missing", StatusActive); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("update missing: %v", err)
	}

	at := time.Now()
	if err := s.UpdateLastSeen(ctx, "p1", at); err != nil {
		t.Fatalf("update last seen: %v", err)
	}
	got, _ = s.Get(ctx, "p1")
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(at) {
		t.Fatalf("last seen not set")
	}
	if err := s.UpdateLastSeen(ctx, "missing", at); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("update last seen missing: %v", err)
	}
}

func TestMemoryCredentialStore(t *testing.T) {
	s := NewMemoryCredentialStore()
	ctx := context.Background()

	if _, err := s.FindBySubject(ctx, CredentialAPIKey, "x"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected not-found, got %v", err)
	}

	cred, _, _ := NewAPIKey("p1", "ci")
	if err := s.Save(ctx, cred); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.Save(ctx, cred); err != nil {
		t.Fatalf("save idempotent: %v", err)
	}

	got, err := s.FindBySubject(ctx, CredentialAPIKey, cred.Subject())
	if err != nil || got.PrincipalID() != "p1" {
		t.Fatalf("find: %v %v", got, err)
	}

	all, _ := s.Lookup(ctx, "p1")
	if len(all) != 1 {
		t.Fatalf("lookup: %d", len(all))
	}

	if err := s.Revoke(ctx, CredentialAPIKey, cred.Subject()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.FindBySubject(ctx, CredentialAPIKey, cred.Subject()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected not-found after revoke, got %v", err)
	}
	if err := s.Revoke(ctx, CredentialAPIKey, cred.Subject()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
}

type fakeNoSubject struct{}

func (fakeNoSubject) Kind() CredentialKind                       { return CredentialAPIKey }
func (fakeNoSubject) PrincipalID() string                        { return "p" }
func (fakeNoSubject) Verify(context.Context, AuthFactor) error   { return nil }

func TestMemoryCredentialStore_RejectsNonSubjectCarrier(t *testing.T) {
	s := NewMemoryCredentialStore()
	if err := s.Save(context.Background(), fakeNoSubject{}); !errors.Is(err, ErrUnsupportedFactor) {
		t.Fatalf("expected ErrUnsupportedFactor, got %v", err)
	}
}
