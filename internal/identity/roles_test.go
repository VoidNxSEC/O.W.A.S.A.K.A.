package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func mkCertWithOU(t *testing.T, ous ...string) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "test",
			OrganizationalUnit: ous,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestRolesFromCert_SingleRole(t *testing.T) {
	cert := mkCertWithOU(t, "role:service")
	got := RolesFromCert(cert)
	if len(got) != 1 || got[0] != "service" {
		t.Fatalf("expected [service], got %v", got)
	}
}

func TestRolesFromCert_MultipleRoles(t *testing.T) {
	cert := mkCertWithOU(t, "role:service", "role:rule-author")
	got := RolesFromCert(cert)
	if len(got) != 2 {
		t.Fatalf("expected 2 roles, got %v", got)
	}
}

func TestRolesFromCert_IgnoresNonRoleOUs(t *testing.T) {
	cert := mkCertWithOU(t, "org:voidnxlabs", "team:security")
	if got := RolesFromCert(cert); len(got) != 0 {
		t.Fatalf("expected no roles, got %v", got)
	}
}

func TestRolesFromCert_IgnoresEmptyRoleSuffix(t *testing.T) {
	cert := mkCertWithOU(t, "role:", "role:   ")
	if got := RolesFromCert(cert); len(got) != 0 {
		t.Fatalf("expected no roles for empty suffixes, got %v", got)
	}
}

func TestRolesFromCert_NilCert(t *testing.T) {
	if got := RolesFromCert(nil); got != nil {
		t.Fatalf("nil cert should yield nil, got %v", got)
	}
}

func TestAssignRoles_NormalizesAndDedupes(t *testing.T) {
	p := &Principal{}
	AssignRoles(p, "admin", "", "service", "admin", " analyst ")
	if len(p.Roles) != 3 {
		t.Fatalf("expected 3 roles after dedup, got %v", p.Roles)
	}
	if p.Roles[0] != "admin" || p.Roles[2] != "analyst" {
		t.Fatalf("unexpected order/values: %v", p.Roles)
	}
}

func TestAssignRoles_NilPrincipalNoop(t *testing.T) {
	// Just shouldn't panic.
	AssignRoles(nil, "admin")
}

func TestPrincipal_HasRole(t *testing.T) {
	p := &Principal{Roles: []string{"admin", "viewer"}}
	if !p.HasRole("admin") {
		t.Fatal("admin role missing")
	}
	if p.HasRole("ghost") {
		t.Fatal("ghost role should not match")
	}

	var nilP *Principal
	if nilP.HasRole("admin") {
		t.Fatal("nil principal should not match any role")
	}
}
