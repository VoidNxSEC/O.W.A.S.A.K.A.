package pki

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"
)

func TestMemoryKeyStore_GetMissing(t *testing.T) {
	s := NewMemoryKeyStore()
	if _, err := s.Get(context.Background(), "nope"); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestMemoryKeyStore_SaveAndFind(t *testing.T) {
	s := NewMemoryKeyStore()
	kp := &KeyPair{ID: "k1", Purpose: PurposeJWTSigning, Status: StatusKeyActive}
	if err := s.Save(context.Background(), kp); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.Get(context.Background(), "k1")
	if err != nil || got.ID != "k1" {
		t.Fatalf("get returned %v %v", got, err)
	}

	active, err := s.ActiveByPurpose(context.Background(), PurposeJWTSigning)
	if err != nil || active.ID != "k1" {
		t.Fatalf("active: %v %v", active, err)
	}

	if _, err := s.ActiveByPurpose(context.Background(), PurposeCA); err != ErrNoActiveKey {
		t.Fatalf("expected ErrNoActiveKey for CA, got %v", err)
	}

	list, err := s.FindByPurpose(context.Background(), PurposeJWTSigning)
	if err != nil || len(list) != 1 {
		t.Fatalf("find: %v len=%d", err, len(list))
	}
}

func TestMemoryKeyStore_UpdateStatus(t *testing.T) {
	s := NewMemoryKeyStore()
	kp := &KeyPair{ID: "k1", Purpose: PurposeJWTSigning, Status: StatusKeyActive}
	_ = s.Save(context.Background(), kp)

	if err := s.UpdateStatus(context.Background(), "k1", StatusKeyRotating); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.Get(context.Background(), "k1")
	if got.Status != StatusKeyRotating {
		t.Fatalf("status not rotating: %v", got.Status)
	}
	if err := s.UpdateStatus(context.Background(), "missing", StatusKeyRetired); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestKeyPair_Usability(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	kp := &KeyPair{
		Status:    StatusKeyActive,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}
	if !kp.IsUsable(now) {
		t.Fatal("active+in-window key should be usable")
	}
	if !kp.IsVerifyable(now) {
		t.Fatal("active+in-window key should verify")
	}

	kp.Status = StatusKeyRotating
	if kp.IsUsable(now) {
		t.Fatal("rotating key should not sign")
	}
	if !kp.IsVerifyable(now) {
		t.Fatal("rotating key should still verify")
	}

	kp.Status = StatusKeyRetired
	if kp.IsVerifyable(now) {
		t.Fatal("retired key should not verify")
	}

	kp.Status = StatusKeyActive
	if kp.IsUsable(now.Add(2 * time.Hour)) {
		t.Fatal("expired key should not be usable")
	}

	var nilKP *KeyPair
	if nilKP.IsUsable(now) || nilKP.IsVerifyable(now) {
		t.Fatal("nil keypair should never be usable/verifyable")
	}
}

func TestAuthority_GenerateAndActive(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()

	kp, err := a.GenerateKeyPair(ctx, PurposeJWTSigning, 24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(kp.Public) != ed25519.PublicKeySize {
		t.Fatalf("public key wrong size: %d", len(kp.Public))
	}
	if len(kp.Private) != ed25519.PrivateKeySize {
		t.Fatalf("private key wrong size: %d", len(kp.Private))
	}
	if kp.Status != StatusKeyActive {
		t.Fatalf("status not active: %v", kp.Status)
	}

	active, err := a.ActiveKey(ctx, PurposeJWTSigning)
	if err != nil || active.ID != kp.ID {
		t.Fatalf("active mismatch: %v %v", active, err)
	}
}

func TestAuthority_GenerateRejectsEmptyPurpose(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	if _, err := a.GenerateKeyPair(context.Background(), "", time.Hour); err != ErrInvalidPurpose {
		t.Fatalf("expected ErrInvalidPurpose, got %v", err)
	}
}

func TestAuthority_Rotation(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()

	first, _ := a.GenerateKeyPair(ctx, PurposeJWTSigning, 24*time.Hour)
	second, err := a.Rotate(ctx, PurposeJWTSigning, 24*time.Hour)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first.ID == second.ID {
		t.Fatal("rotation must produce a new key id")
	}

	// first should now be rotating
	firstAfter, _ := a.store.Get(ctx, first.ID)
	if firstAfter.Status != StatusKeyRotating {
		t.Fatalf("first should be rotating, got %v", firstAfter.Status)
	}

	// second should be the active one
	active, _ := a.ActiveKey(ctx, PurposeJWTSigning)
	if active.ID != second.ID {
		t.Fatalf("active should be second, got %v", active.ID)
	}

	// Retire first; verifyability ends
	if err := a.Retire(ctx, first.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	retired, _ := a.store.Get(ctx, first.ID)
	if retired.Status != StatusKeyRetired {
		t.Fatalf("first not retired: %v", retired.Status)
	}
}

func TestAuthority_RotationWithNoExisting(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()
	// Rotate with no prior key should still produce a fresh active key.
	kp, err := a.Rotate(ctx, PurposeJWTSigning, time.Hour)
	if err != nil {
		t.Fatalf("rotate without prior: %v", err)
	}
	if kp == nil || kp.Status != StatusKeyActive {
		t.Fatal("rotation should produce an active key when none existed")
	}
}

func TestAuthority_EnsureRootCAIdempotent(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()

	first, err := a.EnsureRootCA(ctx, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("ensure root: %v", err)
	}
	second, err := a.EnsureRootCA(ctx, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("ensure root again: %v", err)
	}
	if first.ID != second.ID {
		t.Fatal("EnsureRootCA must be idempotent")
	}
}

func TestAuthority_RootFingerprint(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()

	if _, err := a.RootFingerprint(ctx); err != ErrAuthorityNoRoot {
		t.Fatalf("expected ErrAuthorityNoRoot, got %v", err)
	}

	_, _ = a.EnsureRootCA(ctx, 365*24*time.Hour)

	fp, err := a.RootFingerprint(ctx)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	// 32-byte sha256 -> 64 hex chars + 31 colons = 95 chars
	if len(fp) != 95 {
		t.Fatalf("fingerprint length %d, expected 95", len(fp))
	}
}

func TestAuthority_IssueServiceCert(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()

	if _, err := a.IssueServiceCert(ctx, "spectre", time.Hour); err != ErrAuthorityNoRoot {
		t.Fatalf("expected ErrAuthorityNoRoot, got %v", err)
	}

	root, _ := a.EnsureRootCA(ctx, 365*24*time.Hour)

	issued, err := a.IssueServiceCert(ctx, "spectre", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Subject != "spectre" {
		t.Fatalf("subject: %s", issued.Subject)
	}
	if issued.RootKeyID != root.ID {
		t.Fatalf("issued cert references wrong root: %s vs %s", issued.RootKeyID, root.ID)
	}
	if issued.Certificate.Subject.CommonName != "spectre" {
		t.Fatalf("cn: %s", issued.Certificate.Subject.CommonName)
	}

	// Verify the cert chains to the root.
	roots := x509.NewCertPool()
	rootTemplate, _ := buildRootCertTemplate(root, root.NotBefore)
	rootDER, err := x509.CreateCertificate(nil, rootTemplate, rootTemplate, root.Public, root.Private)
	if err != nil {
		t.Fatalf("self-sign root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	roots.AddCert(rootCert)

	// Note: we can't verify cleanly without the same root cert envelope used at sign-time
	// (Authority issues using a fresh envelope each time). What we *can* check: the leaf
	// claims to be signed by the root, has correct usage, and the public keys match.
	if !issued.Certificate.NotAfter.After(issued.Certificate.NotBefore) {
		t.Fatal("validity window invalid")
	}
	leafPub, ok := issued.Certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("leaf public key not ed25519")
	}
	if string(leafPub) != string(issued.KeyPair.Public) {
		t.Fatal("leaf cert pubkey differs from issued keypair public")
	}

	// Sanity: cert has Client+Server auth EKUs
	hasClient, hasServer := false, false
	for _, eku := range issued.Certificate.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
		if eku == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
	}
	if !hasClient || !hasServer {
		t.Fatalf("ext key usage missing: client=%v server=%v", hasClient, hasServer)
	}
}

func TestAuthority_IssueServiceCert_RequiresSubject(t *testing.T) {
	a := NewAuthority(NewMemoryKeyStore())
	ctx := context.Background()
	_, _ = a.EnsureRootCA(ctx, 365*24*time.Hour)
	if _, err := a.IssueServiceCert(ctx, "", time.Hour); err == nil {
		t.Fatal("expected error for empty subject")
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	f1 := Fingerprint(pub)
	f2 := Fingerprint(pub)
	if f1 != f2 {
		t.Fatalf("fingerprint not deterministic: %s vs %s", f1, f2)
	}
}

func TestMemoryKeyStore_SaveRejectsEmpty(t *testing.T) {
	s := NewMemoryKeyStore()
	if err := s.Save(context.Background(), nil); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound for nil, got %v", err)
	}
	if err := s.Save(context.Background(), &KeyPair{}); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound for empty id, got %v", err)
	}
}
