package pki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Authority is the central PKI service: it generates Ed25519 keypairs,
// manages their rotation, owns the root certificate authority, and issues
// X.509 leaf certificates for ecosystem services (Spectre, Cerebro,
// agents).
//
// Authority is the only place where private key material is created.
// Callers that need to sign or verify should obtain a KeyPair through the
// Authority rather than reaching into the KeyStore directly.
type Authority struct {
	store  KeyStore
	clock  func() time.Time // injectable for tests
	random io.Reader        // injectable for tests
}

// AuthorityOption configures an Authority.
type AuthorityOption func(*Authority)

// WithClock injects a custom time source. Default: time.Now.
func WithClock(c func() time.Time) AuthorityOption {
	return func(a *Authority) { a.clock = c }
}

// WithRandom injects a custom entropy source. Default: crypto/rand.Reader.
func WithRandom(r io.Reader) AuthorityOption {
	return func(a *Authority) { a.random = r }
}

// NewAuthority builds an Authority over the given KeyStore.
//
// The store retains all keys ever generated; the Authority is stateless
// beyond it. This means an Authority can be reconstructed at any time
// from its backing store, simplifying restart and migration.
func NewAuthority(store KeyStore, opts ...AuthorityOption) *Authority {
	a := &Authority{
		store:  store,
		clock:  time.Now,
		random: rand.Reader,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// GenerateKeyPair creates a new Ed25519 keypair, persists it as active,
// and returns it.
//
// If a previous key for the same purpose is currently active, the caller
// is responsible for transitioning it (typically via Rotate). This method
// does not enforce single-active because some flows (initial bootstrap,
// forced rollover) legitimately create multiple actives.
func (a *Authority) GenerateKeyPair(ctx context.Context, purpose Purpose, ttl time.Duration) (*KeyPair, error) {
	if purpose == "" {
		return nil, ErrInvalidPurpose
	}

	pub, priv, err := ed25519.GenerateKey(a.random)
	if err != nil {
		return nil, fmt.Errorf("pki: generate ed25519: %w", err)
	}

	now := a.clock()
	kp := &KeyPair{
		ID:        uuid.NewString(),
		Purpose:   purpose,
		Public:    pub,
		Private:   priv,
		Status:    StatusKeyActive,
		CreatedAt: now,
		NotBefore: now,
		NotAfter:  now.Add(ttl),
	}

	if err := a.store.Save(ctx, kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// ActiveKey returns the current active key for a purpose.
func (a *Authority) ActiveKey(ctx context.Context, purpose Purpose) (*KeyPair, error) {
	return a.store.ActiveByPurpose(ctx, purpose)
}

// GetKey fetches a KeyPair by its stable ID. Used by verifiers
// resolving a token's "kid" header against the JWKS.
func (a *Authority) GetKey(ctx context.Context, id string) (*KeyPair, error) {
	return a.store.Get(ctx, id)
}

// KeysForPurpose returns all keys (any status) for a purpose. Used by
// the JWKS handler to expose verifying material to downstream services.
func (a *Authority) KeysForPurpose(ctx context.Context, purpose Purpose) ([]*KeyPair, error) {
	return a.store.FindByPurpose(ctx, purpose)
}

// Rotate transitions the currently-active key to "rotating", generates a
// new active key, and returns the new key. Rotating keys remain in the
// store for the overlap window so previously-issued tokens still verify.
//
// Callers schedule a follow-up Retire after the overlap window passes.
func (a *Authority) Rotate(ctx context.Context, purpose Purpose, newTTL time.Duration) (*KeyPair, error) {
	current, err := a.store.ActiveByPurpose(ctx, purpose)
	if err != nil && err != ErrNoActiveKey {
		return nil, err
	}
	if current != nil {
		if err := a.store.UpdateStatus(ctx, current.ID, StatusKeyRotating); err != nil {
			return nil, err
		}
	}
	return a.GenerateKeyPair(ctx, purpose, newTTL)
}

// Retire marks a rotating key as permanently retired. Retired keys are
// kept (do not delete) but cannot be used to verify post-retirement.
func (a *Authority) Retire(ctx context.Context, id string) error {
	return a.store.UpdateStatus(ctx, id, StatusKeyRetired)
}

// EnsureRootCA returns the active root CA keypair, generating one with
// the given TTL if no active root exists. Idempotent and safe to call on
// every boot.
//
// The root CA is the trust anchor for all issued leaf certificates and
// for the JWKS endpoint's identity. Its fingerprint is what operators
// inspect on first boot.
func (a *Authority) EnsureRootCA(ctx context.Context, ttl time.Duration) (*KeyPair, error) {
	kp, err := a.store.ActiveByPurpose(ctx, PurposeCA)
	if err == nil {
		return kp, nil
	}
	if err != ErrNoActiveKey {
		return nil, err
	}
	return a.GenerateKeyPair(ctx, PurposeCA, ttl)
}

// RootFingerprint returns the colon-separated SHA-256 fingerprint of the
// active root CA public key. Suitable for boot banners and operator
// trust prompts ("Trust this fingerprint?").
//
// Returns ErrAuthorityNoRoot if no root has been bootstrapped yet.
func (a *Authority) RootFingerprint(ctx context.Context) (string, error) {
	kp, err := a.store.ActiveByPurpose(ctx, PurposeCA)
	if err == ErrNoActiveKey {
		return "", ErrAuthorityNoRoot
	}
	if err != nil {
		return "", err
	}
	return Fingerprint(kp.Public), nil
}

// Fingerprint returns the colon-separated SHA-256 fingerprint of an
// Ed25519 public key. Exposed so callers that hold a KeyPair directly
// (JWKS, mTLS validators) can format it consistently.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	hex := hex.EncodeToString(sum[:])
	// Format as XX:XX:XX:... for human readability.
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

// IssueServiceCert generates a new Ed25519 keypair under PurposeServiceCert
// and signs an X.509 leaf certificate with the root CA. The resulting cert
// is suitable for mTLS use by ecosystem services (Spectre, Cerebro, agents).
//
// subject names the service (e.g., "spectre", "cerebro", "agent-ci-runner-3").
// It is placed in the cert's CommonName and DNSNames so peer verification
// can match against expected service identities.
func (a *Authority) IssueServiceCert(ctx context.Context, subject string, ttl time.Duration) (*IssuedCert, error) {
	if subject == "" {
		return nil, fmt.Errorf("pki: subject required for service cert")
	}

	root, err := a.store.ActiveByPurpose(ctx, PurposeCA)
	if err == ErrNoActiveKey {
		return nil, ErrAuthorityNoRoot
	}
	if err != nil {
		return nil, err
	}

	leafKP, err := a.GenerateKeyPair(ctx, PurposeServiceCert, ttl)
	if err != nil {
		return nil, err
	}

	now := a.clock()
	serial, err := randomSerial(a.random)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   subject,
			Organization: []string{"voidnxlabs"},
		},
		DNSNames:    []string{subject},
		NotBefore:   now,
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	rootCert, err := buildRootCertTemplate(root, now)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(a.random, tmpl, rootCert, leafKP.Public, root.Private)
	if err != nil {
		return nil, fmt.Errorf("pki: sign leaf cert: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse leaf cert: %w", err)
	}

	return &IssuedCert{
		Subject:     subject,
		Certificate: leaf,
		DER:         der,
		KeyPair:     leafKP,
		RootKeyID:   root.ID,
	}, nil
}

// IssuedCert bundles a freshly-signed leaf certificate with the keypair
// that owns it.
type IssuedCert struct {
	Subject     string
	Certificate *x509.Certificate
	DER         []byte
	KeyPair     *KeyPair
	RootKeyID   string
}

// buildRootCertTemplate constructs a self-signed X.509 cert envelope for
// the root CA keypair. Created on demand because we only store the raw
// keypair, not the wrapping cert. Idempotent: same inputs produce the
// same envelope (modulo serial number, but that doesn't affect signing).
func buildRootCertTemplate(root *KeyPair, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "OWASAKA Root CA",
			Organization: []string{"voidnxlabs"},
		},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}, nil
}

func randomSerial(r io.Reader) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128) // 128-bit serials
	serial, err := rand.Int(r, max)
	if err != nil {
		return nil, fmt.Errorf("pki: random serial: %w", err)
	}
	return serial, nil
}
