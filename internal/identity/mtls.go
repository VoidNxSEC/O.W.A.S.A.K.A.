package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// MTLSCredential binds a Principal to an X.509 client certificate
// fingerprint. Verification is delegated to the TLS handshake; this
// credential's role is to map a verified cert back to a Principal.
//
// Used by Service principals (Spectre, Cerebro) and optionally by Agent
// principals that prefer cert-based auth over API keys.
type MTLSCredential struct {
	principalID string
	subject     string // CN of the cert (e.g., "spectre", "cerebro")
	fingerprint string // SHA-256 of the leaf cert's SPKI, colon-separated
}

// NewMTLSCredential binds a Principal to a leaf certificate. The cert
// must have already been validated against the internal CA chain by the
// TLS layer — this constructor only extracts and pins the fingerprint.
func NewMTLSCredential(principalID, subject string, leaf *x509.Certificate) (*MTLSCredential, error) {
	if principalID == "" || subject == "" {
		return nil, errors.New("identity: principal id and subject required")
	}
	if leaf == nil {
		return nil, errors.New("identity: leaf cert required")
	}
	return &MTLSCredential{
		principalID: principalID,
		subject:     subject,
		fingerprint: SPKIFingerprint(leaf),
	}, nil
}

// LoadMTLSCredential reconstructs an mTLS credential from persisted
// material (principal id + cert fingerprint).
func LoadMTLSCredential(principalID, subject, fingerprint string) *MTLSCredential {
	return &MTLSCredential{
		principalID: principalID,
		subject:     subject,
		fingerprint: normalizeFingerprint(fingerprint),
	}
}

// SPKIFingerprint returns the colon-separated SHA-256 fingerprint of a
// certificate's Subject Public Key Info. SPKI rather than the full DER
// so cert re-issuance with the same key preserves identity.
func SPKIFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	hexEncoded := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(hexEncoded)/2)
	for i := 0; i < len(hexEncoded); i += 2 {
		parts = append(parts, hexEncoded[i:i+2])
	}
	return strings.Join(parts, ":")
}

// MTLSValidator verifies leaf certificates against a trusted root pool.
//
// The Authority's root CA is the trust anchor; verification accepts any
// cert chaining to that root, with a non-expired leaf and ClientAuth
// extended key usage.
type MTLSValidator struct {
	roots   *x509.CertPool
	clock   func() time.Time
}

// NewMTLSValidator builds a validator over a fixed root pool.
func NewMTLSValidator(roots *x509.CertPool) *MTLSValidator {
	return &MTLSValidator{roots: roots, clock: time.Now}
}

// WithMTLSClock overrides the time source for testing.
func (v *MTLSValidator) WithClock(c func() time.Time) *MTLSValidator {
	v.clock = c
	return v
}

// Validate checks the leaf chains to a trusted root, is currently valid,
// and is authorized for client authentication. Returns the SPKI
// fingerprint of the validated leaf on success.
func (v *MTLSValidator) Validate(leaf *x509.Certificate, intermediates *x509.CertPool) (string, error) {
	if leaf == nil {
		return "", ErrCredentialInvalid
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   v.clock(),
	}
	if _, err := leaf.Verify(opts); err != nil {
		return "", ErrCredentialInvalid
	}
	return SPKIFingerprint(leaf), nil
}

// Kind implements Credential.
func (c *MTLSCredential) Kind() CredentialKind { return CredentialMTLS }

// PrincipalID implements Credential.
func (c *MTLSCredential) PrincipalID() string { return c.principalID }

// Subject returns the CN bound to this credential — the store indexes
// by fingerprint, but the subject is exposed for human-readable audit.
func (c *MTLSCredential) Subject() string { return c.fingerprint }

// CommonName returns the human-readable CN of the cert.
func (c *MTLSCredential) CommonName() string { return c.subject }

// Fingerprint returns the colon-separated SHA-256 SPKI fingerprint.
func (c *MTLSCredential) Fingerprint() string { return c.fingerprint }

// Verify compares a presented fingerprint against the bound value.
//
// The mTLS handshake at the TLS layer already validates the cert chain;
// this method's role is the final binding check. AuthFactor.Subject
// should be the presented cert's fingerprint (extracted by the caller
// via SPKIFingerprint).
func (c *MTLSCredential) Verify(_ context.Context, factor AuthFactor) error {
	if factor.Kind != CredentialMTLS {
		return ErrUnsupportedFactor
	}
	presented := normalizeFingerprint(factor.Subject)
	if presented == "" || presented != c.fingerprint {
		return ErrCredentialInvalid
	}
	return nil
}

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
