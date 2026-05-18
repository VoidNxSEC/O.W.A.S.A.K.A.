package events

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// Verifier validates Ed25519 signatures attached by a Signer. Identical
// algorithm and serialization rules; only the key direction differs.
//
// Downstream services (Spectre, Cerebro) instantiate a Verifier from a
// snapshot of the PKI store (via JWKS sync) — they don't need write
// access to the Authority.
type Verifier struct {
	authority *pki.Authority
	clock     func() time.Time
}

// NewVerifier builds a Verifier. WithVerifierClock overrides the time
// source for key-validity checks during tests.
func NewVerifier(authority *pki.Authority, opts ...VerifierOption) *Verifier {
	v := &Verifier{authority: authority, clock: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithVerifierClock injects a custom time source. Useful in tests that
// exercise rotation overlap windows.
func WithVerifierClock(c func() time.Time) VerifierOption {
	return func(v *Verifier) { v.clock = c }
}

// Verify returns nil iff the event's signature validates against the
// resolved public key, the key is currently verifyable, and the
// canonical bytes were not tampered with.
//
// Verify is the central tamper-detection primitive: any byte changed
// after Sign breaks verification, regardless of where the change
// happened (BoltDB write, NATS in-flight, Cerebro re-encode).
func (v *Verifier) Verify(ctx context.Context, e models.NetworkEvent) error {
	if !e.IsSigned() {
		return ErrSignatureMissing
	}

	kp, err := v.authority.GetKey(ctx, e.SignerKeyID)
	if err == pki.ErrKeyNotFound {
		return ErrSignerKeyUnknown
	}
	if err != nil {
		return fmt.Errorf("events: lookup verifying key: %w", err)
	}
	if !kp.IsVerifyable(v.clock()) {
		return ErrSignerKeyRetired
	}
	if kp.Purpose != pki.PurposeEventSigning {
		// The kid resolved to a different key purpose — refuse.
		// Prevents cross-purpose verification (e.g., trying to verify
		// an event signature against a JWT signing key).
		return ErrSignerKeyUnknown
	}

	canonical, err := e.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("events: canonical bytes: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(kp.Public), canonical, e.Signature) {
		return ErrSignatureInvalid
	}
	return nil
}

// SignerErrorIs reports whether err is one of this package's sentinel
// errors. Equivalent to a chain of errors.Is checks; provided as a
// readability shorthand for callers that want to log a category.
func SignerErrorIs(err error) (category string, ok bool) {
	switch {
	case errors.Is(err, ErrSignatureMissing):
		return "missing", true
	case errors.Is(err, ErrSignatureInvalid):
		return "invalid", true
	case errors.Is(err, ErrSignerKeyUnknown):
		return "unknown_key", true
	case errors.Is(err, ErrSignerKeyRetired):
		return "retired_key", true
	case errors.Is(err, ErrSignerNoActiveKey):
		return "no_active_key", true
	}
	return "", false
}
