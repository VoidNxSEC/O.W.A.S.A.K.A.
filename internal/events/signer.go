package events

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// Sentinel errors for event signing / verification. Exposed so callers
// (pipeline, transparency log, Spectre/Cerebro libraries) can map onto
// HTTP responses and audit reasons without parsing strings.
var (
	ErrSignerNoActiveKey = errors.New("events: no active PurposeEventSigning key")
	ErrSignatureMissing  = errors.New("events: event has no signature")
	ErrSignatureInvalid  = errors.New("events: signature failed verification")
	ErrSignerKeyUnknown  = errors.New("events: signer key id not found in PKI store")
	ErrSignerKeyRetired  = errors.New("events: signer key retired (no longer verifyable)")
)

// Signer attaches an Ed25519 signature to every NetworkEvent passing
// through it. The signing key is drawn from the PKI Authority under
// pki.PurposeEventSigning so it rotates on the standard 24h cadence
// (ADR-0059) and survives swaps without disturbing JWT signing
// (ADR-0062 §"Key purpose").
type Signer struct {
	authority *pki.Authority
}

// NewSigner builds a Signer over a PKI Authority. The Authority must
// already hold an active PurposeEventSigning key; callers wire
// authority.EnsureEventSigningKey at boot.
func NewSigner(authority *pki.Authority) *Signer {
	return &Signer{authority: authority}
}

// Sign attaches a signature + key id to the event. Mutates *e in
// place — typical call sites (pipeline pre-publish) already hold a
// pointer.
//
// Returns ErrSignerNoActiveKey if no PurposeEventSigning key exists.
// Errors during canonical-bytes computation propagate verbatim.
func (s *Signer) Sign(ctx context.Context, e *models.NetworkEvent) error {
	if e == nil {
		return errors.New("events: nil event")
	}
	kp, err := s.authority.ActiveKey(ctx, pki.PurposeEventSigning)
	if err == pki.ErrNoActiveKey {
		return ErrSignerNoActiveKey
	}
	if err != nil {
		return fmt.Errorf("events: lookup signing key: %w", err)
	}

	// Clear any previous signature on the event before computing
	// canonical bytes — a re-sign should produce the same bytes
	// regardless of stale signature material from upstream.
	e.Signature = nil
	e.SignerKeyID = ""

	canonical, err := e.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("events: canonical bytes: %w", err)
	}

	e.Signature = ed25519.Sign(ed25519.PrivateKey(kp.Private), canonical)
	e.SignerKeyID = kp.ID
	return nil
}
