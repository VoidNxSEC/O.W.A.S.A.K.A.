// Package pki provides the OWASAKA Public Key Infrastructure: Ed25519
// keypair management, an internal Certificate Authority, and leaf
// certificate issuance for mTLS between ecosystem services. See ADR-0059.
package pki

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// Purpose categorizes what a KeyPair is used for. Different purposes have
// different rotation policies and storage rules.
type Purpose string

const (
	// PurposeCA: the long-lived root certificate authority key. Rotated
	// rarely (years) and only with operator intervention.
	PurposeCA Purpose = "ca"

	// PurposeJWTSigning: short-lived keypairs used to sign JWT access
	// tokens. Rotated every 24 hours with a 1-hour overlap window.
	PurposeJWTSigning Purpose = "jwt-signing"

	// PurposeServiceCert: keypairs underlying leaf X.509 certs issued
	// for mTLS to ecosystem services (Spectre, Cerebro, agents).
	PurposeServiceCert Purpose = "service-cert"

	// PurposeEventSigning: keypair used by ADR-EventSigning (Sprint 3)
	// to sign published NetworkEvents. Allocated here so the same
	// rotation/distribution primitives apply.
	PurposeEventSigning Purpose = "event-signing"
)

// KeyStatus reflects whether a KeyPair is currently usable.
//
// A typical rotation lifecycle: active → rotating → retired.
//
//   - active:   sole signer/issuer for its purpose.
//   - rotating: a successor exists; this key may still verify but no
//     longer signs. Kept for the overlap window so in-flight tokens
//     verify cleanly.
//   - retired:  removed from active use; kept only for historical
//     attribution and verification of archived material.
type KeyStatus string

const (
	StatusKeyActive   KeyStatus = "active"
	StatusKeyRotating KeyStatus = "rotating"
	StatusKeyRetired  KeyStatus = "retired"
)

// KeyPair holds an Ed25519 public/private keypair with lifecycle metadata.
//
// ID is the stable JWKS "kid" used by downstream verifiers (Spectre,
// Cerebro). It survives status transitions; only generation creates a new ID.
type KeyPair struct {
	ID        string
	Purpose   Purpose
	Public    ed25519.PublicKey
	Private   ed25519.PrivateKey
	Status    KeyStatus
	CreatedAt time.Time
	NotBefore time.Time
	NotAfter  time.Time
}

// IsUsable reports whether the keypair can still sign new material.
//
// A key can sign only when active and within its validity window.
func (k *KeyPair) IsUsable(at time.Time) bool {
	if k == nil || k.Status != StatusKeyActive {
		return false
	}
	if at.Before(k.NotBefore) || at.After(k.NotAfter) {
		return false
	}
	return true
}

// IsVerifyable reports whether the keypair's public key is still trusted
// for verifying previously-signed material.
//
// Rotating keys verify but do not sign; retired keys do neither.
func (k *KeyPair) IsVerifyable(at time.Time) bool {
	if k == nil || k.Status == StatusKeyRetired {
		return false
	}
	return !at.After(k.NotAfter)
}

// Sentinel errors returned by pki operations.
var (
	ErrKeyNotFound      = errors.New("pki: keypair not found")
	ErrNoActiveKey      = errors.New("pki: no active key for purpose")
	ErrKeyExpired       = errors.New("pki: key past its validity window")
	ErrInvalidPurpose   = errors.New("pki: unsupported key purpose")
	ErrAuthorityNoRoot  = errors.New("pki: authority has no root CA initialized")
)
