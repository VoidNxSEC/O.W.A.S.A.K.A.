package transparency

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// STHSigner produces Signed Tree Heads using a pki.PurposeTransparencyLogSTH
// keypair. Distinct from the event signer (ADR-0062) so compromise of
// one does not invalidate the other.
//
// STHs are signed over `treeSize || rootHash || timestamp (unix nanos)`
// — a deterministic byte string with no JSON ambiguity. Verifiers
// reproduce the same byte string and check the signature against the
// public key published in the JWKS endpoint.
type STHSigner struct {
	authority *pki.Authority
	clock     func() time.Time
}

// NewSTHSigner builds an STHSigner.
func NewSTHSigner(authority *pki.Authority) *STHSigner {
	return &STHSigner{authority: authority, clock: time.Now}
}

// WithSTHClock overrides the time source. Test-only.
func (s *STHSigner) WithClock(c func() time.Time) *STHSigner {
	s.clock = c
	return s
}

// SignSTH produces a fresh STH for the given tree size and root.
// The Tree calls this after every Append (or batch of appends).
func (s *STHSigner) SignSTH(ctx context.Context, size TreeSize, root RootHash) (STH, error) {
	kp, err := s.authority.ActiveKey(ctx, pki.PurposeTransparencyLogSTH)
	if err == pki.ErrNoActiveKey {
		return STH{}, ErrNoSTHSigningKey
	}
	if err != nil {
		return STH{}, fmt.Errorf("transparency: lookup STH key: %w", err)
	}

	ts := s.clock()
	canonical := canonicalSTHBytes(size, root, ts)
	sig := ed25519.Sign(ed25519.PrivateKey(kp.Private), canonical)
	return STH{
		TreeSize:    size,
		RootHash:    append([]byte{}, root[:]...),
		Timestamp:   ts,
		Signature:   sig,
		SignerKeyID: kp.ID,
	}, nil
}

// VerifySTH checks an STH's signature against the PKI store. Returns
// nil iff the signature validates and the key is still verifyable.
// Used by tests, the demo, and downstream consumers that fetch STHs
// via HTTP and need a Go primitive to verify them.
func VerifySTH(ctx context.Context, authority *pki.Authority, sth STH, now time.Time) error {
	if len(sth.RootHash) != 32 {
		return errors.New("transparency: STH RootHash must be 32 bytes")
	}
	if len(sth.Signature) == 0 || sth.SignerKeyID == "" {
		return errors.New("transparency: STH has no signature")
	}
	kp, err := authority.GetKey(ctx, sth.SignerKeyID)
	if err == pki.ErrKeyNotFound {
		return errors.New("transparency: STH signer key not found")
	}
	if err != nil {
		return err
	}
	if !kp.IsVerifyable(now) {
		return errors.New("transparency: STH signer key retired")
	}
	if kp.Purpose != pki.PurposeTransparencyLogSTH {
		return errors.New("transparency: STH signer key has wrong purpose")
	}
	var root RootHash
	copy(root[:], sth.RootHash)
	canonical := canonicalSTHBytes(sth.TreeSize, root, sth.Timestamp)
	if !ed25519.Verify(ed25519.PublicKey(kp.Public), canonical, sth.Signature) {
		return errors.New("transparency: STH signature invalid")
	}
	return nil
}

// canonicalSTHBytes is the byte string covered by the STH signature:
//
//   [8 bytes BE TreeSize][32 bytes RootHash][8 bytes BE Timestamp UnixNano]
//
// Fixed-width and deterministic; no JSON ambiguity, no canonicalization
// drift between Go versions.
func canonicalSTHBytes(size TreeSize, root RootHash, ts time.Time) []byte {
	buf := make([]byte, 8+32+8)
	binary.BigEndian.PutUint64(buf[0:8], uint64(size))
	copy(buf[8:40], root[:])
	binary.BigEndian.PutUint64(buf[40:48], uint64(ts.UnixNano()))
	return buf
}

// PersistSTH writes the STH to the latest slot and appends to history.
// History is keyed by tree size so the full STH timeline is queryable.
func PersistSTH(db *bolt.DB, sth STH) error {
	if db == nil {
		return errors.New("transparency: nil bolt db")
	}
	raw, err := json.Marshal(sth)
	if err != nil {
		return fmt.Errorf("transparency: marshal STH: %w", err)
	}
	return db.Update(func(tx *bolt.Tx) error {
		latest := tx.Bucket([]byte(BucketSTH))
		if err := latest.Put([]byte(LatestSTHKey), raw); err != nil {
			return err
		}
		history := tx.Bucket([]byte(BucketSTHHistory))
		return history.Put(encodeIndex(uint64(sth.TreeSize)), raw)
	})
}

// LatestSTH returns the most recent persisted STH. Returns nil with
// no error when no STH has been persisted yet (fresh deployment).
func LatestSTH(db *bolt.DB) (*STH, error) {
	var out *STH
	err := db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(BucketSTH)).Get([]byte(LatestSTHKey))
		if raw == nil {
			return nil
		}
		var sth STH
		if err := json.Unmarshal(raw, &sth); err != nil {
			return err
		}
		out = &sth
		return nil
	})
	return out, err
}

// STHAt returns the STH recorded for a specific tree size, or nil if
// no STH was issued at that size. Used by consistency-proof flows
// that need a historical anchor.
func STHAt(db *bolt.DB, size TreeSize) (*STH, error) {
	var out *STH
	err := db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte(BucketSTHHistory)).Get(encodeIndex(uint64(size)))
		if raw == nil {
			return nil
		}
		var sth STH
		if err := json.Unmarshal(raw, &sth); err != nil {
			return err
		}
		out = &sth
		return nil
	})
	return out, err
}
