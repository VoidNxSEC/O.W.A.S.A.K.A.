// Package transparency implements OWASAKA's RFC 6962-inspired
// transparency log. Critical events (principal lifecycle, policy
// reload, key rotation, high-severity alerts) are appended as Merkle
// leaves; a Signed Tree Head (STH) is produced after every append, and
// inclusion + consistency proofs are queryable.
//
// The implementation is intentionally narrower than full Certificate
// Transparency: we borrow the data structures (Merkle tree, STH,
// proofs) and skip the trust-distribution overlay (gossip, monitors,
// auditors) because we own and run the log. When the ecosystem grows
// to need external witnesses, that scope lands in a follow-up ADR.
//
// See ADR-0063 for design rationale and ADR-0062 for the per-event
// signing layer this log sits on top of.
package transparency

import (
	"errors"
	"time"
)

// Bucket names used in BoltDB persistence.
const (
	BucketLeaves    = "transparency.leaves"
	BucketNodes     = "transparency.nodes"
	BucketSTH       = "transparency.sth"
	BucketSTHHistory = "transparency.sth.history"

	// LatestSTHKey is the single key in BucketSTH that holds the most
	// recent STH. The full STH history (one per tree size that ever
	// existed) lives in BucketSTHHistory keyed by tree size.
	LatestSTHKey = "latest"
)

// LeafKind classifies the source of a leaf so consumers can filter
// without parsing the payload.
type LeafKind string

const (
	LeafPrincipalLifecycle LeafKind = "principal.lifecycle"
	LeafTokenLifecycle     LeafKind = "token.lifecycle"
	LeafPolicyReload       LeafKind = "policy.reload"
	LeafKeyRotation        LeafKind = "key.rotation"
	LeafAlertHigh          LeafKind = "alert.high"
	LeafOperatorOverride   LeafKind = "operator.override"
	LeafBackup             LeafKind = "backup"
)

// Leaf is the input to Tree.Append. The payload is opaque to the tree;
// only its bytes feed the leaf hash function. Kind is captured so the
// HTTP endpoint can filter without decoding.
type Leaf struct {
	// Kind classifies the leaf's source for query/filter purposes.
	Kind LeafKind `json:"kind"`
	// Timestamp records when the producer emitted the event (NOT
	// when it was appended; clock skew is a feature here, not a bug
	// — we want producer ordering).
	Timestamp time.Time `json:"timestamp"`
	// Payload is the canonical bytes of the event the leaf attests.
	// For signed NetworkEvents (ADR-0062) this is the result of
	// NetworkEvent.CanonicalBytes() ++ Signature. Consumers verify
	// the signature inside Payload independently.
	Payload []byte `json:"payload"`
}

// LeafIndex is the 0-based position of a leaf in the tree. Stable
// once assigned; never reused after retraction (retractions are out of
// scope — append-only is the whole point).
type LeafIndex uint64

// TreeSize is the count of leaves in the tree.
type TreeSize uint64

// RootHash is the 32-byte Merkle root for a tree at a given size.
type RootHash [32]byte

// Proof is the audit path for an inclusion or consistency proof: an
// ordered list of 32-byte hashes that, combined with the leaf or the
// previous root, reproduces the new root.
type Proof [][]byte

// STH is the Signed Tree Head — a tamper-evident commitment to the
// log's state at a specific size. Signed with a pki.PurposeTransparencyLogSTH
// keypair; verifiers fetch the public key from the JWKS endpoint that
// already serves JWT + event-signing keys.
type STH struct {
	TreeSize    TreeSize  `json:"tree_size"`
	RootHash    []byte    `json:"root_hash"`
	Timestamp   time.Time `json:"timestamp"`
	Signature   []byte    `json:"signature"`
	SignerKeyID string    `json:"signer_key_id"`
}

// Sentinel errors. Exposed so HTTP endpoints can map them onto status
// codes and the pipeline can audit-log reasons without parsing strings.
var (
	ErrLeafIndexOutOfRange = errors.New("transparency: leaf index out of range")
	ErrTreeSizeMismatch    = errors.New("transparency: requested tree size larger than current")
	ErrConsistencyRange    = errors.New("transparency: first must be ≤ second and both must be ≤ current size")
	ErrNoSTHSigningKey     = errors.New("transparency: no active PurposeTransparencyLogSTH key")
	ErrCorruptedTree       = errors.New("transparency: stored tree state is corrupt")
)
