package transparency

import "crypto/sha256"

// RFC 6962 §2.1 hashing:
//
//   leaf hash:   SHA-256(0x00 || leaf_bytes)
//   inner hash:  SHA-256(0x01 || left || right)
//   empty tree:  SHA-256("")
//
// The 0x00 / 0x01 prefixes prevent second-preimage attacks: an inner
// hash output cannot be mistaken for a leaf hash input.

const (
	leafPrefix  byte = 0x00
	innerPrefix byte = 0x01
)

// HashLeaf returns the leaf hash for raw payload bytes.
func HashLeaf(payload []byte) RootHash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(payload)
	var out RootHash
	copy(out[:], h.Sum(nil))
	return out
}

// HashChildren returns the inner-node hash for a left/right pair.
func HashChildren(left, right RootHash) RootHash {
	h := sha256.New()
	h.Write([]byte{innerPrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out RootHash
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRoot returns the canonical RFC 6962 empty-tree root.
func EmptyRoot() RootHash {
	h := sha256.New()
	var out RootHash
	copy(out[:], h.Sum(nil))
	return out
}

// largestPowerOfTwoLessThan returns the largest power of 2 strictly
// less than n. RFC 6962 §2.1 calls this k(n). n must be > 1.
func largestPowerOfTwoLessThan(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	k := uint64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// MerkleTreeHash computes MTH(D[n]) recursively per RFC 6962 §2.1
// over a slice of pre-hashed leaves. Pure function; no I/O.
//
// The caller is responsible for materializing leaves[]; in practice
// the Tree stores leaf hashes and feeds slices of them to this
// function for root + proof computation.
func MerkleTreeHash(leafHashes []RootHash) RootHash {
	n := uint64(len(leafHashes))
	switch n {
	case 0:
		return EmptyRoot()
	case 1:
		return leafHashes[0]
	default:
		k := largestPowerOfTwoLessThan(n)
		left := MerkleTreeHash(leafHashes[:k])
		right := MerkleTreeHash(leafHashes[k:])
		return HashChildren(left, right)
	}
}
