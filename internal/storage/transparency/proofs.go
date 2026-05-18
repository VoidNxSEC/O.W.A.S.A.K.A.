package transparency

// RFC 6962 §2.1.1 / §2.1.2 proof algorithms.
//
// Generation operates over a pre-materialized slice of leaf hashes via
// the recursive PATH / SUBPROOF definitions from the spec.
//
// Verification uses the canonical bottom-up algorithm (same approach
// as Google Trillian and Sigsum) — walking from the leaf up the audit
// path, tracking `fn` (the leaf's position at the current level) and
// `sn` (the rightmost position at the current level) to handle
// unbalanced trees correctly. The naive "left-half vs right-half"
// recursion does NOT work for non-power-of-2 sizes because subtree
// sizes diverge from `k = largestPow2Less(n)` at each level.

// InclusionProof returns the audit path for leaf m (0-indexed) in a
// tree built from leafHashes[:n]. The path consists of sibling hashes
// from leaf to root, deepest-first.
//
// Per RFC 6962 §2.1.1, the recursive definition:
//
//	PATH(m, D[n]):
//	  n = 1, m = 0: []
//	  n > 1:
//	    k = largest power of 2 < n
//	    if m < k: PATH(m, D[0:k]) ++ [MTH(D[k:n])]
//	    else:     PATH(m - k, D[k:n]) ++ [MTH(D[0:k])]
func InclusionProof(m uint64, leafHashes []RootHash) Proof {
	n := uint64(len(leafHashes))
	if n == 0 || m >= n {
		return nil
	}
	return inclusionPath(m, leafHashes)
}

func inclusionPath(m uint64, d []RootHash) Proof {
	n := uint64(len(d))
	if n == 1 {
		return Proof{}
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		path := inclusionPath(m, d[:k])
		sibling := MerkleTreeHash(d[k:])
		return appendHash(path, sibling)
	}
	path := inclusionPath(m-k, d[k:])
	sibling := MerkleTreeHash(d[:k])
	return appendHash(path, sibling)
}

// VerifyInclusion reproduces the root from a leaf hash, leaf index,
// tree size, and audit path. Callers compare the returned root against
// their authoritative (STH-bound) root.
//
// Algorithm (Trillian-equivalent):
//
//	fn := leafIndex
//	sn := treeSize - 1
//	for each sibling p in proof:
//	  if (fn == sn) or (fn & 1 == 1):
//	    current = H(p, current)          // p is left sibling
//	    skip rightmost-edge zero-bits of fn
//	  else:
//	    current = H(current, p)          // p is right sibling
//	  fn >>= 1
//	  sn >>= 1
//	return current
func VerifyInclusion(leafHash RootHash, leafIndex, treeSize uint64, proof Proof) RootHash {
	if treeSize == 0 || leafIndex >= treeSize {
		return RootHash{}
	}
	if treeSize == 1 {
		// Single-leaf tree: the leaf hash IS the root.
		return leafHash
	}

	fn := leafIndex
	sn := treeSize - 1
	current := leafHash

	for _, raw := range proof {
		if sn == 0 {
			// Proof has more entries than levels — truncate; caller
			// will detect mismatch when comparing the returned root.
			break
		}
		var p RootHash
		copy(p[:], raw)

		if fn&1 == 1 || fn == sn {
			current = HashChildren(p, current)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			current = HashChildren(current, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return current
}

// ConsistencyProof returns the proof that the tree of size n2 is a
// consistent extension of the tree of size n1.
//
// Per RFC 6962 §2.1.2:
//
//	PROOF(m, D[n]) = SUBPROOF(m, D[n], true)
//
//	SUBPROOF(m, D[n], b):
//	  m = n:
//	    b = true:  []
//	    b = false: [MTH(D[n])]
//	  m < n:
//	    k = largest power of 2 < n
//	    m <= k:    SUBPROOF(m, D[0:k], b) ++ [MTH(D[k:n])]
//	    m > k:     SUBPROOF(m-k, D[k:n], false) ++ [MTH(D[0:k])]
func ConsistencyProof(n1, n2 uint64, leafHashes []RootHash) Proof {
	if n1 == 0 || n1 > n2 || n2 > uint64(len(leafHashes)) {
		return nil
	}
	if n1 == n2 {
		return Proof{}
	}
	return subProof(n1, leafHashes[:n2], true)
}

func subProof(m uint64, d []RootHash, b bool) Proof {
	n := uint64(len(d))
	if m == n {
		if b {
			return Proof{}
		}
		root := MerkleTreeHash(d)
		return Proof{root[:]}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		sp := subProof(m, d[:k], b)
		sibling := MerkleTreeHash(d[k:])
		return appendHash(sp, sibling)
	}
	sp := subProof(m-k, d[k:], false)
	sibling := MerkleTreeHash(d[:k])
	return appendHash(sp, sibling)
}

// VerifyConsistency reproduces the second root from the first root,
// the two tree sizes, and the proof. Returns (computed second root,
// ok). The caller compares the computed root against their
// authoritative second STH.
//
// Algorithm follows Google Trillian's reference implementation
// (Apache 2.0): the boundary `node = n1-1` (rightmost position of the
// smaller tree) is walked up the levels. While `node` is odd (right
// child), it's part of the smaller tree's right spine and consumes a
// left-sibling proof element shared between hash1 and hash2; when
// `node` is even AND `node < lastNode`, only hash2 takes a sibling
// (the larger tree extends right beyond what the smaller tree had).
// After both walks complete, hash1 must equal root1 (which validates
// the proof's coherence with the supplied snapshot1) and hash2 is
// the computed root2.
//
// When n1 is a power of 2, node becomes 0 after the pre-walk; root1
// is the implicit starting hash and the algorithm's hash1 check is
// trivially satisfied. Forgery in that scenario is caught by the
// caller comparing the returned root2 to the authoritative source.
func VerifyConsistency(n1, n2 uint64, root1 RootHash, proof Proof) (root2 RootHash, ok bool) {
	if n1 == 0 || n1 > n2 {
		return RootHash{}, false
	}
	if n1 == n2 {
		if len(proof) != 0 {
			return RootHash{}, false
		}
		return root1, true
	}

	node := n1 - 1
	lastNode := n2 - 1

	// Walk past right-spine levels of the smaller tree: a node that
	// is a right child (odd) carries no consistency proof entry at
	// this level — the entire subtree below it is sealed inside
	// root1's hash.
	for node%2 == 1 {
		node >>= 1
		lastNode >>= 1
	}

	var hash1, hash2 RootHash
	proofIdx := 0

	if node > 0 {
		// Pre-walk didn't reach the root; the first proof entry is
		// the starting hash for both walks.
		if proofIdx >= len(proof) {
			return RootHash{}, false
		}
		copy(hash1[:], proof[proofIdx])
		copy(hash2[:], proof[proofIdx])
		proofIdx++
	} else {
		// n1 was a perfect prefix (power of 2 spine); root1 is the
		// starting hash.
		hash1 = root1
		hash2 = root1
	}

	for node > 0 {
		if proofIdx >= len(proof) {
			return RootHash{}, false
		}
		var p RootHash
		copy(p[:], proof[proofIdx])

		if node%2 == 1 {
			// Right child: sibling is to the left for both trees.
			hash1 = HashChildren(p, hash1)
			hash2 = HashChildren(p, hash2)
			proofIdx++
		} else if node < lastNode {
			// Larger tree has a sibling to the right that the
			// smaller tree did not; only hash2 absorbs it.
			hash2 = HashChildren(hash2, p)
			proofIdx++
		}
		// When node%2 == 0 and node == lastNode, no proof element is
		// consumed at this level — both walks ascend silently.

		node >>= 1
		lastNode >>= 1
	}

	// The larger tree may still have higher levels we haven't
	// reached. Continue extending hash2 to the larger tree's root.
	for lastNode > 0 {
		if proofIdx >= len(proof) {
			return RootHash{}, false
		}
		var p RootHash
		copy(p[:], proof[proofIdx])
		hash2 = HashChildren(hash2, p)
		proofIdx++
		lastNode >>= 1
	}

	if proofIdx != len(proof) {
		// Extra unused proof entries — refuse.
		return RootHash{}, false
	}
	if hash1 != root1 {
		return RootHash{}, false
	}
	return hash2, true
}

func appendHash(p Proof, h RootHash) Proof {
	cp := make(Proof, len(p)+1)
	copy(cp, p)
	h2 := make([]byte, 32)
	copy(h2, h[:])
	cp[len(p)] = h2
	return cp
}

func isPowerOfTwo(n uint64) bool {
	return n > 0 && (n&(n-1)) == 0
}
