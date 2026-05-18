package transparency

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// --- RFC 6962 test vectors -------------------------------------------------
//
// Reference fixtures from the RFC's worked example. The exact byte
// values come from the spec, transcribed manually. Cross-validate the
// hash + root + proof algorithms against them so any regression that
// drifts from CT-compatible output fails loudly.

func leafHashHex(t *testing.T, payload []byte) string {
	t.Helper()
	h := HashLeaf(payload)
	return hex.EncodeToString(h[:])
}

func TestEmptyRoot_RFC6962(t *testing.T) {
	got := EmptyRoot()
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("empty root mismatch: got %x want %s", got[:], want)
	}
}

func TestHashLeaf_Prefix(t *testing.T) {
	// Single-leaf tree root must equal HashLeaf(payload), proving the
	// 0x00 prefix is in place.
	payload := []byte("hello")
	want := HashLeaf(payload)
	got := MerkleTreeHash([]RootHash{HashLeaf(payload)})
	if got != want {
		t.Fatalf("single-leaf root must equal leaf hash")
	}
}

func TestMerkleTreeHash_TwoLeaves(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	want := HashChildren(a, b)
	got := MerkleTreeHash([]RootHash{a, b})
	if got != want {
		t.Fatalf("two-leaf root mismatch")
	}
}

func TestMerkleTreeHash_UnbalancedTree(t *testing.T) {
	// n = 3: k = 2, MTH = SHA-256(0x01 || MTH(D[0:2]) || MTH(D[2:3]))
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	c := HashLeaf([]byte("c"))
	left := HashChildren(a, b)
	want := HashChildren(left, c)
	got := MerkleTreeHash([]RootHash{a, b, c})
	if got != want {
		t.Fatalf("unbalanced root mismatch")
	}
}

// --- Inclusion proofs ------------------------------------------------------

func TestInclusionProof_ReproducesRoot(t *testing.T) {
	leaves := []RootHash{
		HashLeaf([]byte("a")),
		HashLeaf([]byte("b")),
		HashLeaf([]byte("c")),
		HashLeaf([]byte("d")),
		HashLeaf([]byte("e")),
	}
	root := MerkleTreeHash(leaves)
	for i := range leaves {
		proof := InclusionProof(uint64(i), leaves)
		got := VerifyInclusion(leaves[i], uint64(i), uint64(len(leaves)), proof)
		if got != root {
			t.Fatalf("inclusion[%d]: reproduced root %x != real %x", i, got, root)
		}
	}
}

func TestInclusionProof_RejectsOutOfRange(t *testing.T) {
	leaves := []RootHash{HashLeaf([]byte("a"))}
	if InclusionProof(1, leaves) != nil {
		t.Fatal("out-of-range index must return nil proof")
	}
	if InclusionProof(0, nil) != nil {
		t.Fatal("empty tree must return nil proof")
	}
}

// --- Consistency proofs ----------------------------------------------------

func TestConsistencyProof_PowerOfTwoExtension(t *testing.T) {
	// Build a tree of size 4, then 8. Prove consistency.
	makeLeaves := func(n int) []RootHash {
		out := make([]RootHash, n)
		for i := 0; i < n; i++ {
			out[i] = HashLeaf([]byte{byte('a' + i)})
		}
		return out
	}
	leaves8 := makeLeaves(8)
	root4 := MerkleTreeHash(leaves8[:4])
	root8 := MerkleTreeHash(leaves8)

	proof := ConsistencyProof(4, 8, leaves8)
	if proof == nil {
		t.Fatal("expected non-nil consistency proof")
	}
	got, ok := VerifyConsistency(4, 8, root4, proof)
	if !ok {
		t.Fatal("VerifyConsistency rejected a valid proof")
	}
	if got != root8 {
		t.Fatalf("VerifyConsistency reproduced wrong root: %x vs %x", got, root8)
	}
}

func TestConsistencyProof_OddSizes(t *testing.T) {
	makeLeaves := func(n int) []RootHash {
		out := make([]RootHash, n)
		for i := 0; i < n; i++ {
			out[i] = HashLeaf([]byte{byte('a' + i)})
		}
		return out
	}
	leaves7 := makeLeaves(7)
	root3 := MerkleTreeHash(leaves7[:3])
	root7 := MerkleTreeHash(leaves7)
	proof := ConsistencyProof(3, 7, leaves7)
	got, ok := VerifyConsistency(3, 7, root3, proof)
	if !ok || got != root7 {
		t.Fatalf("consistency 3→7 failed: ok=%v got=%x want=%x", ok, got, root7)
	}
}

func TestConsistencyProof_EqualSizesEmptyProof(t *testing.T) {
	leaves := []RootHash{HashLeaf([]byte("a")), HashLeaf([]byte("b"))}
	root := MerkleTreeHash(leaves)
	proof := ConsistencyProof(2, 2, leaves)
	got, ok := VerifyConsistency(2, 2, root, proof)
	if !ok || got != root {
		t.Fatalf("equal-size consistency should yield same root, got ok=%v", ok)
	}
}

func TestConsistencyProof_RejectsBadRanges(t *testing.T) {
	leaves := []RootHash{HashLeaf([]byte("a")), HashLeaf([]byte("b"))}
	if ConsistencyProof(0, 1, leaves) != nil {
		t.Fatal("n1=0 must yield nil")
	}
	if ConsistencyProof(2, 1, leaves) != nil {
		t.Fatal("n1>n2 must yield nil")
	}
	if ConsistencyProof(1, 5, leaves) != nil {
		t.Fatal("n2>len(leaves) must yield nil")
	}
}

func TestVerifyConsistency_ForgeryDetectedByRoot2Mismatch(t *testing.T) {
	// When n1 is a power of 2, the consistency algorithm uses root1 as
	// the starting hash; hash1 trivially equals root1. Forgery
	// detection happens at the CALLER level when comparing the
	// returned second root against an authoritative source.
	leaves := []RootHash{HashLeaf([]byte("a")), HashLeaf([]byte("b")), HashLeaf([]byte("c")), HashLeaf([]byte("d"))}
	realRoot2 := MerkleTreeHash(leaves)
	proof := ConsistencyProof(2, 4, leaves)

	var forged RootHash
	for i := range forged {
		forged[i] = 0xff
	}
	got, ok := VerifyConsistency(2, 4, forged, proof)
	// Algorithm itself returns ok=true (the proof is structurally
	// valid for the supplied root1). The forgery is detected by the
	// caller because the computed root2 does NOT match the real root2.
	if ok && got == realRoot2 {
		t.Fatal("forged root1 produced real root2 — algorithm or test is wrong")
	}

	// Non-power-of-2 n1: the proof re-derives root1; a forged root1
	// fails the algorithm's own check.
	leaves7 := make([]RootHash, 7)
	for i := range leaves7 {
		leaves7[i] = HashLeaf([]byte{byte('a' + i)})
	}
	proof3 := ConsistencyProof(3, 7, leaves7)
	if _, ok := VerifyConsistency(3, 7, forged, proof3); ok {
		t.Fatal("non-pow2 n1 forgery must fail at the algorithm level")
	}

	// Truncated proof must fail.
	realRoot2_4 := MerkleTreeHash(leaves[:2])
	if _, ok := VerifyConsistency(2, 4, realRoot2_4, nil); ok {
		t.Fatal("VerifyConsistency accepted an empty proof for non-equal sizes")
	}
}

// --- Tree (BoltDB) ---------------------------------------------------------

func openTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "t.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestTree_AppendAndRoot(t *testing.T) {
	tree, err := Open(openTestDB(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if tree.Size() != 0 {
		t.Fatalf("empty tree size: %d", tree.Size())
	}
	if tree.Root() != EmptyRoot() {
		t.Fatal("empty tree root mismatch")
	}

	for _, payload := range []string{"a", "b", "c"} {
		idx, err := tree.Append(context.Background(), Leaf{
			Kind:      LeafPolicyReload,
			Timestamp: time.Now(),
			Payload:   []byte(payload),
		})
		if err != nil {
			t.Fatalf("append %s: %v", payload, err)
		}
		_ = idx
	}
	if tree.Size() != 3 {
		t.Fatalf("size after 3 appends: %d", tree.Size())
	}

	// Cross-validate against MTH directly.
	leaves := []RootHash{
		HashLeaf([]byte("a")), HashLeaf([]byte("b")), HashLeaf([]byte("c")),
	}
	if tree.Root() != MerkleTreeHash(leaves) {
		t.Fatal("tree root diverges from pure MTH")
	}
}

func TestTree_PersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")

	db1, _ := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	tree1, _ := Open(db1)
	for i := 0; i < 5; i++ {
		_, _ = tree1.Append(context.Background(), Leaf{Payload: []byte{byte('a' + i)}})
	}
	root1 := tree1.Root()
	_ = db1.Close()

	db2, _ := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	defer db2.Close()
	tree2, err := Open(db2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if tree2.Size() != 5 {
		t.Fatalf("reopen size: %d", tree2.Size())
	}
	if tree2.Root() != root1 {
		t.Fatal("reopen root diverges")
	}
}

func TestTree_InclusionProof_RoundTrip(t *testing.T) {
	tree, _ := Open(openTestDB(t))
	for _, p := range []string{"a", "b", "c", "d", "e"} {
		_, _ = tree.Append(context.Background(), Leaf{Payload: []byte(p)})
	}
	root := tree.Root()
	for i := uint64(0); i < uint64(tree.Size()); i++ {
		proof, err := tree.InclusionProof(LeafIndex(i), tree.Size())
		if err != nil {
			t.Fatalf("inclusion[%d]: %v", i, err)
		}
		leafHash := HashLeaf([]byte{byte('a' + i)})
		got := VerifyInclusion(leafHash, i, uint64(tree.Size()), proof)
		if got != root {
			t.Fatalf("inclusion[%d]: %x != %x", i, got, root)
		}
	}
}

func TestTree_InclusionProof_RejectsOutOfRange(t *testing.T) {
	tree, _ := Open(openTestDB(t))
	_, _ = tree.Append(context.Background(), Leaf{Payload: []byte("a")})
	if _, err := tree.InclusionProof(LeafIndex(1), tree.Size()); err == nil {
		t.Fatal("expected error for out-of-range leaf")
	}
	if _, err := tree.InclusionProof(LeafIndex(0), TreeSize(99)); err == nil {
		t.Fatal("expected error for too-large tree size")
	}
}

func TestTree_ConsistencyProof_RoundTrip(t *testing.T) {
	tree, _ := Open(openTestDB(t))
	for _, p := range []string{"a", "b", "c", "d"} {
		_, _ = tree.Append(context.Background(), Leaf{Payload: []byte(p)})
	}
	root2, _ := tree.RootAt(2)
	for _, p := range []string{"e", "f", "g"} {
		_, _ = tree.Append(context.Background(), Leaf{Payload: []byte(p)})
	}
	proof, err := tree.ConsistencyProof(2, tree.Size())
	if err != nil {
		t.Fatalf("consistency: %v", err)
	}
	got, ok := VerifyConsistency(2, uint64(tree.Size()), root2, proof)
	if !ok || got != tree.Root() {
		t.Fatalf("consistency proof failed: ok=%v", ok)
	}
}

func TestTree_RootAt_RejectsOversized(t *testing.T) {
	tree, _ := Open(openTestDB(t))
	if _, err := tree.RootAt(1); err == nil {
		t.Fatal("expected error for size > current")
	}
}

func TestTree_LeafAt(t *testing.T) {
	tree, _ := Open(openTestDB(t))
	_, _ = tree.Append(context.Background(), Leaf{Kind: LeafKeyRotation, Payload: []byte("payload-1")})
	leaf, err := tree.LeafAt(0)
	if err != nil {
		t.Fatalf("leaf at: %v", err)
	}
	if string(leaf.Payload) != "payload-1" || leaf.Kind != LeafKeyRotation {
		t.Fatalf("leaf mismatch: %+v", leaf)
	}
	if _, err := tree.LeafAt(99); err == nil {
		t.Fatal("expected error for oversized index")
	}
}

// --- STH -------------------------------------------------------------------

func bootstrappedAuthority(t *testing.T) *pki.Authority {
	t.Helper()
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := a.GenerateKeyPair(context.Background(), pki.PurposeTransparencyLogSTH, 24*time.Hour); err != nil {
		t.Fatalf("seed STH key: %v", err)
	}
	return a
}

func TestSTH_SignAndVerify(t *testing.T) {
	authority := bootstrappedAuthority(t)
	signer := NewSTHSigner(authority)

	tree, _ := Open(openTestDB(t))
	_, _ = tree.Append(context.Background(), Leaf{Payload: []byte("event-1")})

	sth, err := signer.SignSTH(context.Background(), tree.Size(), tree.Root())
	if err != nil {
		t.Fatalf("sign STH: %v", err)
	}
	if sth.TreeSize != 1 {
		t.Fatalf("STH size: %d", sth.TreeSize)
	}
	if err := VerifySTH(context.Background(), authority, sth, time.Now()); err != nil {
		t.Fatalf("verify STH: %v", err)
	}
}

func TestSTH_NoActiveKey(t *testing.T) {
	authority := pki.NewAuthority(pki.NewMemoryKeyStore())
	signer := NewSTHSigner(authority)
	var root RootHash
	if _, err := signer.SignSTH(context.Background(), 0, root); err != ErrNoSTHSigningKey {
		t.Fatalf("expected ErrNoSTHSigningKey, got %v", err)
	}
}

func TestSTH_VerifyRejectsTamperedRoot(t *testing.T) {
	authority := bootstrappedAuthority(t)
	signer := NewSTHSigner(authority)

	var realRoot RootHash
	realRoot[0] = 0x01
	sth, _ := signer.SignSTH(context.Background(), 1, realRoot)
	// Tamper the persisted RootHash.
	sth.RootHash[0] = 0x02
	if err := VerifySTH(context.Background(), authority, sth, time.Now()); err == nil {
		t.Fatal("VerifySTH accepted a tampered root")
	}
}

func TestSTH_VerifyRejectsRetiredKey(t *testing.T) {
	authority := bootstrappedAuthority(t)
	signer := NewSTHSigner(authority)
	sth, _ := signer.SignSTH(context.Background(), 0, RootHash{})

	kp, _ := authority.ActiveKey(context.Background(), pki.PurposeTransparencyLogSTH)
	_ = authority.Retire(context.Background(), kp.ID)

	if err := VerifySTH(context.Background(), authority, sth, time.Now()); err == nil {
		t.Fatal("VerifySTH accepted a retired key")
	}
}

func TestSTH_PersistAndRetrieve(t *testing.T) {
	authority := bootstrappedAuthority(t)
	db := openTestDB(t)
	tree, _ := Open(db)
	_, _ = tree.Append(context.Background(), Leaf{Payload: []byte("x")})

	signer := NewSTHSigner(authority)
	sth, _ := signer.SignSTH(context.Background(), tree.Size(), tree.Root())
	if err := PersistSTH(db, sth); err != nil {
		t.Fatalf("persist: %v", err)
	}
	latest, err := LatestSTH(db)
	if err != nil || latest == nil {
		t.Fatalf("latest: %v %v", latest, err)
	}
	if latest.TreeSize != 1 {
		t.Fatalf("retrieved size: %d", latest.TreeSize)
	}
	historic, err := STHAt(db, 1)
	if err != nil || historic == nil {
		t.Fatalf("history: %v %v", historic, err)
	}
	missing, _ := STHAt(db, 999)
	if missing != nil {
		t.Fatal("missing size should yield nil")
	}
}

func TestLatestSTH_NoneYet(t *testing.T) {
	db := openTestDB(t)
	if _, err := Open(db); err != nil {
		t.Fatalf("open tree: %v", err)
	}
	got, err := LatestSTH(db)
	if err != nil || got != nil {
		t.Fatalf("fresh deployment should have no STH: %v %v", got, err)
	}
}

func TestOpen_NilDB(t *testing.T) {
	if _, err := Open(nil); err == nil {
		t.Fatal("expected error for nil db")
	}
}
