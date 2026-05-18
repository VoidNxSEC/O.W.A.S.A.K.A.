package transparency

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func setupHTTP(t *testing.T) (*HTTPMux, *Tree) {
	t.Helper()
	authority := bootstrappedAuthority(t)
	signer := NewSTHSigner(authority)
	tree, db := buildTreeWithDB(t)

	// Append a handful of leaves and persist an STH after each so
	// the endpoint tests have non-trivial state to exercise.
	for i, payload := range []string{"alpha", "beta", "gamma"} {
		_, err := tree.Append(context.Background(), Leaf{
			Kind:      LeafPolicyReload,
			Timestamp: time.Date(2026, 5, 18, 0, i, 0, 0, time.UTC),
			Payload:   []byte(payload),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		sth, err := signer.SignSTH(context.Background(), tree.Size(), tree.Root())
		if err != nil {
			t.Fatalf("sign STH: %v", err)
		}
		if err := PersistSTH(db, sth); err != nil {
			t.Fatalf("persist STH: %v", err)
		}
	}

	return NewHTTPMux(tree, db), tree
}

// buildTreeWithDB creates a fresh tree + returns the DB so tests can
// drive PersistSTH directly.
func buildTreeWithDB(t *testing.T) (*Tree, *bolt.DB) {
	t.Helper()
	db := openTestDB(t)
	tree, err := Open(db)
	if err != nil {
		t.Fatalf("open tree: %v", err)
	}
	return tree, db
}

func TestHTTP_STH_HappyPath(t *testing.T) {
	mux, tree := setupHTTP(t)
	req := httptest.NewRequest("GET", "/api/transparency/sth", nil)
	rr := httptest.NewRecorder()
	mux.STHHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	var resp STHResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TreeSize != tree.Size() {
		t.Fatalf("STH tree size: %d, tree size: %d", resp.TreeSize, tree.Size())
	}
	wantRoot := tree.Root()
	if resp.RootHash != hex.EncodeToString(wantRoot[:]) {
		t.Fatalf("STH root mismatch")
	}
}

func TestHTTP_STH_EmptyLog(t *testing.T) {
	tree, db := buildTreeWithDB(t)
	_ = tree
	mux := NewHTTPMux(tree, db)
	rr := httptest.NewRecorder()
	mux.STHHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for empty log, got %d", rr.Code)
	}
}

func TestHTTP_Inclusion_HappyPath(t *testing.T) {
	mux, _ := setupHTTP(t)
	rr := httptest.NewRecorder()
	mux.InclusionHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/?leaf_index=1&tree_size=3", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	var resp ProofResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.LeafIndex == nil || *resp.LeafIndex != 1 {
		t.Fatalf("leaf_index echoed wrong: %+v", resp.LeafIndex)
	}
	if len(resp.AuditPath) == 0 {
		t.Fatal("expected non-empty audit path for leaf 1 in tree of 3")
	}
}

func TestHTTP_Inclusion_BadParam(t *testing.T) {
	mux, _ := setupHTTP(t)
	cases := []string{
		"/",
		"/?leaf_index=abc&tree_size=3",
		"/?leaf_index=1",
		"/?tree_size=3",
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.InclusionHandler().ServeHTTP(rr, httptest.NewRequest("GET", q, nil))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %q, got %d", q, rr.Code)
			}
		})
	}
}

func TestHTTP_Inclusion_OutOfRange(t *testing.T) {
	mux, _ := setupHTTP(t)
	rr := httptest.NewRecorder()
	mux.InclusionHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/?leaf_index=99&tree_size=3", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestHTTP_Consistency_HappyPath(t *testing.T) {
	mux, _ := setupHTTP(t)
	rr := httptest.NewRecorder()
	mux.ConsistencyHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/?first=1&second=3", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	var resp ProofResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.FirstSize == nil || *resp.FirstSize != 1 {
		t.Fatalf("first_size echo: %+v", resp.FirstSize)
	}
	if resp.SecondSize == nil || *resp.SecondSize != 3 {
		t.Fatalf("second_size echo: %+v", resp.SecondSize)
	}
	if len(resp.AuditPath) == 0 {
		t.Fatal("expected non-empty consistency proof")
	}
}

func TestHTTP_Consistency_BadRange(t *testing.T) {
	mux, _ := setupHTTP(t)
	cases := []string{
		"/?first=0&second=3",  // n1 = 0
		"/?first=5&second=3",  // n1 > n2
		"/?first=1&second=99", // n2 > current
	}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ConsistencyHandler().ServeHTTP(rr, httptest.NewRequest("GET", q, nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("expected 404 for %q, got %d", q, rr.Code)
			}
		})
	}
}

func TestHTTP_Leaf_HappyPath(t *testing.T) {
	mux, _ := setupHTTP(t)
	rr := httptest.NewRecorder()
	mux.LeafHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/?index=2", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rr.Code, rr.Body.String())
	}
	var resp LeafResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Index != 2 || resp.Kind != string(LeafPolicyReload) {
		t.Fatalf("leaf shape: %+v", resp)
	}
	// gamma in hex
	if resp.Payload != hex.EncodeToString([]byte("gamma")) {
		t.Fatalf("payload hex: %s", resp.Payload)
	}
}

func TestHTTP_Leaf_NotFound(t *testing.T) {
	mux, _ := setupHTTP(t)
	rr := httptest.NewRecorder()
	mux.LeafHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/?index=99", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
