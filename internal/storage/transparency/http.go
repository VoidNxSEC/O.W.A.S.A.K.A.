package transparency

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

// HTTPMux exposes the transparency log endpoints expected by external
// verifiers (Spectre, Cerebro, auditors). Mount at "/api/transparency":
//
//	mux.Handle("/api/transparency/sth",         t.STHHandler())
//	mux.Handle("/api/transparency/inclusion",   t.InclusionHandler())
//	mux.Handle("/api/transparency/consistency", t.ConsistencyHandler())
//	mux.Handle("/api/transparency/leaf",        t.LeafHandler())
//
// The STH endpoint is intentionally unauthenticated — it is a public
// commitment, by design pinnable by external monitors. Inclusion /
// consistency proofs are likewise public. The leaf endpoint is
// access-controlled at the caller's middleware layer because leaf
// payloads can carry sensitive material (principal lifecycle entries
// include subject names, policy reloads include rule diffs).
//
// All responses are JSON; binary hashes are emitted as lowercase hex
// for human + machine readability without forcing a base64 decode in
// every consumer.
type HTTPMux struct {
	tree *Tree
	db   *bolt.DB
}

// NewHTTPMux wraps a Tree + its backing DB with the HTTP surface.
func NewHTTPMux(tree *Tree, db *bolt.DB) *HTTPMux {
	return &HTTPMux{tree: tree, db: db}
}

// STHResponse is the JSON shape returned at /api/transparency/sth.
type STHResponse struct {
	TreeSize    TreeSize `json:"tree_size"`
	RootHash    string   `json:"root_hash"`     // hex
	Timestamp   int64    `json:"timestamp_ns"`  // UnixNano
	Signature   string   `json:"signature"`     // hex
	SignerKeyID string   `json:"signer_key_id"`
}

// ProofResponse is the JSON shape returned for inclusion + consistency
// queries. AuditPath is an ordered list of hex-encoded 32-byte hashes.
type ProofResponse struct {
	TreeSize  TreeSize `json:"tree_size"`
	LeafIndex *uint64  `json:"leaf_index,omitempty"`
	FirstSize *uint64  `json:"first_size,omitempty"`
	SecondSize *uint64 `json:"second_size,omitempty"`
	AuditPath []string `json:"audit_path"`
}

// LeafResponse exposes a stored leaf at /api/transparency/leaf.
type LeafResponse struct {
	Index     uint64 `json:"index"`
	Kind      string `json:"kind"`
	Timestamp int64  `json:"timestamp_ns"`
	Payload   string `json:"payload"` // hex
	LeafHash  string `json:"leaf_hash"`
}

// STHHandler serves the most recent persisted STH. Returns 503 if no
// STH has been persisted yet (fresh deployment with zero leaves
// appended); operators interpret this as "log is initialized but
// nothing significant has happened yet".
func (h *HTTPMux) STHHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sth, err := LatestSTH(h.db)
		if err != nil {
			http.Error(w, "sth read: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if sth == nil {
			http.Error(w, "no STH yet — log is empty", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, STHResponse{
			TreeSize:    sth.TreeSize,
			RootHash:    hex.EncodeToString(sth.RootHash),
			Timestamp:   sth.Timestamp.UnixNano(),
			Signature:   hex.EncodeToString(sth.Signature),
			SignerKeyID: sth.SignerKeyID,
		})
	})
}

// InclusionHandler serves audit paths.
//
//	GET /api/transparency/inclusion?leaf_index=<m>&tree_size=<n>
//
// Returns 400 on bad / missing parameters, 404 when the leaf or tree
// size is out of range, 200 with the audit path otherwise.
func (h *HTTPMux) InclusionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leafIdx, err := parseUintParam(r, "leaf_index")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		treeSize, err := parseUintParam(r, "tree_size")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		proof, err := h.tree.InclusionProof(LeafIndex(leafIdx), TreeSize(treeSize))
		switch err {
		case nil:
		case ErrLeafIndexOutOfRange, ErrTreeSizeMismatch:
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, ProofResponse{
			TreeSize:  TreeSize(treeSize),
			LeafIndex: &leafIdx,
			AuditPath: hexProof(proof),
		})
	})
}

// ConsistencyHandler serves consistency proofs.
//
//	GET /api/transparency/consistency?first=<n1>&second=<n2>
//
// Returns 400 on bad parameters, 404 if the requested sizes are
// out of range, 200 with the proof otherwise.
func (h *HTTPMux) ConsistencyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first, err := parseUintParam(r, "first")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		second, err := parseUintParam(r, "second")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		proof, err := h.tree.ConsistencyProof(TreeSize(first), TreeSize(second))
		switch err {
		case nil:
		case ErrConsistencyRange, ErrTreeSizeMismatch:
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, ProofResponse{
			TreeSize:   TreeSize(second),
			FirstSize:  &first,
			SecondSize: &second,
			AuditPath:  hexProof(proof),
		})
	})
}

// LeafHandler returns the persisted leaf at a given index.
//
//	GET /api/transparency/leaf?index=<m>
//
// Returns 404 if the index is out of range. CALLERS MUST protect this
// endpoint with appropriate permissions — leaf payloads can carry
// sensitive material.
func (h *HTTPMux) LeafHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx, err := parseUintParam(r, "index")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		leaf, err := h.tree.LeafAt(LeafIndex(idx))
		if err == ErrLeafIndexOutOfRange {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		leafHash := HashLeaf(leaf.Payload)
		writeJSON(w, http.StatusOK, LeafResponse{
			Index:     idx,
			Kind:      string(leaf.Kind),
			Timestamp: leaf.Timestamp.UnixNano(),
			Payload:   hex.EncodeToString(leaf.Payload),
			LeafHash:  hex.EncodeToString(leafHash[:]),
		})
	})
}

// parseUintParam extracts a non-negative uint64 query parameter,
// returning a descriptive error on missing / non-numeric / negative.
func parseUintParam(r *http.Request, name string) (uint64, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, &paramError{name: name, reason: "missing"}
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, &paramError{name: name, reason: "must be a non-negative integer"}
	}
	return v, nil
}

type paramError struct {
	name   string
	reason string
}

func (e *paramError) Error() string {
	return "parameter " + e.name + ": " + e.reason
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func hexProof(p Proof) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = hex.EncodeToString(h)
	}
	return out
}
