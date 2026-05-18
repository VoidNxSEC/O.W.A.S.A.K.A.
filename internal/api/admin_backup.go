package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/backup"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// AdminBackupHandler exposes an authenticated POST endpoint that
// triggers an in-process encrypted backup using the running server's
// own DB handle. This is the operator-friendly counterpart to the
// `oswaka backup` CLI: it doesn't require stopping the binary.
//
// Concurrency: a mutex-free atomic flag prevents two concurrent
// runs from competing for the bbolt Tx; the second concurrent call
// returns 409 Conflict.
type AdminBackupHandler struct {
	DB         *bolt.DB
	Tree       *transparency.Tree
	Recipients []age.Recipient
	SinkDir    string
	KeepLast   int
	Logger     *logging.Logger

	running atomic.Bool
}

// adminBackupResponse is the JSON shape returned on success.
type adminBackupResponse struct {
	Filename    string `json:"filename"`
	TreeSize    uint64 `json:"tree_size"`
	RootHashHex string `json:"root_hash_hex,omitempty"`
	CreatedAt   string `json:"created_at"`
	SinkDir     string `json:"sink_dir"`
}

// ServeHTTP runs one backup and returns the artifact metadata.
// The handler is intended to be wrapped with auth + authz
// middleware by the caller; it does not enforce identity itself.
func (h *AdminBackupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if h.DB == nil {
		http.Error(w, "backup unavailable (db not initialised)", http.StatusServiceUnavailable)
		return
	}
	if len(h.Recipients) == 0 {
		http.Error(w, "backup unconfigured (no age recipients)", http.StatusServiceUnavailable)
		return
	}
	if h.SinkDir == "" {
		http.Error(w, "backup unconfigured (no output dir)", http.StatusServiceUnavailable)
		return
	}

	if !h.running.CompareAndSwap(false, true) {
		http.Error(w, "backup already in progress", http.StatusConflict)
		return
	}
	defer h.running.Store(false)

	sink, err := backup.NewLocalSink(h.SinkDir, h.KeepLast)
	if err != nil {
		h.writeError(w, "sink init", err, http.StatusInternalServerError)
		return
	}
	engine, err := backup.NewEngine(
		backup.NewBoltSource(h.DB, h.Tree),
		[]backup.Sink{sink},
		h.Recipients,
	)
	if err != nil {
		h.writeError(w, "engine init", err, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	art, err := engine.Run(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			h.writeError(w, "backup timed out", err, http.StatusGatewayTimeout)
		} else {
			h.writeError(w, "backup failed", err, http.StatusInternalServerError)
		}
		return
	}

	resp := adminBackupResponse{
		Filename:    art.Filename,
		TreeSize:    art.TreeSize,
		RootHashHex: art.RootHashHex,
		CreatedAt:   art.CreatedAt.UTC().Format(time.RFC3339),
		SinkDir:     h.SinkDir,
	}
	if h.Logger != nil {
		h.Logger.Infow("admin backup succeeded",
			"filename", resp.Filename, "tree_size", resp.TreeSize)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeError emits a structured error body without leaking the raw
// error text into the response when the operation is sensitive.
// At present we surface the error verbatim — the endpoint is admin-
// only by authz and the caller is privileged.
func (h *AdminBackupHandler) writeError(w http.ResponseWriter, summary string, err error, status int) {
	if h.Logger != nil {
		h.Logger.Errorw("admin backup error", "summary", summary, "error", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  summary,
		"detail": err.Error(),
	})
}
