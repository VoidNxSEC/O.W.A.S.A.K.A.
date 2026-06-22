package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/canary"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// CanaryAdminHandler exposes authenticated endpoints to mint and list
// DNS/HTTP canary tokens. Wrapped with auth + authz middleware by the
// caller, same convention as AdminBackupHandler.
type CanaryAdminHandler struct {
	Repo   *db.Repository
	Cfg    *config.CanaryConfig
	Logger *logging.Logger
}

type canaryTokenResponse struct {
	ID                string     `json:"id"`
	Token             string     `json:"token"`
	Type              string     `json:"type"`
	Label             string     `json:"label"`
	Subdomain         string     `json:"subdomain,omitempty"`
	URL               string     `json:"url,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	TriggeredAt       *time.Time `json:"triggered_at,omitempty"`
	TriggerCount      int        `json:"trigger_count"`
	LastTriggerSource string     `json:"last_trigger_source,omitempty"`
}

func toCanaryResponse(t models.CanaryToken) canaryTokenResponse {
	return canaryTokenResponse{
		ID:                t.ID,
		Token:             t.Token,
		Type:              string(t.Type),
		Label:             t.Label,
		Subdomain:         t.Subdomain,
		URL:               t.URL,
		CreatedAt:         t.CreatedAt,
		TriggeredAt:       t.TriggeredAt,
		TriggerCount:      t.TriggerCount,
		LastTriggerSource: t.LastTriggerSource,
	}
}

type createCanaryRequest struct {
	Label string `json:"label"`
}

// CreateDNS handles POST /api/admin/canary/dns.
func (h *CanaryAdminHandler) CreateDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req createCanaryRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // label is optional

	t, err := canary.GenerateDNSToken(h.Repo, h.Cfg.DNSZone, req.Label)
	if err != nil {
		h.Logger.Errorw("Failed to generate DNS canary token", "error", err)
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toCanaryResponse(*t))
}

// CreateHTTP handles POST /api/admin/canary/http.
func (h *CanaryAdminHandler) CreateHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req createCanaryRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	t, err := canary.GenerateHTTPToken(h.Repo, h.Cfg.WebhookBaseURL, h.Cfg.WebhookPath, req.Label)
	if err != nil {
		h.Logger.Errorw("Failed to generate HTTP canary token", "error", err)
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toCanaryResponse(*t))
}

// List handles GET /api/admin/canary.
func (h *CanaryAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	tokens, err := h.Repo.ListCanaryTokens()
	if err != nil {
		h.Logger.Errorw("Failed to list canary tokens", "error", err)
		http.Error(w, "failed to list tokens", http.StatusInternalServerError)
		return
	}
	out := make([]canaryTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, toCanaryResponse(t))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
