package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// AlertsHandler exposes alert CRUD + incident containment over HTTP.
type AlertsHandler struct {
	Repo   *db.Repository
	Hub    *WSHub
	Logger *logging.Logger
}

func (h *AlertsHandler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *AlertsHandler) writeErr(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, map[string]string{"error": msg})
}

// ServeAlerts dispatches GET /api/alerts and GET /api/alerts/{id}.
func (h *AlertsHandler) ServeAlerts(w http.ResponseWriter, r *http.Request) {
	// Extract optional id suffix: /api/alerts/abc123
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts")
	id = strings.Trim(id, "/")

	switch r.Method {
	case http.MethodGet:
		if id != "" {
			h.getAlert(w, r, id)
		} else {
			h.listAlerts(w, r)
		}
	default:
		h.writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// PatchAlert handles PATCH /api/alerts/{id}.
func (h *AlertsHandler) PatchAlert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		h.writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/")
	if id == "" {
		h.writeErr(w, http.StatusBadRequest, "missing alert id")
		return
	}

	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	updated, err := h.Repo.UpdateAlert(id, models.AlertStatus(body.Status), body.Note)
	if err != nil {
		h.writeErr(w, http.StatusNotFound, err.Error())
		return
	}

	// Broadcast status change to all WebSocket clients
	h.Hub.Broadcast(map[string]any{
		"type":  "ALERT_UPDATE",
		"alert": updated,
	})

	h.writeJSON(w, http.StatusOK, updated)
}

// ServeContainment handles POST /api/incidents/containment.
func (h *AlertsHandler) ServeContainment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		h.writeErr(w, http.StatusBadRequest, "invalid body: require {\"ip\":\"...\"}")
		return
	}

	// Audit log via WebSocket broadcast — every connected operator sees this
	h.Hub.Broadcast(map[string]any{
		"type":   "CONTAINMENT_REQUEST",
		"ip":     body.IP,
		"action": "seal_host",
		"note":   "operator initiated via web interface",
	})

	h.Logger.Infow("Containment request received", "ip", body.IP)

	h.writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "accepted",
		"ip":      body.IP,
		"command": "nft add rule inet filter input ip saddr " + body.IP + " drop",
	})
}

func (h *AlertsHandler) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := db.AlertFilter{
		Status:   models.AlertStatus(q.Get("status")),
		Severity: q.Get("severity"),
		Limit:    limit,
	}
	alerts, err := h.Repo.ListAlerts(filter)
	if err != nil {
		h.writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	h.writeJSON(w, http.StatusOK, alerts)
}

func (h *AlertsHandler) getAlert(w http.ResponseWriter, r *http.Request, id string) {
	alert, err := h.Repo.GetAlert(id)
	if err != nil {
		h.writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, alert)
}
