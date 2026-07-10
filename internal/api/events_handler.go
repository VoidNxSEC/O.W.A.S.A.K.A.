package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// EventsHandler exposes historical event search over HTTP.
type EventsHandler struct {
	Repo   *db.Repository
	Logger *logging.Logger
}

func (h *EventsHandler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeEvents handles GET /api/events?type=THREAT_ALERT&from=2h&limit=100
func (h *EventsHandler) ServeEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	q := r.URL.Query()
	eventType := q.Get("type")
	limitStr := q.Get("limit")
	fromStr := q.Get("from")

	limit, _ := strconv.Atoi(limitStr)

	var since time.Time
	if fromStr != "" {
		fromStr = strings.TrimSpace(fromStr)
		dur, err := parseDuration(fromStr)
		if err == nil {
			since = time.Now().Add(-dur)
		}
	}

	events, err := h.Repo.ListEventsByType(eventType, since, limit)
	if err != nil {
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = nil // json.Encode will emit null; frontend normalises
	}
	h.writeJSON(w, http.StatusOK, events)
}

// parseDuration extends time.ParseDuration with shorthand units like "2h", "30m", "7d".
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
