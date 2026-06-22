package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
)

// eventPusher is satisfied by *events.Pipeline. Kept as a narrow local
// interface — internal/events already imports internal/api (for
// api.WSHub), so importing internal/events here would be a cycle.
type eventPusher interface {
	PushNetworkEvent(models.NetworkEvent)
}

// CanaryWebhookHandler accepts an unauthenticated POST from a remote
// app/website that embedded a decoy canary URL. The token in the path
// is the secret — no JWT required, mirroring how the DNS canary path
// needs no credential either. Path: /api/canary/webhook/{token}.
func CanaryWebhookHandler(repo *db.Repository, pipeline eventPusher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, "/api/canary/webhook/")
		if token == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := repo.FindCanaryTokenByToken(token); err != nil {
			// Do not leak whether the token format is merely invalid
			// vs. unknown — both look identical to the caller.
			w.WriteHeader(http.StatusNotFound)
			return
		}

		pipeline.PushNetworkEvent(models.NetworkEvent{
			Type:        models.EventCanary,
			Source:      r.RemoteAddr,
			Destination: token,
			Metadata: map[string]any{
				"canary_token": token,
				"canary_type":  "HTTP",
				"user_agent":   r.Header.Get("User-Agent"),
				"referer":      r.Header.Get("Referer"),
			},
			Timestamp: time.Now(),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}
