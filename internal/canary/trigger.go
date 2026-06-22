package canary

import (
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
)

// RecordTrigger updates a CanaryToken's TriggerCount/TriggeredAt when the
// given correlation-engine alert is a canary tripwire. Intended to be
// composed alongside pipeline.PushNetworkEvent in the engine's alert
// callback (see internal/app/app.go) — it is a no-op for any other rule.
func RecordTrigger(repo *db.Repository, alert models.NetworkEvent) {
	rule, _ := alert.Metadata["rule"].(string)
	if rule != "DNS_CANARY_TRIGGERED" && rule != "HTTP_CANARY_TRIGGERED" {
		return
	}

	// The correlation engine's synthesized alert only carries
	// {rule, description, severity, trigger_id} — the original event's
	// metadata (DNS query name / canary_token) must be re-fetched by ID.
	triggerID, _ := alert.Metadata["trigger_id"].(string)
	orig, err := repo.GetEvent(triggerID)
	if err != nil {
		return
	}

	var token string
	switch rule {
	case "DNS_CANARY_TRIGGERED":
		name, _ := orig.Metadata["name"].(string)
		token = dnsTokenFromQueryName(name)
	case "HTTP_CANARY_TRIGGERED":
		token, _ = orig.Metadata["canary_token"].(string)
	}
	if token == "" {
		return
	}

	ct, err := repo.FindCanaryTokenByToken(token)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	ct.TriggeredAt = &now
	ct.TriggerCount++
	ct.LastTriggerSource = alert.Destination
	_ = repo.SaveCanaryToken(ct)
}

// dnsTokenFromQueryName extracts the leading slug from a canary
// subdomain query, e.g. "a1b2c3d4.canary.internal.example." -> "a1b2c3d4".
func dnsTokenFromQueryName(name string) string {
	name = strings.TrimSuffix(name, ".")
	idx := strings.Index(name, ".")
	if idx < 0 {
		return name
	}
	return name[:idx]
}
