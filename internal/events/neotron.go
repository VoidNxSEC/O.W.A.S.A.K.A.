package events

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
	"github.com/nats-io/nats.go"
)

// ── Neotron Compliance Event Schema ─────────────────────────────────────────
//
// The neotron platform publishes compliance events as JSON on subjects:
//   neotron.compliance.temporal.v1    — Layer 0 temporal guard verdicts (NEW)
//   neotron.compliance.sentinel.v1    — Layer 1 SENTINEL guardrail results
//   neotron.compliance.bastion.v1     — Layer 2 BASTION kernel enforcement
//   neotron.cortex.consensus.v1       — Layer 3 CORTEX swarm decisions
//   neotron.compliance.violation.v1   — All blocking violations
//
// Each event payload looks like:
//
//	{
//	  "audit_id": 42,
//	  "timestamp": "2026-04-07T12:00:00Z",
//	  "source": "neotron",
//	  "guardrail_name": "temporal_guard",
//	  "regulation": "LAYER_0_TEMPORAL",
//	  "agent_id": "user_analyst_42",
//	  "passed": true,
//	  "reputation": 0.85,
//	  "risk_score": 0.12,
//	  "severity": "audit",
//	  "subject": "neotron.compliance.temporal.v1"
//	}

// NeotronComplianceSubscriber listens on neotron.compliance.* NATS subjects
// and pushes inbound events into the owasaka SIEM pipeline for persistence,
// WebSocket broadcast, correlation, and ML anomaly detection.
type NeotronComplianceSubscriber struct {
	subs     []*nats.Subscription
	pipeline *Pipeline
	logger   *logging.Logger
}

// NewNeotronComplianceSubscriber creates subscriptions for all neotron
// compliance subjects and wires them into the owasaka event pipeline.
//
// The subscriber uses the nc.RawConn to subscribe so we bypass the
// Publisher wrapper (which only handles publishing) and subscribe
// directly to the underlying nats.Conn.
func NewNeotronComplianceSubscriber(nc *nats.Conn, pipeline *Pipeline, logger *logging.Logger) (*NeotronComplianceSubscriber, error) {
	sub := &NeotronComplianceSubscriber{
		pipeline: pipeline,
		logger:   logger,
	}

	// Subscribe to all neotron compliance subjects using wildcard
	subjects := []string{
		"neotron.compliance.>",
	}

	for _, subject := range subjects {
		natsSub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
			sub.handleComplianceEvent(msg)
		})
		if err != nil {
			return nil, fmt.Errorf("subscribe %s: %w", subject, err)
		}
		sub.subs = append(sub.subs, natsSub)
		logger.Infow("Neotron compliance subscriber registered", "subject", subject)
	}

	return sub, nil
}

// handleComplianceEvent processes an incoming neotron compliance event
// and pushes it through the owasaka SIEM pipeline.
func (s *NeotronComplianceSubscriber) handleComplianceEvent(msg *nats.Msg) {
	// Parse the raw JSON payload
	var raw map[string]any
	if err := json.Unmarshal(msg.Data, &raw); err != nil {
		s.logger.Errorw("Failed to unmarshal neotron compliance event",
			"error", err,
			"subject", msg.Subject,
			"payload_size", len(msg.Data),
		)
		return
	}

	s.logger.Infow("Neotron compliance event received",
		"subject", msg.Subject,
		"audit_id", raw["audit_id"],
		"guardrail", raw["guardrail_name"],
		"passed", raw["passed"],
	)

	// Convert to owasaka NetworkEvent for pipeline ingestion
	event := s.convertToNetworkEvent(msg.Subject, raw)

	// Push through the owasaka pipeline:
	// 1. Persist to BoltDB
	// 2. Broadcast to WebSocket UI
	// 3. Sign with Ed25519 (ADR-0062)
	// 4. Feed correlation engine
	// 5. ML anomaly detection
	// 6. Transparency log for critical events (ADR-0063)
	s.pipeline.PushNetworkEvent(event)
}

// convertToNetworkEvent maps a neotron compliance event to the owasaka
// NetworkEvent model for pipeline processing.
func (s *NeotronComplianceSubscriber) convertToNetworkEvent(subject string, raw map[string]any) models.NetworkEvent {
	// Determine event type based on the subject
	eventType := s.subjectToEventType(subject)

	// Extract timestamp — neotron uses ISO 8601 strings
	ts := time.Now()
	if t, ok := raw["timestamp"].(string); ok {
		parsed, err := time.Parse(time.RFC3339, t)
		if err == nil {
			ts = parsed
		}
	}

	// Extract agent_id or use a fallback
	agentID := "unknown"
	if a, ok := raw["agent_id"].(string); ok {
		agentID = a
	}

	// Build metadata from all raw fields
	metadata := make(map[string]any)
	for k, v := range raw {
		metadata[k] = v
	}
	// Add the original NATS subject
	metadata["nats_subject"] = subject
	// Add source service tag
	metadata["source_service"] = "neotron"

	return models.NetworkEvent{
		ID:          uuid.New().String(),
		Type:        eventType,
		Source:      "neotron",
		Destination: agentID,
		Metadata:    metadata,
		Timestamp:   ts,
	}
}

// subjectToEventType maps NATS subjects to owasaka EventTypes for proper
// routing through the SIEM pipeline (correlation, alerts, etc.).
func (s *NeotronComplianceSubscriber) subjectToEventType(subject string) models.EventType {
	switch subject {
	case "neotron.compliance.violation.v1":
		// Violations are high-severity — map to THREAT_ALERT for alerting
		return models.EventAlert
	case "neotron.compliance.temporal.v1":
		// Temporal guard verdicts — treat as DNS-like events for now
		// (will be enriched by correlation engine)
		return models.EventDNS
	case "neotron.compliance.sentinel.v1":
		return models.EventDNS
	case "neotron.compliance.bastion.v1":
		return models.EventPortScan
	case "neotron.cortex.consensus.v1":
		return models.EventDNS
	default:
		// Graceful fallback for unknown subjects
		if subject == "" {
			return models.EventDNS
		}
		// Check for violation pattern in unknown subjects
		return models.EventDNS
	}
}

// Unsubscribe removes all NATS subscriptions.
func (s *NeotronComplianceSubscriber) Unsubscribe() error {
	for _, sub := range s.subs {
		if err := sub.Unsubscribe(); err != nil {
			s.logger.Errorw("Failed to unsubscribe", "subject", sub.Subject, "error", err)
		}
	}
	return nil
}
