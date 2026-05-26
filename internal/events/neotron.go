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

// ── Neotron Compliance Event Integration ────────────────────────────────────
//
// The neotron platform (Python) publishes compliance events as JSON on NATS:
//
//   neotron.compliance.temporal.v1    — Layer 0 TEMPORAL guard (boiling-frog)
//   neotron.compliance.sentinel.v1    — Layer 1 SENTINEL guardrails (LGPD/GDPR)
//   neotron.compliance.bastion.v1     — Layer 2 BASTION kernel enforcement
//   neotron.cortex.consensus.v1       — Layer 3 CORTEX swarm consensus
//   neotron.compliance.violation.v1   — Blocking violations (any layer)
//   neotron.compliance.siem.v1        — SIEM export bridge
//
// Event payload (JSON):
//
//   {
//     "audit_id": 42,
//     "timestamp": "2026-04-07T12:00:00Z",
//     "source": "neotron",
//     "subject": "neotron.compliance.sentinel.v1",
//     "guardrail_name": "lgpd_art18_explanation",
//     "regulation": "LGPD",
//     "severity": "block",         // debug|info|low|medium|high|critical|block
//     "passed": false,
//     "confidence": 0.98,
//     "agent_output_hash": "sha256:abc123...",
//     "details": "Explanation missing for automated decision"
//   }
//
// Severity mapping (Neotron → Owasaka):
//
//   Neotron severity    passed    Owasaka EventType    Transparency log
//   ─────────────────   ──────    ─────────────────    ────────────────
//   block/critical      false     EventAlert           ✅ (ADR-0063)
//   high                false     EventAlert           ✅
//   medium/low/info     false     EventCompliance      ❌
//   any                 true      EventCompliance      ❌
//
// All events carry compliance metadata (severity, regulation, guardrail)
// for downstream correlation and ML anomaly detection.

// ── Subscriber ──────────────────────────────────────────────────────────────

// NeotronComplianceSubscriber listens on neotron.compliance.> NATS subjects
// and pushes inbound events into the owasaka SIEM pipeline for persistence,
// WebSocket broadcast, correlation, and ML anomaly detection.
type NeotronComplianceSubscriber struct {
	subs     []*nats.Subscription
	pipeline *Pipeline
	logger   *logging.Logger
}

// NewNeotronComplianceSubscriber creates subscriptions for all neotron
// compliance subjects and wires them into the owasaka event pipeline.
func NewNeotronComplianceSubscriber(nc *nats.Conn, pipeline *Pipeline, logger *logging.Logger) (*NeotronComplianceSubscriber, error) {
	sub := &NeotronComplianceSubscriber{
		pipeline: pipeline,
		logger:   logger,
	}

	// Subscribe to all neotron compliance subjects using wildcard
	subject := "neotron.compliance.>"

	natsSub, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		sub.handleComplianceEvent(msg)
	})
	if err != nil {
		return nil, fmt.Errorf("subscribe %s: %w", subject, err)
	}
	sub.subs = append(sub.subs, natsSub)
	logger.Infow("Neotron compliance subscriber registered", "subject", subject)

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

	// Extract key fields for structured logging
	auditID, _ := raw["audit_id"].(float64)
	guardrail, _ := raw["guardrail_name"].(string)
	passed, _ := raw["passed"].(bool)
	severity, _ := raw["severity"].(string)
	regulation, _ := raw["regulation"].(string)

	logFields := []any{
		"subject", msg.Subject,
		"audit_id", int(auditID),
		"guardrail", guardrail,
		"regulation", regulation,
		"severity", severity,
		"passed", passed,
	}

	if !passed {
		s.logger.Warnw("Neotron compliance VIOLATION", logFields...)
	} else {
		s.logger.Infow("Neotron compliance event", logFields...)
	}

	// Convert to owasaka NetworkEvent for pipeline ingestion
	event := s.convertToNetworkEvent(msg.Subject, raw)

	// Push through the owasaka pipeline:
	// 1. Persist to BoltDB
	// 2. Broadcast to WebSocket UI
	// 3. Sign with Ed25519 (ADR-0062)
	// 4. Feed correlation engine
	// 5. ML anomaly detection
	// 6. Transparency log for violations (ADR-0063)
	s.pipeline.PushNetworkEvent(event)
}

// convertToNetworkEvent maps a neotron compliance event to the owasaka
// NetworkEvent model for pipeline processing.
func (s *NeotronComplianceSubscriber) convertToNetworkEvent(subject string, raw map[string]any) models.NetworkEvent {
	// Determine event type based on severity and pass/fail
	eventType := s.determineEventType(subject, raw)

	// Extract timestamp — neotron uses ISO 8601 strings
	ts := time.Now()
	if tsStr, ok := raw["timestamp"].(string); ok {
		parsed, err := time.Parse(time.RFC3339, tsStr)
		if err == nil {
			ts = parsed
		}
	}

	// Extract agent/guardrail identity
	guardrail, _ := raw["guardrail_name"].(string)
	regulation, _ := raw["regulation"].(string)
	severity, _ := raw["severity"].(string)
	passed, _ := raw["passed"].(bool)
	auditID, _ := raw["audit_id"].(float64)

	// Build enriched metadata — compliance-specific fields at top level
	// for correlation engine and ML feature extraction
	metadata := make(map[string]any)

	// ── Compliance-first fields (queried by correlation/ML) ──
	metadata["compliance_guardrail"] = guardrail
	metadata["compliance_regulation"] = regulation
	metadata["compliance_severity"] = severity
	metadata["compliance_passed"] = passed
	metadata["compliance_audit_id"] = int(auditID)
	metadata["nats_subject"] = subject
	metadata["source_service"] = "neotron"

	// Confidence score (for ML anomaly detection)
	if conf, ok := raw["confidence"].(float64); ok {
		metadata["compliance_confidence"] = conf
	}

	// Risk score (Temporal guard specific)
	if risk, ok := raw["risk_score"].(float64); ok {
		metadata["compliance_risk_score"] = risk
	}

	// Agent reputation (Temporal guard specific)
	if rep, ok := raw["reputation"].(float64); ok {
		metadata["compliance_reputation"] = rep
	}

	// Agent ID
	if agentID, ok := raw["agent_id"].(string); ok {
		metadata["agent_id"] = agentID
	}

	// Output hash (for audit trail linking)
	if hash, ok := raw["agent_output_hash"].(string); ok {
		metadata["output_hash"] = hash
	}

	// Details / explanation
	if details, ok := raw["details"].(string); ok {
		metadata["details"] = details
	}

	// Copy all remaining raw fields not already captured
	for k, v := range raw {
		switch k {
		case "guardrail_name", "regulation", "severity", "passed",
			"audit_id", "timestamp", "confidence", "risk_score",
			"reputation", "agent_id", "agent_output_hash", "details",
			"subject", "source":
			// already handled above
		default:
			metadata[k] = v
		}
	}

	return models.NetworkEvent{
		ID:          uuid.New().String(),
		Type:        eventType,
		Source:      "neotron",
		Destination: guardrail, // guardrail name as destination for routing
		Metadata:    metadata,
		Timestamp:   ts,
	}
}

// determineEventType maps a neotron compliance event to an owasaka EventType.
//
// Decision matrix:
//
//   severity     | passed  → EventType
//   ──────────── | ──────    ─────────
//   block        | false  → EventAlert (critical — transparency log)
//   critical     | false  → EventAlert
//   high         | false  → EventAlert
//   medium       | false  → EventCompliance
//   low/info     | false  → EventCompliance
//   any          | true   → EventCompliance
func (s *NeotronComplianceSubscriber) determineEventType(subject string, raw map[string]any) models.EventType {
	severity, _ := raw["severity"].(string)
	passed, _ := raw["passed"].(bool)

	// Explicit violation subject always maps to alert
	if subject == "neotron.compliance.violation.v1" {
		return models.EventAlert
	}

	// If the event passed, it's a routine compliance check → EventCompliance
	if passed {
		return models.EventCompliance
	}

	// Failed events: severity determines alert level
	switch severity {
	case "block", "critical", "high":
		return models.EventAlert
	default:
		return models.EventCompliance
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
