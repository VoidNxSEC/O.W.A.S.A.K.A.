package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
)

// TestNeotronConvertToNetworkEvent_Violation_Block verifies that a
// block-severity violation event is correctly mapped to EventAlert
// and carries the right compliance metadata.
func TestNeotronConvertToNetworkEvent_Violation_Block(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	raw := map[string]any{
		"audit_id":            float64(42),
		"timestamp":           "2026-05-21T14:33:00.000Z",
		"source":              "neotron",
		"subject":             "neotron.compliance.sentinel.v1",
		"guardrail_name":      "lgpd_art18_explanation",
		"regulation":          "LGPD",
		"severity":            "block",
		"passed":              false,
		"confidence":          0.98,
		"agent_output_hash":   "sha256:abc123def456",
		"details":             "Output blocked: automated decision without explanation",
	}

	event := sub.convertToNetworkEvent("neotron.compliance.sentinel.v1", raw)

	// Type check
	if event.Type != models.EventAlert {
		t.Errorf("expected EventAlert, got %s", event.Type)
	}

	// Source
	if event.Source != "neotron" {
		t.Errorf("expected source 'neotron', got '%s'", event.Source)
	}

	// Timestamp parsing
	expectedTime, _ := time.Parse(time.RFC3339, "2026-05-21T14:33:00.000Z")
	if !event.Timestamp.Equal(expectedTime) {
		t.Errorf("expected timestamp %v, got %v", expectedTime, event.Timestamp)
	}

	// Metadata checks
	if v, ok := event.Metadata["compliance_severity"].(string); !ok || v != "block" {
		t.Errorf("expected compliance_severity 'block', got '%v'", event.Metadata["compliance_severity"])
	}
	if v, ok := event.Metadata["compliance_passed"].(bool); !ok || v != false {
		t.Errorf("expected compliance_passed=false, got %v", event.Metadata["compliance_passed"])
	}
	if v, ok := event.Metadata["compliance_regulation"].(string); !ok || v != "LGPD" {
		t.Errorf("expected compliance_regulation 'LGPD', got '%v'", event.Metadata["compliance_regulation"])
	}
	if v, ok := event.Metadata["compliance_guardrail"].(string); !ok || v != "lgpd_art18_explanation" {
		t.Errorf("expected compliance_guardrail 'lgpd_art18_explanation', got '%v'", event.Metadata["compliance_guardrail"])
	}
	if v, ok := event.Metadata["compliance_audit_id"].(int); !ok || v != 42 {
		t.Errorf("expected compliance_audit_id=42, got %v", event.Metadata["compliance_audit_id"])
	}
	if v, ok := event.Metadata["compliance_confidence"].(float64); !ok || v != 0.98 {
		t.Errorf("expected compliance_confidence=0.98, got %v", event.Metadata["compliance_confidence"])
	}
	if v, ok := event.Metadata["output_hash"].(string); !ok || v != "sha256:abc123def456" {
		t.Errorf("expected output_hash, got '%v'", event.Metadata["output_hash"])
	}
}

// TestNeotronConvertToNetworkEvent_Passed_Compliance verifies that a
// passed compliance check maps to EventCompliance (not EventAlert).
func TestNeotronConvertToNetworkEvent_Passed_Compliance(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	raw := map[string]any{
		"audit_id":       float64(100),
		"timestamp":      "2026-05-21T15:00:00.000Z",
		"source":         "neotron",
		"subject":        "neotron.compliance.sentinel.v1",
		"guardrail_name": "lgpd_consent_check",
		"regulation":     "LGPD",
		"severity":       "info",
		"passed":         true,
		"confidence":     0.95,
	}

	event := sub.convertToNetworkEvent("neotron.compliance.sentinel.v1", raw)

	if event.Type != models.EventCompliance {
		t.Errorf("expected EventCompliance for passed event, got %s", event.Type)
	}
	if v, ok := event.Metadata["compliance_passed"].(bool); !ok || v != true {
		t.Errorf("expected compliance_passed=true, got %v", event.Metadata["compliance_passed"])
	}
}

// TestNeotronDetermineEventType_ViolationSubject tests that the
// explicit violation subject always returns EventAlert.
func TestNeotronDetermineEventType_ViolationSubject(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	// Even a low-severity event on the violation subject should be an alert
	raw := map[string]any{
		"severity": "low",
		"passed":   false,
	}

	eventType := sub.determineEventType("neotron.compliance.violation.v1", raw)
	if eventType != models.EventAlert {
		t.Errorf("violation subject should always be EventAlert, got %s", eventType)
	}
}

// TestNeotronDetermineEventType_SeverityMatrix tests the full severity matrix.
func TestNeotronDetermineEventType_SeverityMatrix(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	tests := []struct {
		severity string
		passed   bool
		subject  string
		expected models.EventType
	}{
		{"block", false, "neotron.compliance.sentinel.v1", models.EventAlert},
		{"critical", false, "neotron.compliance.sentinel.v1", models.EventAlert},
		{"high", false, "neotron.compliance.sentinel.v1", models.EventAlert},
		{"medium", false, "neotron.compliance.sentinel.v1", models.EventCompliance},
		{"low", false, "neotron.compliance.sentinel.v1", models.EventCompliance},
		{"info", false, "neotron.compliance.sentinel.v1", models.EventCompliance},
		{"block", true, "neotron.compliance.sentinel.v1", models.EventCompliance}, // passed → compliance
		{"info", true, "neotron.compliance.sentinel.v1", models.EventCompliance},
		{"debug", true, "neotron.compliance.siem.v1", models.EventCompliance},
	}

	for _, tc := range tests {
		raw := map[string]any{
			"severity": tc.severity,
			"passed":   tc.passed,
		}
		got := sub.determineEventType(tc.subject, raw)
		if got != tc.expected {
			t.Errorf("severity=%s passed=%v subject=%s: expected %s, got %s",
				tc.severity, tc.passed, tc.subject, tc.expected, got)
		}
	}
}

// TestNeotronConvertToNetworkEvent_CanonicalBytes verifies that the
// converted event can be serialized for Ed25519 signing (ADR-0062).
func TestNeotronConvertToNetworkEvent_CanonicalBytes(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	raw := map[string]any{
		"audit_id":       float64(1),
		"timestamp":      "2026-05-21T12:00:00.000Z",
		"guardrail_name": "test_guard",
		"regulation":     "TEST",
		"severity":       "info",
		"passed":         true,
	}

	event := sub.convertToNetworkEvent("neotron.compliance.sentinel.v1", raw)

	// Verify canonical bytes can be generated (for signing)
	canonical, err := event.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes failed: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("expected non-empty canonical bytes")
	}

	// Verify it's valid JSON
	var js map[string]any
	if err := json.Unmarshal(canonical, &js); err != nil {
		t.Fatalf("canonical bytes not valid JSON: %v", err)
	}

	// Signature fields should be absent from canonical form
	if _, ok := js["sig"]; ok {
		t.Error("canonical bytes should not contain 'sig' field")
	}
	if _, ok := js["kid"]; ok {
		t.Error("canonical bytes should not contain 'kid' field")
	}
}

// TestNeotronConvertToNetworkEvent_TemporalGuard verifies Temporal guard
// events with risk_score and reputation are properly enriched.
func TestNeotronConvertToNetworkEvent_TemporalGuard(t *testing.T) {
	sub := &NeotronComplianceSubscriber{}

	raw := map[string]any{
		"audit_id":       float64(7),
		"timestamp":      "2026-05-21T10:00:00.000Z",
		"guardrail_name": "temporal_guard",
		"regulation":     "LAYER_0_TEMPORAL",
		"severity":       "high",
		"passed":         false,
		"risk_score":     0.87,
		"reputation":     0.42,
		"agent_id":       "user_analyst_42",
	}

	event := sub.convertToNetworkEvent("neotron.compliance.temporal.v1", raw)

	if event.Type != models.EventAlert {
		t.Errorf("high severity temporal guard should be EventAlert, got %s", event.Type)
	}

	if v, ok := event.Metadata["compliance_risk_score"].(float64); !ok || v != 0.87 {
		t.Errorf("expected compliance_risk_score=0.87, got %v", event.Metadata["compliance_risk_score"])
	}
	if v, ok := event.Metadata["compliance_reputation"].(float64); !ok || v != 0.42 {
		t.Errorf("expected compliance_reputation=0.42, got %v", event.Metadata["compliance_reputation"])
	}
	if v, ok := event.Metadata["agent_id"].(string); !ok || v != "user_analyst_42" {
		t.Errorf("expected agent_id='user_analyst_42', got '%v'", event.Metadata["agent_id"])
	}
}
