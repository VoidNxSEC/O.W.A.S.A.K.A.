package correlation

import (
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

func testLogger() *logging.Logger {
	cfg := &config.LoggingConfig{Level: "error", Format: "text", Output: "stdout"}
	l, _ := logging.NewLogger(cfg)
	return l
}

func newTestEngine() *Engine {
	cfg := &config.CorrelationConfig{Enabled: true}
	return &Engine{
		cfg:    cfg,
		logger: testLogger(),
		rules:  DefaultRules(),
	}
}

func TestEngine_DGADetection(t *testing.T) {
	var alerts []models.NetworkEvent
	e := newTestEngine()
	e.onAlert = func(ev models.NetworkEvent) { alerts = append(alerts, ev) }

	// Legitimate domain — should NOT trigger (low entropy, normal vowel ratio).
	e.Analyze(models.NetworkEvent{
		ID:   "1",
		Type: models.EventDNS,
		Metadata: map[string]any{
			"name": "google.com.",
		},
	})
	if len(alerts) != 0 {
		t.Fatal("expected no alert for legitimate domain")
	}

	// DGA-like domain: high entropy, all consonants, long label — should trigger.
	// "xzkmbqwjvlrptfns" has entropy ≈ 4.09 and 0 vowels.
	e.Analyze(models.NetworkEvent{
		ID:   "2",
		Type: models.EventDNS,
		Metadata: map[string]any{
			"name": "xzkmbqwjvlrptfns.c2example.net.",
		},
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 DGA alert, got %d", len(alerts))
	}
	if alerts[0].Type != models.EventAlert {
		t.Fatalf("expected EventAlert, got %s", alerts[0].Type)
	}
	if alerts[0].Metadata["rule"] != "DGA_DOMAIN_DETECTED" {
		t.Fatalf("expected DGA_DOMAIN_DETECTED rule, got %v", alerts[0].Metadata["rule"])
	}
}

func TestEngine_EmbeddedRulesLoad(t *testing.T) {
	cfg := &config.CorrelationConfig{Enabled: true}
	e := NewEngine(cfg, testLogger())

	// Engine should have more than just the built-in Go rules after embedding.
	if len(e.rules) <= 1 {
		t.Fatalf("expected embedded YAML rules to be loaded, got %d total rules", len(e.rules))
	}
}

func TestEngine_AnalyzeDNSExfiltration(t *testing.T) {
	var alerts []models.NetworkEvent
	// Use the full engine (with embedded YAML rules) to verify dns_malicious_tld.yaml fires.
	cfg := &config.CorrelationConfig{Enabled: true}
	e := NewEngine(cfg, testLogger())
	e.onAlert = func(ev models.NetworkEvent) { alerts = append(alerts, ev) }

	// Benign query — should NOT trigger the malicious TLD rule.
	e.Analyze(models.NetworkEvent{
		ID:   "1",
		Type: models.EventDNS,
		Metadata: map[string]any{
			"name": "google.com.",
		},
	})
	if len(alerts) != 0 {
		t.Fatal("expected no alert for benign query")
	}

	// Query to a known-malicious TLD — should trigger DNS_MALICIOUS_TLD via embedded YAML.
	e.Analyze(models.NetworkEvent{
		ID:   "2",
		Type: models.EventDNS,
		Metadata: map[string]any{
			"name": "data.exfil.tk.somedomain.com.",
		},
	})
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for malicious TLD, got %d", len(alerts))
	}
	if alerts[0].Type != models.EventAlert {
		t.Fatalf("expected EventAlert, got %s", alerts[0].Type)
	}
}

func TestEngine_SkipsAlertEvents(t *testing.T) {
	var alerts []models.NetworkEvent
	e := newTestEngine()
	e.onAlert = func(ev models.NetworkEvent) { alerts = append(alerts, ev) }

	// Alert events should be skipped (no feedback loop)
	e.Analyze(models.NetworkEvent{
		ID:   "3",
		Type: models.EventAlert,
		Metadata: map[string]any{
			"name": "evil.com.",
		},
	})
	if len(alerts) != 0 {
		t.Fatal("alert events should be skipped to prevent feedback loops")
	}
}

func TestEngine_DisabledSkipsAnalysis(t *testing.T) {
	cfg := &config.CorrelationConfig{Enabled: false}
	e := &Engine{cfg: cfg, logger: testLogger(), rules: DefaultRules()}
	var alerts []models.NetworkEvent
	e.onAlert = func(ev models.NetworkEvent) { alerts = append(alerts, ev) }

	e.Analyze(models.NetworkEvent{
		ID:   "4",
		Type: models.EventDNS,
		Metadata: map[string]any{
			"name": "evil.com.",
		},
	})
	if len(alerts) != 0 {
		t.Fatal("disabled engine should not produce alerts")
	}
}

func TestEngine_NonDNSEventIgnored(t *testing.T) {
	var alerts []models.NetworkEvent
	e := newTestEngine()
	e.onAlert = func(ev models.NetworkEvent) { alerts = append(alerts, ev) }

	e.Analyze(models.NetworkEvent{
		ID:        "5",
		Type:      models.EventARP,
		Timestamp: time.Now(),
	})
	if len(alerts) != 0 {
		t.Fatal("non-DNS event should not trigger DNS exfiltration rule")
	}
}
