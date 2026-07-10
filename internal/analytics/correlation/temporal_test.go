package correlation

import (
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
)

func TestTemporalCorrelator_NoAlert_SingleEvent(t *testing.T) {
	tc := NewTemporalCorrelator(DefaultChains(), testLogger())
	var alerts []models.NetworkEvent
	tc.SetAlertCallback(func(a models.NetworkEvent) { alerts = append(alerts, a) })

	tc.Observe(models.NetworkEvent{ID: "1", Source: "10.0.0.1", Type: models.EventARP, Timestamp: time.Now()})
	if len(alerts) != 0 {
		t.Fatal("single ARP event should not fire a chain alert")
	}
}

func TestTemporalCorrelator_ReconToPortscan_Fires(t *testing.T) {
	tc := NewTemporalCorrelator(DefaultChains(), testLogger())
	var alerts []models.NetworkEvent
	tc.SetAlertCallback(func(a models.NetworkEvent) { alerts = append(alerts, a) })

	now := time.Now()
	tc.Observe(models.NetworkEvent{ID: "1", Source: "10.0.0.5", Type: models.EventARP, Timestamp: now})
	tc.Observe(models.NetworkEvent{ID: "2", Source: "10.0.0.5", Type: models.EventPortScan, Timestamp: now.Add(time.Minute)})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 chain alert for RECON_TO_PORTSCAN, got %d", len(alerts))
	}
	if alerts[0].Metadata["rule"] != "RECON_TO_PORTSCAN" {
		t.Fatalf("expected rule RECON_TO_PORTSCAN, got %v", alerts[0].Metadata["rule"])
	}
	if alerts[0].Metadata["mitre_tactic"] != "TA0043" {
		t.Fatalf("expected tactic TA0043, got %v", alerts[0].Metadata["mitre_tactic"])
	}
}

func TestTemporalCorrelator_OutOfWindow_NoFire(t *testing.T) {
	chains := []ChainRule{
		{Name: "FAST_CHAIN", Tactic: "TA0000", Window: time.Minute, Sequence: []models.EventType{models.EventARP, models.EventPortScan}},
	}
	tc := NewTemporalCorrelator(chains, testLogger())
	var alerts []models.NetworkEvent
	tc.SetAlertCallback(func(a models.NetworkEvent) { alerts = append(alerts, a) })

	now := time.Now()
	tc.Observe(models.NetworkEvent{ID: "1", Source: "10.0.0.9", Type: models.EventARP, Timestamp: now.Add(-5 * time.Minute)})
	tc.Observe(models.NetworkEvent{ID: "2", Source: "10.0.0.9", Type: models.EventPortScan, Timestamp: now})

	if len(alerts) != 0 {
		t.Fatal("events outside the window should not fire a chain alert")
	}
}

func TestTemporalCorrelator_DifferentSources_NoFire(t *testing.T) {
	tc := NewTemporalCorrelator(DefaultChains(), testLogger())
	var alerts []models.NetworkEvent
	tc.SetAlertCallback(func(a models.NetworkEvent) { alerts = append(alerts, a) })

	now := time.Now()
	tc.Observe(models.NetworkEvent{ID: "1", Source: "10.0.0.1", Type: models.EventARP, Timestamp: now})
	tc.Observe(models.NetworkEvent{ID: "2", Source: "10.0.0.2", Type: models.EventPortScan, Timestamp: now.Add(time.Second)})

	if len(alerts) != 0 {
		t.Fatal("events from different sources should not form a chain")
	}
}

func TestTemporalCorrelator_TorEvasionScan_Fires(t *testing.T) {
	tc := NewTemporalCorrelator(DefaultChains(), testLogger())
	var alerts []models.NetworkEvent
	tc.SetAlertCallback(func(a models.NetworkEvent) { alerts = append(alerts, a) })

	now := time.Now()
	tc.Observe(models.NetworkEvent{ID: "a", Source: "192.168.1.10", Type: models.EventTor, Timestamp: now})
	tc.Observe(models.NetworkEvent{ID: "b", Source: "192.168.1.10", Type: models.EventPortScan, Timestamp: now.Add(30 * time.Second)})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 TOR_EVASION_SCAN alert, got %d", len(alerts))
	}
	if alerts[0].Metadata["rule"] != "TOR_EVASION_SCAN" {
		t.Fatalf("expected TOR_EVASION_SCAN, got %v", alerts[0].Metadata["rule"])
	}
	severity := alerts[0].Metadata["severity"]
	if severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity for Tor evasion, got %v", severity)
	}
}
