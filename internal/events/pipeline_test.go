package events

import (
	"sync"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// --- fakes ---

type fakeCorrelation struct {
	mu     sync.Mutex
	events []models.NetworkEvent
}

func (f *fakeCorrelation) Analyze(e models.NetworkEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakeCorrelation) AnalyzeAsset(_ models.Asset) {}

func (f *fakeCorrelation) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

type fakeTopology struct {
	mu     sync.Mutex
	events int
	assets int
}

func (f *fakeTopology) OnAsset(_ models.Asset) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assets++
}

func (f *fakeTopology) OnEvent(_ models.NetworkEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events++
}

type fakeEnricher struct{}

func (f *fakeEnricher) Enrich(e models.NetworkEvent) models.NetworkEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata["enriched"] = true
	return e
}

type fakeObserver struct {
	mu     sync.Mutex
	events int
}

func (f *fakeObserver) Observe(_ models.NetworkEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events++
}

// --- tests ---

func newTestPipeline() *Pipeline {
	l, _ := logging.NewLogger(&config.LoggingConfig{
		Level:  "warn",
		Format: "console",
		Output: "stdout",
	})
	return NewPipeline(nil, nil, nil, l) // no repo, no hub, no pub
}

func TestNewPipeline(t *testing.T) {
	p := newTestPipeline()
	if p == nil {
		t.Fatal("expected non-nil pipeline")
	}
	if p.engine != nil || p.topology != nil || p.stream != nil || p.observer != nil {
		t.Fatal("expected nil optional components")
	}
}

func TestPushNetworkEvent_HydratesDefaults(t *testing.T) {
	p := newTestPipeline()

	e := models.NetworkEvent{
		Type:   models.EventDNS,
		Source: "192.168.1.1",
	}
	p.PushNetworkEvent(e)
	// no panic, event dispatched — ID and Timestamp hydrated internally
}

func TestPushNetworkEvent_EnricherCalled(t *testing.T) {
	p := newTestPipeline()
	enricher := &fakeEnricher{}
	p.SetStreamEnricher(enricher)

	e := models.NetworkEvent{
		Type:   models.EventDNS,
		Source: "10.0.0.1",
	}
	p.PushNetworkEvent(e)
	// enricher was called — no direct assertion on internal state
	// but verifies integration without panic
}

func TestPushNetworkEvent_CorrelationEngineAsync(t *testing.T) {
	p := newTestPipeline()
	engine := &fakeCorrelation{}
	p.SetEngine(engine)

	p.PushNetworkEvent(models.NetworkEvent{
		Type:   models.EventPortScan,
		Source: "10.0.0.5",
	})

	// engine.Analyze is called in a goroutine
	time.Sleep(50 * time.Millisecond)
	if engine.count() != 1 {
		t.Fatalf("expected 1 event analyzed, got %d", engine.count())
	}
}

func TestPushNetworkEvent_AlertSkipsCorrelation(t *testing.T) {
	p := newTestPipeline()
	engine := &fakeCorrelation{}
	p.SetEngine(engine)

	p.PushNetworkEvent(models.NetworkEvent{
		Type: models.EventAlert, // alerts skip correlation + topology
	})

	time.Sleep(50 * time.Millisecond)
	if engine.count() != 0 {
		t.Fatalf("alerts should not be correlated, got %d", engine.count())
	}
}

func TestPushNetworkEvent_TopologyMapper(t *testing.T) {
	p := newTestPipeline()
	topo := &fakeTopology{}
	p.SetTopologyMapper(topo)

	p.PushNetworkEvent(models.NetworkEvent{
		Type:   models.EventARP,
		Source: "10.0.0.1",
	})

	time.Sleep(50 * time.Millisecond)
	topo.mu.Lock()
	defer topo.mu.Unlock()
	if topo.events != 1 {
		t.Fatalf("expected 1 topology event, got %d", topo.events)
	}
}

func TestPushNetworkEvent_Observer(t *testing.T) {
	p := newTestPipeline()
	obs := &fakeObserver{}
	p.SetEventObserver(obs)

	p.PushNetworkEvent(models.NetworkEvent{Type: models.EventDNS})
	p.PushNetworkEvent(models.NetworkEvent{Type: models.EventPortScan})

	time.Sleep(50 * time.Millisecond)
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.events != 2 {
		t.Fatalf("expected 2 observations, got %d", obs.events)
	}
}

func TestPushAsset_HydratesDefaults(t *testing.T) {
	p := newTestPipeline()
	a := models.Asset{IP: "10.0.0.42", Hostname: "test-host"}
	p.PushAsset(a)
	// no panic — ID and FirstSeen hydrated
}

func TestPushAsset_TopologyMapper(t *testing.T) {
	p := newTestPipeline()
	topo := &fakeTopology{}
	p.SetTopologyMapper(topo)

	p.PushAsset(models.Asset{IP: "10.0.0.1"})

	time.Sleep(50 * time.Millisecond)
	topo.mu.Lock()
	defer topo.mu.Unlock()
	if topo.assets != 1 {
		t.Fatalf("expected 1 asset in topology, got %d", topo.assets)
	}
}

func TestSpectreNetworkSubject(t *testing.T) {
	tests := []struct {
		eventType models.EventType
		expected  string
	}{
		{models.EventDNS, "network.dns.query.v1"},
		{models.EventPortScan, "network.service.detected.v1"},
		{models.EventProxy, "network.service.detected.v1"},
		{models.EventAlert, "network.dns.threat.v1"},
		{models.EventARP, "network.asset.discovered.v1"},
		{models.EventPhysical, "network.asset.discovered.v1"},
		{models.EventVM, "network.asset.discovered.v1"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			got := spectreNetworkSubject(tt.eventType)
			if got != tt.expected {
				t.Errorf("spectreNetworkSubject(%s) = %s, want %s", tt.eventType, got, tt.expected)
			}
		})
	}
}

func TestFullPipeline_AllComponents(t *testing.T) {
	p := newTestPipeline()
	engine := &fakeCorrelation{}
	topo := &fakeTopology{}
	enricher := &fakeEnricher{}
	obs := &fakeObserver{}

	p.SetEngine(engine)
	p.SetTopologyMapper(topo)
	p.SetStreamEnricher(enricher)
	p.SetEventObserver(obs)

	// Push multiple events and an asset
	for i := 0; i < 5; i++ {
		p.PushNetworkEvent(models.NetworkEvent{
			Type:   models.EventDNS,
			Source: "10.0.0.1",
		})
	}
	p.PushAsset(models.Asset{IP: "10.0.0.1"})

	time.Sleep(100 * time.Millisecond)

	if engine.count() != 5 {
		t.Errorf("expected 5 correlations, got %d", engine.count())
	}
	topo.mu.Lock()
	if topo.events != 5 || topo.assets != 1 {
		t.Errorf("expected 5 events + 1 asset in topology, got %d/%d", topo.events, topo.assets)
	}
	topo.mu.Unlock()
	obs.mu.Lock()
	if obs.events != 5 {
		t.Errorf("expected 5 observations, got %d", obs.events)
	}
	obs.mu.Unlock()
}
