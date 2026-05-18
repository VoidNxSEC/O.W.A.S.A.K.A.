package stream

import (
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
)

func newTestProcessor() *Processor {
	cfg := &config.StreamConfig{
		Enabled:              true,
		BufferSize:           100,
		FlushIntervalSeconds: 60,
		Workers:              2,
	}
	return NewProcessor(cfg, nil)
}

func TestProcessor_EnrichAddsWindowStats(t *testing.T) {
	p := newTestProcessor()

	ev := models.NetworkEvent{
		ID:        "1",
		Type:      models.EventDNS,
		Source:    "192.168.1.10",
		Timestamp: time.Now(),
	}

	enriched := p.Enrich(ev)

	if enriched.Metadata == nil {
		t.Fatal("expected metadata to be populated")
	}
	if _, ok := enriched.Metadata["stream.count_1m"]; !ok {
		t.Fatal("expected stream.count_1m in metadata")
	}
	if _, ok := enriched.Metadata["stream.rate_1m"]; !ok {
		t.Fatal("expected stream.rate_1m in metadata")
	}
}

func TestProcessor_BufferCapacity(t *testing.T) {
	p := newTestProcessor()

	// Push 150 events into buffer of size 100
	for i := 0; i < 150; i++ {
		p.Enrich(models.NetworkEvent{
			ID:        "ev",
			Type:      models.EventARP,
			Source:    "10.0.0.1",
			Timestamp: time.Now(),
		})
	}

	stats := p.Stats()
	if stats.BufferedEvents != 100 {
		t.Fatalf("expected buffer capped at 100, got %d", stats.BufferedEvents)
	}
}

func TestProcessor_EmptySourceSkipsWindowing(t *testing.T) {
	p := newTestProcessor()

	ev := models.NetworkEvent{
		ID:        "1",
		Type:      models.EventDNS,
		Source:    "",
		Timestamp: time.Now(),
	}

	enriched := p.Enrich(ev)

	// No source → no window stats injected
	if _, ok := enriched.Metadata["stream.count_1m"]; ok {
		t.Fatal("expected no stream stats for empty source")
	}
}

func TestProcessor_StatsExposesPolicyAndDrops(t *testing.T) {
	cfg := &config.StreamConfig{
		Enabled:            true,
		BufferSize:         10,
		BackpressurePolicy: "drop_oldest",
	}
	p := NewProcessor(cfg, nil)

	for i := 0; i < 15; i++ {
		p.Enrich(models.NetworkEvent{ID: "x", Type: models.EventARP, Source: "10.0.0.2", Timestamp: time.Now()})
	}

	s := p.Stats()
	if s.Policy != "drop_oldest" {
		t.Fatalf("expected policy drop_oldest, got %q", s.Policy)
	}
	if s.BufferedEvents != 10 {
		t.Fatalf("expected buffered=10, got %d", s.BufferedEvents)
	}
	if s.DroppedEvents != 5 {
		t.Fatalf("expected 5 dropped, got %d", s.DroppedEvents)
	}
}

func TestProcessor_DropNewestPolicy(t *testing.T) {
	cfg := &config.StreamConfig{
		Enabled:            true,
		BufferSize:         5,
		BackpressurePolicy: "drop_newest",
	}
	p := NewProcessor(cfg, nil)

	for i := 0; i < 8; i++ {
		p.Enrich(models.NetworkEvent{ID: "x", Type: models.EventARP, Source: "10.0.0.3", Timestamp: time.Now()})
	}

	s := p.Stats()
	if s.Policy != "drop_newest" {
		t.Fatalf("expected policy drop_newest, got %q", s.Policy)
	}
	if s.BufferedEvents != 5 {
		t.Fatalf("expected buffered=5, got %d", s.BufferedEvents)
	}
	if s.DroppedEvents != 3 {
		t.Fatalf("expected 3 refused, got %d", s.DroppedEvents)
	}
}

func TestProcessor_TryEnrichSurfacesError(t *testing.T) {
	cfg := &config.StreamConfig{
		Enabled:            true,
		BufferSize:         2,
		BackpressurePolicy: "drop_newest",
	}
	p := NewProcessor(cfg, nil)

	ev := models.NetworkEvent{ID: "x", Type: models.EventDNS, Source: "10.0.0.9", Timestamp: time.Now()}
	if _, err := p.TryEnrich(ev); err != nil {
		t.Fatalf("expected first push to succeed: %v", err)
	}
	if _, err := p.TryEnrich(ev); err != nil {
		t.Fatalf("expected second push to succeed: %v", err)
	}
	enriched, err := p.TryEnrich(ev)
	if err == nil {
		t.Fatal("expected ErrBufferFull on overflow")
	}
	// Windowing still ran; metadata still annotated
	if _, ok := enriched.Metadata["stream.count_1m"]; !ok {
		t.Fatal("expected enriched metadata even on overflow")
	}
}

func TestProcessor_WindowStatsForIP(t *testing.T) {
	p := newTestProcessor()

	for i := 0; i < 5; i++ {
		p.Enrich(models.NetworkEvent{
			ID:        "ev",
			Type:      models.EventDNS,
			Source:    "10.0.0.5",
			Timestamp: time.Now(),
		})
	}

	ws := p.WindowStatsForIP("10.0.0.5")
	if ws.Count1m != 5 {
		t.Fatalf("expected 5 events in 1m window, got %d", ws.Count1m)
	}
}
