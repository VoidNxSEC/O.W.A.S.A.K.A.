package stream

import (
	"context"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// ProcessorStats is the payload returned by /api/stats
type ProcessorStats struct {
	BufferedEvents int           `json:"buffered_events"`
	DroppedEvents  uint64        `json:"dropped_events"`
	Policy         string        `json:"backpressure_policy"`
	TopIPs         []WindowStats `json:"top_ips_5m"`
}

// Processor is the stream analytics middleware.
// It normalizes events, maintains sliding window counters, and enriches
// event metadata with window context before the correlation engine sees it.
type Processor struct {
	cfg    *config.StreamConfig
	logger *logging.Logger
	buf    *circularBuffer
	win    *windower
}

// NewProcessor constructs a stream processor from config
func NewProcessor(cfg *config.StreamConfig, logger *logging.Logger) *Processor {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 10000
	}
	policy := BackpressurePolicy(cfg.BackpressurePolicy)
	if policy != PolicyDropNewest {
		policy = PolicyDropOldest
	}
	return &Processor{
		cfg:    cfg,
		logger: logger,
		buf:    newCircularBuffer(bufSize, policy),
		win:    newWindower(),
	}
}

// Start launches background housekeeping goroutines
func (p *Processor) Start(ctx context.Context) {
	go p.gcLoop(ctx)
}

// Enrich normalizes an event, records it in the buffer and windower,
// then annotates its metadata with sliding-window counts.
// Implements the StreamEnricher interface consumed by the pipeline.
func (p *Processor) Enrich(e models.NetworkEvent) models.NetworkEvent {
	e = Normalize(e)

	// Record into buffer and windowed counters; drops are tracked via buf.Dropped()
	_ = p.buf.push(e)
	if e.Source != "" {
		p.win.record(e.Source, e.Type)
	}

	// Annotate metadata with window stats so correlation rules can use them
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	if e.Source != "" {
		stats := p.win.stats(e.Source)
		e.Metadata["stream.count_1m"] = stats.Count1m
		e.Metadata["stream.count_5m"] = stats.Count5m
		e.Metadata["stream.count_15m"] = stats.Count15m
		e.Metadata["stream.rate_1m"] = stats.Rate1m
	}

	return e
}

// Stats returns a snapshot of processor state for the /api/stats endpoint
func (p *Processor) Stats() ProcessorStats {
	return ProcessorStats{
		BufferedEvents: p.buf.len(),
		DroppedEvents:  p.buf.Dropped(),
		Policy:         string(p.buf.policy),
		TopIPs:         p.win.topIPs(10),
	}
}

// TryEnrich is a non-silent variant that surfaces ErrBufferFull when the
// configured backpressure policy refuses the event. The returned event is
// still enriched (windowing always runs) so callers can choose to forward it.
func (p *Processor) TryEnrich(e models.NetworkEvent) (models.NetworkEvent, error) {
	e = Normalize(e)
	err := p.buf.push(e)
	if e.Source != "" {
		p.win.record(e.Source, e.Type)
	}
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	if e.Source != "" {
		stats := p.win.stats(e.Source)
		e.Metadata["stream.count_1m"] = stats.Count1m
		e.Metadata["stream.count_5m"] = stats.Count5m
		e.Metadata["stream.count_15m"] = stats.Count15m
		e.Metadata["stream.rate_1m"] = stats.Rate1m
	}
	return e, err
}

// WindowStatsForIP exposes per-IP window data for external consumers (e.g. ML detector)
func (p *Processor) WindowStatsForIP(ip string) WindowStats {
	return p.win.stats(ip)
}

// gcLoop periodically logs a health summary; future: evict stale buffer entries
func (p *Processor) gcLoop(ctx context.Context) {
	interval := time.Duration(p.cfg.FlushIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.logger.Infow("Stream processor heartbeat",
				"buffered", p.buf.len(),
				"top_ip_count", len(p.win.topIPs(1)),
			)
		}
	}
}
