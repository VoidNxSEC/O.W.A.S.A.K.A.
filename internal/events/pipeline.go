package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/api"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// CorrelationEngine acts as a non-blocking hook to inspect passing objects for anomalies
type CorrelationEngine interface {
	Analyze(event models.NetworkEvent)
	AnalyzeAsset(asset models.Asset)
}

// TopologyMapper builds and maintains the live network topology graph
type TopologyMapper interface {
	OnAsset(a models.Asset)
	OnEvent(e models.NetworkEvent)
}

// StreamEnricher normalizes events and annotates them with sliding-window context
type StreamEnricher interface {
	Enrich(e models.NetworkEvent) models.NetworkEvent
}

// EventObserver receives a copy of every event for passive analysis (e.g., ML).
type EventObserver interface {
	Observe(e models.NetworkEvent)
}

// Pipeline operates as a universal bus unifying physical persistence, Web UI pushing, and NATS brokering
type Pipeline struct {
	repo     *db.Repository
	hub      *api.WSHub
	pub      *Publisher
	logger   *logging.Logger
	engine   CorrelationEngine
	topology TopologyMapper
	stream   StreamEnricher
	observer EventObserver
	signer   *Signer
}

func spectreNetworkSubject(eventType models.EventType) string {
	switch eventType {
	case models.EventDNS:
		return "network.dns.query.v1"
	case models.EventPortScan, models.EventProxy:
		return "network.service.detected.v1"
	case models.EventAlert:
		return "network.dns.threat.v1"
	case models.EventARP, models.EventPhysical, models.EventVM:
		return "network.asset.discovered.v1"
	default:
		return "network.asset.discovered.v1"
	}
}

// NewPipeline constructs an event dispatcher bridging all output formats
func NewPipeline(repo *db.Repository, hub *api.WSHub, pub *Publisher, logger *logging.Logger) *Pipeline {
	return &Pipeline{
		repo:   repo,
		hub:    hub,
		pub:    pub,
		logger: logger,
	}
}

// SetSigner installs the provenance signer (ADR-0062). When set, every
// event passing through PushNetworkEvent is signed with the current
// PurposeEventSigning key before BoltDB persistence and NATS publish.
// A nil signer leaves events unsigned — fine for tests and dev mode,
// rejected by production verifiers.
func (p *Pipeline) SetSigner(s *Signer) {
	p.signer = s
}

// SetEngine dynamically binds a Correlation module onto the live pipeline layer
func (p *Pipeline) SetEngine(engine CorrelationEngine) {
	p.engine = engine
}

// SetTopologyMapper binds a topology builder to the pipeline
func (p *Pipeline) SetTopologyMapper(t TopologyMapper) {
	p.topology = t
}

// SetStreamEnricher binds the stream processor to the pipeline
func (p *Pipeline) SetStreamEnricher(s StreamEnricher) {
	p.stream = s
}

// SetEventObserver binds a passive observer (e.g., ML anomaly detector) to the pipeline
func (p *Pipeline) SetEventObserver(o EventObserver) {
	p.observer = o
}

// PushNetworkEvent accepts an event structure and dispatches globally
func (p *Pipeline) PushNetworkEvent(e models.NetworkEvent) {
	// 1. Hydrate defaults safely
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}

	// 1b. Normalize and enrich with sliding-window context
	if p.stream != nil {
		e = p.stream.Enrich(e)
	}

	// 1c. Sign the event (ADR-0062). Signature is computed over the
	// canonical bytes BEFORE persistence or publish, so tampering
	// anywhere downstream invalidates the signature. Signing failure
	// is logged but non-fatal; production verifiers will reject the
	// unsigned event, surfacing the breakage at the consumer rather
	// than dropping the event silently.
	if p.signer != nil {
		if err := p.signer.Sign(context.Background(), &e); err != nil {
			p.logger.Errorw("Failed to sign event", "error", err, "event_id", e.ID)
		}
	}

	// 2. Persist cleanly to disk locally via BoltDB
	if p.repo != nil {
		if err := p.repo.LogEvent(&e); err != nil {
			p.logger.Errorw("Failed to flush event to storage", "error", err, "event_id", e.ID)
		}
	}

	// 3. Forward JSON straight to Svelte Web UI socket
	if p.hub != nil {
		p.hub.Broadcast(e)
	}

	// 4. (Optional) Stream into NATS for inter-application architectures
	if p.pub != nil {
		out := Event{
			EventID:       e.ID,
			EventType:     string(e.Type),
			Timestamp:     e.Timestamp,
			SourceService: "SIEM",
			Payload:       e.Metadata,
		}

		// embed intrinsic data
		if out.Payload == nil {
			out.Payload = make(map[string]any)
		}
		out.Payload["source"] = e.Source
		out.Payload["destination"] = e.Destination

		p.pub.Publish(spectreNetworkSubject(e.Type), out)
	}

	// 5. Feed topology mapper to track source/destination connections
	if p.topology != nil && e.Type != models.EventAlert {
		go p.topology.OnEvent(e)
	}

	// 6. Fire un-blocking analysis asynchronously against the Threat module
	if p.engine != nil && e.Type != models.EventAlert {
		go p.engine.Analyze(e)
	}

	// 7. Feed passive observers (ML anomaly detection)
	if p.observer != nil && e.Type != models.EventAlert {
		go p.observer.Observe(e)
	}
}

// PushAsset records hardware configurations and network nodes to BoltDB and UI
func (p *Pipeline) PushAsset(a models.Asset) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}

	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now()
	}
	a.LastSeen = time.Now()

	// 1. Persist definitively to BoltDB key store
	if p.repo != nil {
		if err := p.repo.SaveAsset(&a); err != nil {
			p.logger.Errorw("Failed to save asset entity", "error", err, "asset_id", a.ID)
		}
	}

	// 2. Stream to GUI topology graph via WebSocket Hub
	if p.hub != nil {
		// Wrap as an 'asset' discovery envelope so Svelte knows what it is
		envelope := map[string]any{
			"type":      "ASSET_DISCOVERY",
			"data":      a,
			"timestamp": time.Now(),
		}

		p.hub.Broadcast(envelope)
	}

	// 3. Update topology graph with the new asset
	if p.topology != nil {
		go p.topology.OnAsset(a)
	}

	// 4. Inform external services consuming NATS optionally
	if p.pub != nil {
		data, _ := json.Marshal(a)
		payload := map[string]any{"asset": string(data)}
		p.pub.Publish("network.topology.updated.v1", Event{
			EventID:   a.ID,
			EventType: "TOPOLOGY_UPDATE",
			Timestamp: time.Now(),
			Payload:   payload,
		})
	}
}
