package correlation

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// ChainRule defines a multi-event kill-chain sequence that must occur within a time window.
type ChainRule struct {
	Name     string
	Tactic   string // MITRE ATT&CK tactic ID (e.g. "TA0008")
	Severity string
	Window   time.Duration
	Sequence []models.EventType // ordered event types that must appear in order
}

// stampedEvent is a lightweight snapshot of an event for window tracking.
type stampedEvent struct {
	ID        string
	Type      models.EventType
	Timestamp time.Time
}

// TemporalCorrelator detects ordered sequences of events (kill chains) from the same source
// within sliding time windows. It is stateful and goroutine-safe.
type TemporalCorrelator struct {
	mu      sync.Mutex
	windows map[string][]stampedEvent // key: source IP/identifier
	chains  []ChainRule
	onAlert AlertCallback
	logger  *logging.Logger
	maxAge  time.Duration // longest window across all rules (for GC)
}

// DefaultChains returns the built-in kill-chain detection rules with MITRE ATT&CK mappings.
func DefaultChains() []ChainRule {
	return []ChainRule{
		{
			Name:     "RECON_TO_PORTSCAN",
			Tactic:   "TA0043", // Reconnaissance → Discovery
			Severity: "HIGH",
			Window:   10 * time.Minute,
			Sequence: []models.EventType{models.EventARP, models.EventPortScan},
		},
		{
			Name:     "TOR_EVASION_SCAN",
			Tactic:   "TA0005", // Defense Evasion
			Severity: "CRITICAL",
			Window:   5 * time.Minute,
			Sequence: []models.EventType{models.EventTor, models.EventPortScan},
		},
		{
			Name:     "TOR_EVASION_DNS",
			Tactic:   "TA0011", // Command and Control
			Severity: "HIGH",
			Window:   5 * time.Minute,
			Sequence: []models.EventType{models.EventTor, models.EventDNS},
		},
		{
			Name:     "CANARY_THEN_SCAN",
			Tactic:   "TA0007", // Discovery (attacker found canary, now mapping)
			Severity: "CRITICAL",
			Window:   15 * time.Minute,
			Sequence: []models.EventType{models.EventCanary, models.EventPortScan},
		},
		{
			Name:     "PROXY_TO_SCAN",
			Tactic:   "TA0003", // Initial Access
			Severity: "HIGH",
			Window:   5 * time.Minute,
			Sequence: []models.EventType{models.EventProxy, models.EventPortScan},
		},
	}
}

// NewTemporalCorrelator creates a correlator with the provided chain rules.
func NewTemporalCorrelator(chains []ChainRule, logger *logging.Logger) *TemporalCorrelator {
	maxAge := time.Minute
	for _, c := range chains {
		if c.Window > maxAge {
			maxAge = c.Window
		}
	}
	return &TemporalCorrelator{
		windows: make(map[string][]stampedEvent),
		chains:  chains,
		logger:  logger,
		maxAge:  maxAge,
	}
}

// SetAlertCallback registers the function called when a kill chain fires.
func (t *TemporalCorrelator) SetAlertCallback(cb AlertCallback) {
	t.onAlert = cb
}

// Observe adds the event to the source's sliding window and checks for completed chains.
// It is safe to call from multiple goroutines.
func (t *TemporalCorrelator) Observe(e models.NetworkEvent) {
	if e.Source == "" || e.Type == models.EventAlert {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	src := e.Source
	now := e.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	// Evict events older than the longest window to bound memory.
	cutoff := now.Add(-t.maxAge)
	existing := t.windows[src]
	trimmed := existing[:0]
	for _, ev := range existing {
		if ev.Timestamp.After(cutoff) {
			trimmed = append(trimmed, ev)
		}
	}
	trimmed = append(trimmed, stampedEvent{ID: e.ID, Type: e.Type, Timestamp: now})
	t.windows[src] = trimmed

	// Check each chain rule against the updated window.
	for _, chain := range t.chains {
		if ids := t.matchChain(trimmed, chain, now); ids != nil {
			t.fireChainAlert(e, chain, ids)
		}
	}
}

// matchChain returns the event IDs forming the first complete sequence match within the window,
// or nil if no match exists.
func (t *TemporalCorrelator) matchChain(window []stampedEvent, chain ChainRule, now time.Time) []string {
	seq := chain.Sequence
	if len(seq) == 0 {
		return nil
	}
	cutoff := now.Add(-chain.Window)

	// Find first occurrence of seq[0], then walk forward through the sequence.
	ids := make([]string, 0, len(seq))
	idx := 0 // position in sequence
	for _, ev := range window {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		if ev.Type == seq[idx] {
			ids = append(ids, ev.ID)
			idx++
			if idx == len(seq) {
				return ids
			}
		}
	}
	return nil
}

func (t *TemporalCorrelator) fireChainAlert(trigger models.NetworkEvent, chain ChainRule, chainIDs []string) {
	if t.onAlert == nil {
		return
	}

	severity := chain.Severity
	if severity == "" {
		severity = "HIGH"
	}

	alert := models.NetworkEvent{
		ID:          uuid.NewString(),
		Type:        models.EventAlert,
		Timestamp:   time.Now().UTC(),
		Source:      "TemporalCorrelator",
		Destination: trigger.Source,
		Metadata: map[string]any{
			"rule":         chain.Name,
			"description":  "Kill-chain sequence detected: " + chain.Name,
			"severity":     severity,
			"mitre_tactic": chain.Tactic,
			"chain_events": chainIDs,
			"trigger_id":   trigger.ID,
			"window":       chain.Window.String(),
		},
	}

	t.logger.Warnw("⛓️  KILL CHAIN DETECTED",
		"rule", chain.Name,
		"tactic", chain.Tactic,
		"source", trigger.Source,
		"chain_length", len(chainIDs),
	)

	// Clear the matched sequence from the window to avoid repeated firing on the same chain.
	src := trigger.Source
	if events, ok := t.windows[src]; ok {
		matchSet := make(map[string]bool, len(chainIDs))
		for _, id := range chainIDs {
			matchSet[id] = true
		}
		filtered := events[:0]
		for _, ev := range events {
			if !matchSet[ev.ID] {
				filtered = append(filtered, ev)
			}
		}
		t.windows[src] = filtered
	}

	t.onAlert(alert)
}
