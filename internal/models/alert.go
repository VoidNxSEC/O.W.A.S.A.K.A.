package models

import "time"

// AlertStatus tracks where an alert sits in the triage lifecycle.
type AlertStatus string

const (
	AlertStatusNew       AlertStatus = "NEW"
	AlertStatusTriaging  AlertStatus = "TRIAGING"
	AlertStatusContained AlertStatus = "CONTAINED"
	AlertStatusClosed    AlertStatus = "CLOSED"
)

// Alert is the persisted representation of a THREAT_ALERT event.
// Every alert emitted by the correlation engine or TemporalCorrelator
// lands here so analysts can triage, annotate, and close it.
type Alert struct {
	ID          string      `json:"id"`
	RuleName    string      `json:"rule_name"`
	Severity    string      `json:"severity"`
	Status      AlertStatus `json:"status"`
	Source      string      `json:"source"`
	Destination string      `json:"destination,omitempty"`
	MitreTactic string      `json:"mitre_tactic,omitempty"`
	ChainEvents []string    `json:"chain_events,omitempty"`
	Note        string      `json:"note,omitempty"`
	TriggeredAt time.Time   `json:"triggered_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// AlertFromEvent constructs an Alert from a THREAT_ALERT NetworkEvent.
func AlertFromEvent(e NetworkEvent) Alert {
	a := Alert{
		ID:          e.ID,
		Status:      AlertStatusNew,
		Source:      e.Source,
		Destination: e.Destination,
		TriggeredAt: e.Timestamp,
		UpdatedAt:   e.Timestamp,
	}
	if e.Metadata != nil {
		if v, ok := e.Metadata["rule"].(string); ok {
			a.RuleName = v
		}
		if v, ok := e.Metadata["severity"].(string); ok {
			a.Severity = v
		}
		if v, ok := e.Metadata["mitre_tactic"].(string); ok {
			a.MitreTactic = v
		}
		if v, ok := e.Metadata["chain_events"].([]string); ok {
			a.ChainEvents = v
		} else if raw, ok := e.Metadata["chain_events"].([]any); ok {
			for _, item := range raw {
				if s, ok := item.(string); ok {
					a.ChainEvents = append(a.ChainEvents, s)
				}
			}
		}
	}
	return a
}
