package models

import "time"

// CanaryTokenType distinguishes a decoy DNS subdomain from a decoy
// HTTP/URL token.
type CanaryTokenType string

const (
	CanaryDNS  CanaryTokenType = "DNS"
	CanaryHTTP CanaryTokenType = "HTTP"
)

// CanaryToken is a planted tripwire. DNS tokens are unique subdomains
// that should never resolve except when an attacker's recon/exfil
// tooling queries them; HTTP tokens are decoy URLs embedded in a
// user's own apps/websites that POST to OWASAKA's webhook when touched.
type CanaryToken struct {
	ID                string          `json:"id"`
	Token             string          `json:"token"` // random unique slug
	Type              CanaryTokenType `json:"type"`
	Label             string          `json:"label"` // operator-supplied note
	Subdomain         string          `json:"subdomain,omitempty"`
	URL               string          `json:"url,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	TriggeredAt       *time.Time      `json:"triggered_at,omitempty"`
	TriggerCount      int             `json:"trigger_count"`
	LastTriggerSource string          `json:"last_trigger_source,omitempty"`
}
