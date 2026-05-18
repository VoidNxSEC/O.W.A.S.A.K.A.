// Package identity defines the OWASAKA authentication and authorization
// foundations. It is the single source of truth for who is acting on the
// system. See ADR-0059 for the design rationale.
package identity

import (
	"time"
)

// PrincipalType classifies the kind of actor a Principal represents.
//
// The three types map to distinct credential lifecycles and trust models:
//
//   - Human:   operators using the SIEM via UI or CLI. MFA-mandatory.
//   - Service: ecosystem peers (Spectre, Cerebro) authenticated via mTLS.
//   - Agent:   automation (CI, scripts, runbooks) using API keys or mTLS.
type PrincipalType string

const (
	PrincipalHuman   PrincipalType = "human"
	PrincipalService PrincipalType = "service"
	PrincipalAgent   PrincipalType = "agent"
)

// PrincipalStatus reflects the lifecycle state of a Principal.
//
// A revoked Principal cannot authenticate; a suspended Principal cannot
// authenticate but may be reactivated; an active Principal is operational.
type PrincipalStatus string

const (
	StatusActive    PrincipalStatus = "active"
	StatusSuspended PrincipalStatus = "suspended"
	StatusRevoked   PrincipalStatus = "revoked"
)

// Principal is the canonical identity of any actor on the system.
//
// Every authenticated request, every published event, and every audit
// entry carries a reference to a Principal. IDs are stable across
// credential rotations so historical events remain attributable.
//
// Roles are the input to authorization decisions (see internal/authz).
// They live as a typed field because authz reads them on every request;
// arbitrary identity metadata stays in Claims.
type Principal struct {
	ID          string          `json:"id"`
	Type        PrincipalType   `json:"type"`
	Subject     string          `json:"subject"`
	DisplayName string          `json:"display_name,omitempty"`
	Status      PrincipalStatus `json:"status"`
	Roles       []string        `json:"roles,omitempty"`
	Claims      map[string]any  `json:"claims,omitempty"`

	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

// IsActive reports whether the Principal may currently authenticate.
func (p *Principal) IsActive() bool {
	return p != nil && p.Status == StatusActive
}

// Claim returns a string-typed claim by name, or empty if absent.
func (p *Principal) Claim(name string) string {
	if p == nil || p.Claims == nil {
		return ""
	}
	if v, ok := p.Claims[name].(string); ok {
		return v
	}
	return ""
}

// HasRole reports whether the Principal carries the given role. Used by
// callers that need a quick allow/deny short of running the full authz
// engine (rare; prefer authz.PrincipalAllowed for real decisions).
func (p *Principal) HasRole(name string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == name {
			return true
		}
	}
	return false
}
