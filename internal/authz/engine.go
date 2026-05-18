package authz

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
)

// Engine evaluates authorization decisions against a snapshot of the
// loaded policy. Reads are lock-free via sync/atomic.Value; reloads
// swap the pointer atomically so in-flight decisions always see a
// consistent Policy.
type Engine struct {
	current atomic.Value // *Policy
}

// NewEngine builds an Engine over an initial Policy. Pass nil only in
// tests that exercise ErrEngineNotInitialized behavior.
func NewEngine(initial *Policy) *Engine {
	e := &Engine{}
	if initial != nil {
		e.current.Store(initial)
	}
	return e
}

// Policy returns the current snapshot. Useful for diagnostics and the
// Explain CLI; production decisions go through Allowed.
func (e *Engine) Policy() *Policy {
	p, _ := e.current.Load().(*Policy)
	return p
}

// Replace swaps the engine's policy for a new snapshot. Used by
// hot-reload paths after Load succeeds.
func (e *Engine) Replace(p *Policy) {
	if p == nil {
		return
	}
	e.current.Store(p)
}

// Allowed reports whether the given principal may perform `action` on
// `resource` under the supplied attributes. Returns a Decision with the
// audit reason so callers do not need to re-run the matcher to log.
//
// attrs MUST include "principal_id" (caller convention; the matcher uses
// it for the `not-self` sentinel). Other keys are matched against
// Condition.Key (case-sensitive).
//
// Decisions are pure functions of the current Policy snapshot; concurrent
// callers see a consistent view even during a hot-reload.
func (e *Engine) Allowed(_ context.Context, p *identity.Principal, resource Resource, action Action, attrs map[string]any) (Decision, error) {
	policy := e.Policy()
	if policy == nil {
		return Decision{}, ErrEngineNotInitialized
	}
	if p == nil {
		return Decision{Reason: "denied: nil principal"}, nil
	}

	roles := principalRoles(p)
	if len(roles) == 0 {
		return Decision{Reason: "denied: principal has no roles"}, nil
	}

	// Inject the principal id as an implicit attribute so `not-self`
	// works even if callers forget to set it explicitly.
	if attrs == nil {
		attrs = map[string]any{}
	}
	if _, ok := attrs["principal_id"]; !ok {
		attrs["principal_id"] = p.ID
	}

	for _, roleName := range roles {
		role, ok := policy.Roles[roleName]
		if !ok {
			continue // unknown role on principal — silently skip; audit elsewhere
		}
		for i := range role.Permissions {
			perm := &role.Permissions[i]
			if !matchesResource(perm.Resource, resource) {
				continue
			}
			if !matchesAction(perm.Action, action) {
				continue
			}
			if reason, ok := evaluateConditions(perm.Conditions, attrs); !ok {
				// Continue searching other permissions; record only if
				// nothing else matches.
				_ = reason
				continue
			}
			return Decision{
				Allowed:    true,
				Role:       roleName,
				Permission: perm,
				Reason:     fmt.Sprintf("matched %s:%s:%s", roleName, perm.Resource, perm.Action),
			}, nil
		}
	}

	return Decision{
		Reason: fmt.Sprintf("denied: no grant for %s:%s under roles %v", resource, action, roles),
	}, nil
}

// Explain runs Allowed and returns the resulting Decision unchanged.
// Distinct method so future versions can attach extra trace (which
// rules were considered, which conditions failed) without breaking the
// hot-path Allowed contract.
func (e *Engine) Explain(ctx context.Context, p *identity.Principal, resource Resource, action Action, attrs map[string]any) (Decision, error) {
	return e.Allowed(ctx, p, resource, action, attrs)
}

// principalRoles extracts the role names from a Principal.
//
// Reads the typed Principal.Roles field first; falls back to the older
// claims["roles"] shape for compat with credentials and external token
// formats that store roles inside claims (OIDC ID tokens, JWT payloads
// from outside our issuer). Supported claim shapes:
//
//   - claims["roles"] = []string{"admin"}
//   - claims["roles"] = []any{"admin", "service"}  (YAML/JSON decode)
//   - claims["roles"] = "admin"                    (single-role shortcut)
func principalRoles(p *identity.Principal) []string {
	if p == nil {
		return nil
	}
	if len(p.Roles) > 0 {
		return p.Roles
	}
	if p.Claims == nil {
		return nil
	}
	raw, ok := p.Claims["roles"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// matchesResource returns true when the policy resource string matches
// the request's resource. Wildcard "*" matches anything; otherwise
// case-sensitive equality.
func matchesResource(policy Resource, request Resource) bool {
	if string(policy) == Wildcard {
		return true
	}
	return policy == request
}

// matchesAction returns true when the policy action matches the
// request's action, honoring the `admin` supremum (admin on a resource
// implies every other action on that resource).
func matchesAction(policy Action, request Action) bool {
	if policy == ActionAdmin {
		return true
	}
	if string(policy) == Wildcard {
		return true
	}
	return policy == request
}

// evaluateConditions returns true when every condition is satisfied.
// Missing attributes fail closed (denying the grant) — explicit
// principle: a permission with conditions never falls through to
// "allow because we don't know".
func evaluateConditions(conditions []Condition, attrs map[string]any) (reason string, allowed bool) {
	for _, c := range conditions {
		got, present := attrs[c.Key]
		if !present {
			return fmt.Sprintf("condition %s missing", c.Key), false
		}
		gotStr := fmt.Sprint(got)
		if c.Value == ValueNotSelf {
			pidRaw, hasPID := attrs["principal_id"]
			if !hasPID {
				return "principal_id missing for not-self check", false
			}
			if fmt.Sprint(pidRaw) == gotStr {
				return fmt.Sprintf("condition %s=not-self failed (self)", c.Key), false
			}
			continue
		}
		if gotStr != c.Value {
			return fmt.Sprintf("condition %s=%s not satisfied (got %s)", c.Key, c.Value, gotStr), false
		}
	}
	return "", true
}
