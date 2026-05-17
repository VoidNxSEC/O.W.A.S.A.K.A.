package authz

import (
	"context"
	"net/http"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// AuditEvent is the structured payload an authorization decision emits.
// Sprint 2 R10 wires it into the audit-log bucket; Sprint 3
// transparency log consumes the same shape.
type AuditEvent struct {
	PrincipalID string         `json:"principal_id"`
	Roles       []string       `json:"roles"`
	Resource    string         `json:"resource"`
	Action      string         `json:"action"`
	Decision    string         `json:"decision"` // "allow" | "deny"
	Reason      string         `json:"reason"`
	Attrs       map[string]any `json:"attrs,omitempty"`
}

// AuditSink receives an AuditEvent for every authorization decision.
// Default sinks log; production wiring persists to BoltDB and republishes
// to NATS for Spectre consumption.
type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent)
}

// LogAuditSink is the default sink: emits structured logs via the
// package's logger. Useful in dev and for the demo.
type LogAuditSink struct{ Logger *logging.Logger }

// Record implements AuditSink.
func (s LogAuditSink) Record(_ context.Context, ev AuditEvent) {
	if s.Logger == nil {
		return
	}
	s.Logger.Infow("authz decision",
		"principal_id", ev.PrincipalID,
		"resource", ev.Resource,
		"action", ev.Action,
		"decision", ev.Decision,
		"reason", ev.Reason,
		"roles", ev.Roles,
	)
}

// nopAuditSink is the sink used when callers do not configure one.
type nopAuditSink struct{}

func (nopAuditSink) Record(context.Context, AuditEvent) {}

// RequirePermission returns an http middleware that enforces an authz
// check on top of identity middleware's RequireAuth. The Principal
// must already be in context — chain this AFTER middleware.RequireAuth.
//
// Usage:
//
//	mux.Handle("/api/rules", mwAuth.RequireAuth(
//	    authz.RequirePermission(engine, "rules", "write", sink)(
//	        rulesHandler)))
//
// Behavior:
//   - Principal absent (caller forgot RequireAuth): 401.
//   - Decision denied: 403, structured body, audit-logged.
//   - Decision allowed: handler called normally, audit-logged.
func RequirePermission(engine *Engine, resource Resource, action Action, sink AuditSink) func(http.Handler) http.Handler {
	if sink == nil {
		sink = nopAuditSink{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := middleware.PrincipalFromContext(r.Context())
			if principal == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			attrs := AttrsFromRequest(r)
			decision, err := engine.Allowed(r.Context(), principal, resource, action, attrs)
			ev := AuditEvent{
				PrincipalID: principal.ID,
				Roles:       principalRoles(principal),
				Resource:    string(resource),
				Action:      string(action),
				Decision:    "deny",
				Reason:      decision.Reason,
				Attrs:       attrs,
			}
			if err != nil {
				ev.Reason = "engine error: " + err.Error()
				sink.Record(r.Context(), ev)
				http.Error(w, "authorization unavailable", http.StatusInternalServerError)
				return
			}
			if !decision.Allowed {
				sink.Record(r.Context(), ev)
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			ev.Decision = "allow"
			sink.Record(r.Context(), ev)
			next.ServeHTTP(w, r)
		})
	}
}

// AttrsFromRequest derives the attribute map fed to the engine from an
// http.Request. Default fields:
//
//   - principal_id: the authenticated principal's ID (also injected
//     by the engine, kept here for clarity).
//   - cn:           the TLS peer's CommonName, if mTLS was used.
//   - subject:      pulled from query param `?subject=` when present
//                   (used by audit-resource checks that need not-self).
//
// Handlers can add domain-specific attributes by wrapping this and
// merging into the returned map before calling engine.Allowed
// directly. For middleware-level checks, the defaults suffice for
// the baseline policy.
func AttrsFromRequest(r *http.Request) map[string]any {
	out := make(map[string]any, 4)
	if principal := middleware.PrincipalFromContext(r.Context()); principal != nil {
		out["principal_id"] = principal.ID
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		out["cn"] = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	if subj := r.URL.Query().Get("subject"); subj != "" {
		out["subject"] = subj
	}
	return out
}

// PrincipalAllowed is the in-process variant for code paths that
// cannot or should not go through http middleware (background workers,
// event-pipeline hooks, CLI invocations). Same engine, same audit, no
// HTTP plumbing.
func PrincipalAllowed(ctx context.Context, engine *Engine, p *identity.Principal, resource Resource, action Action, attrs map[string]any, sink AuditSink) (bool, error) {
	if sink == nil {
		sink = nopAuditSink{}
	}
	decision, err := engine.Allowed(ctx, p, resource, action, attrs)
	ev := AuditEvent{
		Resource: string(resource),
		Action:   string(action),
		Decision: "deny",
		Reason:   decision.Reason,
		Attrs:    attrs,
	}
	if p != nil {
		ev.PrincipalID = p.ID
		ev.Roles = principalRoles(p)
	}
	if err != nil {
		ev.Reason = "engine error: " + err.Error()
		sink.Record(ctx, ev)
		return false, err
	}
	if decision.Allowed {
		ev.Decision = "allow"
	}
	sink.Record(ctx, ev)
	return decision.Allowed, nil
}
