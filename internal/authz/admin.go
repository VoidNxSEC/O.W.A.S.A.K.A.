package authz

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReloadHandler returns an http.Handler that triggers a policy reload.
//
// Behavior:
//   - GET  → 405; reload is a side-effecting operation
//   - POST with no body → reload from `policyPath` on disk
//   - POST with YAML body (Content-Type: application/x-yaml or text/yaml)
//     → reload from request body (lets a CI pipeline or admin tool ship
//     the new policy without first writing it to disk)
//
// The handler does NOT enforce its own auth. Mount it behind
// `identity/middleware.RequireAuth` and
// `authz.RequirePermission(engine, "config", "admin", sink)` to gate
// access to the `admin` role:
//
//	mux.Handle("/api/admin/authz/reload",
//	    authMW.RequireAuth(
//	        authz.RequirePermission(engine, "config", "admin", sink)(
//	            authz.ReloadHandler(engine, "/etc/owasaka/roles.yaml", sink))))
//
// On success returns 200 with a JSON body carrying the Diff. On parse
// failure returns 400 with the validation error string. On disk read
// failure (no-body POST) returns 500. Every outcome feeds the AuditSink
// so the reload itself is audit-tracked alongside individual decisions.
func ReloadHandler(engine *Engine, policyPath string, sink AuditSink) http.Handler {
	if sink == nil {
		sink = nopAuditSink{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var (
			diff Diff
			err  error
		)
		ct := r.Header.Get("Content-Type")
		if ct == "application/x-yaml" || ct == "text/yaml" || ct == "application/yaml" {
			body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if readErr != nil {
				http.Error(w, "read body: "+readErr.Error(), http.StatusBadRequest)
				return
			}
			diff, err = engine.ReloadBytes(body)
		} else {
			if policyPath == "" {
				http.Error(w, "no policy path configured for inline reload", http.StatusInternalServerError)
				return
			}
			diff, err = engine.ReloadFrom(policyPath)
		}

		// Audit reload outcome regardless of success.
		ev := AuditEvent{
			Resource: "config",
			Action:   "admin",
		}
		if err != nil {
			ev.Decision = "deny"
			ev.Reason = "reload failed: " + err.Error()
			sink.Record(r.Context(), ev)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ev.Decision = "allow"
		ev.Reason = "reload: " + diff.String()
		sink.Record(r.Context(), ev)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  engine.Policy().Version,
			"diff":     diff,
			"summary":  diff.String(),
		})
	})
}
