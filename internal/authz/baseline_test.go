package authz

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
)

// TestShippedBaselinePolicy guarantees the configs/rbac/roles.yaml that
// ships with the binary parses cleanly and grants the expected
// permissions to each baseline role. Drift between the docs repo and
// the YAML breaks here.
func TestShippedBaselinePolicy(t *testing.T) {
	path := shippedRolesPath(t)
	policy, err := Load(path)
	if err != nil {
		t.Fatalf("ship baseline policy must load: %v", err)
	}

	// All four baseline roles present.
	for _, role := range []string{"viewer", "auditor", "admin", "service"} {
		if _, ok := policy.Roles[role]; !ok {
			t.Errorf("baseline role %q missing from %s", role, path)
		}
	}

	engine := NewEngine(policy)
	ctx := context.Background()

	// Spot-check expected behavior.
	cases := []struct {
		name     string
		roles    []string
		resource Resource
		action   Action
		attrs    map[string]any
		want     bool
	}{
		{"viewer reads events",        []string{"viewer"},  "events", "read", nil, true},
		{"viewer cannot write events", []string{"viewer"},  "events", "write", nil, false},
		{"viewer cannot read audit",   []string{"viewer"},  "audit",  "read", nil, false},

		{"auditor reads audit (other)", []string{"auditor"}, "audit", "read", map[string]any{"subject": "other-id"}, true},
		{"auditor cannot self-audit",   []string{"auditor"}, "audit", "read", map[string]any{"principal_id": "self-id", "subject": "self-id"}, false},
		{"auditor reads principals",    []string{"auditor"}, "principals", "read", nil, true},
		{"auditor cannot read events",  []string{"auditor"}, "events", "read", nil, false},

		{"admin can anything",         []string{"admin"},   "anything",   "delete", nil, true},

		{"spectre writes events",      []string{"service"}, "events", "write", map[string]any{"cn": "spectre"}, true},
		{"spectre cannot read events", []string{"service"}, "events", "read",  map[string]any{"cn": "spectre"}, false},
		{"cerebro reads events",       []string{"service"}, "events", "read",  map[string]any{"cn": "cerebro"}, true},
		{"cerebro cannot write",       []string{"service"}, "events", "write", map[string]any{"cn": "cerebro"}, false},
		{"unknown cn denied",          []string{"service"}, "events", "write", map[string]any{"cn": "intruder"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &identity.Principal{
				ID:     "self-id",
				Status: identity.StatusActive,
				Claims: map[string]any{"roles": tc.roles},
			}
			d, err := engine.Allowed(ctx, p, tc.resource, tc.action, tc.attrs)
			if err != nil {
				t.Fatalf("engine error: %v", err)
			}
			if d.Allowed != tc.want {
				t.Fatalf("got allowed=%v want=%v (reason=%s)", d.Allowed, tc.want, d.Reason)
			}
		})
	}
}

// shippedRolesPath walks up from this test file to find the repo root,
// then points at configs/rbac/roles.yaml. Robust to running with `go
// test ./...` from anywhere in the tree.
func shippedRolesPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/authz/baseline_test.go -> repo root
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "configs", "rbac", "roles.yaml")
}
