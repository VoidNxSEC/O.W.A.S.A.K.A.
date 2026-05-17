package authz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
)

// --- Load / validation ------------------------------------------------------

func TestLoadBytes_BaselinePolicy(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  viewer:
    description: "Read-only operational access"
    permissions:
      - { resource: events,   action: read }
      - { resource: assets,   action: read }
      - { resource: rules,    action: read }
      - { resource: topology, action: read }
      - { resource: ml,       action: read }
  auditor:
    description: "Compliance review"
    permissions:
      - { resource: audit,      action: read, conditions: { subject: not-self } }
      - { resource: principals, action: read }
      - { resource: tokens,     action: read }
  admin:
    description: "Owner"
    permissions:
      - { resource: '*', action: admin }
  service:
    description: "Ecosystem peer"
    permissions:
      - { resource: events, action: write, conditions: { cn: spectre } }
      - { resource: events, action: read,  conditions: { cn: cerebro } }
`)
	p, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if p.Version != 1 {
		t.Fatalf("version: %d", p.Version)
	}
	if len(p.Roles) != 4 {
		t.Fatalf("roles count: %d", len(p.Roles))
	}
	if _, ok := p.Roles["admin"]; !ok {
		t.Fatal("admin role missing")
	}
}

func TestLoad_FromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.yaml")
	body := `
version: 1
roles:
  admin:
    description: "owner"
    permissions:
      - { resource: '*', action: admin }
`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestLoadBytes_RejectsMissingAdmin(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  viewer:
    description: "x"
    permissions:
      - { resource: events, action: read }
`)
	_, err := LoadBytes(yaml)
	if !errors.Is(err, ErrPolicyNoAdmin) {
		t.Fatalf("expected ErrPolicyNoAdmin, got %v", err)
	}
}

func TestLoadBytes_RejectsMalformedYAML(t *testing.T) {
	_, err := LoadBytes([]byte("not: [valid"))
	if !errors.Is(err, ErrPolicyMalformed) {
		t.Fatalf("expected ErrPolicyMalformed, got %v", err)
	}
}

func TestLoadBytes_RejectsEmptyPermission(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  broken:
    permissions:
      - { resource: events, action: '' }
`)
	if _, err := LoadBytes(yaml); !errors.Is(err, ErrPolicyEmptyPermission) {
		t.Fatalf("expected ErrPolicyEmptyPermission, got %v", err)
	}
}

func TestLoadBytes_RejectsWildcardOnNonAdmin(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  sneaky:
    permissions:
      - { resource: '*', action: read }
`)
	if _, err := LoadBytes(yaml); !errors.Is(err, ErrPolicyWildcardOnNonAdmin) {
		t.Fatalf("expected ErrPolicyWildcardOnNonAdmin, got %v", err)
	}
}

func TestLoadBytes_InheritsExpansion(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  viewer:
    permissions:
      - { resource: events, action: read }
  analyst:
    inherits: [viewer]
    permissions:
      - { resource: events, action: acknowledge }
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	p, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	analyst := p.Roles["analyst"]
	if len(analyst.Permissions) != 2 {
		t.Fatalf("expected analyst to have 2 perms after expansion, got %d", len(analyst.Permissions))
	}
}

func TestLoadBytes_InheritsCycleRejected(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  a:
    inherits: [b]
    permissions:
      - { resource: events, action: read }
  b:
    inherits: [a]
    permissions:
      - { resource: events, action: write }
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	if _, err := LoadBytes(yaml); !errors.Is(err, ErrPolicyInheritsCycle) {
		t.Fatalf("expected ErrPolicyInheritsCycle, got %v", err)
	}
}

func TestLoadBytes_InheritsUnknownRejected(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  weird:
    inherits: [ghost]
    permissions:
      - { resource: events, action: read }
`)
	if _, err := LoadBytes(yaml); !errors.Is(err, ErrPolicyInheritsUnknown) {
		t.Fatalf("expected ErrPolicyInheritsUnknown, got %v", err)
	}
}

func TestLoadBytes_DedupesOverlappingInherits(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  base:
    permissions:
      - { resource: events, action: read }
  branch_a:
    inherits: [base]
    permissions: []
  branch_b:
    inherits: [base]
    permissions: []
  combined:
    inherits: [branch_a, branch_b]
    permissions: []
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	p, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	combined := p.Roles["combined"]
	if len(combined.Permissions) != 1 {
		t.Fatalf("expected dedup to leave 1 permission, got %d: %+v", len(combined.Permissions), combined.Permissions)
	}
}

// --- Engine -----------------------------------------------------------------

func baselineEngine(t *testing.T) *Engine {
	t.Helper()
	yaml := []byte(`
version: 1
roles:
  viewer:
    permissions:
      - { resource: events, action: read }
      - { resource: assets, action: read }
  auditor:
    permissions:
      - { resource: audit,      action: read, conditions: { subject: not-self } }
      - { resource: principals, action: read }
  admin:
    permissions:
      - { resource: '*', action: admin }
  service:
    permissions:
      - { resource: events, action: write, conditions: { cn: spectre } }
      - { resource: events, action: read,  conditions: { cn: cerebro } }
`)
	policy, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	return NewEngine(policy)
}

func principal(id string, roles ...string) *identity.Principal {
	return &identity.Principal{
		ID:     id,
		Type:   identity.PrincipalHuman,
		Status: identity.StatusActive,
		Claims: map[string]any{"roles": roles},
	}
}

func TestEngine_UninitializedFailsClosed(t *testing.T) {
	e := NewEngine(nil)
	if _, err := e.Allowed(context.Background(), principal("p", "admin"), "events", "read", nil); !errors.Is(err, ErrEngineNotInitialized) {
		t.Fatalf("expected ErrEngineNotInitialized, got %v", err)
	}
}

func TestEngine_NilPrincipalDenied(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), nil, "events", "read", nil)
	if d.Allowed {
		t.Fatal("nil principal must not be allowed")
	}
}

func TestEngine_NoRolesDenied(t *testing.T) {
	e := baselineEngine(t)
	p := &identity.Principal{ID: "x", Status: identity.StatusActive}
	d, _ := e.Allowed(context.Background(), p, "events", "read", nil)
	if d.Allowed {
		t.Fatal("principal with no roles must be denied")
	}
}

func TestEngine_ViewerCanRead(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), principal("p", "viewer"), "events", "read", nil)
	if !d.Allowed {
		t.Fatalf("viewer:events:read should be allowed, reason=%s", d.Reason)
	}
}

func TestEngine_ViewerCannotWrite(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), principal("p", "viewer"), "events", "write", nil)
	if d.Allowed {
		t.Fatal("viewer:events:write must be denied")
	}
	if !strings.HasPrefix(d.Reason, "denied:") {
		t.Fatalf("reason should explain denial: %q", d.Reason)
	}
}

func TestEngine_AdminWildcardImpliesEverything(t *testing.T) {
	e := baselineEngine(t)
	for _, action := range []Action{"read", "write", "delete", "override", "admin"} {
		d, _ := e.Allowed(context.Background(), principal("p", "admin"), "anything", action, nil)
		if !d.Allowed {
			t.Fatalf("admin should allow %s, got %s", action, d.Reason)
		}
	}
}

func TestEngine_ConditionMatch(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), principal("svc", "service"), "events", "write", map[string]any{"cn": "spectre"})
	if !d.Allowed {
		t.Fatalf("service+cn=spectre should write events, got %s", d.Reason)
	}
}

func TestEngine_ConditionMismatch(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), principal("svc", "service"), "events", "write", map[string]any{"cn": "intruder"})
	if d.Allowed {
		t.Fatal("service+cn=intruder must not write events")
	}
}

func TestEngine_ConditionMissingFailsClosed(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Allowed(context.Background(), principal("svc", "service"), "events", "write", nil)
	if d.Allowed {
		t.Fatal("missing cn attribute should deny service write")
	}
}

func TestEngine_NotSelfBlocksSelfAuditRead(t *testing.T) {
	e := baselineEngine(t)
	// auditor reading audit log for someone else: allowed
	d, _ := e.Allowed(context.Background(), principal("a", "auditor"), "audit", "read", map[string]any{"subject": "other-principal"})
	if !d.Allowed {
		t.Fatalf("auditor reading other's audit should be allowed, got %s", d.Reason)
	}
	// auditor reading their OWN audit: denied
	d, _ = e.Allowed(context.Background(), principal("a", "auditor"), "audit", "read", map[string]any{"subject": "a"})
	if d.Allowed {
		t.Fatal("auditor must not read self audit (not-self condition)")
	}
}

func TestEngine_MultipleRolesUnion(t *testing.T) {
	e := baselineEngine(t)
	p := principal("p", "viewer", "auditor")
	// viewer permission
	d, _ := e.Allowed(context.Background(), p, "events", "read", nil)
	if !d.Allowed {
		t.Fatalf("viewer half: %s", d.Reason)
	}
	// auditor permission
	d, _ = e.Allowed(context.Background(), p, "principals", "read", nil)
	if !d.Allowed {
		t.Fatalf("auditor half: %s", d.Reason)
	}
}

func TestEngine_UnknownRoleOnPrincipalSkipped(t *testing.T) {
	e := baselineEngine(t)
	// principal lists a role that's not in policy; engine skips it and
	// proceeds. Combined with no other roles, decision is denied.
	d, _ := e.Allowed(context.Background(), principal("p", "ghost"), "events", "read", nil)
	if d.Allowed {
		t.Fatal("unknown role must not grant access")
	}
}

func TestEngine_PrincipalRolesAcceptsScalarAndAny(t *testing.T) {
	e := baselineEngine(t)
	// scalar string
	p1 := &identity.Principal{ID: "p1", Status: identity.StatusActive, Claims: map[string]any{"roles": "admin"}}
	d, _ := e.Allowed(context.Background(), p1, "anything", "read", nil)
	if !d.Allowed {
		t.Fatal("string role should work")
	}
	// []any from JSON/YAML decoder
	p2 := &identity.Principal{ID: "p2", Status: identity.StatusActive, Claims: map[string]any{"roles": []any{"admin", "service"}}}
	d, _ = e.Allowed(context.Background(), p2, "anything", "read", nil)
	if !d.Allowed {
		t.Fatal("[]any roles should work")
	}
}

func TestEngine_ExplainDelegatesToAllowed(t *testing.T) {
	e := baselineEngine(t)
	d, _ := e.Explain(context.Background(), principal("p", "viewer"), "events", "read", nil)
	if !d.Allowed {
		t.Fatal("Explain should mirror Allowed")
	}
}

func TestEngine_PolicyAccessor(t *testing.T) {
	e := baselineEngine(t)
	if e.Policy() == nil {
		t.Fatal("Policy() returned nil after init")
	}
	if e.Policy().Version != 1 {
		t.Fatalf("policy version: %d", e.Policy().Version)
	}
}

func TestEngine_Replace(t *testing.T) {
	e := baselineEngine(t)
	original := e.Policy()
	yaml := []byte(`
version: 2
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	updated, _ := LoadBytes(yaml)
	e.Replace(updated)
	if e.Policy().Version != 2 {
		t.Fatalf("expected version 2 after replace, got %d", e.Policy().Version)
	}
	// Replace(nil) is ignored — keeps existing.
	e.Replace(nil)
	if e.Policy().Version != 2 {
		t.Fatal("nil replace must be ignored")
	}
	_ = original
}

func TestPermissionKey_Stable(t *testing.T) {
	a := Permission{Resource: "events", Action: "read", Conditions: []Condition{{Key: "cn", Value: "spectre"}}}
	b := Permission{Resource: "events", Action: "read", Conditions: []Condition{{Key: "cn", Value: "spectre"}}}
	if permissionKey(a) != permissionKey(b) {
		t.Fatal("permissionKey not stable for equal permissions")
	}
}
