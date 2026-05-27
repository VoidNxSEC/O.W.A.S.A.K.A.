//go:build demo

// Package demo exercises the OWASAKA Sprint 2 RBAC stack end-to-end as
// a runnable narrative. Build-tagged "demo" so it stays out of CI; run
// explicitly with:
//
//	make demo-sprint2
//	# or
//	go test -tags=demo -v ./internal/authz/demo/...
//
// The transcript mirrors the Sprint 1 demo style. See ADR-0061
// §"Acceptance" for the success criteria checked at the end.
package demo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/authz"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

func banner(t *testing.T, n int, title string) {
	t.Helper()
	bar := strings.Repeat("─", 60)
	t.Logf("\n%s\n  STEP %d — %s\n%s", bar, n, title, bar)
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func TestSprint2Demo(t *testing.T) {
	ctx := context.Background()
	t.Logf("\n╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║   OWASAKA SIEM — Sprint 2 acceptance demo                    ║")
	t.Logf("║   Scenario: 4 baseline roles + hot-reload + analyst recipe   ║")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")

	// ── STEP 1: bootstrap PKI + JWT (reuse Sprint 1 wiring) ───────
	banner(t, 1, "Bootstrap auth stack (PKI + JWT issuer/verifier)")
	authority := pki.NewAuthority(pki.NewMemoryKeyStore())
	_, err := authority.GenerateKeyPair(ctx, pki.PurposeJWTSigning, 24*time.Hour)
	must(t, err, "GenerateKeyPair")
	issuer := owjwt.NewIssuer(authority)
	verifier := owjwt.NewVerifier(authority)
	principals := identity.NewMemoryPrincipalStore()
	authMW := middleware.New(verifier, principals, nil)
	t.Logf("  Signing key + Issuer + Verifier wired")

	// ── STEP 2: load baseline RBAC policy ─────────────────────────
	banner(t, 2, "Load baseline RBAC policy from configs/rbac/roles.yaml")
	policy, err := authz.Load(shippedRolesPath(t))
	must(t, err, "authz.Load baseline")
	engine := authz.NewEngine(policy)
	t.Logf("  Loaded version=%d", engine.Policy().Version)
	for name, role := range engine.Policy().Roles {
		t.Logf("    role %-12s (%d permission entries)", name, len(role.Permissions))
		_ = role
	}

	sink := &recordingSink{}

	// ── STEP 3: provision 4 principals, one per baseline role ─────
	banner(t, 3, "Provision Alice (admin), Bob (viewer), Carol (auditor), Spectre (service)")
	alice := provision(t, principals, "p-alice", "alice", "admin")
	bob := provision(t, principals, "p-bob", "bob", "viewer")
	carol := provision(t, principals, "p-carol", "carol", "auditor")
	spectre := provision(t, principals, "p-spectre", "spectre", "service")
	for _, p := range []*identity.Principal{alice, bob, carol, spectre} {
		t.Logf("  %-8s id=%s roles=%v", p.Subject, p.ID, p.Claims["roles"])
	}

	// ── STEP 4: build the protected API ───────────────────────────
	banner(t, 4, "Stand up protected API (each endpoint gated by a permission)")
	mux := http.NewServeMux()
	mux.Handle("/api/events",
		authMW.RequireAuth(authz.RequirePermission(engine, "events", "read", sink)(
			respond(http.StatusOK, "events"))))
	mux.Handle("/api/events/write",
		authMW.RequireAuth(authz.RequirePermission(engine, "events", "write", sink)(
			respond(http.StatusOK, "events written"))))
	mux.Handle("/api/audit",
		authMW.RequireAuth(authz.RequirePermission(engine, "audit", "read", sink)(
			respond(http.StatusOK, "audit"))))
	mux.Handle("/api/rules",
		authMW.RequireAuth(authz.RequirePermission(engine, "rules", "write", sink)(
			respond(http.StatusOK, "rules written"))))

	server := httptest.NewServer(mux)
	defer server.Close()
	t.Logf("  Listening at %s", server.URL)
	t.Logf("  GET  /api/events           (events:read)")
	t.Logf("  POST /api/events/write     (events:write)")
	t.Logf("  GET  /api/audit?subject=…  (audit:read with not-self)")
	t.Logf("  POST /api/rules            (rules:write)")

	// ── STEP 5: exercise the matrix ───────────────────────────────
	banner(t, 5, "Exercise the role/endpoint matrix")
	type call struct {
		who      *identity.Principal
		method   string
		path     string
		wantCode int
		note     string
	}

	cases := []call{
		// Bob (viewer)
		{bob, "GET", "/api/events", 200, "viewer reads events ✓"},
		{bob, "POST", "/api/events/write", 403, "viewer cannot write events ✗"},
		{bob, "GET", "/api/audit?subject=other", 403, "viewer cannot read audit ✗"},

		// Carol (auditor)
		{carol, "GET", "/api/audit?subject=p-other", 200, "auditor reads other's audit ✓"},
		{carol, "GET", "/api/audit?subject=" + carol.ID, 403, "auditor blocked on self-audit ✗"},
		{carol, "GET", "/api/events", 403, "auditor cannot read operational data ✗"},

		// Alice (admin)
		{alice, "POST", "/api/rules", 200, "admin writes rules ✓"},
		{alice, "POST", "/api/events/write", 200, "admin writes events ✓"},
		{alice, "GET", "/api/audit?subject=anyone", 200, "admin reads audit ✓"},

		// Spectre (service) — no cn attr in HTTP path so writes are denied
		// at the middleware layer; this is by design (HTTPS without mTLS
		// has no CN to compare). The in-process path with cn populated
		// works — exercised below.
		{spectre, "POST", "/api/events/write", 403, "service via plain HTTP has no cn ✗"},
	}

	for _, c := range cases {
		issuePair, err := issuer.Issue(ctx, c.who)
		must(t, err, "issue token")
		req, _ := http.NewRequest(c.method, server.URL+c.path, nil)
		req.Header.Set("Authorization", "Bearer "+issuePair.AccessToken)
		resp, err := http.DefaultClient.Do(req)
		must(t, err, c.method+" "+c.path)
		resp.Body.Close()
		mark := "✓"
		if resp.StatusCode != c.wantCode {
			mark = "✗ (got " + http.StatusText(resp.StatusCode) + ")"
		}
		t.Logf("  %-9s %-6s %-30s → %d  %s — %s",
			c.who.Subject, c.method, c.path, resp.StatusCode, mark, c.note)
		if resp.StatusCode != c.wantCode {
			t.Fatalf("matrix regression: %s %s for %s expected %d got %d",
				c.method, c.path, c.who.Subject, c.wantCode, resp.StatusCode)
		}
	}

	// ── STEP 6: in-process service-with-cn check ─────────────────
	banner(t, 6, "In-process service decision with cn=spectre (mTLS attribute)")
	allowed, err := authz.PrincipalAllowed(ctx, engine, spectre, "events", "write",
		map[string]any{"cn": "spectre"}, sink)
	must(t, err, "PrincipalAllowed")
	if !allowed {
		t.Fatal("spectre with cn=spectre must be allowed to write events")
	}
	t.Logf("  Spectre + cn=spectre → events:write ✓")
	allowed, _ = authz.PrincipalAllowed(ctx, engine, spectre, "events", "write",
		map[string]any{"cn": "intruder"}, sink)
	if allowed {
		t.Fatal("spectre with cn=intruder must be denied")
	}
	t.Logf("  Spectre + cn=intruder → denied ✓")

	// ── STEP 7: extend policy via 'analyst' recipe + hot-reload ──
	banner(t, 7, "Append the 'analyst' recipe and hot-reload via SIGHUP")
	policyPath := writeTempPolicy(t, baselinePlusAnalyst())
	// Point the engine at the new file: we use ReloadFrom directly so
	// the demo doesn't require the SIGHUP timing window.
	diff, err := engine.ReloadFrom(policyPath)
	must(t, err, "ReloadFrom analyst")
	t.Logf("  Reload diff: %s", diff)
	// And demonstrate the SIGHUP wiring too, so the transcript covers
	// both code paths.
	doneCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	gotSig := make(chan struct{}, 1)
	stop := authz.ReloadWatcher(doneCtx, engine, policyPath, func(_ authz.Diff, _ error) {
		select {
		case gotSig <- struct{}{}:
		default:
		}
	})
	defer stop()
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	select {
	case <-gotSig:
		t.Logf("  SIGHUP handled; reload watcher fired ✓")
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not fire on SIGHUP")
	}

	// ── STEP 8: re-provision Dan as analyst, exercise new role ───
	banner(t, 8, "Provision Dan (analyst) and verify the new permissions")
	dan := provision(t, principals, "p-dan", "dan", "analyst")
	t.Logf("  %-8s id=%s roles=%v", dan.Subject, dan.ID, dan.Claims["roles"])

	mux.Handle("/api/events/ack",
		authMW.RequireAuth(authz.RequirePermission(engine, "events", "acknowledge", sink)(
			respond(http.StatusOK, "acknowledged"))))

	analystCases := []call{
		{dan, "GET", "/api/events", 200, "analyst reads events (inherits viewer) ✓"},
		{dan, "POST", "/api/events/ack", 200, "analyst acknowledges events ✓"},
		{dan, "POST", "/api/rules", 403, "analyst cannot write rules ✗"},
	}
	for _, c := range analystCases {
		pair, _ := issuer.Issue(ctx, c.who)
		req, _ := http.NewRequest(c.method, server.URL+c.path, nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()
		mark := "✓"
		if resp.StatusCode != c.wantCode {
			mark = "✗ (got " + http.StatusText(resp.StatusCode) + ")"
		}
		t.Logf("  %-9s %-6s %-30s → %d  %s — %s",
			c.who.Subject, c.method, c.path, resp.StatusCode, mark, c.note)
		if resp.StatusCode != c.wantCode {
			t.Fatalf("analyst regression: expected %d got %d", c.wantCode, resp.StatusCode)
		}
	}

	// ── STEP 9: malformed reload preserves prior policy ──────────
	banner(t, 9, "Malformed policy reload is rejected; engine keeps known-good state")
	_, err = engine.ReloadBytes([]byte("not: [valid yaml"))
	if err == nil {
		t.Fatal("expected error on malformed reload")
	}
	t.Logf("  Reload error (expected): %s", truncate(err.Error(), 80))
	if engine.Policy().Roles["analyst"] == nil {
		t.Fatal("engine lost the analyst role on failed reload")
	}
	t.Logf("  Engine still serves analyst role from prior valid policy ✓")

	// ── STEP 10: audit sink summary ──────────────────────────────
	banner(t, 10, "Audit sink summary — every authz decision was recorded")
	allows, denies := 0, 0
	for _, ev := range sink.events {
		if ev.Decision == "allow" {
			allows++
		} else {
			denies++
		}
	}
	t.Logf("  Total decisions recorded: %d (allow=%d, deny=%d)",
		len(sink.events), allows, denies)
	t.Logf("  First 5 reasons:")
	for i, ev := range sink.events {
		if i >= 5 {
			break
		}
		t.Logf("    [%s] %s:%s — %s", ev.Decision, ev.Resource, ev.Action, ev.Reason)
	}

	// ── DONE ─────────────────────────────────────────────────────
	t.Logf("\n╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║   ✓ Sprint 2 demo complete — every step passed                ║")
	t.Logf("║                                                              ║")
	t.Logf("║   Acceptance per ADR-0061:                                   ║")
	t.Logf("║     • viewer reads, cannot write                   ✓         ║")
	t.Logf("║     • auditor reads audit, blocked on self          ✓         ║")
	t.Logf("║     • auditor cannot see operational data           ✓         ║")
	t.Logf("║     • admin can do everything                       ✓         ║")
	t.Logf("║     • service scoped by mTLS cn condition           ✓         ║")
	t.Logf("║     • hot-reload via ReloadFrom + SIGHUP            ✓         ║")
	t.Logf("║     • recipe-added analyst works without rebuild    ✓         ║")
	t.Logf("║     • malformed policy preserves prior known-good   ✓         ║")
	t.Logf("║     • every decision audit-logged                   ✓         ║")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")
}

// --- helpers ---------------------------------------------------------------

type recordingSink struct {
	events []authz.AuditEvent
}

func (r *recordingSink) Record(_ context.Context, ev authz.AuditEvent) {
	r.events = append(r.events, ev)
}

func provision(t *testing.T, store *identity.MemoryPrincipalStore, id, subject string, roles ...string) *identity.Principal {
	t.Helper()
	p := &identity.Principal{
		ID:      id,
		Type:    identity.PrincipalHuman,
		Subject: subject,
		Status:  identity.StatusActive,
		Claims:  map[string]any{"roles": roles},
	}
	must(t, store.Save(context.Background(), p), "store.Save "+subject)
	return p
}

func respond(code int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	})
}

func shippedRolesPath(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	// internal/authz/demo -> repo root
	return filepath.Clean(filepath.Join(wd, "..", "..", "..", "configs", "rbac", "roles.yaml"))
}

func writeTempPolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.yaml")
	must(t, os.WriteFile(path, []byte(body), 0o600), "write temp policy")
	return path
}

func baselinePlusAnalyst() string {
	// Replicates configs/rbac/roles.yaml + the analyst recipe from
	// ../owasaka-docs/docs/auth/ROLE_RECIPES.md. Inline here so the demo is self-
	// contained and can run from an empty FS.
	return `
version: 2
roles:
  viewer:
    permissions:
      - { resource: events,   action: read }
      - { resource: assets,   action: read }
      - { resource: rules,    action: read }
      - { resource: topology, action: read }
      - { resource: ml,       action: read }
  analyst:
    inherits: [viewer]
    permissions:
      - { resource: events, action: acknowledge }
      - { resource: events, action: annotate }
  auditor:
    permissions:
      - { resource: audit,      action: read, conditions: { subject: not-self } }
      - { resource: principals, action: read }
      - { resource: tokens,     action: read }
  admin:
    permissions:
      - { resource: '*', action: admin }
  service:
    permissions:
      - { resource: events, action: write, conditions: { cn: spectre } }
      - { resource: events, action: read,  conditions: { cn: cerebro } }
`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ = fmt.Sprintf
