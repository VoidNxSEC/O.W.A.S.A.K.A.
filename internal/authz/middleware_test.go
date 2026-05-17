package authz

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
)

// --- Diff / Reload ----------------------------------------------------------

func TestDiff_String(t *testing.T) {
	if (Diff{}).String() != "no changes" {
		t.Fatal("empty diff should stringify to 'no changes'")
	}
	d := Diff{Added: []string{"x"}, Removed: []string{"y"}, Modified: []string{"z"}}
	got := d.String()
	for _, expect := range []string{"added=[x]", "removed=[y]", "modified=[z]"} {
		if !strings.Contains(got, expect) {
			t.Fatalf("diff string missing %q: %s", expect, got)
		}
	}
}

func TestReloadBytes_HappyPath(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	policy, _ := LoadBytes(yaml)
	e := NewEngine(policy)

	updated := []byte(`
version: 2
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  viewer:
    permissions:
      - { resource: events, action: read }
`)
	diff, err := e.ReloadBytes(updated)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if diff.IsEmpty() {
		t.Fatal("expected diff to report viewer added")
	}
	if len(diff.Added) != 1 || diff.Added[0] != "viewer" {
		t.Fatalf("expected added=[viewer], got %+v", diff)
	}
	if e.Policy().Version != 2 {
		t.Fatalf("engine should now hold version 2, got %d", e.Policy().Version)
	}
}

func TestReloadBytes_KeepsOldOnFailure(t *testing.T) {
	yaml := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	policy, _ := LoadBytes(yaml)
	e := NewEngine(policy)

	// Malformed payload — must NOT swap.
	_, err := e.ReloadBytes([]byte("not: [valid"))
	if err == nil {
		t.Fatal("expected error on malformed reload")
	}
	if e.Policy().Version != 1 {
		t.Fatal("engine should retain previous policy when reload fails")
	}
}

func TestReloadBytes_RemovedAndModified(t *testing.T) {
	v1 := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  goer:
    permissions:
      - { resource: events, action: read }
  changer:
    permissions:
      - { resource: events, action: read }
`)
	p1, _ := LoadBytes(v1)
	e := NewEngine(p1)

	v2 := []byte(`
version: 2
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  changer:
    permissions:
      - { resource: events, action: write }
`)
	diff, err := e.ReloadBytes(v2)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !contains(diff.Removed, "goer") {
		t.Fatalf("expected goer removed, got %+v", diff)
	}
	if !contains(diff.Modified, "changer") {
		t.Fatalf("expected changer modified, got %+v", diff)
	}
}

func TestReloadFrom_FromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.yaml")
	v1 := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	if err := os.WriteFile(path, v1, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, _ := LoadBytes(v1)
	e := NewEngine(policy)

	v2 := []byte(`
version: 7
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	if err := os.WriteFile(path, v2, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReloadFrom(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if e.Policy().Version != 7 {
		t.Fatalf("version after disk reload: %d", e.Policy().Version)
	}

	// Missing file -> read error propagated.
	if _, err := e.ReloadFrom(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Fatal("expected reload error for missing file")
	}
}

func TestReloadWatcher_SIGHUPTriggersReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.yaml")
	v1 := []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	_ = os.WriteFile(path, v1, 0o600)
	policy, _ := LoadBytes(v1)
	e := NewEngine(policy)

	v2 := []byte(`
version: 42
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`)
	_ = os.WriteFile(path, v2, 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reloaded := make(chan struct{}, 1)
	stop := ReloadWatcher(ctx, e, path, func(_ Diff, err error) {
		if err == nil {
			select {
			case reloaded <- struct{}{}:
			default:
			}
		}
	})
	defer stop()

	// Send SIGHUP to ourselves; signal package routes it to the watcher.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("kill SIGHUP: %v", err)
	}
	select {
	case <-reloaded:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not reload within 2s")
	}
	if e.Policy().Version != 42 {
		t.Fatalf("watcher reload did not apply: version=%d", e.Policy().Version)
	}
}

// --- Middleware -------------------------------------------------------------

type recordingSink struct {
	events []AuditEvent
}

func (r *recordingSink) Record(_ context.Context, ev AuditEvent) {
	r.events = append(r.events, ev)
}

func mkRequestWithPrincipal(p *identity.Principal) *http.Request {
	req := httptest.NewRequest("GET", "/api/events", nil)
	return req.WithContext(middleware.WithPrincipal(req.Context(), p))
}

func TestRequirePermission_Allow(t *testing.T) {
	e := baselineEngine(t)
	sink := &recordingSink{}
	called := false
	handler := RequirePermission(e, "events", "read", sink)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, mkRequestWithPrincipal(principal("p", "viewer")))

	if !called {
		t.Fatal("handler should run on allow")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status: %d", rr.Code)
	}
	if len(sink.events) != 1 || sink.events[0].Decision != "allow" {
		t.Fatalf("audit not recorded as allow: %+v", sink.events)
	}
}

func TestRequirePermission_Deny(t *testing.T) {
	e := baselineEngine(t)
	sink := &recordingSink{}
	handler := RequirePermission(e, "events", "write", sink)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run on deny")
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, mkRequestWithPrincipal(principal("p", "viewer")))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: %d", rr.Code)
	}
	if len(sink.events) != 1 || sink.events[0].Decision != "deny" {
		t.Fatalf("audit not recorded as deny: %+v", sink.events)
	}
}

func TestRequirePermission_NoPrincipal(t *testing.T) {
	e := baselineEngine(t)
	handler := RequirePermission(e, "events", "read", nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run without principal")
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequirePermission_EngineError(t *testing.T) {
	// Engine without policy returns ErrEngineNotInitialized.
	e := NewEngine(nil)
	sink := &recordingSink{}
	handler := RequirePermission(e, "events", "read", sink)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run on engine error")
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, mkRequestWithPrincipal(principal("p", "admin")))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status: %d", rr.Code)
	}
	if len(sink.events) != 1 || !strings.Contains(sink.events[0].Reason, "engine error") {
		t.Fatalf("audit should capture engine error: %+v", sink.events)
	}
}

func TestAttrsFromRequest_SubjectQueryParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/audit?subject=other", nil)
	req = req.WithContext(middleware.WithPrincipal(req.Context(), principal("a", "auditor")))
	attrs := AttrsFromRequest(req)
	if attrs["subject"] != "other" {
		t.Fatalf("subject attr: %v", attrs["subject"])
	}
	if attrs["principal_id"] != "a" {
		t.Fatalf("principal_id attr: %v", attrs["principal_id"])
	}
}

func TestPrincipalAllowed_RecordsAudit(t *testing.T) {
	e := baselineEngine(t)
	sink := &recordingSink{}
	allowed, err := PrincipalAllowed(context.Background(), e, principal("p", "admin"), "anything", "read", nil, sink)
	if err != nil || !allowed {
		t.Fatalf("admin should be allowed: %v %v", allowed, err)
	}
	if len(sink.events) != 1 || sink.events[0].Decision != "allow" {
		t.Fatalf("audit: %+v", sink.events)
	}
}

func TestPrincipalAllowed_EngineErrorPropagates(t *testing.T) {
	e := NewEngine(nil)
	sink := &recordingSink{}
	allowed, err := PrincipalAllowed(context.Background(), e, principal("p", "admin"), "anything", "read", nil, sink)
	if !errors.Is(err, ErrEngineNotInitialized) {
		t.Fatalf("expected ErrEngineNotInitialized, got %v", err)
	}
	if allowed {
		t.Fatal("must not allow on engine error")
	}
	if len(sink.events) != 1 || !strings.Contains(sink.events[0].Reason, "engine error") {
		t.Fatalf("audit should note engine error: %+v", sink.events)
	}
}

func TestLogAuditSink_NilLoggerSafe(t *testing.T) {
	(LogAuditSink{}).Record(context.Background(), AuditEvent{})
	// Just exercising the nil-safe path.
}

// contains tests util.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// Unused import guard.
var _ = bytes.NewReader
