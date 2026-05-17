package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReloadHandler_RejectsGET(t *testing.T) {
	e := baselineEngine(t)
	h := ReloadHandler(e, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestReloadHandler_ReloadFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.yaml")
	_ = os.WriteFile(path, []byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`), 0o600)
	policy, _ := Load(path)
	e := NewEngine(policy)

	// Update file on disk to bump version.
	_ = os.WriteFile(path, []byte(`
version: 99
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  viewer:
    permissions:
      - { resource: events, action: read }
`), 0o600)

	sink := &recordingSink{}
	h := ReloadHandler(e, path, sink)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/api/admin/authz/reload", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if int(body["version"].(float64)) != 99 {
		t.Fatalf("expected version 99, got %v", body["version"])
	}
	if sink.events[0].Decision != "allow" {
		t.Fatalf("audit decision: %+v", sink.events)
	}
	if !strings.Contains(sink.events[0].Reason, "viewer") {
		t.Fatalf("audit reason should mention added role: %s", sink.events[0].Reason)
	}
}

func TestReloadHandler_ReloadFromBody(t *testing.T) {
	policy, _ := LoadBytes([]byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`))
	e := NewEngine(policy)

	body := []byte(`
version: 5
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
  ops:
    permissions:
      - { resource: events, action: read }
`)
	sink := &recordingSink{}
	h := ReloadHandler(e, "", sink)
	req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-yaml")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if e.Policy().Version != 5 {
		t.Fatalf("engine should be at version 5, got %d", e.Policy().Version)
	}
}

func TestReloadHandler_MalformedBodyKeepsPolicy(t *testing.T) {
	policy, _ := LoadBytes([]byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`))
	e := NewEngine(policy)
	h := ReloadHandler(e, "", &recordingSink{})

	req := httptest.NewRequest("POST", "/", strings.NewReader("not: [valid"))
	req.Header.Set("Content-Type", "application/x-yaml")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if e.Policy().Version != 1 {
		t.Fatal("engine must keep prior policy on bad body")
	}
}

func TestReloadHandler_NoPathNoBody_500(t *testing.T) {
	policy, _ := LoadBytes([]byte(`
version: 1
roles:
  admin:
    permissions:
      - { resource: '*', action: admin }
`))
	e := NewEngine(policy)
	h := ReloadHandler(e, "", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}
