package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubProbe is a hand-rolled Probe for tests where we want to flip
// state on demand without going through StaticProbe's closure.
type stubProbe struct {
	name     string
	required bool
	result   Result
	calls    int
}

func (s *stubProbe) Name() string   { return s.name }
func (s *stubProbe) Required() bool { return s.required }
func (s *stubProbe) Check() Result {
	s.calls++
	return s.result
}

func TestRegistry_RegisterDeregister(t *testing.T) {
	r := NewRegistry()
	p := &stubProbe{name: "x", required: true, result: Result{Status: StatusHealthy}}

	r.Register(p)
	snap := r.snapshot()
	if len(snap.Subsystems) != 1 || snap.Subsystems[0].Name != "x" {
		t.Fatalf("expected probe registered, got %+v", snap)
	}

	// Re-register replaces by name (no duplicate).
	r.Register(&stubProbe{name: "x", required: false, result: Result{Status: StatusDegraded}})
	snap = r.snapshot()
	if len(snap.Subsystems) != 1 {
		t.Fatalf("re-register should replace, not append; got %d entries", len(snap.Subsystems))
	}
	if snap.Subsystems[0].Required {
		t.Fatalf("replaced probe should carry the new Required=false")
	}

	r.Deregister("x")
	if got := len(r.snapshot().Subsystems); got != 0 {
		t.Fatalf("deregister failed: %d entries remain", got)
	}
}

func TestRegistry_NilOrEmptyProbeIgnored(t *testing.T) {
	r := NewRegistry()
	r.Register(nil)
	r.Register(&stubProbe{name: "", required: true})
	if got := len(r.snapshot().Subsystems); got != 0 {
		t.Fatalf("nil/empty probe must be ignored; got %d entries", got)
	}
}

func TestSnapshot_DeterministicOrdering(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubProbe{name: "zeta", required: true, result: Result{Status: StatusHealthy}})
	r.Register(&stubProbe{name: "alpha", required: true, result: Result{Status: StatusHealthy}})
	r.Register(&stubProbe{name: "mike", required: false, result: Result{Status: StatusHealthy}})

	snap := r.snapshot()
	if len(snap.Subsystems) != 3 {
		t.Fatalf("expected 3 subsystems")
	}
	want := []string{"alpha", "mike", "zeta"}
	for i, n := range want {
		if snap.Subsystems[i].Name != n {
			t.Errorf("order[%d] = %q, want %q", i, snap.Subsystems[i].Name, n)
		}
	}
}

func TestSnapshot_AggregateWorstStatus(t *testing.T) {
	cases := []struct {
		name           string
		probes         []*stubProbe
		wantRequired   Status
		wantOverall    Status
	}{
		{
			name: "all healthy",
			probes: []*stubProbe{
				{name: "a", required: true, result: Result{Status: StatusHealthy}},
				{name: "b", required: false, result: Result{Status: StatusHealthy}},
			},
			wantRequired: StatusHealthy,
			wantOverall:  StatusHealthy,
		},
		{
			name: "optional degraded keeps required green",
			probes: []*stubProbe{
				{name: "a", required: true, result: Result{Status: StatusHealthy}},
				{name: "b", required: false, result: Result{Status: StatusDegraded}},
			},
			wantRequired: StatusHealthy,
			wantOverall:  StatusDegraded,
		},
		{
			name: "required unhealthy dominates",
			probes: []*stubProbe{
				{name: "a", required: true, result: Result{Status: StatusUnhealthy}},
				{name: "b", required: false, result: Result{Status: StatusHealthy}},
			},
			wantRequired: StatusUnhealthy,
			wantOverall:  StatusUnhealthy,
		},
		{
			name: "required degraded but optional unhealthy",
			probes: []*stubProbe{
				{name: "a", required: true, result: Result{Status: StatusDegraded}},
				{name: "b", required: false, result: Result{Status: StatusUnhealthy}},
			},
			wantRequired: StatusDegraded,
			wantOverall:  StatusUnhealthy,
		},
		{
			name: "starting beats healthy but not degraded",
			probes: []*stubProbe{
				{name: "a", required: true, result: Result{Status: StatusStarting}},
				{name: "b", required: true, result: Result{Status: StatusDegraded}},
			},
			wantRequired: StatusDegraded,
			wantOverall:  StatusDegraded,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			for _, p := range tc.probes {
				r.Register(p)
			}
			snap := r.snapshot()
			if snap.RequiredStatus != tc.wantRequired {
				t.Errorf("required = %q, want %q", snap.RequiredStatus, tc.wantRequired)
			}
			if snap.OverallStatus != tc.wantOverall {
				t.Errorf("overall = %q, want %q", snap.OverallStatus, tc.wantOverall)
			}
		})
	}
}

func TestLivenessHandler_AlwaysOK(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubProbe{name: "down", required: true, result: Result{Status: StatusUnhealthy}})

	w := httptest.NewRecorder()
	LivenessHandler(r).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("liveness must return 200 even with unhealthy required probes; got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestReadinessHandler_503OnRequiredFailure(t *testing.T) {
	cases := []struct {
		name       string
		required   Status
		wantStatus int
	}{
		{"healthy → 200", StatusHealthy, http.StatusOK},
		{"starting → 200 (handled by /startupz)", StatusStarting, http.StatusOK},
		{"degraded required → 503", StatusDegraded, http.StatusServiceUnavailable},
		{"unhealthy required → 503", StatusUnhealthy, http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			r.Register(&stubProbe{name: "x", required: true, result: Result{Status: tc.required}})

			w := httptest.NewRecorder()
			ReadinessHandler(r).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", w.Code, tc.wantStatus, w.Body.String())
			}

			var got Snapshot
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("response body not valid JSON: %v", err)
			}
			if got.RequiredStatus != tc.required {
				t.Errorf("body.required_status = %q, want %q", got.RequiredStatus, tc.required)
			}
		})
	}
}

func TestReadinessHandler_OptionalDegradedStaysGreen(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubProbe{name: "core", required: true, result: Result{Status: StatusHealthy}})
	r.Register(&stubProbe{name: "nas", required: false, result: Result{Status: StatusDegraded, Message: "NAS unreachable"}})

	w := httptest.NewRecorder()
	ReadinessHandler(r).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("optional degraded must NOT flip readiness; got %d (body=%s)", w.Code, w.Body.String())
	}

	var got Snapshot
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.OverallStatus != StatusDegraded {
		t.Errorf("overall should reflect degraded optional; got %q", got.OverallStatus)
	}
}

func TestStartupHandler(t *testing.T) {
	r := NewRegistry()

	// Before MarkStartupComplete: 503 starting.
	w := httptest.NewRecorder()
	StartupHandler(r).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/startupz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-startup must be 503; got %d", w.Code)
	}

	r.MarkStartupComplete()

	w = httptest.NewRecorder()
	StartupHandler(r).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/startupz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("post-startup must be 200; got %d", w.Code)
	}
	if !r.snapshot().StartupComplete {
		t.Error("snapshot should report startup complete")
	}
}

func TestMarkStartupComplete_Idempotent(t *testing.T) {
	r := NewRegistry()
	r.MarkStartupComplete()
	first := r.snapshot().StartupCompleteAt
	if first.IsZero() {
		t.Fatal("StartupCompleteAt should be set")
	}
	// Second call must not overwrite the timestamp.
	r.MarkStartupComplete()
	if got := r.snapshot().StartupCompleteAt; !got.Equal(first) {
		t.Errorf("StartupCompleteAt should be idempotent; first=%v second=%v", first, got)
	}
}

func TestStaticProbe(t *testing.T) {
	calls := 0
	p := NewStaticProbe("db", true, func() Result {
		calls++
		return Result{Status: StatusHealthy, Message: "ok"}
	})

	if p.Name() != "db" || !p.Required() {
		t.Errorf("StaticProbe metadata wrong: name=%q required=%v", p.Name(), p.Required())
	}
	if got := p.Check(); got.Status != StatusHealthy || got.Message != "ok" {
		t.Errorf("StaticProbe.Check = %+v, want healthy/ok", got)
	}
	if calls != 1 {
		t.Errorf("StaticProbe.Check should invoke the closure exactly once, got %d", calls)
	}

	// Nil check function defaults to healthy.
	nilP := NewStaticProbe("none", false, nil)
	if got := nilP.Check(); got.Status != StatusHealthy {
		t.Errorf("nil-check StaticProbe = %+v, want healthy", got)
	}
}

func TestSnapshot_EmptyRegistryIsHealthy(t *testing.T) {
	r := NewRegistry()
	snap := r.snapshot()
	if snap.OverallStatus != StatusHealthy || snap.RequiredStatus != StatusHealthy {
		t.Errorf("empty registry should be healthy/healthy; got overall=%q required=%q",
			snap.OverallStatus, snap.RequiredStatus)
	}
}
