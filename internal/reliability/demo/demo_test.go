//go:build demo

// Package demo exercises the OWASAKA Sprint 5 reliability stack
// end-to-end. Build-tagged "demo" so it stays out of CI; run
// explicitly:
//
//	make demo-sprint5
//
// The transcript mirrors Sprints 1-4 demo style. See ADR-0064 for
// the acceptance criteria checked at the end.
package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/health"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/reliability"
)

func banner(t *testing.T, n int, title string) {
	t.Helper()
	bar := strings.Repeat("─", 60)
	t.Logf("\n%s\n  STEP %d — %s\n%s", bar, n, title, bar)
}

func TestSprint5Demo(t *testing.T) {
	t.Logf("\n╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║   OWASAKA SIEM — Sprint 5 acceptance demo                    ║")
	t.Logf("║   Scenario: graceful degradation + breakers + health         ║")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")

	registry := health.NewRegistry()

	// ── STEP 1: register a few subsystem probes ───────────────────
	banner(t, 1, "Register required + optional probes")

	dbState := atomic.Bool{}
	dbState.Store(true)
	registry.Register(health.NewStaticProbe("boltdb", true, func() health.Result {
		if dbState.Load() {
			return health.Result{Status: health.StatusHealthy}
		}
		return health.Result{Status: health.StatusUnhealthy, Message: "simulated DB outage"}
	}))

	natsConnected := atomic.Bool{}
	natsConnected.Store(true)
	registry.Register(health.NewStaticProbe("nats", false, func() health.Result {
		if natsConnected.Load() {
			return health.Result{Status: health.StatusHealthy}
		}
		return health.Result{Status: health.StatusDegraded, Message: "nats reconnecting"}
	}))

	t.Logf("  Registered: boltdb (required), nats (optional)")

	// ── STEP 2: pre-startup probes are 503/starting ───────────────
	banner(t, 2, "Pre-startup: /startupz returns 503 starting")
	resp := hit(t, health.StartupHandler(registry), "/startupz")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("/startupz pre-ready should be 503, got %d", resp.Code)
	}
	t.Logf("  /startupz → %d (body=%s)", resp.Code, strings.TrimSpace(resp.Body.String()))

	// ── STEP 3: mark startup complete, all probes green ────────────
	banner(t, 3, "MarkStartupComplete; /readyz green")
	registry.MarkStartupComplete()
	resp = hit(t, health.ReadinessHandler(registry), "/readyz")
	if resp.Code != http.StatusOK {
		t.Fatalf("/readyz with all green should be 200, got %d", resp.Code)
	}
	t.Logf("  /readyz → %d (overall=%s)", resp.Code, decodeStatus(t, resp))

	// ── STEP 4: NATS drops; optional probe degrades but readyz stays green ─
	banner(t, 4, "Graceful degradation: NATS drops, /readyz stays 200")
	natsConnected.Store(false)
	resp = hit(t, health.ReadinessHandler(registry), "/readyz")
	if resp.Code != http.StatusOK {
		t.Fatalf("optional NATS degraded must NOT flip /readyz; got %d", resp.Code)
	}
	t.Logf("  /readyz → %d (still ready; overall=%s)", resp.Code, decodeStatus(t, resp))

	// ── STEP 5: DB drops; required probe trips /readyz to 503 ─────
	banner(t, 5, "Required failure: DB drops → /readyz 503")
	dbState.Store(false)
	resp = hit(t, health.ReadinessHandler(registry), "/readyz")
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("required DB failure should be 503, got %d", resp.Code)
	}
	t.Logf("  /readyz → %d (overall=%s)", resp.Code, decodeStatus(t, resp))

	// Recover DB for subsequent steps.
	dbState.Store(true)
	natsConnected.Store(true)

	// ── STEP 6: backoff + retry survives transient failures ────────
	banner(t, 6, "Backoff+Retry: 3 transient failures, then success")
	calls := 0
	err := reliability.Retry(
		context.Background(),
		reliability.NewBackoff(time.Microsecond, time.Millisecond),
		5,
		func(context.Context) error {
			calls++
			if calls < 4 {
				return errors.New("upstream flake")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Retry should have succeeded by call 4; got %v", err)
	}
	t.Logf("  Retry survived %d attempts, final call succeeded", calls)

	// ── STEP 7: circuit breaker trips after threshold ─────────────
	banner(t, 7, "Breaker trips after 3 consecutive failures")
	transitions := []string{}
	b := reliability.NewBreaker(reliability.BreakerConfig{
		Name:             "demo-nats-publish",
		FailureThreshold: 3,
		Timeout:          30 * time.Millisecond,
		OnStateChange: func(_, from, to string) {
			transitions = append(transitions, from+"->"+to)
		},
	})
	upstream := errors.New("nats publish refused")
	for i := 0; i < 3; i++ {
		if err := b.Execute(func() error { return upstream }); !errors.Is(err, upstream) {
			t.Fatalf("call %d should pass upstream, got %v", i, err)
		}
	}
	t.Logf("  After 3 failures: breaker state=%s, transitions=%v", b.State(), transitions)

	// ── STEP 8: fail-fast rejection while breaker open ────────────
	banner(t, 8, "Open breaker fails fast (does not invoke upstream)")
	invoked := false
	err = b.Execute(func() error {
		invoked = true
		return nil
	})
	if !errors.Is(err, reliability.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
	if invoked {
		t.Fatal("open breaker must NOT invoke upstream")
	}
	opens, rejects := b.Counters()
	t.Logf("  Fail-fast: opens=%d rejects=%d", opens, rejects)

	// ── STEP 9: breaker recovers after timeout ───────────────────
	banner(t, 9, "After Timeout, breaker half-opens; success closes it")
	time.Sleep(50 * time.Millisecond)
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("half-open call should succeed, got %v", err)
	}
	t.Logf("  Recovered: breaker state=%s", b.State())

	// ── STEP 10: context cancellation excluded from breaker ──────
	banner(t, 10, "Context cancellation does not trip the breaker")
	b2 := reliability.NewBreaker(reliability.BreakerConfig{
		Name:             "demo-ctx-aware",
		FailureThreshold: 2,
	})
	for i := 0; i < 10; i++ {
		_ = b2.Execute(func() error { return context.Canceled })
	}
	if b2.State() != "closed" {
		t.Fatalf("ctx-cancelled errors must not trip breaker; got %s", b2.State())
	}
	t.Logf("  10 ctx.Canceled errors did not trip; state=%s", b2.State())

	// ── DONE ────────────────────────────────────────────────────
	t.Logf("\n╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║   ✓ Sprint 5 demo complete — every step passed                ║")
	t.Logf("║                                                              ║")
	t.Logf("║   Acceptance per ADR-0064:                                   ║")
	t.Logf("║     • /healthz /readyz /startupz wired                ✓      ║")
	t.Logf("║     • Optional subsystem degraded keeps /readyz green ✓      ║")
	t.Logf("║     • Required subsystem unhealthy flips /readyz 503  ✓      ║")
	t.Logf("║     • Backoff+Retry survives transient upstream pain  ✓      ║")
	t.Logf("║     • Circuit breaker trips after threshold           ✓      ║")
	t.Logf("║     • Open breaker fails fast                          ✓      ║")
	t.Logf("║     • Breaker recovers after Timeout                  ✓      ║")
	t.Logf("║     • Context cancellation is not counted as failure  ✓      ║")
	t.Logf("╚══════════════════════════════════════════════════════════════╝")
}

func hit(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func decodeStatus(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var snap struct {
		Overall  string `json:"overall_status"`
		Required string `json:"required_status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		return "(non-json body)"
	}
	return fmt.Sprintf("overall=%s required=%s", snap.Overall, snap.Required)
}
