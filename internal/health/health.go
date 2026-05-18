// Package health serves liveness, readiness, and startup probes per
// the Kubernetes / systemd convention. See ADR Sprint 5 task H1.
//
//   /healthz   — liveness: process is up. Should answer 200 as long
//                as the binary is running and not panicking.
//   /readyz    — readiness: every required subsystem is operational.
//                503 when a required subsystem is failing; the
//                response body enumerates which.
//   /startupz  — startup: initialization complete. Probes during
//                startup window should hit this; once it returns 200
//                the operator switches to /readyz.
//
// Subsystems register via Probe.Register; they expose a Status that
// the handler aggregates. Subsystems can be `Required` (their
// failure flips /readyz to 503) or `Optional` (their failure surfaces
// as `degraded` but readiness stays green — see ADR-0064 §"Graceful
// degradation" for the rationale).
package health

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Status is the per-subsystem health verdict. Aggregated by the
// handler.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
	StatusStarting  Status = "starting"
)

// Probe is the contract a subsystem implements to report its state.
// Implementations are called on every /readyz / /healthz / /startupz
// hit, so they MUST be fast (a few ms at most). For expensive checks,
// run them in a background goroutine and surface the cached result.
type Probe interface {
	// Name is a short identifier ("nats", "boltdb", "transparency").
	Name() string

	// Required reports whether a failure of this probe should flip
	// /readyz to 503. Optional subsystems surface as `degraded` but
	// keep readiness green.
	Required() bool

	// Check evaluates current state and returns a Result. The
	// returned message accompanies non-healthy statuses in the JSON
	// response body — it should be short and operator-friendly.
	Check() Result
}

// Result is what a Probe returns from Check.
type Result struct {
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
}

// Registry holds the active set of probes. Thread-safe; probes may
// register at any time (subsystems often register when they
// successfully initialize).
type Registry struct {
	mu     sync.RWMutex
	probes map[string]Probe

	// startupComplete flips to true when MarkStartupComplete is
	// called. Until then, /startupz returns "starting".
	startupComplete bool
	startupCompleteAt time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{probes: make(map[string]Probe)}
}

// Register adds (or replaces) a probe. Replace happens by name; a
// subsystem can update its probe after a config reload.
func (r *Registry) Register(p Probe) {
	if p == nil || p.Name() == "" {
		return
	}
	r.mu.Lock()
	r.probes[p.Name()] = p
	r.mu.Unlock()
}

// Deregister removes a probe by name. Used during subsystem shutdown
// so a probe doesn't outlive the thing it's checking.
func (r *Registry) Deregister(name string) {
	r.mu.Lock()
	delete(r.probes, name)
	r.mu.Unlock()
}

// MarkStartupComplete flips the registry from "starting" to fully
// operational. Called once by app.go after every required subsystem
// has finished initializing.
func (r *Registry) MarkStartupComplete() {
	r.mu.Lock()
	if !r.startupComplete {
		r.startupComplete = true
		r.startupCompleteAt = time.Now().UTC()
	}
	r.mu.Unlock()
}

// snapshot returns all probe results plus the aggregate status.
// Internal helper for the handlers.
func (r *Registry) snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := Snapshot{
		Subsystems: make([]SubsystemStatus, 0, len(r.probes)),
		StartupComplete: r.startupComplete,
		StartupCompleteAt: r.startupCompleteAt,
	}

	// Iterate probes in name order so JSON output is deterministic.
	names := make([]string, 0, len(r.probes))
	for n := range r.probes {
		names = append(names, n)
	}
	sort.Strings(names)

	worstRequired := StatusHealthy
	worstOverall := StatusHealthy
	for _, n := range names {
		p := r.probes[n]
		res := p.Check()
		ss := SubsystemStatus{
			Name:     p.Name(),
			Required: p.Required(),
			Status:   res.Status,
			Message:  res.Message,
		}
		out.Subsystems = append(out.Subsystems, ss)

		if statusWorse(res.Status, worstOverall) {
			worstOverall = res.Status
		}
		if p.Required() && statusWorse(res.Status, worstRequired) {
			worstRequired = res.Status
		}
	}

	out.RequiredStatus = worstRequired
	out.OverallStatus = worstOverall
	return out
}

// Snapshot is the aggregate the handlers serialize.
type Snapshot struct {
	OverallStatus     Status            `json:"overall_status"`
	RequiredStatus    Status            `json:"required_status"`
	StartupComplete   bool              `json:"startup_complete"`
	StartupCompleteAt time.Time         `json:"startup_complete_at,omitempty"`
	Subsystems        []SubsystemStatus `json:"subsystems"`
}

// SubsystemStatus is one probe's snapshot.
type SubsystemStatus struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Status   Status `json:"status"`
	Message  string `json:"message,omitempty"`
}

// statusWorse reports whether a is "worse" than b in the standard
// healthy < starting < degraded < unhealthy ordering.
func statusWorse(a, b Status) bool {
	return rank(a) > rank(b)
}

func rank(s Status) int {
	switch s {
	case StatusUnhealthy:
		return 3
	case StatusDegraded:
		return 2
	case StatusStarting:
		return 1
	default:
		return 0
	}
}

// LivenessHandler returns an http.Handler that answers 200 as long
// as the registry exists (the process is up). Body is the empty JSON
// object so log scrapers can parse it uniformly.
func LivenessHandler(r *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	})
}

// ReadinessHandler returns 200 when every Required probe is healthy
// (Optional probes can be degraded without flipping the verdict).
// 503 otherwise; body enumerates per-subsystem state.
func ReadinessHandler(r *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s := r.snapshot()
		status := http.StatusOK
		if s.RequiredStatus == StatusUnhealthy || s.RequiredStatus == StatusDegraded {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, s)
	})
}

// StartupHandler returns 200 once MarkStartupComplete has been
// called, 503 otherwise. Kubernetes uses this to suppress liveness
// failures during slow initialization.
func StartupHandler(r *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s := r.snapshot()
		if !s.StartupComplete {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "starting",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":              "ready",
			"startup_complete_at": s.StartupCompleteAt,
		})
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// StaticProbe is a convenience for subsystems that have a simple
// boolean state. Most probes implement Probe directly for richer
// reporting.
type StaticProbe struct {
	name     string
	required bool
	get      func() Result
}

// NewStaticProbe wires a name + required flag + check function into
// a Probe.
func NewStaticProbe(name string, required bool, check func() Result) *StaticProbe {
	return &StaticProbe{name: name, required: required, get: check}
}

// Name implements Probe.
func (s *StaticProbe) Name() string { return s.name }

// Required implements Probe.
func (s *StaticProbe) Required() bool { return s.required }

// Check implements Probe.
func (s *StaticProbe) Check() Result {
	if s.get == nil {
		return Result{Status: StatusHealthy}
	}
	return s.get()
}
