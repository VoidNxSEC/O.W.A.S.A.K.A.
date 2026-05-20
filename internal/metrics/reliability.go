package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// breakerStateClosed/HalfOpen/Open mirror gobreaker's three states as
// numeric values so the gauge is queryable in Prometheus without
// resorting to label cardinality on state names.
const (
	breakerStateClosed   = 0
	breakerStateHalfOpen = 1
	breakerStateOpen     = 2
)

// BreakerState is a gauge encoding the live state of every circuit
// breaker by name. 0=closed, 1=half-open, 2=open. Useful for "any
// breaker open right now?" alerts and dashboards that color a tile by
// state.
var BreakerState = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "oswaka_breaker_state",
		Help: "Current circuit breaker state (0=closed, 1=half-open, 2=open).",
	},
	[]string{"name"},
)

// BreakerOpensTotal counts lifetime transitions into the open state per
// breaker. Pair with rate() to detect a flapping breaker.
var BreakerOpensTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oswaka_breaker_opens_total",
		Help: "Total number of times a breaker transitioned to open.",
	},
	[]string{"name"},
)

// BreakerRejectsTotal counts fail-fast rejections (ErrCircuitOpen)
// returned to callers while the breaker was open or half-open-saturated.
// High rejection rate indicates downstream is still unhealthy.
var BreakerRejectsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oswaka_breaker_rejects_total",
		Help: "Total number of calls rejected by an open or saturated breaker.",
	},
	[]string{"name"},
)

// RecordBreakerState updates the breaker gauge for `name` based on the
// gobreaker state string ("closed", "half-open", "open"). Unknown
// strings leave the gauge unchanged. Designed to be called from the
// breaker's OnStateChange hook wired in app.go, keeping the
// internal/reliability package free of a metrics dependency (cycle
// avoidance).
//
// On transition to "open" this helper also increments BreakerOpensTotal
// so callers can subscribe via a single hook.
func RecordBreakerState(name, state string) {
	switch state {
	case "closed":
		BreakerState.WithLabelValues(name).Set(breakerStateClosed)
	case "half-open":
		BreakerState.WithLabelValues(name).Set(breakerStateHalfOpen)
	case "open":
		BreakerState.WithLabelValues(name).Set(breakerStateOpen)
		BreakerOpensTotal.WithLabelValues(name).Inc()
	}
}

// RecordBreakerReject bumps the reject counter for a named breaker.
// Wired from app.go around the Execute path (or via a wrapper) so the
// reliability package itself stays metrics-free.
func RecordBreakerReject(name string) {
	BreakerRejectsTotal.WithLabelValues(name).Inc()
}
