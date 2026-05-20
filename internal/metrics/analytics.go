package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CorrelationRuleEvalDuration observes per-rule evaluation time. The
// rule_id label is the rule's Name(). Rules that consistently fall in
// the slow buckets are candidates for refactoring (the engine evaluates
// every rule against every event).
//
// Sub-millisecond evals are common, so we use an exponential bucket
// scheme starting at 100us up to ~100ms.
var CorrelationRuleEvalDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "oswaka_correlation_rule_eval_duration_seconds",
		Help:    "Per-rule correlation evaluation duration in seconds.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
	},
	[]string{"rule_id"},
)

// MLInferenceDuration observes Isolation Forest predict time. Trees
// are walked sequentially; cost scales with numTrees * avg depth.
// Sub-millisecond is the expected regime for the default 100-tree
// forest at depth 10, so we use the same exponential bucket scheme as
// the correlation rule eval histogram.
var MLInferenceDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "oswaka_ml_inference_duration_seconds",
		Help:    "Isolation Forest predict-call duration in seconds.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
	},
)

// StreamEventsDroppedTotal counts events dropped or displaced by the
// stream buffer under backpressure, labelled by the configured policy
// (drop_oldest, drop_newest). Non-zero rate means downstream consumers
// can't keep up with the producer; widen the buffer or scale up the
// pipeline.
var StreamEventsDroppedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oswaka_stream_events_dropped_total",
		Help: "Total events dropped or displaced by the stream buffer, by policy.",
	},
	[]string{"policy"},
)
