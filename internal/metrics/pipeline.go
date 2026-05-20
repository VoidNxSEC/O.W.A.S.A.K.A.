package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PipelineEventsTotal counts every event that enters the events.Pipeline,
// labelled by NetworkEvent type (DNS, PORT_SCAN, ARP, THREAT_ALERT, ...).
// Useful as a top-line throughput signal and to alert on a sudden drop in
// traffic (e.g., a capture process died).
var PipelineEventsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oswaka_pipeline_events_total",
		Help: "Total events entering the owasaka pipeline, by event type.",
	},
	[]string{"type"},
)

// PipelineStageDuration observes the time spent in each named stage of
// PushNetworkEvent. Stage labels: enrich, sign, persist, transparency_append,
// nats_publish, correlate. Default buckets work well for sub-second stages;
// stages that routinely exceed 1s should be reviewed regardless of bucket choice.
var PipelineStageDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "oswaka_pipeline_stage_duration_seconds",
		Help:    "Duration of each pipeline stage in seconds.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"stage"},
)

// PipelinePublishFailuresTotal counts publish-path failures by structured
// reason. Used to alert on persistent NATS disconnection, signing-key
// rollover gone wrong, or transparency-log backpressure.
//
// Reason labels:
//   - nats_disconnected: pub.Publish returned a "not connected" error
//   - sign_failed: signer.Sign returned an error
//   - transparency_failed: transparency.Append returned an error
//   - marshal_failed: CanonicalBytes / json.Marshal failed before signing
var PipelinePublishFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "oswaka_pipeline_publish_failures_total",
		Help: "Total pipeline publish/sign/transparency failures, by reason.",
	},
	[]string{"reason"},
)
