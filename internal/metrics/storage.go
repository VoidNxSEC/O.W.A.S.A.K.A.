package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RetentionSweepDuration observes wall-clock time for a single retention
// Sweep. Default buckets cover the typical seconds-to-tens-of-seconds
// range; a sweep that exceeds a minute should be investigated.
var RetentionSweepDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "oswaka_retention_sweep_duration_seconds",
		Help:    "Wall-clock duration of a retention sweep.",
		Buckets: prometheus.DefBuckets,
	},
)

// RetentionEventsRemovedTotal counts lifetime routine-event deletions
// from the retention sweep. Useful for capacity planning and detecting
// configuration drift (sudden zeroes after a sweep means TTL changed).
var RetentionEventsRemovedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "oswaka_retention_events_removed_total",
		Help: "Total events deleted by the retention sweep.",
	},
)

// RetentionAlertsRemovedTotal counts lifetime alert deletions. Alerts
// have a separate, longer TTL — a rate spike here usually means TTL was
// shortened.
var RetentionAlertsRemovedTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "oswaka_retention_alerts_removed_total",
		Help: "Total alerts deleted by the retention sweep.",
	},
)

// BackupDuration observes wall-clock time for backup.Engine.Run.
// Backups copy the entire BoltDB and age-encrypt the bytes; typical
// durations are seconds to a couple of minutes depending on DB size.
var BackupDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "oswaka_backup_duration_seconds",
		Help:    "Duration of a backup run (source read + encrypt + sink writes).",
		Buckets: prometheus.DefBuckets,
	},
)

// BackupSizeBytes is the size of the last successful encrypted backup
// artifact in bytes. Sudden growth indicates DB bloat (retention
// misconfigured) or genuine activity increase.
var BackupSizeBytes = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "oswaka_backup_size_bytes",
		Help: "Size of the last successful backup artifact in bytes.",
	},
)

// TransparencySize is the current Merkle log tree size (leaf count).
// Set immediately after every successful Append. Useful as a monotonic
// progress signal — a non-increasing value while events are flowing
// indicates the transparency log is wedged.
var TransparencySize = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "oswaka_transparency_size",
		Help: "Current size of the transparency log (leaf count).",
	},
)

// TransparencyAppendDuration observes wall-clock time for a single
// transparency.Tree.Append (which serializes against the bbolt write
// txn). Append is in the critical path for THREAT_ALERT events, so
// p99 here directly impacts alert latency.
var TransparencyAppendDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Name:    "oswaka_transparency_append_duration_seconds",
		Help:    "Duration of a transparency log Append (leaf write + hash cache update).",
		Buckets: prometheus.DefBuckets,
	},
)

// RecordTransparencyAppend is the cycle-safe hook the parent wires
// from app.go: the transparency package emits (size, duration) to this
// helper via a callback, so internal/storage/transparency does NOT
// import internal/metrics.
func RecordTransparencyAppend(size uint64, durationSeconds float64) {
	TransparencySize.Set(float64(size))
	TransparencyAppendDuration.Observe(durationSeconds)
}
