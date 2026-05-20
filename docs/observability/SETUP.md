# OWASAKA — Observability Setup

Operator guide for wiring OWASAKA into a Prometheus + Tempo (or Jaeger)
stack. Both knobs are **opt-in** because OWASAKA defaults to air-gap:
turning them on means the process talks to the network beyond its
configured collectors. Read the air-gap caveat below before you flip
either toggle in production.

For incident triage once telemetry is live, see
[docs/runbooks/INCIDENT.md](../runbooks/INCIDENT.md).

---

## What's emitted

When opted in, OWASAKA exports three signals:

- **Prometheus metrics** on `GET /metrics`, gated by
  `observability.metrics.enabled` (default `false`). The handler is
  not registered when disabled — the path returns 404.
- **OpenTelemetry traces** via OTLP gRPC to a configurable collector
  endpoint, gated by `observability.traces.enabled` (default `false`).
  When disabled the tracer provider is a no-op; spans are created in
  code but nothing is exported.
- **Structured logs** that automatically include `trace_id` and
  `span_id` fields whenever a span is active on the goroutine's
  context, so log search jumps straight to the trace in Tempo/Jaeger.

---

## Config block

Add to `configs/examples/default.yaml` (or your operator override).
The fields below match `ObservabilityConfig` / `TracesConfig` /
`MetricsToggle` in `pkg/config/config.go`:

```yaml
observability:
  metrics:
    enabled: true                          # serves /metrics
  traces:
    enabled: true                          # ships OTLP spans
    endpoint: tempo.observability:4317     # host:port, no scheme
    service_name: oswaka                   # defaults to "oswaka"
    environment: production                # production / staging / dev
    sampling_ratio: 1.0                    # 0.0-1.0; see "Sampling" below
    insecure: false                        # true ONLY for dev/loopback
```

Both blocks omitted → both signals off. There is no partial mode:
either you want telemetry or you don't.

---

## Wiring Prometheus

OWASAKA exposes metrics on the same HTTP server as the API (port from
`server.port`, default `8080`). Point your Prometheus at it:

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: oswaka
    scrape_interval: 15s
    static_configs:
      - targets: ['oswaka:8080']
```

Verify the endpoint is up before you wait for Prometheus to discover it:

```bash
curl -s http://oswaka:8080/metrics | grep owasaka_events_published_total
# owasaka_events_published_total{subject="spectre.events.dns"} 1247
```

A `404` here means `metrics.enabled=false`. A `Connection refused`
means the API server is down — see
[docs/runbooks/INCIDENT.md](../runbooks/INCIDENT.md).

---

## Wiring traces

The exporter speaks OTLP over gRPC (port `4317` by convention).
`endpoint` is `host:port` with no scheme — do not prefix `grpc://` or
`http://`. `insecure: true` skips TLS to the collector; **only**
acceptable when the collector is on `localhost` or inside a wireguard
mesh you trust. Production points at a collector that terminates mTLS.

### Tempo collector (sample)

```yaml
# tempo.yaml
distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
          tls:
            cert_file: /etc/tempo/tls/cert.pem
            key_file:  /etc/tempo/tls/key.pem
            client_ca_file: /etc/tempo/tls/clients-ca.pem  # mTLS
storage:
  trace:
    backend: local
    local:
      path: /var/lib/tempo/traces
```

OWASAKA config:

```yaml
observability:
  traces:
    enabled: true
    endpoint: tempo.observability:4317
    insecure: false
```

### Jaeger collector (sample)

Jaeger v1.35+ accepts OTLP natively:

```yaml
# docker-compose-style
services:
  jaeger:
    image: jaegertracing/all-in-one:1.55
    environment:
      COLLECTOR_OTLP_ENABLED: "true"
    ports:
      - "4317:4317"   # OTLP gRPC
      - "16686:16686" # UI
```

OWASAKA config (dev / loopback only — note `insecure: true`):

```yaml
observability:
  traces:
    enabled: true
    endpoint: 127.0.0.1:4317
    insecure: true
```

---

## Importing the Grafana dashboard

The reference dashboard lives at
`deploy/grafana/dashboards/owasaka-overview.json`.

1. In Grafana: **Dashboards → Import**.
2. Upload the JSON or paste its contents.
3. On the import screen, set the `$datasource` variable to your
   Prometheus datasource. The dashboard does not hardcode a UID — each
   operator's Prometheus has a different one.
4. Save. Panels populate as soon as the next scrape lands.

If panels stay "No data" after a scrape interval, the metric isn't
being emitted — most often `metrics.enabled=false` or the
corresponding subsystem (e.g., DNS monitor) is disabled in its own
config block.

---

## Verifying the wiring

### Metrics

```bash
curl -s http://oswaka:8080/metrics | grep owasaka_events_published_total
curl -s http://oswaka:8080/metrics | grep owasaka_http_requests_total
```

Both should return at least one line. Zero output on a freshly booted
node is normal until the first event flows — generate one with any
API call (e.g., `curl http://oswaka:8080/api/stats`) and re-check
`owasaka_http_requests_total`.

### Traces

Trigger any traced operation, then query the collector:

```bash
# Trigger a span
curl -s http://oswaka:8080/api/stats > /dev/null

# Tempo: search by service
curl -s "http://tempo:3200/api/search?tags=service.name=oswaka" | jq '.traces | length'

# Jaeger: same idea, different API
curl -s "http://jaeger:16686/api/traces?service=oswaka&limit=5" | jq '.data | length'
```

A non-zero count confirms end-to-end wiring. Zero with metrics
flowing fine → see "no spans" in Troubleshooting.

---

## Sampling guidance

`sampling_ratio` is a head-based ParentBased sampler:

- **At a root span** (no upstream parent), sample with probability
  `sampling_ratio`.
- **At a child span** (upstream context present), inherit the parent's
  decision — a sampled trace stays sampled end-to-end, an unsampled
  one stays unsampled. This is why a value of `0.1` does **not** give
  you 10% of arbitrary spans; it gives you 10% of new traces, each
  complete.

Operational recommendation:

| Phase | Ratio | Why |
|-------|-------|-----|
| First few hours after enabling | `1.0` | Catch every span; confirm wiring + dashboards. |
| Steady state, light load | `1.0` | Span volume tolerable; full coverage is cheap. |
| Steady state, collector pressure | `0.1` | Drop volume 10x without losing trace completeness. |
| Forensic / incident | `1.0` | Crank back up while investigating. |

`sampling_ratio: 0` is legal and means "create spans, export nothing"
— equivalent to `traces.enabled: false` but slightly more expensive.
Use the toggle, not the ratio, to disable.

---

## Air-gap caveat

OWASAKA's default posture is **air-gapped**: no outbound network beyond
configured intelligence sinks. Turning on traces or metrics breaks
that posture by definition — the process now ships data to a
collector.

Hard rules for keeping the air-gap meaningful:

- **Collector co-location.** Run Tempo + Prometheus on the same
  physical host (or the same trusted segment) as OWASAKA. If your
  telemetry crosses a perimeter, you have just enlarged the blast
  radius of every secret in OWASAKA's process memory.
- **No SaaS collectors.** Datadog / Honeycomb / Lightstep are
  excellent products and the wrong tool for this deployment. The
  whole point of OWASAKA is that observed events do not leave the
  perimeter.
- **mTLS to the collector.** `insecure: true` is a development
  affordance. Production collectors authenticate the OWASAKA client
  certificate; OWASAKA verifies the collector's certificate.
- **Log review.** `trace_id` in logs is convenient for SOC analysts
  and equally convenient for an attacker who exfiltrates the log
  store. Treat log retention with the same care as event retention.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `GET /metrics` returns 404 | `observability.metrics.enabled = false` (default). |
| `/metrics` returns 200 but no `owasaka_*` series | Subsystem disabled (e.g., DNS monitor off → no `owasaka_dns_queries_total`). |
| Prometheus target `DOWN` | API server not bound to expected address, or firewall between Prometheus and OWASAKA. |
| No spans in Tempo / Jaeger | `traces.enabled=false`, wrong `endpoint`, wrong port, firewall, or `sampling_ratio=0`. |
| `OTLP: connection refused` in logs | Collector not listening on `endpoint`, or `insecure: false` against a plaintext collector (or vice-versa). |
| `OTLP: x509: certificate signed by unknown authority` | Collector cert not in OWASAKA's trust store; either fix the trust chain or (dev only) set `insecure: true`. |
| Spans missing their parent (orphan spans in UI) | An upstream caller is not propagating W3C `traceparent`. Wrap its HTTP client with `otelhttp` or equivalent; the issue is on the caller, not OWASAKA. |
| Logs lack `trace_id` / `span_id` | The code path isn't inside a span — confirm the request entered through an instrumented entrypoint. Background goroutines need an explicit context. |
| Dashboard panels "No data" after import | `$datasource` variable not set, or metrics genuinely zero (no traffic / subsystem off). |

For deeper triage — log correlation, ingest backpressure, or
collector-side issues — see
[docs/runbooks/INCIDENT.md](../runbooks/INCIDENT.md) and
[docs/runbooks/LOG_ANALYSIS.md](../runbooks/LOG_ANALYSIS.md).

---

## See also

- [docs/runbooks/INCIDENT.md](../runbooks/INCIDENT.md) — incident triage
- [docs/runbooks/LOG_ANALYSIS.md](../runbooks/LOG_ANALYSIS.md) — log queries
- [docs/runbooks/COMMON_FAILURES.md](../runbooks/COMMON_FAILURES.md) — known failure modes
- `pkg/config/config.go` — authoritative `ObservabilityConfig` schema
- `internal/metrics/` — authoritative list of exported Prometheus series
