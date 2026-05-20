// Package observability sets up OpenTelemetry tracing for the
// OWASAKA SIEM. Tracing is OFF by default — operators opt in via the
// observability.traces.enabled config flag because shipping spans
// out of the binary breaks the air-gap default.
//
// When disabled, Setup installs a no-op tracer provider and the
// package's global tracer is a no-op too. Code that wraps work in
// spans pays only the cost of a recording-disabled span: a handful
// of nanoseconds. The instrumented code does not need to branch on
// "tracing enabled".
//
// Propagation: W3C trace-context + baggage, set as the package's
// global propagator. Any HTTP client / NATS publisher injecting the
// propagator's carriers will be picked up by an upstream collector.
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config mirrors pkg/config.TracesConfig but lives in this package so
// observability does not import pkg/config (cycle-prone). app.go does
// the field-by-field copy at boot.
type Config struct {
	Enabled        bool
	Endpoint       string  // host:port for OTLP gRPC
	ServiceName    string  // defaults to "oswaka"
	ServiceVersion string  // resource attribute service.version
	Environment    string  // deployment.environment
	SamplingRatio  float64 // 0.0 disables, 1.0 always; defaults to 1.0 when enabled
	Insecure       bool    // skip TLS to the collector (dev only)
}

// Provider wraps a trace.TracerProvider plus a shutdown hook. Code
// that needs a tracer should call observability.Tracer; Provider is
// kept around so app.go can flush + tear down at shutdown.
type Provider struct {
	tp       trace.TracerProvider
	shutdown func(context.Context) error
}

// Setup wires global tracing per cfg. Returns a Provider whose
// Shutdown MUST be called before process exit so in-flight spans are
// flushed; callers typically `defer provider.Shutdown(ctx)` right
// after Setup returns nil error.
//
// When cfg.Enabled is false, Setup installs a no-op provider and
// returns immediately. The propagator is still installed so
// distributed traces from upstream callers continue to be carried
// through HTTP + NATS headers — the local binary just doesn't
// export anything.
func Setup(ctx context.Context, cfg Config) (*Provider, error) {
	// Always install the propagator so the binary plays nicely with
	// upstream traces even when local tracing is disabled.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return &Provider{tp: tp, shutdown: noopShutdown}, nil
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("observability: traces enabled but endpoint is empty")
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "oswaka"
	}
	if cfg.SamplingRatio <= 0 {
		cfg.SamplingRatio = 1.0
	}

	dialOpts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		dialOpts = append(dialOpts, otlptracegrpc.WithInsecure())
	}

	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient(dialOpts...))
	if err != nil {
		return nil, fmt.Errorf("observability: dial otlp %s: %w", cfg.Endpoint, err)
	}

	attrs := []attribute.KeyValue{semconv.ServiceName(cfg.ServiceName)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, semconv.DeploymentEnvironment(cfg.Environment))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		// Resource detection can fail in container/sandbox envs; fall
		// back to the static attribute set so tracing still works.
		res = resource.NewSchemaless(attrs...)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SamplingRatio))),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return &Provider{
		tp: tp,
		shutdown: func(ctx context.Context) error {
			if err := tp.ForceFlush(ctx); err != nil {
				return fmt.Errorf("flush: %w", err)
			}
			return tp.Shutdown(ctx)
		},
	}, nil
}

// Shutdown flushes any pending spans and tears down the exporter.
// Safe to call on a nil Provider — useful when Setup returned an
// error and the caller defers Shutdown without checking.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// TracerProvider exposes the underlying provider for callers that
// need to register custom span processors. Most code should use
// observability.Tracer instead.
func (p *Provider) TracerProvider() trace.TracerProvider {
	if p == nil {
		return noop.NewTracerProvider()
	}
	return p.tp
}

// Tracer is the convenience accessor most call sites should use:
//
//	tracer := observability.Tracer("internal/events")
//	ctx, span := tracer.Start(ctx, "pipeline.push")
//	defer span.End()
//
// Returns a tracer that resolves through the global provider, so it
// picks up Setup-installed config transparently.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func noopShutdown(context.Context) error { return nil }
