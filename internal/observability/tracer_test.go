package observability

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// resetGlobals returns the global tracer/propagator to a known
// state between tests. The OTel globals are sticky, so without this
// a disabled-mode test followed by an enabled-mode test would race.
func resetGlobals(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})
}

func TestSetup_Disabled_InstallsNoopButKeepsPropagator(t *testing.T) {
	resetGlobals(t)

	provider, err := Setup(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Setup disabled returned error: %v", err)
	}
	defer provider.Shutdown(context.Background())

	// Tracer should produce a span object, but it should not record
	// (i.e. IsRecording == false).
	_, span := Tracer("test").Start(context.Background(), "noop-span")
	defer span.End()
	if span.IsRecording() {
		t.Errorf("disabled tracer must not record spans")
	}

	// Propagator must still round-trip a W3C traceparent so upstream
	// traces don't get severed.
	carrier := propagation.MapCarrier{}
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x42},
		SpanID:     trace.SpanID{0x37},
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), parent)
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if got := carrier.Get("traceparent"); got == "" {
		t.Fatal("traceparent not injected by composite propagator")
	}

	round := otel.GetTextMapPropagator().Extract(context.Background(), carrier)
	if !trace.SpanContextFromContext(round).TraceID().IsValid() {
		t.Error("propagator round-trip lost the trace id")
	}
}

func TestSetup_Enabled_RequiresEndpoint(t *testing.T) {
	resetGlobals(t)
	_, err := Setup(context.Background(), Config{Enabled: true, Endpoint: ""})
	if err == nil {
		t.Fatal("Setup(enabled, endpoint=\"\") should error")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("error should mention endpoint, got %v", err)
	}
}

func TestSetup_Enabled_DialsCollector(t *testing.T) {
	resetGlobals(t)

	// Fake collector: just a TCP listener that accepts and discards.
	// otlptracegrpc.New does the initial connection asynchronously
	// (it's a non-blocking gRPC dial), so any TCP listener satisfies
	// the smoke test that Setup wires plumbing without a real backend.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	provider, err := Setup(ctx, Config{
		Enabled:        true,
		Endpoint:       ln.Addr().String(),
		ServiceName:    "test-oswaka",
		ServiceVersion: "v0.0.0-test",
		Environment:    "test",
		SamplingRatio:  1.0,
		Insecure:       true,
	})
	if err != nil {
		t.Fatalf("Setup enabled returned error: %v", err)
	}

	// Span created via the global tracer should be recording.
	_, span := Tracer("test").Start(context.Background(), "real-span")
	if !span.IsRecording() {
		t.Error("enabled tracer must record spans")
	}
	span.End()

	// Shutdown is allowed to fail against our fake collector (the
	// flush won't get a gRPC response); we just need it to NOT
	// panic and to return promptly within the bounded ctx.
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer shutCancel()
	_ = provider.Shutdown(shutCtx)
}

func TestSetup_Enabled_DefaultsServiceNameAndSampling(t *testing.T) {
	resetGlobals(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go acceptLoop(ln)

	provider, err := Setup(context.Background(), Config{
		Enabled:  true,
		Endpoint: ln.Addr().String(),
		Insecure: true,
		// ServiceName and SamplingRatio intentionally zero.
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer provider.Shutdown(context.Background())

	// We can't introspect the defaults via the public API; this test
	// guards the happy path against a regression where zero values
	// would bypass the if-blocks. If those branches are removed, the
	// SDK will reject a 0.0 sampler ratio and the next Span would
	// not record.
	_, span := Tracer("test").Start(context.Background(), "default-span")
	if !span.IsRecording() {
		t.Error("default sampling ratio should be 1.0 (always record)")
	}
	span.End()
}

func TestShutdown_NilProvider_NoPanic(t *testing.T) {
	var p *Provider
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil Provider.Shutdown should not error: %v", err)
	}
}

func TestProvider_FlushesViaInMemoryExporter(t *testing.T) {
	resetGlobals(t)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)

	tracer := otel.Tracer("test")
	_, span := tracer.Start(context.Background(), "unit-of-work")
	span.SetAttributes()
	span.End()

	_ = tp.ForceFlush(context.Background())

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 exported span, got %d", len(spans))
	}
	if spans[0].Name != "unit-of-work" {
		t.Errorf("span name = %q, want unit-of-work", spans[0].Name)
	}
}

// acceptLoop drains incoming connections so the fake collector
// doesn't block the dial. gRPC will try to negotiate; the connection
// gets dropped after a few bytes — that's fine for a smoke test.
func acceptLoop(ln net.Listener) {
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			buf := make([]byte, 1024)
			_, _ = c.Read(buf)
		}(conn)
	}
}
