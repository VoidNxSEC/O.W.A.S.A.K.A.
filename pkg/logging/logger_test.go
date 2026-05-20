package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
)

// newCapturingLogger builds a Logger that writes JSON lines into the
// returned buffer so tests can assert on emitted fields without
// touching stdout.
func newCapturingLogger(t *testing.T) (*Logger, *threadSafeBuffer) {
	t.Helper()
	buf := &threadSafeBuffer{}
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.AddSync(buf), zapcore.DebugLevel)
	z := zap.New(core).Sugar()
	return &Logger{SugaredLogger: z}, buf
}

type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestNewLogger_UnknownLevelRejected(t *testing.T) {
	_, err := NewLogger(&config.LoggingConfig{
		Level:  "vibes",
		Format: "json",
		Output: "stdout",
	})
	if err == nil {
		t.Fatal("unknown level should produce an error")
	}
}

func TestNewLogger_ProducesUsableLogger(t *testing.T) {
	l, err := NewLogger(&config.LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if l == nil || l.SugaredLogger == nil {
		t.Fatal("logger or its inner SugaredLogger is nil")
	}
}

func TestWithFields_AppendsKVs(t *testing.T) {
	l, buf := newCapturingLogger(t)
	l.WithFields(map[string]interface{}{"k": "v", "n": 42}).Infow("hello")
	line := buf.String()
	if !strings.Contains(line, `"k":"v"`) {
		t.Errorf("expected k=v in log line, got %s", line)
	}
	if !strings.Contains(line, `"n":42`) {
		t.Errorf("expected n=42 in log line, got %s", line)
	}
}

func TestWithContext_NoSpan_ReturnsReceiverUnchanged(t *testing.T) {
	l, buf := newCapturingLogger(t)

	enriched := l.WithContext(context.Background())
	if enriched != l {
		t.Errorf("WithContext(ctx-without-span) should return same logger; got different pointer")
	}

	enriched.Infow("no-span")
	line := buf.String()
	if strings.Contains(line, "trace_id") || strings.Contains(line, "span_id") {
		t.Errorf("trace_id/span_id leaked when no span active: %s", line)
	}
}

func TestWithContext_NilCtx_NoPanic(t *testing.T) {
	l, _ := newCapturingLogger(t)
	got := l.WithContext(nil)
	if got != l {
		t.Errorf("WithContext(nil) should be a no-op")
	}
}

func TestWithContext_NilReceiver_NoPanic(t *testing.T) {
	var l *Logger
	if got := l.WithContext(context.Background()); got != nil {
		t.Errorf("WithContext on nil receiver must return nil, got %v", got)
	}
}

func TestWithContext_ActiveSpan_AddsIDs(t *testing.T) {
	l, buf := newCapturingLogger(t)

	traceID := trace.TraceID{0x10, 0x20}
	spanID := trace.SpanID{0xaa, 0xbb}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	l.WithContext(ctx).Infow("traced")
	line := buf.String()

	// Parse the emitted JSON line and assert the values precisely.
	var rec map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &rec); err != nil {
		t.Fatalf("emitted log not valid JSON: %v -- %q", err, line)
	}
	if rec["trace_id"] != traceID.String() {
		t.Errorf("trace_id = %v, want %s", rec["trace_id"], traceID.String())
	}
	if rec["span_id"] != spanID.String() {
		t.Errorf("span_id = %v, want %s", rec["span_id"], spanID.String())
	}
}
