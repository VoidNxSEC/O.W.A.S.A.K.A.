package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// HeaderRequestID is the standard correlation-ID header. We accept
// it on incoming requests; if absent, the middleware mints a fresh
// one and echoes it back so the client can correlate logs.
const HeaderRequestID = "X-Request-ID"

// ctxKey is the unexported type used for context lookups, per the
// stdlib convention. Two values: requestID and a marker for the
// inbound-span (the span itself is reached via trace.SpanFromContext).
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
)

// RequestIDFromContext returns the request ID injected by the
// observability middleware, or "" when there isn't one.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// observabilityMiddleware is the always-on chain entry that:
//
//  1. Extracts W3C trace-context from incoming headers via the global
//     propagator so distributed traces from upstream callers continue.
//  2. Starts a server span named "<METHOD> <path>" (or just the path
//     when METHOD would be redundant).
//  3. Injects a request ID into context + the response header so the
//     client can quote it back in support tickets.
//  4. Records the response status as a span attribute on completion.
//
// Cheap when tracing is disabled: the global tracer in that case is
// a no-op, so Start returns a non-recording span and SetAttributes
// is effectively free.
func observabilityMiddleware(next http.Handler) http.Handler {
	tracer := otel.Tracer("internal/api")
	propagator := otel.GetTextMapPropagator()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		reqID := r.Header.Get(HeaderRequestID)
		if reqID == "" {
			reqID = newRequestID()
		}
		ctx = context.WithValue(ctx, ctxKeyRequestID, reqID)
		w.Header().Set(HeaderRequestID, reqID)

		spanName := r.Method + " " + r.URL.Path
		ctx, span := tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
				attribute.String("http.request_id", reqID),
			),
		)
		defer span.End()

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r.WithContext(ctx))

		span.SetAttributes(semconv.HTTPResponseStatusCode(rw.status))
	})
}

// newRequestID mints a 128-bit hex ID. We avoid pulling in a UUID
// dependency for this — 16 bytes of crypto/rand hex-encoded is
// indistinguishable from a v4 UUID without dashes for correlation
// purposes.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal in practice. Return a
		// deterministic-but-distinguishable fallback so logs still
		// have something to correlate on.
		return "norand"
	}
	return hex.EncodeToString(b[:])
}
