package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	l, _ := logging.NewLogger(&config.LoggingConfig{
		Level:  "warn",
		Format: "console",
		Output: "stdout",
	})
	cfg := &config.ServerConfig{
		Host: "127.0.0.1",
		Port: 0, // unused for httptest
		WebSocket: config.WebSocketConfig{
			Enabled: false,
		},
	}
	return NewServer(cfg, l)
}

func TestHealth(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Result().Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["status"] != "online" {
		t.Fatalf("expected status 'online', got %q", result["status"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	// Prometheus metrics endpoint should contain standard Go metrics at minimum
	if !strings.Contains(text, "go_") {
		t.Fatal("expected Prometheus go_ metrics in /metrics response")
	}
}

func TestRegisterHandler(t *testing.T) {
	s := newTestServer(t)
	s.RegisterHandler("/test-custom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"custom": true}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/test-custom", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
}

func TestInstrumentedHandler_RecordsMetrics(t *testing.T) {
	called := false
	handler := instrumentedHandler("/test-instrumented", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test-instrumented", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestResponseWriterCaptures(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)
	if rw.status != http.StatusNotFound {
		t.Fatalf("expected 404 captured, got %d", rw.status)
	}
}
