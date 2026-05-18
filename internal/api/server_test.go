package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestHSTSMiddleware_AlwaysSetsHeader(t *testing.T) {
	called := false
	h := hstsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/anything", nil))

	if !called {
		t.Fatal("downstream handler not invoked")
	}
	got := w.Header().Get("Strict-Transport-Security")
	if got == "" {
		t.Fatal("HSTS header missing")
	}
	if !strings.Contains(got, "max-age=31536000") {
		t.Errorf("HSTS max-age wrong: %q", got)
	}
}

// makeTestCert generates a self-signed cert + key, writes both to a
// tempdir, returns the file paths. Uses ECDSA P-256 because it's
// cheap to generate and TLS 1.3 supports it natively.
func makeTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oswaka-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()
	return certPath, keyPath
}

func TestServer_TLSRequiresCertAndKey(t *testing.T) {
	cases := []struct {
		name string
		cert string
		key  string
	}{
		{"both empty", "", ""},
		{"only cert", "/tmp/c", ""},
		{"only key", "", "/tmp/k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			s.cfg.TLS = config.TLSConfig{Enabled: true, CertFile: tc.cert, KeyFile: tc.key}
			err := s.Start(context.Background())
			if err == nil {
				t.Fatal("expected error when TLS enabled but cert/key incomplete")
			}
			if !strings.Contains(err.Error(), "TLS") {
				t.Errorf("error should mention TLS, got %v", err)
			}
		})
	}
}

func TestServer_TLSServesAndEnforcesTLS13(t *testing.T) {
	certPath, keyPath := makeTestCert(t)

	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	s := newTestServer(t)
	s.cfg.Port = port
	s.cfg.TLS = config.TLSConfig{Enabled: true, CertFile: certPath, KeyFile: keyPath}

	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)

	// Give the goroutine a moment to bind.
	deadline := time.Now().Add(2 * time.Second)
	var conn *tls.Conn
	for time.Now().Before(deadline) {
		conn, err = tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Errorf("TLS version = %x, want TLS 1.3 (%x)", state.Version, tls.VersionTLS13)
	}

	// TLS 1.2-only client must be REJECTED.
	bad, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err == nil {
		bad.Close()
		t.Error("TLS 1.2 client should have been refused; handshake succeeded")
	}

	// HSTS header must be present on an HTTPS response.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got == "" {
		t.Error("HSTS header missing on TLS response")
	}
}
