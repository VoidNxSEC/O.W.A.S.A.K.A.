package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/metrics"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// hstsMaxAgeSeconds is the HSTS max-age advertised to clients (1 year).
// Browsers will refuse plaintext connections to this host for this
// duration after the first HTTPS response. We do not advertise
// includeSubDomains or preload — that's an explicit operator choice
// not made in code.
const hstsMaxAgeSeconds = 31536000

// Server encapsulates the HTTP and WebSocket API server
type Server struct {
	cfg        *config.ServerConfig
	logger     *logging.Logger
	httpServer *http.Server
	Hub        *WSHub
	mux        *http.ServeMux

	// Auth components (optional — nil means no auth, dev mode or unsecured)
	authMiddleware interface {
		RequireAuth(next http.Handler) http.Handler
	}
	authzMiddleware interface {
		RequirePermission(resource, action string, next http.Handler) http.Handler
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Instrument wraps a handler with Prometheus request metrics (exported for use in app.go).
func Instrument(path string, h http.HandlerFunc) http.HandlerFunc {
	return instrumentedHandler(path, h)
}

// instrumentedHandler wraps a handler with Prometheus request metrics.
func instrumentedHandler(path string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		h(rw, r)
		dur := time.Since(start).Seconds()
		status := strconv.Itoa(rw.status)
		metrics.HTTPRequestsTotal.WithLabelValues(r.Method, path, status).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(r.Method, path).Observe(dur)
	}
}

// NewServer builds a new API manager
func NewServer(cfg *config.ServerConfig, logger *logging.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
		Hub:    NewWSHub(logger),
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/health", instrumentedHandler("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"online"}`))
	}))
	s.mux.Handle("/metrics", promhttp.Handler())
	return s
}

// RegisterHandler registers an HTTP handler before or after Start
func (s *Server) RegisterHandler(path string, handler http.HandlerFunc) {
	s.mux.HandleFunc(path, handler)
}

// RegisterProtectedHandler registers a handler behind the auth middleware.
// If no auth middleware is configured, the handler is registered unprotected
// with a warning log.
func (s *Server) RegisterProtectedHandler(path string, handler http.HandlerFunc) {
	if s.authMiddleware != nil {
		s.mux.Handle(path, s.authMiddleware.RequireAuth(http.HandlerFunc(handler)))
	} else {
		s.logger.Warnw("registering unprotected handler (no auth middleware)", "path", path)
		s.mux.HandleFunc(path, handler)
	}
}

// SetAuthMiddleware injects the identity middleware for RequireAuth wrappers.
func (s *Server) SetAuthMiddleware(mw interface {
	RequireAuth(next http.Handler) http.Handler
}) {
	s.authMiddleware = mw
}

// hstsMiddleware injects HSTS on every response so the browser
// remembers to use HTTPS for the next hstsMaxAgeSeconds. Applied
// unconditionally — even on plaintext responses (which only happen
// when TLS is disabled in config). When the header arrives over
// plaintext browsers ignore it per RFC 6797 §7.2, so this is safe.
func hstsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security",
			fmt.Sprintf("max-age=%d", hstsMaxAgeSeconds))
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Start opens the main port listeners. If cfg.TLS.Enabled is true,
// the listener uses TLS 1.3 minimum with a conservative cipher list
// and serves HTTPS only — there is no automatic plaintext-to-TLS
// redirect because owasaka clients (frontend, CLI) are configured
// directly with the https:// URL and we'd rather fail loudly than
// silently downgrade.
func (s *Server) Start(ctx context.Context) error {
	go s.Hub.Run()

	if s.cfg.WebSocket.Enabled {
		s.mux.HandleFunc(s.cfg.WebSocket.Path, s.Hub.Handler)
		s.logger.Infow("WebSocket endpoint registered", "path", s.cfg.WebSocket.Path)
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           observabilityMiddleware(corsMiddleware(hstsMiddleware(s.mux))),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if s.cfg.TLS.Enabled {
		if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
			return fmt.Errorf("api: TLS enabled but cert_file or key_file missing")
		}
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
		s.logger.Infow("Starting Command Center API (TLS 1.3)",
			"addr", addr, "cert", s.cfg.TLS.CertFile)
		go func() {
			if err := s.httpServer.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				s.logger.Errorw("Command Center API (TLS) failed", "error", err)
			}
		}()
		return nil
	}

	s.logger.Warnw("Starting Command Center API in PLAINTEXT — TLS disabled in config",
		"addr", addr)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Errorw("Command Center API failed", "error", err)
		}
	}()

	return nil
}

// Stop enforces an elegant drop of API traffic
func (s *Server) Stop() {
	s.logger.Info("Stopping Command Center API")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Errorw("Failed to gracefully shutdown API", "error", err)
	}
}
