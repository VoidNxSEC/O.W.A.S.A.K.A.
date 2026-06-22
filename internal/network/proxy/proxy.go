package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// Server is the transparent HTTP/HTTPS forward proxy.
type Server struct {
	cfg        *config.ProxyConfig
	logger     *logging.Logger
	intercept  *interceptor
	ca         *CA // nil when MITM disabled
	httpServer *http.Server
}

// NewServer constructs the proxy server. If MITM is enabled the local CA is
// loaded (or generated on first boot) from cfg.CertStorage. torNodes may be
// nil to disable Tor exit-node tagging.
func NewServer(cfg *config.ProxyConfig, logger *logging.Logger, pipeline *events.Pipeline, torNodes exitNodeChecker) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		logger:    logger,
		intercept: newInterceptor(pipeline, logger, torNodes),
	}
	if cfg.MITMEnabled {
		ca, err := newCA(cfg.CertStorage)
		if err != nil {
			return nil, err
		}
		s.ca = ca
		logger.Infow("MITM CA loaded", "dir", cfg.CertStorage)
	}
	return s, nil
}

// Start opens the proxy listener. Call from a goroutine or with a cancellable context.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	// Catch-all: all non-CONNECT requests arrive here.
	mux.HandleFunc("/", s.handleHTTP)

	s.httpServer = &http.Server{
		Addr: s.cfg.ListenAddress,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				s.handleConnect(w, r)
				return
			}
			s.handleHTTP(w, r)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	s.logger.Infow("Starting Transparent Proxy", "addr", s.cfg.ListenAddress, "mitm", s.ca != nil)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Errorw("Proxy server failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	return nil
}

// Stop gracefully shuts down the proxy.
func (s *Server) Stop() {
	s.logger.Info("Stopping Transparent Proxy")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Errorw("Proxy shutdown error", "error", err)
	}
}

// handleHTTP forwards plain HTTP requests and logs them.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Build outbound request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)

	resp, err := http.DefaultTransport.(*http.Transport).RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		s.logger.Warnw("Upstream error", "host", r.Host, "error", err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	_, port, _ := net.SplitHostPort(r.Host)
	s.intercept.logRequest(r, port, time.Since(start), resp.StatusCode)
}

// handleConnect implements HTTP CONNECT for TLS tunnelling.
// With MITM disabled this is a raw TCP relay; with MITM enabled the proxy
// decrypts, inspects, and re-encrypts the stream.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host, "443")

	// ---- MITM path ----
	if s.ca != nil {
		s.handleMITM(w, r, host, port)
		return
	}

	// ---- Simple tunnel (no inspection) ----
	upstream, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "tunnel failed", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		upstream.Close()
		return
	}

	// Tell client the tunnel is open
	w.WriteHeader(http.StatusOK)
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}

	// Bidirectional relay
	go relay(upstream, client)
	relay(client, upstream)

	s.intercept.logTunnel(r.RemoteAddr, r.Host)
}

// handleMITM performs a full man-in-the-middle interception on a CONNECT tunnel.
func (s *Server) handleMITM(w http.ResponseWriter, r *http.Request, host, port string) {
	cert, err := s.ca.certFor(host)
	if err != nil {
		s.logger.Errorw("MITM cert generation failed", "host", host, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	// Acknowledge CONNECT to client
	w.WriteHeader(http.StatusOK)
	raw, _, err := hj.Hijack()
	if err != nil {
		return
	}

	// TLS-wrap the client connection with the forged certificate
	tlsConn := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		s.logger.Warnw("MITM client handshake failed", "host", host, "error", err)
		raw.Close()
		return
	}

	// Read the now-decrypted HTTP request from the client
	clientBuf := bufio.NewReader(tlsConn)
	clientReq, err := http.ReadRequest(clientBuf)
	if err != nil {
		// Fallback: just relay bytes if we can't parse HTTP
		upstream, dialErr := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{})
		if dialErr != nil {
			tlsConn.Close()
			return
		}
		go relay(upstream, tlsConn)
		relay(tlsConn, upstream)
		return
	}

	// Forward to real upstream over TLS
	start := time.Now()
	upstream, err := tls.Dial("tcp", net.JoinHostPort(host, port), &tls.Config{})
	if err != nil {
		tlsConn.Close()
		s.logger.Warnw("MITM upstream dial failed", "host", host, "error", err)
		return
	}
	defer upstream.Close()

	if err := clientReq.Write(upstream); err != nil {
		tlsConn.Close()
		return
	}
	upstreamBuf := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamBuf, clientReq)
	if err != nil {
		tlsConn.Close()
		return
	}
	defer resp.Body.Close()

	resp.Write(tlsConn)
	tlsConn.Close()

	s.intercept.logRequest(clientReq, port, time.Since(start), resp.StatusCode)
}

// relay copies data from src to dst until EOF or error.
func relay(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// copyHeaders copies HTTP headers, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	skip := map[string]bool{
		"Connection":          true,
		"Proxy-Connection":    true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	for k, vv := range src {
		if skip[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// splitHostPort splits host:port with a default port fallback.
func splitHostPort(addr, defaultPort string) (string, string) {
	if !strings.Contains(addr, ":") {
		return addr, defaultPort
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defaultPort
	}
	return host, port
}
