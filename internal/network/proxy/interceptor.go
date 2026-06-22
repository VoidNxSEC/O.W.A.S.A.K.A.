package proxy

import (
	"net"
	"net/http"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// exitNodeChecker reports whether an IP is a known Tor exit/relay node.
// Satisfied by *tor.ExitNodeService; kept as a narrow local interface
// so this package doesn't import internal/network/tor directly.
type exitNodeChecker interface {
	IsExitNode(ip string) bool
}

// interceptor captures HTTP request metadata and emits pipeline events.
type interceptor struct {
	pipeline *events.Pipeline
	logger   *logging.Logger
	torNodes exitNodeChecker // nil when Tor detection is disabled
}

func newInterceptor(pipeline *events.Pipeline, logger *logging.Logger, torNodes exitNodeChecker) *interceptor {
	return &interceptor{pipeline: pipeline, logger: logger, torNodes: torNodes}
}

// tagTorExitNode adds a "tor_exit_node" flag to meta when host (an
// address, optionally "host:port") is a literal IP matching a known
// Tor exit/relay. Domain names are left unresolved here to avoid extra
// DNS lookups in the hot path — only literal-IP CONNECT/request targets
// are checked.
func (i *interceptor) tagTorExitNode(meta map[string]any, host string) {
	if i.torNodes == nil {
		return
	}
	h := host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		h = hostOnly
	}
	if net.ParseIP(h) == nil {
		return
	}
	if i.torNodes.IsExitNode(h) {
		meta["tor_exit_node"] = true
	}
}

// logRequest emits a PROXY NetworkEvent for a captured HTTP request.
func (i *interceptor) logRequest(r *http.Request, port string, dur time.Duration, statusCode int) {
	proto := DetectProtocol(r, port)
	meta := ExtractMetadata(r, proto)
	meta["duration_ms"] = dur.Milliseconds()
	if statusCode > 0 {
		meta["status_code"] = statusCode
	}

	clientIP := r.RemoteAddr
	targetHost := r.Host
	i.tagTorExitNode(meta, targetHost)

	i.pipeline.PushNetworkEvent(models.NetworkEvent{
		Type:        models.EventProxy,
		Source:      clientIP,
		Destination: targetHost,
		Metadata:    meta,
		Timestamp:   time.Now(),
	})
}

// logTunnel emits a PROXY event for a CONNECT tunnel (no decryption).
func (i *interceptor) logTunnel(clientAddr, targetHost string) {
	meta := map[string]any{
		"method":   "CONNECT",
		"protocol": string(ProtoHTTPS),
		"tunnel":   true,
	}
	i.tagTorExitNode(meta, targetHost)

	i.pipeline.PushNetworkEvent(models.NetworkEvent{
		Type:        models.EventProxy,
		Source:      clientAddr,
		Destination: targetHost,
		Metadata:    meta,
		Timestamp:   time.Now(),
	})
}
