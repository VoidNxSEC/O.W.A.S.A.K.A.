// Package tor provides Tor integration for OWASAKA: an outbound SOCKS5
// client for the SIEM's own egress, Tor exit-node detection for traffic
// observed on the monitored network, and hidden-service status helpers.
package tor

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/proxy"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// Client wraps an http.Client whose Transport dials through a local Tor
// SOCKS5 proxy when enabled, so outbound IOC/threat-intel lookups never
// expose the SIEM host's real address. When disabled it is a thin
// pass-through over http.DefaultClient.
type Client struct {
	httpClient *http.Client
}

// NewClient builds a Tor-aware HTTP client per cfg. Returns a non-Tor
// client (not an error) when cfg.SOCKSEnabled is false.
func NewClient(cfg *config.TorConfig, logger *logging.Logger) (*Client, error) {
	if cfg == nil || !cfg.SOCKSEnabled {
		return &Client{httpClient: http.DefaultClient}, nil
	}

	dialer, err := proxy.SOCKS5("tcp", cfg.SOCKSAddress, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("tor: build SOCKS5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("tor: SOCKS5 dialer does not support context")
	}

	logger.Infow("Tor SOCKS5 outbound client enabled", "socks_address", cfg.SOCKSAddress)
	return &Client{
		httpClient: &http.Client{
			Transport: &http.Transport{DialContext: contextDialer.DialContext},
			Timeout:   30 * time.Second,
		},
	}, nil
}

// Do performs an HTTP request through the (possibly Tor-routed) client.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
