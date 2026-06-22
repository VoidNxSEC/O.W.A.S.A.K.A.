package proxy

import (
	"context"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// Service manages the transparent proxy lifecycle.
type Service struct {
	cfg      *config.ProxyConfig
	logger   *logging.Logger
	pipeline *events.Pipeline
	torNodes exitNodeChecker
	server   *Server
}

// NewService creates a proxy service (does not start it). torNodes may
// be nil to disable Tor exit-node tagging on proxied traffic.
func NewService(cfg *config.ProxyConfig, logger *logging.Logger, pipeline *events.Pipeline, torNodes exitNodeChecker) *Service {
	return &Service{
		cfg:      cfg,
		logger:   logger,
		pipeline: pipeline,
		torNodes: torNodes,
	}
}

// Start initialises the proxy server and begins accepting connections.
func (s *Service) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.logger.Info("Proxy service is disabled")
		return nil
	}

	srv, err := NewServer(s.cfg, s.logger, s.pipeline, s.torNodes)
	if err != nil {
		return err
	}
	s.server = srv
	return s.server.Start(ctx)
}

// Stop gracefully shuts down the proxy.
func (s *Service) Stop() {
	if s.server != nil {
		s.server.Stop()
	}
}
