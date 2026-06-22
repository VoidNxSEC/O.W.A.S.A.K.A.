package tor

import (
	"context"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// ExitNodeService owns the Tor exit/relay IP list lifecycle: loading the
// local cache at boot and, only if explicitly configured, periodically
// refreshing it from a remote URL. OWASAKA is air-gap-first (see
// config.ObservabilityConfig) — ExitNodeListURL is empty by default, so
// by default this service never makes a network call.
type ExitNodeService struct {
	cfg    *config.TorConfig
	logger *logging.Logger
	client *Client
	list   *ExitNodeList
}

// NewExitNodeService constructs the service (does not start it).
func NewExitNodeService(cfg *config.TorConfig, logger *logging.Logger, client *Client) *ExitNodeService {
	return &ExitNodeService{
		cfg:    cfg,
		logger: logger,
		client: client,
		list:   NewExitNodeList(),
	}
}

// Start loads the local cache (if present) and, when ExitNodeListURL is
// set, spawns a refresh ticker. Refresh failures are logged but
// non-fatal — a stale or empty cache keeps the rest of OWASAKA running.
func (s *ExitNodeService) Start(ctx context.Context) error {
	if !s.cfg.DetectionEnabled {
		s.logger.Info("Tor exit-node detection is disabled")
		return nil
	}

	if s.cfg.ExitNodeListPath != "" {
		if err := s.list.LoadFile(s.cfg.ExitNodeListPath); err != nil {
			s.logger.Warnw("Failed to load cached Tor exit-node list", "error", err)
		} else {
			s.logger.Infow("Loaded Tor exit-node list", "count", s.list.Size(), "path", s.cfg.ExitNodeListPath)
		}
	}

	if s.cfg.ExitNodeListURL == "" {
		return nil
	}

	s.logger.Warnw("Tor exit-node list will be fetched over the network — this deployment is not air-gapped",
		"url", s.cfg.ExitNodeListURL)

	hours := s.cfg.ExitNodeRefreshHours
	if hours <= 0 {
		hours = 24
	}
	interval := time.Duration(hours) * time.Hour

	go func() {
		s.refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.refresh()
			}
		}
	}()
	return nil
}

func (s *ExitNodeService) refresh() {
	if err := s.list.Fetch(s.client, s.cfg.ExitNodeListURL); err != nil {
		s.logger.Warnw("Failed to refresh Tor exit-node list, keeping stale cache", "error", err)
		return
	}
	s.logger.Infow("Refreshed Tor exit-node list", "count", s.list.Size())
	if s.cfg.ExitNodeListPath != "" {
		if err := s.list.SaveFile(s.cfg.ExitNodeListPath); err != nil {
			s.logger.Warnw("Failed to cache refreshed Tor exit-node list", "error", err)
		}
	}
}

// IsExitNode reports whether ip is a known Tor exit/relay node.
func (s *ExitNodeService) IsExitNode(ip string) bool {
	return s.list.Contains(ip)
}
