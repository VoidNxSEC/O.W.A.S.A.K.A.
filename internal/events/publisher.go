package events

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/metrics"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Publisher wraps a NATS connection for publishing Spectre-schema events.
type Publisher struct {
	nc *nats.Conn
}

// Connect dials the NATS server at the given URL and returns a Publisher.
// The connection is configured for infinite reconnect so owasaka survives
// transient NATS restarts without losing event publishing capability.
//
// NKey authentication is used when NATS_NKEY_SEED is set in the environment
// (the seed string itself, not a file path). Falls back to unauthenticated
// connection for local dev when the env var is absent.
func Connect(natsURL string) (*Publisher, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			fmt.Printf("[owasaka/publisher] NATS disconnected: %v\n", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			fmt.Printf("[owasaka/publisher] NATS reconnected to %s\n", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			fmt.Println("[owasaka/publisher] NATS connection closed")
		}),
	}

	// NKey authentication: prefer inline seed string (12-factor / SOPS-encrypted .env),
	// fall back to seed file path (NixOS file-based secrets).
	if seed := strings.TrimSpace(os.Getenv("NATS_NKEY_SEED")); seed != "" {
		kp, err := nkeys.FromSeed([]byte(seed))
		if err != nil {
			return nil, fmt.Errorf("nats nkey from seed: %w", err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("nats nkey public key: %w", err)
		}
		opts = append(opts, nats.Nkey(pub, kp.Sign))
		fmt.Println("[owasaka/publisher] NATS NKey auth enabled")
	} else if seedFile := strings.TrimSpace(os.Getenv("NATS_NKEY_SEED_FILE")); seedFile != "" {
		opt, err := nats.NkeyOptionFromSeed(seedFile)
		if err != nil {
			return nil, fmt.Errorf("nats nkey from seed file %s: %w", seedFile, err)
		}
		opts = append(opts, opt)
		fmt.Println("[owasaka/publisher] NATS NKey auth enabled (file)")
	}
	if caFile := strings.TrimSpace(os.Getenv("NATS_CA_FILE")); caFile != "" {
		opts = append(opts, nats.RootCAs(caFile))
	}
	if certFile := strings.TrimSpace(os.Getenv("NATS_CLIENT_CERT_FILE")); certFile != "" {
		keyFile := strings.TrimSpace(os.Getenv("NATS_CLIENT_KEY_FILE"))
		if keyFile == "" {
			return nil, fmt.Errorf("nats client key file required when NATS_CLIENT_CERT_FILE is set")
		}
		opts = append(opts, nats.ClientCert(certFile, keyFile))
	}
	if strings.HasPrefix(natsURL, "tls://") {
		opts = append(opts, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12}))
	}

	nc, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect %s: %w", natsURL, err)
	}
	return &Publisher{nc: nc}, nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	if p.nc != nil {
		_ = p.nc.Drain()
	}
}

// IsConnected reports whether the underlying NATS connection is
// currently in CONNECTED state. Safe to call on a nil Publisher —
// returns false. Used by health probes and graceful-degradation paths.
func (p *Publisher) IsConnected() bool {
	if p == nil || p.nc == nil {
		return false
	}
	return p.nc.IsConnected()
}

// RawConn returns the underlying NATS connection for direct operations
// such as subscribing to subjects (used by the neotron compliance
// event subscriber). Returns nil if the publisher is nil or was never
// connected.
func (p *Publisher) RawConn() *nats.Conn {
	if p == nil {
		return nil
	}
	return p.nc
}

// Status returns a human-readable status string for the NATS
// connection. Returns "disabled" for nil Publishers so health probes
// can distinguish "operator disabled NATS" from "NATS broken".
func (p *Publisher) Status() string {
	if p == nil || p.nc == nil {
		return "disabled"
	}
	return p.nc.Status().String()
}

// Event mirrors the Spectre Event schema for JSON serialisation.
type Event struct {
	EventID       string         `json:"event_id"`
	EventType     string         `json:"event_type"`
	Timestamp     time.Time      `json:"timestamp"`
	SourceService string         `json:"source_service"`
	CorrelationID string         `json:"correlation_id"`
	Payload       map[string]any `json:"payload"`
}

// Publish serialises e and publishes it on the given NATS subject.
// Returns an error if the connection is not currently established; the
// caller should treat this as a transient failure — the connection will
// reconnect automatically and subsequent publishes will succeed.
func (p *Publisher) Publish(subject string, e Event) error {
	if !p.nc.IsConnected() {
		return fmt.Errorf("nats not connected (status: %s), event dropped: %s", p.nc.Status(), subject)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if err := p.nc.Publish(subject, data); err != nil {
		return err
	}
	metrics.EventsPublished.WithLabelValues(subject).Inc()
	return nil
}
