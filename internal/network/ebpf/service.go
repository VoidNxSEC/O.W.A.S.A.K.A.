package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// connectEvent mirrors struct connect_event in probe.c exactly (field
// order and natural alignment — no gaps on amd64, so no manual padding
// is needed for binary.Read to line up with the kernel-written bytes).
type connectEvent struct {
	PID   uint32
	Comm  [16]byte
	DAddr uint32 // network byte order
	DPort uint16 // network byte order
}

// exitNodeChecker reports whether an IP is a known Tor exit/relay node.
// Satisfied by *tor.ExitNodeService; kept local to avoid importing
// internal/network/tor here (this package only needs the one method).
type exitNodeChecker interface {
	IsExitNode(ip string) bool
}

// Service watches outbound TCP connect() attempts on the local host via
// a kprobe on tcp_v4_connect, filtering in userspace against configured
// Tor ports / known Tor exit nodes (see config.EBPFConfig). Requires
// CAP_BPF + CAP_PERFMON on kernel >= 5.8; failure to start is logged and
// non-fatal — the rest of OWASAKA continues running without it.
type Service struct {
	cfg      *config.EBPFConfig
	logger   *logging.Logger
	pipeline *events.Pipeline
	torNodes exitNodeChecker

	objs   probeObjects
	link   link.Link
	reader *ringbuf.Reader
}

// NewService constructs the service (does not start it). torNodes may
// be nil to disable Tor exit-node cross-referencing.
func NewService(cfg *config.EBPFConfig, logger *logging.Logger, pipeline *events.Pipeline, torNodes exitNodeChecker) *Service {
	return &Service{cfg: cfg, logger: logger, pipeline: pipeline, torNodes: torNodes}
}

// Start loads the eBPF program, attaches the kprobe, and begins reading
// the ring buffer in a background goroutine.
func (s *Service) Start(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.logger.Info("eBPF host network monitor is disabled")
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		s.logger.Warnw("Failed to remove memlock rlimit for eBPF", "error", err)
	}

	if err := loadProbeObjects(&s.objs, nil); err != nil {
		return fmt.Errorf("ebpf: load probe objects (kernel may lack BPF/CAP_BPF support): %w", err)
	}

	kp, err := link.Kprobe("tcp_v4_connect", s.objs.TraceTcpV4Connect, nil)
	if err != nil {
		s.objs.Close()
		return fmt.Errorf("ebpf: attach kprobe tcp_v4_connect: %w", err)
	}
	s.link = kp

	reader, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.link.Close()
		s.objs.Close()
		return fmt.Errorf("ebpf: open ringbuf reader: %w", err)
	}
	s.reader = reader

	s.logger.Infow("eBPF host network monitor started", "hook", "kprobe/tcp_v4_connect")
	go s.readLoop(ctx)
	return nil
}

// Stop releases the kprobe link, ringbuf reader, and loaded program/map.
func (s *Service) Stop() {
	if s.reader != nil {
		s.reader.Close()
	}
	if s.link != nil {
		s.link.Close()
	}
	s.objs.Close()
}

func (s *Service) readLoop(ctx context.Context) {
	go func() {
		<-ctx.Done()
		s.reader.Close()
	}()

	for {
		record, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			s.logger.Warnw("eBPF ringbuf read error", "error", err)
			continue
		}

		var ev connectEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		s.handleEvent(ev)
	}
}

func (s *Service) handleEvent(ev connectEvent) {
	destIP := net.IP(make([]byte, 4))
	binary.BigEndian.PutUint32(destIP, ev.DAddr) // skc_daddr is already network byte order
	destPort := ntohs(ev.DPort)

	isTorPort := containsInt(s.cfg.TorPorts, int(destPort))
	isTorExitNode := s.torNodes != nil && s.torNodes.IsExitNode(destIP.String())

	if !s.cfg.WatchAllEgress && !isTorPort && !isTorExitNode {
		return
	}

	comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
	s.pipeline.PushNetworkEvent(models.NetworkEvent{
		Type:        models.EventTor,
		Source:      fmt.Sprintf("pid:%d:%s", ev.PID, comm),
		Destination: fmt.Sprintf("%s:%d", destIP.String(), destPort),
		Metadata: map[string]any{
			"local_process": comm,
			"pid":           ev.PID,
			"tor_exit_node": isTorExitNode,
			"tor_port":      isTorPort,
		},
	})
}

// ntohs converts a network-byte-order uint16 (as stored by the kernel
// in skc_dport) to host byte order for display.
func ntohs(n uint16) uint16 {
	return (n << 8) | (n >> 8)
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
