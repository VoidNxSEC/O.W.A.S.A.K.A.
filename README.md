# O.W.A.S.A.K.A. SIEM

> **Open Watchful Air-gapped Security Analysis Kit & Architecture**

A zero-trust, air-gapped SIEM platform built for surgical precision monitoring with enterprise-grade security - running locally on dedicated hardware.

---

## Philosophy

> "A SIEM should be like a butler: invisible until needed, impeccably informed when called upon, and never presumptuous about what matters."

**Core Principles:**
- **Isolation-First Design**: Air-gapped by architecture, not configuration
- **Defense in Depth**: Layered security at every level
- **Elegance Over Complexity**: Clean UX, minimal footprint, maximum insight
- **Signal over Noise**: Optimize for what matters

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    O.W.A.S.A.K.A. SIEM                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                 │
│  │  Modern Web UI   │───▶│  WebSocket API   │                 │
│  │  (Svelte + TS)   │    │   (Real-time)    │                 │
│  └──────────────────┘    └──────────────────┘                 │
│                                   │                             │
│  ┌────────────────────────────────▼─────────────────────────┐ │
│  │           Golang Core Engine                             │ │
│  ├──────────────────────────────────────────────────────────┤ │
│  │ Network Intelligence │ Discovery Engine │ Analytics      │ │
│  │  • DNS Resolver      │  • Physical      │  • Correlation │ │
│  │  • Proxy/DPI         │  • Virtual       │  • ML Anomaly  │ │
│  │  • Topology Map      │  • Attack Surface│  • Alerting    │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                   │                             │
│  ┌────────────────────────────────▼─────────────────────────┐ │
│  │         Secure Storage Layer (NAS Integration)           │ │
│  │  • Encrypted at rest (AES-256-GCM)                       │ │
│  │  • Immutable audit logs                                  │ │
│  │  • Integrity verification (Merkle trees)                 │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
        │                          │                    │
        ▼                          ▼                    ▼
   [Physical]              [Virtual/Containers]    [Network]
   Devices                 Docker/VMs              Services
```

---

## Features

### Network Intelligence
- **Custom DNS Resolver** with query logging and anomaly detection
- **Transparent Proxy** with mTLS inspection and protocol detection
- **Network Topology Mapper** with active/passive discovery
- **Deep Packet Inspection** for traffic analysis

### Asset Discovery
- **Multi-layer Discovery**: Physical, virtual, containerized assets
- **Attack Surface Mapping**: ALL ports (0-65535), including dormant services
- **Continuous Reconciliation**: Detect changes and drift in real-time
- **Ghost Port Detection**: Find development/debug endpoints

### Security
- **Air-gapped Architecture**: No external network exposure by design
- **Self-hosted Firefox** with enforced security policies
- **Encrypted Storage**: AES-256-GCM with Argon2id key derivation
- **Immutable Audit Logs**: Tamper-proof event recording

### User Experience
- **Modern, Clean Interface**: Dark mode by default
- **Real-time Updates**: WebSocket-powered live data
- **Customizable Dashboards**: Widget-based layout
- **Low Resource Usage**: <500MB memory footprint (idle)

---

## Project Structure

```
O.W.A.S.A.K.A./
├── cmd/
│   └── oswaka/              # Application entry point
├── internal/                # Private application logic
│   ├── network/            # Network intelligence layer
│   │   ├── dns/           # DNS resolver & logging
│   │   ├── proxy/         # Transparent proxy & DPI
│   │   ├── discovery/     # Network scanning
│   │   └── topology/      # Network graph
│   ├── discovery/         # Asset discovery engine
│   │   ├── physical/      # Physical device enumeration
│   │   ├── virtual/       # VM/container scanning
│   │   ├── attack_surface/# Attack surface mapper
│   │   └── reconciler/    # Change detection
│   ├── browser/           # Firefox integration
│   │   ├── firefox/       # Browser launcher
│   │   ├── policies/      # Security policy enforcer
│   │   └── automation/    # WebDriver integration
│   ├── storage/           # Data persistence
│   │   ├── nas/          # NAS connector
│   │   ├── crypto/       # Encryption/decryption
│   │   └── integrity/    # Verification & checksums
│   └── analytics/         # Intelligence engine
│       ├── stream/       # Event processing
│       ├── correlation/  # Rule engine
│       └── ml/          # Anomaly detection
├── pkg/                   # Public libraries
│   ├── config/           # Configuration management
│   ├── logging/          # Structured logging
│   └── metrics/          # Prometheus metrics
├── web/                   # Frontend application
│   ├── src/
│   │   ├── components/   # Svelte components
│   │   ├── stores/       # State management
│   │   └── lib/         # Utilities
│   └── public/           # Static assets
├── configs/               # Configuration files
│   ├── examples/         # Example configurations
│   └── policies/         # Security policies
└── frontend/              # React frontend experiments
    └── react/            # Vite + React console
```

Documentation now lives in the sibling repository at `../owasaka-docs`.

---

## Quick Start

### Prerequisites

**Option 1: Nix Flakes (Recommended for Development)**
- **Nix with Flakes** - Reproducible development environment
- All dependencies managed automatically
- See the Nix Development Guide in `../owasaka-docs/docs/development/NIX_GUIDE.md`

**Option 2: Manual Installation**
- **Go 1.22+** (tested on 1.24.7)
- **Node.js 18+** (for web UI)
- **Dedicated hardware** (no shared environments)
- **NAS cluster** (for persistent storage)
- **Firefox ESR** (for browser integration)

### Installation with Nix (Recommended)

```bash
# Clone the repository
git clone https://github.com/marcosfpina/O.W.A.S.A.K.A.git
cd O.W.A.S.A.K.A

# Enter development environment (all dependencies auto-installed)
nix develop

# You'll see the O.W.A.S.A.K.A. welcome banner!
# Now you have access to all tools: Go, Node.js, network tools, etc.

# Build the project
oswaka-dev build

# Or use make directly
make build

# Run the SIEM
oswaka-dev run

# Hot reload development mode
oswaka-dev watch

# Show all available commands
oswaka-dev help
```

**What's included in Nix environment:**
- Go 1.22+, Node.js 20, Firefox ESR
- Network tools: nmap, tcpdump, tshark, dig
- Go tools: gopls, delve, golangci-lint, air
- Development utilities: jq, ripgrep, bat, htop
- Custom scripts and aliases

See the complete Nix guide in `../owasaka-docs/docs/development/NIX_GUIDE.md` for advanced usage.

### Installation (Manual)

```bash
# Clone the repository
git clone https://github.com/marcosfpina/O.W.A.S.A.K.A.git
cd O.W.A.S.A.K.A

# Build the project
make build

# Run tests
make test

# Start the SIEM
./bin/oswaka --config configs/examples/default.yaml
```

### Development

```bash
# Install dependencies
make deps

# Run in development mode
make dev

# Run linters
make lint

# Generate documentation
make docs
```

---

## Configuration

Example configuration (`configs/examples/default.yaml`):

```yaml
# Server
server:
  host: "127.0.0.1"
  port: 8080
  websocket:
    enabled: true
    path: "/ws"
    max_connections: 1000

# Logging
logging:
  level: "info"      # debug, info, warn, error
  format: "json"
  output: "stdout"

# Network intelligence
network:
  dns:
    enabled: true
    listen_address: "127.0.0.1:8053"
    upstream_servers: ["1.1.1.1:53", "8.8.8.8:53"]
    threat_detection: true
  discovery:
    enabled: true
    scan_interval_minutes: 60
    methods: [arp, icmp, mdns]

# Attack surface mapping
discovery:
  attack_surface:
    enabled: true
    port_range: { start: 1, end: 65535 }
    banner_grabbing: true

# Analytics
analytics:
  stream:
    enabled: true
    workers: 4
  correlation:
    enabled: true
    sigma_rules_enabled: true

# Metrics
metrics:
  prometheus:
    enabled: true
    listen_address: "127.0.0.1:9090"

# Spectre Fleet event bus
nats_url: "nats://localhost:4222"
```

Full reference: [`configs/examples/default.yaml`](configs/examples/default.yaml)

---

## Development Status

### PHASE 0: Foundation & Environment Setup ✅
- [x] Repository structure + Go module
- [x] Build system (Makefile + Nix flake with `nix develop` shell)
- [x] Configuration templates and validation (`pkg/config/`)
- [x] Architecture documentation

### PHASE 1: Network Intelligence Layer ✅
- [x] High-performance DNS Resolver (`internal/network/dns/`) — miekg/dns, upstream forwarding, query logging
- [x] Transparent Proxy (`internal/network/proxy/`) — HTTP/HTTPS MITM, DPI metadata extraction, TLS cert gen
- [x] Network Topology Mapper (`internal/network/topology/`) — ARP + mDNS, D3.js graph export
- [x] BoltDB Event Persistence (`internal/storage/db/`) — bbolt embedded KV store

### PHASE 2: Asset Discovery ✅
- [x] Virtual/Container discovery — Docker socket scanner + Libvirt XML-RPC + container stats
- [x] Attack surface mapper (`internal/discovery/attack_surface/`) — full TCP 0-65535, banner grabbing, IPv6 safe
- [x] Physical device enumeration (`internal/discovery/physical/`) — sysfs USB + PCI scanning
- [x] Continuous reconciliation (`internal/discovery/reconciliation/`) — asset drift detection + alerting

### PHASE 3: Browser Integration ✅
- [x] Hardened Firefox launcher (`internal/browser/firefox/`) — profile isolation, enterprise policy enforcement
- [x] Browser automation (`internal/browser/automation/`) — CDP client, screenshots, HAR capture, navigation history

### PHASE 4: Modern Frontend ✅
- [x] SvelteKit dashboard (Crimson Red / Glassmorphism design system)
- [x] Real-time WebSocket pipeline (gorilla/websocket + Go event bus)
- [x] D3.js Network Topology Visualization (force-directed graph, live updates)
- [x] Threat Alert HUD with severity classification

### PHASE 5: Analytics Engine ✅
- [x] In-memory Event Pipeline — Pub/Sub with sliding window counters (1m/5m/15m)
- [x] Correlation engine — rule-based threat detection framework
- [x] ML anomaly detection — Isolation Forest (100 trees) + 7-day behavioral baseline

### PHASE 6: SPECTRE Fleet Integration ✅
- [x] NATS publisher (`internal/events/publisher.go`) — Spectre Event schema
- [x] Rust Proxy bridge — NATS EventBus via Axum (ADR-0050)
- [x] JWT Authentication & Rate Limiting

### All 19 Services Wired in `app.go`
Every module above is initialized, started, and connected to the central event pipeline. The system boots as a unified process.

---

## Production Readiness — Resolved Gaps

| Gap | Was | Now | Commit |
|---|---|---|---|
| Test coverage | <5% (2 tests) | **35 tests** across 6 packages | `394f9b6` |
| Correlation rules | 1 hardcoded rule | **YAML rule engine + 10 baseline rules** | `394f9b6` |
| DNS cache | No cache (TODO) | **In-memory TTL cache + background evictor** | `394f9b6` |
| ML persistence | Retrained from zero | **gob serialization, auto-save/load** | `394f9b6` |
| Scanner targets | Hardcoded localhost | **Dynamic from BoltDB asset list** | `394f9b6` |
| CI/CD | None | **GitHub Actions (build+vet+test -race)** | `394f9b6` |

### Remaining
| Gap | Severity | Detail |
|---|---|---|
| OpenTelemetry | LOW | Spectre integration works via NATS; OTel is a nice-to-have |
| Rule hot-reload | LOW | Rules load on startup; restart required for changes |
| Event pipeline tests | MEDIUM | Pipeline + API + topology packages still untested |

---

## Sprint Log

### Sprint 1: Production Hardening (2026-03-28) — COMPLETE
- **P1** Test coverage: 35 tests (correlation, ML, stream, BoltDB, attack surface)
- **P2** YAML rule engine + 10 detection rules (port scan, DNS tunnel, brute force, ARP spoof, lateral movement, service enum, malicious TLD, suspicious proxy, VM escape, anomalous volume)
- **P3** DNS cache, ML model persistence (gob), scanner dynamic targets from asset DB
- **P4** GitHub Actions CI, `make release` target

---

## Performance Targets

- **UI Response Time**: <100ms (p95)
- **Memory Footprint**: <500MB (idle)
- **Network Overhead**: <5% of bandwidth
- **Discovery Scan**: <60s for 1000 assets

---

## Security Model

### Threat Assumptions
- Physical access is controlled
- NAS is in trusted network segment
- Operator is non-malicious (insider threat out of scope)

### Protections
- Memory-safe language (Golang)
- Input validation everywhere
- No external dependencies at runtime
- Reproducible builds
- Encrypted data at rest
- Immutable audit logs

---

## Contributing

This is a personal security infrastructure project. If you're interested in similar work:

1. Fork the repository
2. Study the architecture in `../owasaka-docs/docs/architecture`
3. Build your own variant
4. Share learnings (not code) back

---

## License

**Proprietary** - Personal security infrastructure
Not licensed for commercial use or distribution.

---

## Acknowledgments

Built with inspiration from:
- The Art of Monitoring (James Turnbull)
- Security Engineering (Ross Anderson)
- Designing Data-Intensive Applications (Martin Kleppmann)

---

## Contact

Project maintained by: Marcos Pina
Repository: https://github.com/marcosfpina/O.W.A.S.A.K.A

---

**Status**: 🚀 Pre-Production — Core modules integrated, hardening sprint complete

Last Updated: 2026-03-28
