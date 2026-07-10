# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**O.W.A.S.A.K.A.** (Open Watchful Air-gapped Security Analysis Kit & Architecture) — a zero-trust, air-gapped SIEM platform. Go backend + SvelteKit frontend. Module path: `github.com/marcosfpina/O.W.A.S.A.K.A`.

## Development Environment

Nix flakes is the recommended approach — it provisions Go, Node.js, network tools (nmap, tcpdump, tshark), and all Go tooling automatically:

```bash
nix develop        # enter shell (shows welcome banner with all aliases)
```

Inside the nix shell, the `oswaka-dev` script and `make` aliases are available. Outside Nix, use `make` targets directly.

## Common Commands

### Backend (Go)

```bash
make build            # build ./bin/oswaka (runs go mod download + go build)
make build-release    # optimized release binary (CGO_ENABLED=1, strips debug)
make run              # build and run with configs/examples/default.yaml
make dev              # hot reload via `air` (requires .air.toml)
make test             # go test -v -race -coverprofile=coverage.out ./...
make test-coverage    # test + generate coverage.html
make test-integration # go test -tags=integration ./...
make benchmark        # go test -bench=. -benchmem ./...
make lint             # golangci-lint run --timeout=5m
make fmt              # go fmt ./...
make vet              # go vet ./...
make check            # fmt + vet + lint + test (full CI gate)
make clean            # remove bin/, coverage files, go caches
```

Run a single test package:
```bash
go test -v -run TestFunctionName ./internal/analytics/correlation/...
```

### Frontend (SvelteKit)

```bash
cd web
pnpm dev       # dev server (Vite)
pnpm build     # production build
pnpm check     # svelte-check type checking
```

### Running the binary directly

```bash
./bin/oswaka --config configs/examples/default.yaml
./bin/oswaka --version
```

The binary requires `CAP_NET_RAW` / `CAP_NET_ADMIN` for packet capture. The NixOS module (`nixosModules.default`) handles this via `AmbientCapabilities`.

## Architecture

### Data Flow (Event Pipeline)

All intelligence modules funnel events into a central `events.Pipeline` (`internal/events/pipeline.go`), which:
1. Persists to BoltDB via `db.Repository`
2. Pushes to WebSocket clients via `api.WSHub`
3. Optionally publishes to NATS (Spectre Fleet integration)
4. Passes through `StreamEnricher` (sliding-window enrichment)
5. Feeds `CorrelationEngine` (YAML rule matching)
6. Notifies `EventObserver` (ML anomaly detection)
7. Updates `TopologyMapper` (D3.js network graph)

The pipeline is wired in `internal/app/app.go` — this is the single place where all 19 services are initialized and connected.

### Key Interfaces (`internal/events/pipeline.go`)

- `CorrelationEngine` — `Analyze(NetworkEvent)` / `AnalyzeAsset(Asset)`
- `TopologyMapper` — `OnAsset(Asset)` / `OnEvent(NetworkEvent)`
- `StreamEnricher` — `Enrich(NetworkEvent) NetworkEvent`
- `EventObserver` — `Observe(NetworkEvent)` (passive, non-blocking)

### Module Map

| Path | Responsibility |
|------|---------------|
| `cmd/oswaka/` | Entry point — flags, config load, logger init, `app.New().Run()` |
| `internal/app/app.go` | Wires all 19 services; handles graceful shutdown |
| `internal/api/` | HTTP server + WebSocket hub (`gorilla/websocket`) + Prometheus instrumentation |
| `internal/events/` | Pipeline bus + NATS publisher (Spectre Event schema) |
| `internal/models/` | `NetworkEvent` and `Asset` — the two core data types |
| `internal/network/dns/` | Custom DNS resolver (`miekg/dns`), TTL cache, threat detection |
| `internal/network/proxy/` | Transparent HTTP/HTTPS MITM proxy, DPI |
| `internal/network/discovery/` | ARP + ICMP + mDNS scanner |
| `internal/network/topology/` | Live network graph builder → D3.js export |
| `internal/discovery/attack_surface/` | Full TCP port scanner (0–65535), banner grabbing |
| `internal/discovery/physical/` | sysfs USB/PCI enumeration |
| `internal/discovery/virtual/` | Docker socket + libvirt scanner |
| `internal/discovery/reconciliation/` | Asset drift detection engine |
| `internal/browser/firefox/` | Hardened Firefox launcher (profile isolation, policies) |
| `internal/browser/automation/` | CDP client, HAR capture, screenshots |
| `internal/storage/db/` | BoltDB (bbolt) wrapper + `Repository` |
| `internal/storage/integrity/` | Merkle tree verifier + immutable audit log |
| `internal/storage/nas/` | NFS/SMB connector |
| `internal/analytics/stream/` | In-memory event pipeline, sliding window counters (1m/5m/15m) |
| `internal/analytics/correlation/` | YAML rule engine + DGA detection; built-in rules embedded from `internal/analytics/correlation/rules/*.yaml` |
| `internal/analytics/ml/` | Isolation Forest + 7-day behavioral baseline (gob persistence) |
| `pkg/config/` | YAML config loader (`configs/examples/default.yaml` is the reference) |
| `pkg/logging/` | zap `SugaredLogger` wrapper with lumberjack rotation |

### Core Models (`internal/models/`)

- `NetworkEvent` — `{ID, Type, Source, Destination, Metadata map[string]any, Timestamp}`
- `EventType` constants: `EventDNS`, `EventPortScan`, `EventARP`, `EventPhysical`, `EventAlert`, `EventProxy`, `EventVM`
- `Asset` — carries `RiskScore`, `IPAddresses`, `Status`, `ParentID/Children` for hierarchy

### Configuration

Config is YAML, loaded via `pkg/config/Load(path)`. The canonical reference is `configs/examples/default.yaml`. Key env var overrides: `NATS_URL` (overrides `nats_url`), `OSWAKA_ENV`, `OSWAKA_CONFIG`. The `analytics.correlation.rules_dir` is optional — use it to add operator-specific rules on top of the built-in set.

### Detection Rules

Built-in rules are YAML files embedded into the binary at `internal/analytics/correlation/rules/` (14 rules covering: port scan, DNS tunneling, DGA detection, brute force, ARP spoofing, lateral movement, service enumeration, malicious TLD, suspicious proxy, canary tokens, VM escape, Tor, anomalous volume). They are active out-of-the-box without any filesystem setup.

Operator rules (additional or site-specific) go in the directory configured by `analytics.correlation.rules_dir` (default: `/etc/oswaka/rules` for NixOS deployments). These are appended to the built-in set at startup — a restart is required to pick up changes (hot-reload is a known gap).

### Frontend

SvelteKit + TypeScript + D3.js under `web/`. Uses `pnpm`. The WebSocket endpoint (`/ws`) streams JSON messages from the Go hub. Topology data is served via `GET /api/topology` (D3 force-directed format). Stats via `GET /api/stats`.

## NixOS Module

`nixosModules.default` (in `flake.nix`) exposes `services.owasaka.*` options. It creates a system user/group `owasaka`, runs as a systemd service with `CAP_NET_RAW` + `CAP_NET_ADMIN`, and has hardened systemd options. Useful when deploying on NixOS.
