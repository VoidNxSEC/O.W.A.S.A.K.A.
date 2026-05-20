# OWASAKA SIEM - Development Phases

## Development Strategy

This document outlines the phased development approach for building the O.W.A.S.A.K.A. SIEM platform, from foundation to full production deployment.

---

## PHASE 0: Foundation & Environment Setup ✅

**Status**: IN PROGRESS
**Duration**: Week 1
**Objective**: Establish the development substrate and core dependencies

### Deliverables

- [x] Repository structure initialized
- [x] Go module configuration (go.mod)
- [x] Directory layout (/cmd, /internal, /pkg, /configs, /web, /docs)
- [x] Build system (Makefile)
- [x] .gitignore for Go + Svelte project
- [x] README.md with project overview
- [x] Architecture documentation (OVERVIEW.md, DATA_MODEL.md)
- [ ] Configuration templates (YAML examples)
- [ ] Basic logging infrastructure (pkg/logging)
- [ ] Basic configuration loader (pkg/config)

### Success Criteria

- [ ] `make build` produces a binary
- [ ] `make test` runs (even with no tests yet)
- [ ] Documentation is comprehensive
- [ ] Project structure follows Go best practices

---

## PHASE 1: Network Intelligence Layer

**Status**: PENDING
**Duration**: Week 2-3
**Objective**: Build the nervous system - network monitoring with surgical precision

### Components to Build

#### 1.1 High-Performance DNS Resolver

**Location**: `internal/network/dns/`

**Files to Create**:

- `resolver.go` - Core DNS resolver
- `cache.go` - Query caching with TTL
- `logger.go` - Query logging
- `analyzer.go` - Pattern analysis and anomaly detection
- `resolver_test.go` - Unit tests

**Features**:

- Custom DNS resolver with complete query logging
- DNS-over-HTTPS (DoH) support
- Query pattern analysis
- Malicious domain detection (local threat feeds)
- Metrics: queries/sec, cache hit ratio, anomaly score

**Dependencies**:

```
go get golang.org/x/net/dns
go get github.com/miekg/dns
```

#### 1.2 Transparent Proxy Engine

**Location**: `internal/network/proxy/`

**Files to Create**:

- `proxy.go` - HTTP/HTTPS proxy server
- `interceptor.go` - Request/response interception
- `tls.go` - mTLS termination & cert generation
- `dpi.go` - Deep packet inspection hooks
- `protocol.go` - Protocol detection
- `proxy_test.go` - Unit tests

**Features**:

- mTLS termination for SSL/TLS inspection
- Multi-protocol support (HTTP/HTTPS/WebSocket/gRPC)
- Deep Packet Inspection (DPI)
- Traffic shaping and QoS
- Connection pooling

**Dependencies**:

```
go get github.com/elazarl/goproxy
go get golang.org/x/net/http2
```

#### 1.3 Network Discovery Scanner

**Location**: `internal/network/discovery/`

**Files to Create**:

- `scanner.go` - Network scanner orchestrator
- `arp.go` - ARP scanning
- `icmp.go` - ICMP (ping) scanning
- `mdns.go` - mDNS/Bonjour discovery
- `passive.go` - Passive traffic analysis
- `fingerprint.go` - OS/device fingerprinting
- `scanner_test.go` - Unit tests

**Features**:

- Active discovery (ARP, ICMP, mDNS)
- Passive fingerprinting via traffic analysis
- Device classification
- Concurrent scanning with rate limiting

**Dependencies**:

```
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
```

#### 1.4 Network Topology Mapper

**Location**: `internal/network/topology/`

**Files to Create**:

- `graph.go` - Graph data structure
- `builder.go` - Topology construction
- `differ.go` - Change detection
- `visualizer.go` - Graph export for UI
- `graph_test.go` - Unit tests

**Features**:

- Relationship graph construction
- Device categorization
- Change detection with diffing
- Export to JSON for UI visualization

### Success Criteria

- [ ] DNS resolver intercepts and logs all queries
- [ ] Proxy can intercept HTTP/HTTPS traffic
- [ ] Network scanner discovers all devices on local subnet
- [ ] Topology graph accurately represents network
- [ ] All components have >80% test coverage
- [ ] Performance: &lt;100ms DNS lookup, &lt;50ms proxy overhead

### Testing Plan

- Unit tests for each component
- Integration test: Full network monitoring pipeline
- Performance benchmarks
- Load testing (1000+ concurrent connections)

---

## PHASE 2: Asset Discovery & Attack Surface Mapping

**Status**: PENDING
**Duration**: Week 4-5
**Objective**: Map EVERYTHING - physical, virtual, active, dormant, ghost ports

### Components to Build

#### 2.1 Physical Device Enumerator

**Location**: `internal/discovery/physical/`

**Files to Create**:

- `enumerator.go` - Hardware enumeration orchestrator
- `usb.go` - USB device detection
- `pci.go` - PCIe device detection
- `hardware.go` - Hardware inventory
- `enumerator_test.go` - Unit tests

**Features**:

- USB/Thunderbolt/PCIe enumeration
- Hardware inventory via /sys/bus
- Firmware version detection
- Hotplug event monitoring

#### 2.2 Virtual Machine Scanner

**Location**: `internal/discovery/virtual/`

**Files to Create**:

- `vm_scanner.go` - VM scanner orchestrator
- `libvirt.go` - libvirt integration
- `vmware.go` - VMware vSphere integration
- `hyperv.go` - Hyper-V integration (future)
- `vm_scanner_test.go` - Unit tests

**Features**:

- Hypervisor detection
- VM inventory via APIs
- Resource allocation tracking
- Snapshot detection

**Dependencies**:

```
go get libvirt.org/go/libvirt
```

#### 2.3 Container Scanner

**Location**: `internal/discovery/virtual/` (containers are "virtual" assets)

**Files to Create**:

- `container.go` - Container scanning
- `docker.go` - Docker API integration
- `containerd.go` - containerd integration
- `image.go` - Image layer analysis

**Features**:

- Docker/Podman/containerd integration
- Container inventory and status
- Image vulnerability scanning (basic)
- Network namespace mapping

**Dependencies**:

```
go get github.com/docker/docker/client
```

#### 2.4 Attack Surface Mapper

**Location**: `internal/discovery/attack_surface/`

**Files to Create**:

- `mapper.go` - Attack surface orchestrator
- `port_scanner.go` - Full port scanner (0-65535)
- `service_probe.go` - Service fingerprinting
- `banner.go` - Banner grabbing
- `tls_scanner.go` - TLS/SSL analysis
- `mapper_test.go` - Unit tests

**Features**:

- **FULL port scan** (0-65535, TCP & UDP)
- Service fingerprinting
- Banner grabbing
- TLS/SSL certificate analysis
- Detect dormant/ghost services

#### 2.5 Continuous Reconciliation Engine

**Location**: `internal/discovery/reconciler/`

**Files to Create**:

- `reconciler.go` - Reconciliation orchestrator
- `differ.go` - State diffing algorithm
- `scheduler.go` - Periodic re-scanning
- `alerter.go` - Change alerting
- `reconciler_test.go` - Unit tests

**Features**:

- Periodic re-scanning (configurable)
- State diffing (Merkle trees)
- Drift analysis
- Historical tracking

### Success Criteria

- [ ] Discovers all physical devices
- [ ] Discovers all VMs and containers
- [ ] Scans all 65535 ports (TCP) in &lt;60s
- [ ] Detects dormant and ghost services
- [ ] Change detection triggers alerts
- [ ] All components have >80% test coverage

---

## PHASE 3: Self-Hosted Firefox Integration

**Status**: PENDING
**Duration**: Week 6
**Objective**: Secure browsing with forensic-grade logging

### Components to Build

#### 3.1 Firefox Launcher

**Location**: `internal/browser/firefox/`

**Files to Create**:

- `launcher.go` - Firefox process management
- `profile.go` - Profile isolation
- `sandbox.go` - Process sandboxing
- `launcher_test.go` - Unit tests

#### 3.2 Policy Enforcer

**Location**: `internal/browser/policies/`

**Files to Create**:

- `enforcer.go` - Policy application
- `hardening.go` - Security hardening (user.js)
- `extensions.go` - Extension lockdown
- `enforcer_test.go` - Unit tests

#### 3.3 Browser Automation

**Location**: `internal/browser/automation/`

**Files to Create**:

- `driver.go` - WebDriver/CDP integration
- `capture.go` - Screenshot/HAR capture
- `forensics.go` - Forensic logging
- `driver_test.go` - Unit tests

**Dependencies**:

```
go get github.com/tebeka/selenium
go get github.com/chromedp/chromedp  # For CDP
```

### Success Criteria

- [ ] Firefox launches with hardened config
- [ ] All browsing activity logged
- [ ] Screenshots captured on demand
- [ ] HAR files saved for analysis

---

## PHASE 4: Modern, Elegant Frontend (UX Layer)

**Status**: PENDING
**Duration**: Week 7-8
**Objective**: Build a SIEM dashboard that doesn't suck

### Tech Stack

**Selected**: Svelte + TypeScript + Tailwind CSS

### Components to Build

#### 4.1 Dashboard Skeleton

**Location**: `web/src/`

**Files to Create**:

- `App.svelte` - Main application
- `routes/+page.svelte` - Home dashboard
- `routes/+layout.svelte` - Layout wrapper
- `lib/websocket.ts` - WebSocket client
- `stores/events.ts` - Event store
- `stores/assets.ts` - Asset store
- `stores/alerts.ts` - Alert store

#### 4.2 Core Components

**Location**: `web/src/components/`

**Files to Create**:

- `Dashboard.svelte` - Main dashboard
- `NetworkGraph.svelte` - Network topology visualization
- `AlertPanel.svelte` - Alert listing
- `EventStream.svelte` - Real-time event stream
- `AssetList.svelte` - Asset inventory
- `SearchBar.svelte` - Global search

#### 4.3 Visualization

**Dependencies**:

```
npm install d3
npm install cytoscape
npm install chart.js
```

### Success Criteria

- [ ] Real-time updates via WebSocket
- [ ] &lt;100ms UI response time
- [ ] Dark mode by default
- [ ] Responsive design (desktop focus)
- [ ] Bundle size &lt;500KB (gzipped)

---

## PHASE 5: Local NAS Integration & Data Persistence

**Status**: PENDING
**Duration**: Week 9
**Objective**: Secure, encrypted storage with integrity guarantees

### Components to Build

#### 5.1 NAS Connector

**Location**: `internal/storage/nas/`

**Files to Create**:

- `connector.go` - NAS connection manager
- `nfs.go` - NFS client
- `smb.go` - SMB client
- `healthcheck.go` - Connection monitoring
- `connector_test.go` - Unit tests

#### 5.2 Encryption Engine

**Location**: `internal/storage/crypto/`

**Files to Create**:

- `vault.go` - Encryption/decryption
- `keygen.go` - Key derivation (Argon2id)
- `aes.go` - AES-256-GCM implementation
- `vault_test.go` - Unit tests

#### 5.3 Integrity Verifier

**Location**: `internal/storage/integrity/`

**Files to Create**:

- `verifier.go` - Integrity checking
- `merkle.go` - Merkle tree implementation
- `audit.go` - Audit log (append-only)
- `snapshot.go` - Snapshot management
- `verifier_test.go` - Unit tests

### Success Criteria

- [ ] Connects to NAS via NFS/SMB
- [ ] All data encrypted at rest (AES-256-GCM)
- [ ] Integrity verification passes
- [ ] Audit logs are tamper-proof
- [ ] Automatic snapshot creation

---

## PHASE 6: Intelligence & Correlation Engine

**Status**: PENDING
**Duration**: Week 10-11
**Objective**: Turn data into actionable insights

### Components to Build

#### 6.1 Stream Processor

**Location**: `internal/analytics/stream/`

**Files to Create**:

- `processor.go` - Event stream processor
- `buffer.go` - In-memory event buffer
- `window.go` - Sliding window analysis
- `normalizer.go` - Event normalization
- `processor_test.go` - Unit tests

#### 6.2 Correlation Engine

**Location**: `internal/analytics/correlation/`

**Files to Create**:

- `engine.go` - Correlation orchestrator
- `rule_parser.go` - SIGMA rule parser
- `matcher.go` - Pattern matching
- `graph.go` - Graph-based correlation
- `engine_test.go` - Unit tests

**Dependencies**:

```
go get github.com/bradleyjkemp/sigma-go  # SIGMA support
```

#### 6.3 ML Anomaly Detector

**Location**: `internal/analytics/ml/`

**Files to Create**:

- `detector.go` - Anomaly detection orchestrator
- `statistical.go` - Statistical methods
- `isolation_forest.go` - Isolation Forest implementation
- `baseline.go` - Behavioral baselining
- `detector_test.go` - Unit tests

### Success Criteria

- [ ] Processes >10,000 events/sec
- [ ] SIGMA rules work correctly
- [ ] Anomaly detection &lt;5% false positives
- [ ] Correlation across multiple sources
- [ ] All components have >80% test coverage

---

## Post-MVP (Future Phases)

### PHASE 7: Advanced Features

- Distributed mode (multi-node)
- Blockchain-based audit logs
- Hardware acceleration (FPGA)
- AR/VR visualization
- Voice control interface

---

## Development Principles

1. **Build vertical slices** - End-to-end features, not horizontal layers
2. **Test early, test often** - Unit tests before integration tests
3. **Performance benchmark every commit** - No regressions
4. **Document as you code** - godoc comments mandatory
5. **Security review before merge** - Peer review all crypto/network code

---

**Document Version**: 0.1.0
**Last Updated**: 2025-10-25
**Status**: PHASE 0 - Foundation
