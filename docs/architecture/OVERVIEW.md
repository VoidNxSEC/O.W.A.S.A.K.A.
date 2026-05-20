# OWASAKA SIEM - Architecture Overview

## Executive Summary

O.W.A.S.A.K.A. (Open Watchful Air-gapped Security Analysis Kit & Architecture) is a zero-trust SIEM platform designed for complete isolation and surgical precision in security monitoring. Built entirely in Golang with a Svelte frontend, it operates on dedicated hardware with no external network dependencies.

---

## Design Philosophy

### 1. Isolation-First Design

**Principle**: Air-gapped by architecture, not configuration

- **Physical Isolation**: Runs exclusively on dedicated hardware
- **Network Segmentation**: No external network access by design
- **Local Persistence**: All data stored on connected NAS cluster
- **Self-Contained**: Zero external runtime dependencies

### 2. Defense in Depth

**Principle**: Security through layered protection

```
Layer 1: Hardware Isolation (dedicated device)
   ↓
Layer 2: Operating System Hardening
   ↓
Layer 3: Application Security (memory-safe Go)
   ↓
Layer 4: Data Encryption (AES-256-GCM)
   ↓
Layer 5: Audit & Integrity (immutable logs)
```

### 3. Elegance Over Complexity

**Principle**: Simple, efficient, beautiful

- Clean, modern UI with dark mode
- &lt;500MB memory footprint (idle)
- &lt;100ms UI response time (p95)
- Single binary deployment

### 4. Signal Over Noise

**Principle**: Actionable intelligence, not data deluge

- ML-based anomaly detection
- Correlation engine for complex threats
- Customizable alerting thresholds
- Intelligent event aggregation

---

## System Architecture

### High-Level Component View

```
┌───────────────────────────────────────────────────────────────┐
│                     Presentation Layer                        │
│  ┌────────────────┐         ┌──────────────────┐             │
│  │  Svelte Web UI │◄────────┤  WebSocket API   │             │
│  │   (TypeScript) │         │   (Real-time)    │             │
│  └────────────────┘         └──────────────────┘             │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                      Application Layer                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Golang Core Engine                         │ │
│  ├─────────────────┬─────────────────┬─────────────────────┤ │
│  │    Network      │   Discovery     │    Analytics        │ │
│  │  Intelligence   │     Engine      │     Engine          │ │
│  ├─────────────────┼─────────────────┼─────────────────────┤ │
│  │ • DNS Resolver  │ • Physical Scan │ • Stream Processing │ │
│  │ • Proxy/DPI     │ • Virtual Scan  │ • Correlation Rules │ │
│  │ • Topology Map  │ • Attack Surface│ • ML Anomaly Detect │ │
│  └─────────────────┴─────────────────┴─────────────────────┘ │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌───────────────────────────────▼───────────────────────────────┐
│                       Storage Layer                           │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              NAS Integration Layer                      │ │
│  ├─────────────────────────────────────────────────────────┤ │
│  │  Encryption │ Integrity Verification │ Snapshot Manager │ │
│  │ (AES-256-GCM)│   (Merkle Trees)      │  (Versioning)   │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
```

---

## Core Subsystems

### 1. Network Intelligence Layer

**Purpose**: Monitor and analyze all network activity with surgical precision

#### Components:

**1.1 High-Performance DNS Resolver**

- Custom DNS resolver with complete query logging
- DNS-over-HTTPS (DoH) support for external queries
- Query pattern analysis and anomaly detection
- Malicious domain detection via local threat feeds

**Technical Details:**

- Built using `golang.org/x/net/dns`
- Query cache with TTL management
- Async processing for non-blocking operations
- Metrics: queries/sec, cache hit ratio, anomaly score

**1.2 Transparent Proxy Engine**

- mTLS termination for SSL/TLS inspection
- Multi-protocol support (HTTP/HTTPS/WebSocket/gRPC)
- Deep Packet Inspection (DPI) hooks
- Traffic shaping and QoS

**Technical Details:**

- Uses `net/http` with custom `Transport`
- Certificate generation for MITM inspection
- Protocol detection via magic bytes
- Connection pooling for performance

**1.3 Network Topology Mapper**

- Active discovery (ARP, ICMP, mDNS)
- Passive fingerprinting via traffic analysis
- Device classification using ML
- Relationship graph construction

**Technical Details:**

- `gopacket` for packet capture
- Graph storage using adjacency lists
- Periodic scanning (configurable intervals)
- Change detection with diffing algorithm

---

### 2. Asset Discovery Engine

**Purpose**: Map every asset - physical, virtual, dormant, or ghost

#### Components:

**2.1 Physical Device Enumerator**

- USB/Thunderbolt/PCIe device enumeration
- Hardware inventory via system APIs
- Firmware version detection
- Hardware security module (HSM) discovery

**Technical Details:**

- Linux: `/sys/bus`, `/proc/bus`
- Cross-platform abstractions
- Continuous monitoring for hotplug events

**2.2 Virtual Machine Scanner**

- Hypervisor detection (libvirt, VMware, Hyper-V)
- VM inventory via APIs
- Resource allocation tracking
- Snapshot and backup detection

**Technical Details:**

- libvirt Go bindings
- VMware vSphere API client
- Hyper-V WMI queries (Windows)

**2.3 Container Scanner**

- Docker/Podman/containerd integration
- Container inventory and status
- Image vulnerability scanning
- Network namespace mapping

**Technical Details:**

- Docker API client
- Containerd CRI interface
- Image layer analysis

**2.4 Attack Surface Mapper**

- **Full port scan** (0-65535, TCP & UDP)
- Service fingerprinting
- Banner grabbing
- TLS/SSL certificate analysis
- Detection of:
  - Active services
  - Dormant services (listening but not responding)
  - Ghost ports (development/debug endpoints)
  - Backdoor indicators

**Technical Details:**

- Custom port scanner (SYN scan, Connect scan)
- Parallel scanning with rate limiting
- Service signature database
- Non-intrusive probing

**2.5 Continuous Reconciliation Engine**

- Periodic re-scanning (configurable)
- State diffing and change detection
- Drift analysis and alerting
- Historical state tracking

**Technical Details:**

- Merkle trees for efficient state comparison
- Event-driven architecture
- Time-series database for history

---

### 3. Browser Integration Layer

**Purpose**: Secure, monitored browsing with forensic-grade logging

#### Components:

**3.1 Firefox ESR Launcher**

- Self-hosted Firefox with enforced policies
- Profile isolation per context
- Filesystem sandboxing
- Network namespace isolation

**Technical Details:**

- Custom `user.js` for hardening
- Policy enforcement via `policies.json`
- Process sandboxing

**3.2 Browser Automation**

- WebDriver/CDP integration
- Screenshot capture
- HAR (HTTP Archive) logging
- Cookie and session management

**Technical Details:**

- Chrome DevTools Protocol
- Selenium WebDriver
- Automated forensic captures

**3.3 Security Policy Enforcer**

- Certificate pinning
- Extension lockdown
- Telemetry disabled
- Content Security Policy (CSP)

---

### 4. Storage & Persistence Layer

**Purpose**: Encrypted, integrity-verified storage on local NAS

#### Components:

**4.1 NAS Connector**

- Multi-protocol support (NFS, SMB, iSCSI)
- Automatic failover
- Connection health monitoring
- Bandwidth throttling

**4.2 Encryption Engine**

- Per-file encryption (AES-256-GCM)
- Key derivation (Argon2id)
- HSM integration for key storage
- Encrypted metadata

**4.3 Integrity Verifier**

- Merkle tree verification
- Tamper detection
- Append-only audit logs
- Snapshot management

**Technical Details:**

- Copy-on-write for versioning
- Deduplication (content-addressable storage)
- Compression (zstd)

---

### 5. Analytics & Correlation Engine

**Purpose**: Transform data into actionable intelligence

#### Components:

**5.1 Stream Processor**

- Event ingestion pipeline
- Complex Event Processing (CEP)
- Real-time pattern matching
- Event normalization

**Technical Details:**

- In-memory event buffer
- Sliding window analysis
- Backpressure handling

**5.2 Correlation Engine**

- SIGMA rule support
- Custom DSL for rules
- Multi-source correlation
- Threat intelligence integration

**Technical Details:**

- Rule compiler and optimizer
- Graph-based threat hunting
- Behavioral baselining

**5.3 ML Anomaly Detector**

- Unsupervised learning
- LSTM for time-series prediction
- Isolation Forest for outliers
- Auto-tuning thresholds

**Technical Details:**

- TensorFlow Go bindings (future)
- Statistical anomaly detection (current)
- Model versioning

---

## Data Flow

### Event Collection → Processing → Storage

```
1. Event Source (Network, System, Browser)
      ↓
2. Normalization (Structured JSON)
      ↓
3. Enrichment (Context, Threat Intel)
      ↓
4. Correlation (Rule Matching)
      ↓
5. Analysis (ML Anomaly Detection)
      ↓
6. Alert Generation (If threshold exceeded)
      ↓
7. Storage (Encrypted NAS)
      ↓
8. UI Update (WebSocket push)
```

---

## Security Considerations

### Threat Model

**In Scope:**

- Network-based attacks
- Malware on monitored systems
- Insider threats (monitored users)
- Configuration drift
- Supply chain attacks (dependency scanning)

**Out of Scope:**

- Physical attacks on SIEM hardware (assumed controlled)
- Malicious SIEM operator (trusted administrator)
- NAS compromise (assumed in trusted segment)

### Security Controls

**1. Memory Safety**

- Golang (memory-safe by design)
- No C/C++ dependencies
- Bounds checking

**2. Input Validation**

- All external input sanitized
- Strict type checking
- Schema validation for configs

**3. Least Privilege**

- Capabilities-based model
- No root required (CAP_NET_RAW for packet capture)
- Isolated processes

**4. Cryptography**

- AES-256-GCM for data at rest
- TLS 1.3 for data in transit
- Argon2id for key derivation
- Secure random number generation

**5. Audit & Logging**

- Immutable append-only logs
- Cryptographic signatures
- Tamper detection

---

## Performance Characteristics

### Resource Usage

| Metric           | Target           | Measured (PHASE 0) |
| ---------------- | ---------------- | ------------------ |
| Memory (idle)    | &lt;500MB        | TBD                |
| Memory (active)  | &lt;2GB          | TBD                |
| CPU (idle)       | &lt;5%           | TBD                |
| CPU (scanning)   | &lt;50%          | TBD                |
| Disk I/O         | &lt;100MB/s      | TBD                |
| Network overhead | &lt;5% bandwidth | TBD                |

### Scalability

- **Monitored Assets**: Up to 10,000 devices
- **Events/sec**: Up to 100,000
- **Storage**: Multi-TB NAS cluster
- **Retention**: Configurable (default: 90 days)

---

## Deployment Model

### Hardware Requirements

- **CPU**: 4+ cores (8+ recommended)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB local SSD (for temp data)
- **NAS**: Multi-TB capacity
- **Network**: Gigabit Ethernet

### Software Requirements

- **OS**: Linux (Ubuntu 22.04+, Debian 12+)
- **Go**: 1.22+ (tested on 1.24.7)
- **Node.js**: 18+ (for web UI build)
- **Firefox ESR**: Latest

### Installation

Single binary deployment:

```bash
./oswaka --config /etc/oswaka/config.yaml
```

Systemd service:

```bash
systemctl enable oswaka
systemctl start oswaka
```

---

## Future Enhancements

### Post-MVP Features

1. **Distributed Mode**: Multi-node correlation
2. **Blockchain Audit Logs**: Enhanced immutability
3. **AR/VR Visualization**: 3D network graphs
4. **Voice Control**: Natural language queries
5. **FPGA Acceleration**: Hardware packet inspection

---

## References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SIGMA Rules](https://github.com/SigmaHQ/sigma)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

**Document Version**: 0.1.0
**Last Updated**: 2025-10-25
**Status**: PHASE 0 - Foundation
**Author**: Marcos Pina
