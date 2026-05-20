# OWASAKA SIEM - Data Model

## Overview

This document defines the data structures and schemas used throughout the O.W.A.S.A.K.A. SIEM platform.

---

## Core Entities

### 1. Asset

Represents any discoverable entity in the monitored environment.

```go
type Asset struct {
    ID           string    `json:"id"`           // UUID
    Type         AssetType `json:"type"`         // Physical, Virtual, Container, Service
    Name         string    `json:"name"`
    Description  string    `json:"description"`

    // Discovery metadata
    FirstSeen    time.Time `json:"first_seen"`
    LastSeen     time.Time `json:"last_seen"`
    DiscoveryMethod string `json:"discovery_method"` // ARP, ICMP, API, etc.

    // Classification
    Category     string    `json:"category"`     // Server, Workstation, Network Device, etc.
    Manufacturer string    `json:"manufacturer"`
    Model        string    `json:"model"`
    Version      string    `json:"version"`

    // Network information
    MACAddress   string    `json:"mac_address,omitempty"`
    IPAddresses  []string  `json:"ip_addresses,omitempty"`
    Hostname     string    `json:"hostname,omitempty"`

    // Security posture
    RiskScore    float64   `json:"risk_score"`   // 0.0 - 10.0
    Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

    // Relationships
    ParentID     string    `json:"parent_id,omitempty"`    // For VMs (hypervisor), containers (host)
    Children     []string  `json:"children,omitempty"`     // VMs on hypervisor, containers on host

    // State
    Status       AssetStatus `json:"status"`      // Active, Inactive, Unknown

    // Metadata
    Tags         []string  `json:"tags"`
    Metadata     map[string]interface{} `json:"metadata"`
}

type AssetType string

const (
    AssetTypePhysical  AssetType = "physical"
    AssetTypeVirtual   AssetType = "virtual"
    AssetTypeContainer AssetType = "container"
    AssetTypeService   AssetType = "service"
    AssetTypeNetwork   AssetType = "network"
)

type AssetStatus string

const (
    AssetStatusActive   AssetStatus = "active"
    AssetStatusInactive AssetStatus = "inactive"
    AssetStatusUnknown  AssetStatus = "unknown"
)
```

---

### 2. Network Event

Represents a network-level event (DNS query, HTTP request, connection, etc.)

```go
type NetworkEvent struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`

    // Source/Destination
    SourceIP     string    `json:"source_ip"`
    SourcePort   int       `json:"source_port"`
    SourceAsset  string    `json:"source_asset_id,omitempty"`

    DestIP       string    `json:"dest_ip"`
    DestPort     int       `json:"dest_port"`
    DestAsset    string    `json:"dest_asset_id,omitempty"`

    // Protocol info
    Protocol     string    `json:"protocol"`     // TCP, UDP, ICMP
    Application  string    `json:"application"`  // HTTP, DNS, SSH, etc.

    // Event details
    EventType    string    `json:"event_type"`   // connection_start, dns_query, http_request, etc.
    EventData    map[string]interface{} `json:"event_data"`

    // Size metrics
    BytesSent    uint64    `json:"bytes_sent"`
    BytesRecv    uint64    `json:"bytes_recv"`
    PacketsSent  uint64    `json:"packets_sent"`
    PacketsRecv  uint64    `json:"packets_recv"`

    // Security
    Encrypted    bool      `json:"encrypted"`
    Certificate  *TLSInfo  `json:"certificate,omitempty"`

    // Analysis
    RiskScore    float64   `json:"risk_score"`
    Anomalous    bool      `json:"anomalous"`
    Alerts       []string  `json:"alert_ids,omitempty"`
}

type TLSInfo struct {
    Version      string    `json:"version"`
    CipherSuite  string    `json:"cipher_suite"`
    ServerName   string    `json:"server_name"`
    Issuer       string    `json:"issuer"`
    Subject      string    `json:"subject"`
    NotBefore    time.Time `json:"not_before"`
    NotAfter     time.Time `json:"not_after"`
    Fingerprint  string    `json:"fingerprint"`
}
```

---

### 3. DNS Event

Specialized network event for DNS queries.

```go
type DNSEvent struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`

    // Query info
    QueryName    string    `json:"query_name"`
    QueryType    string    `json:"query_type"`    // A, AAAA, CNAME, MX, etc.
    QueryClass   string    `json:"query_class"`   // IN, CH, HS

    // Response info
    ResponseCode int       `json:"response_code"` // 0=NOERROR, 3=NXDOMAIN, etc.
    ResponseIPs  []string  `json:"response_ips,omitempty"`
    ResponseTTL  uint32    `json:"response_ttl"`

    // Source
    SourceIP     string    `json:"source_ip"`
    SourceAsset  string    `json:"source_asset_id,omitempty"`

    // DNS server
    ServerIP     string    `json:"server_ip"`

    // Analysis
    Malicious    bool      `json:"malicious"`
    ThreatFeeds  []string  `json:"threat_feeds,omitempty"` // Which feeds flagged this
    Anomalous    bool      `json:"anomalous"`
    RiskScore    float64   `json:"risk_score"`
}
```

---

### 4. Service

Represents a network service running on an asset.

```go
type Service struct {
    ID           string    `json:"id"`
    AssetID      string    `json:"asset_id"`

    // Network binding
    Protocol     string    `json:"protocol"`     // TCP, UDP
    Port         int       `json:"port"`
    IPAddress    string    `json:"ip_address"`

    // Service identification
    Name         string    `json:"name"`         // HTTP, SSH, MySQL, etc.
    Version      string    `json:"version"`
    Banner       string    `json:"banner,omitempty"`

    // State
    Status       ServiceStatus `json:"status"`    // Active, Dormant, Ghost

    // Discovery
    FirstSeen    time.Time `json:"first_seen"`
    LastSeen     time.Time `json:"last_seen"`
    DetectionMethod string `json:"detection_method"`

    // Security
    Encrypted    bool      `json:"encrypted"`
    Certificate  *TLSInfo  `json:"certificate,omitempty"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
    RiskScore    float64   `json:"risk_score"`

    // Metadata
    Metadata     map[string]interface{} `json:"metadata"`
}

type ServiceStatus string

const (
    ServiceStatusActive  ServiceStatus = "active"   // Listening and responding
    ServiceStatusDormant ServiceStatus = "dormant"  // Listening but not responding
    ServiceStatusGhost   ServiceStatus = "ghost"    // Debug/dev endpoint detected
    ServiceStatusClosed  ServiceStatus = "closed"
)
```

---

### 5. Alert

Represents a security alert generated by correlation rules or ML.

```go
type Alert struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`

    // Classification
    Severity     Severity  `json:"severity"`     // Critical, High, Medium, Low, Info
    Category     string    `json:"category"`     // Intrusion, Malware, Policy Violation, etc.
    Title        string    `json:"title"`
    Description  string    `json:"description"`

    // Source
    Source       AlertSource `json:"source"`      // CorrelationEngine, MLEngine, Manual
    RuleName     string    `json:"rule_name,omitempty"`
    RuleID       string    `json:"rule_id,omitempty"`

    // Affected entities
    Assets       []string  `json:"asset_ids"`
    Events       []string  `json:"event_ids"`

    // Context
    AttackVector string    `json:"attack_vector,omitempty"`
    MITREIDs     []string  `json:"mitre_ids,omitempty"`  // ATT&CK technique IDs

    // Response
    Status       AlertStatus `json:"status"`
    Assignee     string    `json:"assignee,omitempty"`
    Notes        []Note    `json:"notes,omitempty"`

    // Metrics
    FalsePositive bool     `json:"false_positive"`
    Confidence   float64   `json:"confidence"`    // 0.0 - 1.0
    RiskScore    float64   `json:"risk_score"`    // 0.0 - 10.0
}

type Severity string

const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type AlertSource string

const (
    AlertSourceCorrelation AlertSource = "correlation"
    AlertSourceML          AlertSource = "ml"
    AlertSourceManual      AlertSource = "manual"
    AlertSourceExternal    AlertSource = "external"
)

type AlertStatus string

const (
    AlertStatusOpen       AlertStatus = "open"
    AlertStatusInvestigating AlertStatus = "investigating"
    AlertStatusResolved   AlertStatus = "resolved"
    AlertStatusFalsePositive AlertStatus = "false_positive"
)

type Note struct {
    Timestamp time.Time `json:"timestamp"`
    Author    string    `json:"author"`
    Content   string    `json:"content"`
}
```

---

### 6. Vulnerability

Represents a security vulnerability detected on an asset.

```go
type Vulnerability struct {
    ID           string    `json:"id"`           // CVE ID or custom ID
    AssetID      string    `json:"asset_id"`

    // Vulnerability info
    Name         string    `json:"name"`
    Description  string    `json:"description"`
    CVSSScore    float64   `json:"cvss_score"`   // 0.0 - 10.0
    CVSSVector   string    `json:"cvss_vector"`

    // Classification
    Severity     Severity  `json:"severity"`
    Category     string    `json:"category"`
    CWE          []string  `json:"cwe_ids,omitempty"`

    // Affected component
    Component    string    `json:"component"`     // Software/service affected
    Version      string    `json:"version"`

    // Remediation
    Remediation  string    `json:"remediation"`
    Patch        string    `json:"patch,omitempty"`

    // Discovery
    DetectedAt   time.Time `json:"detected_at"`
    DetectionMethod string `json:"detection_method"`

    // Status
    Status       VulnStatus `json:"status"`
    Exploitable  bool      `json:"exploitable"`
}

type VulnStatus string

const (
    VulnStatusOpen       VulnStatus = "open"
    VulnStatusPatched    VulnStatus = "patched"
    VulnStatusMitigated  VulnStatus = "mitigated"
    VulnStatusAccepted   VulnStatus = "accepted"  // Risk accepted
)
```

---

### 7. Topology Graph

Represents the network topology.

```go
type TopologyGraph struct {
    Nodes []TopologyNode `json:"nodes"`
    Edges []TopologyEdge `json:"edges"`

    Timestamp time.Time `json:"timestamp"`
    Version   int       `json:"version"`
}

type TopologyNode struct {
    ID       string    `json:"id"`          // Asset ID
    Type     AssetType `json:"type"`
    Label    string    `json:"label"`
    Metadata map[string]interface{} `json:"metadata"`

    // Position (for UI)
    X        float64   `json:"x,omitempty"`
    Y        float64   `json:"y,omitempty"`
}

type TopologyEdge struct {
    ID         string    `json:"id"`
    SourceID   string    `json:"source_id"`
    TargetID   string    `json:"target_id"`
    Type       EdgeType  `json:"type"`

    // Metrics
    BytesSent  uint64    `json:"bytes_sent"`
    BytesRecv  uint64    `json:"bytes_recv"`
    LastSeen   time.Time `json:"last_seen"`

    Metadata   map[string]interface{} `json:"metadata"`
}

type EdgeType string

const (
    EdgeTypeNetwork   EdgeType = "network"    // Network connection
    EdgeTypeParent    EdgeType = "parent"     // Parent-child (VM-hypervisor)
    EdgeTypeDependency EdgeType = "dependency" // Service dependency
)
```

---

## Storage Schema

### Time-Series Data (Events)

Stored in time-series optimized format (future: InfluxDB/TimescaleDB).

```
Measurement: network_events
Tags:
  - source_ip
  - dest_ip
  - protocol
  - application
  - asset_id
Fields:
  - bytes_sent
  - bytes_recv
  - packets_sent
  - packets_recv
  - risk_score
Timestamp: nanosecond precision
```

### Document Store (Assets, Alerts)

Stored as JSON documents with indexes.

```
Collection: assets
Indexes:
  - id (unique)
  - type
  - mac_address
  - ip_addresses (array)
  - status
  - last_seen
```

---

## API Response Formats

### Paginated List

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1234,
    "total_pages": 25
  },
  "meta": {
    "timestamp": "2025-10-25T10:30:00Z",
    "query_time_ms": 45
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid asset ID format",
    "details": {
      "field": "asset_id",
      "reason": "must be a valid UUID"
    }
  },
  "timestamp": "2025-10-25T10:30:00Z"
}
```

---

**Document Version**: 0.1.0
**Last Updated**: 2025-10-25
**Status**: PHASE 0 - Foundation
