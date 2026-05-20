package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Logging     LoggingConfig     `yaml:"logging"`
	Network     NetworkConfig     `yaml:"network"`
	Discovery   DiscoveryConfig   `yaml:"discovery"`
	Browser     BrowserConfig     `yaml:"browser"`
	Storage     StorageConfig     `yaml:"storage"`
	Analytics   AnalyticsConfig   `yaml:"analytics"`
	Alerts      AlertsConfig      `yaml:"alerts"`
	Performance PerformanceConfig `yaml:"performance"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Debug       DebugConfig       `yaml:"debug"`
	Security      SecurityConfig      `yaml:"security"`
	Observability ObservabilityConfig `yaml:"observability"`
	NatsURL       string              `yaml:"nats_url"`
}

// ObservabilityConfig controls OpenTelemetry tracing and metrics
// emission. Disabled by default (air-gap-first): an operator must opt
// in to ship telemetry over the network.
type ObservabilityConfig struct {
	Traces  TracesConfig  `yaml:"traces"`
	Metrics MetricsToggle `yaml:"metrics"`
}

// TracesConfig configures the OTLP gRPC tracer exporter. When
// Enabled=false the tracer provider is a no-op — spans are created
// for code clarity but nothing is exported.
type TracesConfig struct {
	Enabled        bool    `yaml:"enabled"`
	Endpoint       string  `yaml:"endpoint"`         // e.g. tempo.observability:4317
	ServiceName    string  `yaml:"service_name"`     // defaults to "oswaka"
	Environment    string  `yaml:"environment"`      // production / staging / dev
	SamplingRatio  float64 `yaml:"sampling_ratio"`   // 0.0-1.0; default 1.0 when enabled
	Insecure       bool    `yaml:"insecure"`         // skip TLS to collector (dev only)
}

// MetricsToggle is a thin on/off for the Prometheus scrape endpoint.
// The /metrics handler is wired regardless — this toggle gates whether
// the binary registers the expanded Sprint 6 metric set.
type MetricsToggle struct {
	Enabled bool `yaml:"enabled"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host      string          `yaml:"host"`
	Port      int             `yaml:"port"`
	WebSocket WebSocketConfig `yaml:"websocket"`
	TLS       TLSConfig       `yaml:"tls"`
}

type WebSocketConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Path           string `yaml:"path"`
	MaxConnections int    `yaml:"max_connections"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	Compress   bool   `yaml:"compress"`
}

// NetworkConfig holds network intelligence configuration
type NetworkConfig struct {
	DNS       DNSConfig      `yaml:"dns"`
	Proxy     ProxyConfig    `yaml:"proxy"`
	Discovery ScanConfig     `yaml:"discovery"`
	Topology  TopologyConfig `yaml:"topology"`
}

type DNSConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ListenAddress   string   `yaml:"listen_address"`
	UpstreamServers []string `yaml:"upstream_servers"`
	DoHEnabled      bool     `yaml:"doh_enabled"`
	DoHURL          string   `yaml:"doh_url"`
	CacheSize       int      `yaml:"cache_size"`
	CacheTTLSeconds int      `yaml:"cache_ttl_seconds"`
	LogQueries      bool     `yaml:"log_queries"`
	ThreatDetection bool     `yaml:"threat_detection"`
}

type ProxyConfig struct {
	Enabled       bool     `yaml:"enabled"`
	ListenAddress string   `yaml:"listen_address"`
	MITMEnabled   bool     `yaml:"mitm_enabled"`
	CertStorage   string   `yaml:"cert_storage"`
	DPIEnabled    bool     `yaml:"dpi_enabled"`
	Protocols     []string `yaml:"protocols"`
}

type ScanConfig struct {
	Enabled             bool     `yaml:"enabled"`
	ScanIntervalMinutes int      `yaml:"scan_interval_minutes"`
	Methods             []string `yaml:"methods"`
	PassiveMonitoring   bool     `yaml:"passive_monitoring"`
	ConcurrentScans     int      `yaml:"concurrent_scans"`
	RateLimitPerSecond  int      `yaml:"rate_limit_per_second"`
}

type TopologyConfig struct {
	Enabled               bool   `yaml:"enabled"`
	UpdateIntervalSeconds int    `yaml:"update_interval_seconds"`
	ExportFormat          string `yaml:"export_format"`
	GraphAlgorithm        string `yaml:"graph_algorithm"`
}

// DiscoveryConfig holds asset discovery configuration
type DiscoveryConfig struct {
	Physical       PhysicalConfig       `yaml:"physical"`
	Virtual        VirtualConfig        `yaml:"virtual"`
	Containers     ContainerConfig      `yaml:"containers"`
	AttackSurface  AttackSurfaceConfig  `yaml:"attack_surface"`
	Reconciliation ReconciliationConfig `yaml:"reconciliation"`
}

type PhysicalConfig struct {
	Enabled             bool     `yaml:"enabled"`
	ScanIntervalMinutes int      `yaml:"scan_interval_minutes"`
	Devices             []string `yaml:"devices"`
}

type VirtualConfig struct {
	Enabled             bool                   `yaml:"enabled"`
	ScanIntervalMinutes int                    `yaml:"scan_interval_minutes"`
	Hypervisors         map[string]interface{} `yaml:"hypervisors"`
}

type ContainerConfig struct {
	Enabled             bool     `yaml:"enabled"`
	ScanIntervalMinutes int      `yaml:"scan_interval_minutes"`
	Runtimes            []string `yaml:"runtimes"`
	DockerSocket        string   `yaml:"docker_socket"`
}

type AttackSurfaceConfig struct {
	Enabled               bool      `yaml:"enabled"`
	ScanIntervalMinutes   int       `yaml:"scan_interval_minutes"`
	ConcurrentScans       int       `yaml:"concurrent_scans"`
	PortRange             PortRange `yaml:"port_range"`
	Protocols             []string  `yaml:"protocols"`
	DetectDormant         bool      `yaml:"detect_dormant"`
	DetectGhost           bool      `yaml:"detect_ghost"`
	ServiceFingerprinting bool      `yaml:"service_fingerprinting"`
	BannerGrabbing        bool      `yaml:"banner_grabbing"`
	TLSAnalysis           bool      `yaml:"tls_analysis"`
}

type PortRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

type ReconciliationConfig struct {
	Enabled              bool `yaml:"enabled"`
	CheckIntervalMinutes int  `yaml:"check_interval_minutes"`
	AlertOnChange        bool `yaml:"alert_on_change"`
	TrackHistory         bool `yaml:"track_history"`
	HistoryRetentionDays int  `yaml:"history_retention_days"`
}

// BrowserConfig holds browser integration configuration
type BrowserConfig struct {
	Enabled    bool             `yaml:"enabled"`
	Firefox    FirefoxConfig    `yaml:"firefox"`
	Automation AutomationConfig `yaml:"automation"`
}

type FirefoxConfig struct {
	BinaryPath        string `yaml:"binary_path"`
	ProfileDir        string `yaml:"profile_dir"`
	HardeningEnabled  bool   `yaml:"hardening_enabled"`
	ExtensionLockdown bool   `yaml:"extension_lockdown"`
	TelemetryDisabled bool   `yaml:"telemetry_disabled"`
}

type AutomationConfig struct {
	Enabled           bool `yaml:"enabled"`
	WebDriverPort     int  `yaml:"webdriver_port"`
	ScreenshotOnAlert bool `yaml:"screenshot_on_alert"`
	HARLogging        bool `yaml:"har_logging"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	NAS        NASConfig          `yaml:"nas"`
	Encryption EncryptionConfig   `yaml:"encryption"`
	Integrity  IntegrityConfig    `yaml:"integrity"`
	Local      LocalStorageConfig `yaml:"local"`
	Retention  RetentionConfig    `yaml:"retention"`
	Migrations MigrationsConfig   `yaml:"migrations"`
	Backup     BackupConfig       `yaml:"backup"`
}

// BackupConfig configures the encrypted hot-backup engine.
// Recipients are age public keys (one per operator + one per offline
// vault). IdentitiesFile points at the age key file used for
// restore — usually loaded via systemd LoadCredential on production.
type BackupConfig struct {
	Recipients      []string `yaml:"recipients"`
	IdentitiesFile  string   `yaml:"identities_file"`
	OutputDir       string   `yaml:"output_dir"`
	KeepLast        int      `yaml:"keep_last"`
}

// RetentionConfig configures the daily retention sweep. Zero TTL on
// any field means "keep forever". See internal/storage/retention.
type RetentionConfig struct {
	Enabled                     bool `yaml:"enabled"`
	EventsDefaultTTLDays        int  `yaml:"events_default_ttl_days"`
	AlertsTTLDays               int  `yaml:"alerts_ttl_days"`
	AssetsStaleTTLDays          int  `yaml:"assets_stale_ttl_days"`
	SweepIntervalHours          int  `yaml:"sweep_interval_hours"`
	CompactionFreelistThreshold int  `yaml:"compaction_freelist_threshold"`
}

// MigrationsConfig controls boot-time schema migration behavior. By
// default the gate REFUSES to start with pending migrations so an
// operator must consciously apply them via `oswaka migrate up`. Set
// AutoMigrate=true to apply pending migrations automatically on
// startup (acceptable for dev, dangerous in production).
type MigrationsConfig struct {
	AutoMigrate bool `yaml:"auto_migrate"`
}

type NASConfig struct {
	Enabled                    bool   `yaml:"enabled"`
	Type                       string `yaml:"type"`
	Host                       string `yaml:"host"`
	Share                      string `yaml:"share"`
	MountPoint                 string `yaml:"mount_point"`
	Username                   string `yaml:"username"`
	Password                   string `yaml:"password"`
	TimeoutSeconds             int    `yaml:"timeout_seconds"`
	RetryAttempts              int    `yaml:"retry_attempts"`
	HealthCheckIntervalSeconds int    `yaml:"health_check_interval_seconds"`
}

type EncryptionConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Algorithm      string `yaml:"algorithm"`
	KeyDerivation  string `yaml:"key_derivation"`
	KeyFile        string `yaml:"key_file"`
	RotateKeysDays int    `yaml:"rotate_keys_days"`
}

type IntegrityConfig struct {
	Enabled               bool   `yaml:"enabled"`
	MerkleTree            bool   `yaml:"merkle_tree"`
	AuditLog              string `yaml:"audit_log"`
	SnapshotIntervalHours int    `yaml:"snapshot_interval_hours"`
	SnapshotRetentionDays int    `yaml:"snapshot_retention_days"`
}

type LocalStorageConfig struct {
	DataDir       string `yaml:"data_dir"`
	MaxSizeGB     int    `yaml:"max_size_gb"`
	CleanupPolicy string `yaml:"cleanup_policy"`
}

// AnalyticsConfig holds analytics configuration
type AnalyticsConfig struct {
	Stream      StreamConfig      `yaml:"stream"`
	Correlation CorrelationConfig `yaml:"correlation"`
	ML          MLConfig          `yaml:"ml"`
}

type StreamConfig struct {
	Enabled              bool   `yaml:"enabled"`
	BufferSize           int    `yaml:"buffer_size"`
	FlushIntervalSeconds int    `yaml:"flush_interval_seconds"`
	Workers              int    `yaml:"workers"`
	BackpressurePolicy   string `yaml:"backpressure_policy"`
}

type CorrelationConfig struct {
	Enabled                     bool   `yaml:"enabled"`
	RulesDir                    string `yaml:"rules_dir"`
	SigmaRulesEnabled           bool   `yaml:"sigma_rules_enabled"`
	CustomRulesEnabled          bool   `yaml:"custom_rules_enabled"`
	MaxCorrelationWindowMinutes int    `yaml:"max_correlation_window_minutes"`
}

type MLConfig struct {
	Enabled               bool     `yaml:"enabled"`
	ModelDir              string   `yaml:"model_dir"`
	TrainingIntervalHours int      `yaml:"training_interval_hours"`
	AnomalyThreshold      float64  `yaml:"anomaly_threshold"`
	Methods               []string `yaml:"methods"`
	BaselineLearningDays  int      `yaml:"baseline_learning_days"`
}

// AlertsConfig holds alerting configuration
type AlertsConfig struct {
	Enabled       bool                   `yaml:"enabled"`
	Thresholds    map[string]float64     `yaml:"thresholds"`
	Destinations  map[string]interface{} `yaml:"destinations"`
	Deduplication DeduplicationConfig    `yaml:"deduplication"`
}

type DeduplicationConfig struct {
	Enabled             bool    `yaml:"enabled"`
	WindowMinutes       int     `yaml:"window_minutes"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"`
}

// PerformanceConfig holds performance tuning configuration
type PerformanceConfig struct {
	MaxMemoryMB        int `yaml:"max_memory_mb"`
	MaxCPUPercent      int `yaml:"max_cpu_percent"`
	MaxConcurrentScans int `yaml:"max_concurrent_scans"`
	EventQueueSize     int `yaml:"event_queue_size"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled    bool             `yaml:"enabled"`
	Prometheus PrometheusConfig `yaml:"prometheus"`
}

type PrometheusConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_address"`
	Path          string `yaml:"path"`
}

// DebugConfig holds debug configuration
type DebugConfig struct {
	Enabled   bool        `yaml:"enabled"`
	Pprof     PprofConfig `yaml:"pprof"`
	Trace     bool        `yaml:"trace"`
	Profiling bool        `yaml:"profiling"`
}

type PprofConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ListenAddress string `yaml:"listen_address"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	APIAuth      APIAuthConfig      `yaml:"api_auth"`
	RateLimiting RateLimitingConfig `yaml:"rate_limiting"`
	RBAC         RBACConfig         `yaml:"rbac"`
}

type APIAuthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Method  string `yaml:"method"`
}

type RateLimitingConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	Burst             int  `yaml:"burst"`
}

type RBACConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RolesFile string `yaml:"roles_file"`
}

// Load reads and parses a YAML configuration file
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if natsURL := os.Getenv("NATS_URL"); natsURL != "" {
		cfg.NatsURL = natsURL
	}

	// TODO: Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// TODO: Add comprehensive validation
	// For now, just basic checks

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}

	return nil
}
