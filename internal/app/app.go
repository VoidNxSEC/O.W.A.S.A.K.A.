package app

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/correlation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/ml"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/stream"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/api"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/authz"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/browser/automation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/browser/firefox"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/canary"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/attack_surface"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/physical"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/reconciliation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/virtual"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/health"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/discovery"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/dns"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/ebpf"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/proxy"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/topology"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/tor"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/integrity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/migrations"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/nas"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/retention"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// App represents the main application
type App struct {
	cfg    *config.Config
	logger *logging.Logger
}

// New creates a new application instance
func New(cfg *config.Config, logger *logging.Logger) *App {
	return &App{
		cfg:    cfg,
		logger: logger,
	}
}

// Run starts the application
func (a *App) Run() error {
	a.logger.Info("Starting O.W.A.S.A.K.A. SIEM...")

	// Create a context that acts as a root for all services
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Log configuration summary
	a.logger.Infow("Configuration loaded",
		"environment", os.Getenv("OSWAKA_ENV"),
		"log_level", a.cfg.Logging.Level,
		"server_port", a.cfg.Server.Port,
	)

	// Health registry — populated as subsystems come online; flipped
	// to "ready" by MarkStartupComplete once every required subsystem
	// has finished initializing.
	healthRegistry := health.NewRegistry()

	// Connect to NATS event bus (optional — nil publisher disables event publishing)
	var pub *events.Publisher
	natsConfigured := a.cfg.NatsURL != ""
	if natsConfigured {
		var err error
		pub, err = events.Connect(a.cfg.NatsURL)
		if err != nil {
			a.logger.Warnw("NATS unavailable, events disabled", "url", a.cfg.NatsURL, "error", err)
		} else {
			a.logger.Infow("NATS connected", "url", a.cfg.NatsURL)
			defer pub.Close()
		}
	}

	// NATS health probe (optional — degraded when configured-but-down,
	// healthy when explicitly disabled via empty NatsURL).
	healthRegistry.Register(health.NewStaticProbe("nats", false, func() health.Result {
		if !natsConfigured {
			return health.Result{Status: health.StatusHealthy, Message: "disabled (no nats_url)"}
		}
		if pub.IsConnected() {
			return health.Result{Status: health.StatusHealthy}
		}
		return health.Result{Status: health.StatusDegraded, Message: "nats status: " + pub.Status()}
	}))

	// Storage Engine
	database, err := db.New(&a.cfg.Storage.Local, a.logger)
	if err != nil {
		a.logger.Errorw("Failed to initialize database", "error", err)
		return err
	}
	defer database.Close()

	repository := db.NewRepository(database)

	// Boot-time migration gate. With AutoMigrate=false (default) the
	// gate REFUSES startup if migrations are pending — operator must
	// run `oswaka migrate up` first so schema changes are an explicit
	// decision, not a silent side effect of a binary upgrade.
	if err := migrations.CheckBoot(database.DB(), a.cfg.Storage.Migrations.AutoMigrate); err != nil {
		a.logger.Errorw("Migration gate refused startup", "error", err,
			"auto_migrate", a.cfg.Storage.Migrations.AutoMigrate,
			"hint", "run `oswaka migrate up` or set storage.migrations.auto_migrate=true")
		return err
	}

	// Register DB health probe (required — readiness flips to 503 if
	// the file lock is dropped or the file becomes unreadable).
	healthRegistry.Register(health.NewStaticProbe("boltdb", true, func() health.Result {
		if err := database.Healthy(); err != nil {
			return health.Result{Status: health.StatusUnhealthy, Message: err.Error()}
		}
		return health.Result{Status: health.StatusHealthy}
	}))

	// Transparency Merkle log (RFC 6962-style). Opening creates the
	// buckets if absent; non-fatal — without the tree, critical event
	// signing still works but no STH journal is maintained.
	tree, err := transparency.Open(database.DB())
	if err != nil {
		a.logger.Warnw("Transparency log open failed; events still sign but no STH", "error", err)
	}

	// Retention sweep (per-bucket TTL + BoltDB compaction). Disabled
	// by default; operator opts in via storage.retention.enabled=true.
	if a.cfg.Storage.Retention.Enabled {
		rcfg := retention.Config{
			EventsDefaultTTL:            time.Duration(a.cfg.Storage.Retention.EventsDefaultTTLDays) * 24 * time.Hour,
			AlertsTTL:                   time.Duration(a.cfg.Storage.Retention.AlertsTTLDays) * 24 * time.Hour,
			AssetsStaleTTL:              time.Duration(a.cfg.Storage.Retention.AssetsStaleTTLDays) * 24 * time.Hour,
			SweepInterval:               time.Duration(a.cfg.Storage.Retention.SweepIntervalHours) * time.Hour,
			CompactionFreelistThreshold: a.cfg.Storage.Retention.CompactionFreelistThreshold,
		}
		retentionEngine, err := retention.NewEngine(rcfg, database.DB(), retentionLoggerAdapter{a.logger})
		if err != nil {
			a.logger.Errorw("Retention engine init failed", "error", err)
		} else {
			stop := retentionEngine.Start(ctx)
			defer stop()
			a.logger.Infow("Retention sweep enabled",
				"interval", rcfg.SweepInterval,
				"events_ttl", rcfg.EventsDefaultTTL,
				"alerts_ttl", rcfg.AlertsTTL)
		}
	}

	// ── Auth Bootstrap ───────────────────────────────────────────────
	// PKI Authority (in-memory keystore for now; BoltDB-backed in Sprint 5)
	keyStore := pki.NewMemoryKeyStore()
	authority := pki.NewAuthority(keyStore)

	// Ensure root CA + JWT signing key exist
	rootCA, err := authority.EnsureRootCA(ctx, 365*24*time.Hour) // 1-year root
	if err != nil {
		a.logger.Errorw("Failed to bootstrap root CA", "error", err)
		return err
	}
	a.logger.Infow("Root CA bootstrapped", "fingerprint", pki.Fingerprint(rootCA.Public))

	jwtSigningKey, err := authority.GenerateKeyPair(ctx, pki.PurposeJWTSigning, 24*time.Hour)
	if err != nil {
		a.logger.Errorw("Failed to generate JWT signing key", "error", err)
		return err
	}
	a.logger.Infow("JWT signing key generated", "kid", jwtSigningKey.ID)

	// Identity stores (memory-backed; BoltDB persistence in Sprint 4 carry-over)
	principalStore := identity.NewMemoryPrincipalStore()
	credentialStore := identity.NewMemoryCredentialStore()

	// Seed admin principal for initial access
	seedAdmin(a.logger, principalStore, credentialStore)

	// JWT issuer + verifier
	authenticator := identity.NewAuthenticator(principalStore, credentialStore)
	jwtIssuer := owjwt.NewIssuer(authority)
	jwtVerifier := owjwt.NewVerifier(authority)

	// Identity middleware
	authMW := middleware.New(jwtVerifier, principalStore, a.logger)

	// Dev mode: if OSWAKA_ENV=development, allow static token
	if env := os.Getenv("OSWAKA_ENV"); env == "development" {
		devToken := os.Getenv("OSWAKA_DEV_TOKEN")
		if devToken == "" {
			devToken = "oswaka-dev"
		}
		devPrincipal, _ := principalStore.Get(ctx, "principal-admin-001")
		if devPrincipal == nil {
			devPrincipal = &identity.Principal{
				ID:      "principal-admin-001",
				Type:    identity.PrincipalHuman,
				Subject: "admin",
				Status:  identity.StatusActive,
				Roles:   []string{"admin"},
			}
		}
		authMW = middleware.New(jwtVerifier, principalStore, a.logger,
			middleware.WithDevMode(devToken, devPrincipal))
		a.logger.Warnw("DEV MODE: static auth token enabled", "token", devToken)
	}

	// Authz engine — load baseline roles
	authzEngine := authz.NewEngine(nil)
	rolesPath := a.cfg.Security.RBAC.RolesFile
	if rolesPath == "" {
		rolesPath = "configs/rbac/roles.yaml"
	}
	if policy, err := authz.Load(rolesPath); err != nil {
		a.logger.Warnw("Failed to load RBAC policy, authz disabled", "path", rolesPath, "error", err)
	} else {
		authzEngine.Replace(policy)
		a.logger.Infow("RBAC policy loaded", "path", rolesPath, "roles", len(policy.Roles))

		// Start SIGHUP hot-reload watcher
		reloadStop := authz.ReloadWatcher(ctx, authzEngine, rolesPath, func(diff authz.Diff, err error) {
			if err != nil {
				a.logger.Errorw("RBAC reload failed", "error", err)
			} else if !diff.IsEmpty() {
				a.logger.Infow("RBAC policy reloaded", "diff", diff.String())
			}
		})
		defer reloadStop()
	}

	// M3 Command Center API (WebSocket/HTTP)
	apiServer := api.NewServer(&a.cfg.Server, a.logger)
	apiServer.SetAuthMiddleware(authMW)

	// Stream Processor — normalizes + enriches events with sliding-window context
	streamProc := stream.NewProcessor(&a.cfg.Analytics.Stream, a.logger)
	streamProc.Start(ctx)

	// Milestone 4: Correlation Engine (Threat Detection)
	engine := correlation.NewEngine(&a.cfg.Analytics.Correlation, a.logger)

	// Form Unified Pipeline
	pipeline := events.NewPipeline(repository, apiServer.Hub, pub, a.logger)

	// Ensure an event-signing key exists; sign every event leaving
	// the pipeline (ADR-0063). Failing to mint the key is non-fatal
	// — the pipeline signer falls back to "unsigned" mode and logs.
	if _, err := authority.GenerateKeyPair(ctx, pki.PurposeEventSigning, 7*24*time.Hour); err != nil {
		a.logger.Warnw("Event signing key generation failed; events will be unsigned",
			"error", err)
	} else {
		pipeline.SetSigner(events.NewSigner(authority))
		a.logger.Infow("Event signing enabled (Ed25519)")
	}

	// Wire transparency log so critical events accumulate inclusion
	// proofs (ADR-0063 §"Transparency log"). Tree may be nil if the
	// earlier Open failed; SetTransparencyLog tolerates that.
	if tree != nil {
		// Ensure an STH-signing key exists so the boot banner +
		// admin endpoints can produce verifiable STHs.
		if _, err := authority.GenerateKeyPair(ctx, pki.PurposeTransparencyLogSTH, 7*24*time.Hour); err != nil {
			a.logger.Warnw("STH signing key generation failed", "error", err)
		}
		pipeline.SetTransparencyLog(transparencyLogAdapter{tree})
		a.logger.Infow("Transparency log wired", "size", tree.Size())
	}

	// Hook Engine into Pipeline. Canary alerts also update the
	// triggered token's bookkeeping (TriggerCount/TriggeredAt) before
	// the alert continues into the pipeline as normal.
	pipeline.SetEngine(engine)
	engine.SetAlertCallback(func(alert models.NetworkEvent) {
		canary.RecordTrigger(repository, alert)
		pipeline.PushNetworkEvent(alert)
	})
	pipeline.SetStreamEnricher(streamProc)

	// ML Anomaly Detector — Isolation Forest + behavioral baselining
	mlService := ml.NewService(&a.cfg.Analytics.ML, a.logger, pipeline)
	if err := mlService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start ML Anomaly Detector", "error", err)
	}
	pipeline.SetEventObserver(mlService)

	// Topology Mapper — builds live network graph from asset/event streams
	topoBuilder := topology.NewBuilder(a.logger)
	topoBuilder.OnChange(func(snap topology.GraphSnapshot) {
		// Push TOPOLOGY_UPDATE to all connected WebSocket clients
		msg := map[string]any{
			"type": "TOPOLOGY_UPDATE",
			"data": topology.ToD3(snap),
		}
		apiServer.Hub.Broadcast(msg)
	})
	pipeline.SetTopologyMapper(topoBuilder)

	// ── Neotron Compliance Event Ingestion ─────────────────────────────
	// Subscribe to neotron compliance events published on NATS subjects:
	//   neotron.compliance.temporal.v1   — Layer 0 TEMPORAL (boiling frog)
	//   neotron.compliance.sentinel.v1   — Layer 1 SENTINEL guardrails
	//   neotron.compliance.bastion.v1    — Layer 2 BASTION seccomp-BPF
	//   neotron.cortex.consensus.v1      — Layer 3 CORTEX swarm consensus
	//   neotron.compliance.violation.v1  — Blocking violations (any layer)
	//
	// The subscriber pushes each event through owasaka's SIEM pipeline
	// for persistence (BoltDB), WebSocket broadcast (M3 Command Center),
	// Ed25519 signing (ADR-0062), transparency Merkle logging (ADR-0063),
	// correlation analysis, and ML anomaly detection.
	var neotronSub *events.NeotronComplianceSubscriber
	if pub != nil && pub.IsConnected() {
		nc := pub.RawConn()
		if nc != nil {
			var err error
			neotronSub, err = events.NewNeotronComplianceSubscriber(nc, pipeline, a.logger)
			if err != nil {
				a.logger.Warnw("Failed to subscribe to neotron compliance events",
					"error", err)
			} else {
				a.logger.Infow("Neotron compliance subscriber active",
					"subjects", "neotron.compliance.>")
			}
		}
	}

	// Health probe for neotron compliance ingestion channel
	healthRegistry.Register(health.NewStaticProbe("neotron-compliance", false, func() health.Result {
		if !natsConfigured || pub == nil || !pub.IsConnected() {
			return health.Result{Status: health.StatusHealthy, Message: "disabled (no NATS)"}
		}
		if neotronSub == nil {
			return health.Result{Status: health.StatusDegraded, Message: "subscription failed"}
		}
		return health.Result{Status: health.StatusHealthy}
	}))

	// Health probes (unprotected — these are scraped by orchestrators
	// before any auth machinery is available).
	apiServer.RegisterHandler("/healthz", api.Instrument("/healthz", health.LivenessHandler(healthRegistry).ServeHTTP))
	apiServer.RegisterHandler("/readyz", api.Instrument("/readyz", health.ReadinessHandler(healthRegistry).ServeHTTP))
	apiServer.RegisterHandler("/startupz", api.Instrument("/startupz", health.StartupHandler(healthRegistry).ServeHTTP))

	// Admin: POST /api/admin/backup — in-process encrypted hot backup.
	// Wired only when recipients are configured; otherwise the
	// endpoint is omitted so the surface area stays minimal.
	if recipients := parseAgeRecipients(a.logger, a.cfg.Storage.Backup.Recipients); len(recipients) > 0 {
		sinkDir := a.cfg.Storage.Backup.OutputDir
		adminBackup := &api.AdminBackupHandler{
			DB:         database.DB(),
			Tree:       tree,
			Recipients: recipients,
			SinkDir:    sinkDir,
			KeepLast:   a.cfg.Storage.Backup.KeepLast,
			Logger:     a.logger,
		}
		apiServer.RegisterProtectedHandler("/api/admin/backup",
			api.Instrument("/api/admin/backup", adminBackup.ServeHTTP))
		a.logger.Infow("Admin backup endpoint registered",
			"path", "/api/admin/backup", "sink_dir", sinkDir)
	}

	// Register auth endpoints (unprotected)
	apiServer.RegisterHandler("/auth/login", api.Instrument("/auth/login", api.LoginHandler(api.LoginHandlerDeps{
		Authenticator:  authenticator,
		Issuer:         jwtIssuer,
		PrincipalStore: principalStore,
		Logger:         a.logger,
	})))
	apiServer.RegisterHandler("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		owjwt.Handler(authority, time.Now).ServeHTTP(w, r)
	})

	// Register REST endpoint for stream processor stats (protected)
	apiServer.RegisterProtectedHandler("/api/stats", api.Instrument("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if err := json.NewEncoder(w).Encode(streamProc.Stats()); err != nil {
			a.logger.Errorw("Failed to encode stream stats", "error", err)
		}
	}))

	// Register REST endpoint for full topology snapshot (protected)
	apiServer.RegisterProtectedHandler("/api/topology", api.Instrument("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		snap := topoBuilder.Snapshot()
		if err := json.NewEncoder(w).Encode(topology.ToD3(snap)); err != nil {
			a.logger.Errorw("Failed to encode topology", "error", err)
		}
	}))

	// Canary tokens: unauthenticated webhook (the token itself is the
	// secret — remote apps/websites that planted a decoy URL don't
	// hold OWASAKA credentials) + authenticated admin endpoints to
	// mint/list tokens.
	apiServer.RegisterHandler("/api/canary/webhook/", api.Instrument("/api/canary/webhook",
		api.CanaryWebhookHandler(repository, pipeline)))

	canaryAdmin := &api.CanaryAdminHandler{Repo: repository, Cfg: &a.cfg.Canary, Logger: a.logger}
	apiServer.RegisterProtectedHandler("/api/admin/canary/dns", api.Instrument("/api/admin/canary/dns", canaryAdmin.CreateDNS))
	apiServer.RegisterProtectedHandler("/api/admin/canary/http", api.Instrument("/api/admin/canary/http", canaryAdmin.CreateHTTP))
	apiServer.RegisterProtectedHandler("/api/admin/canary", api.Instrument("/api/admin/canary", canaryAdmin.List))

	// Tor hidden service status. The tor daemon itself is managed
	// externally (NixOS services.tor / systemd, see flake.nix); this
	// only surfaces the resulting .onion address once published.
	if a.cfg.Network.Tor.HiddenServiceEnabled {
		dataDir := a.cfg.Network.Tor.HiddenServiceDataDir
		if onion, err := tor.ReadOnionHostname(dataDir); err != nil {
			a.logger.Warnw("Tor hidden service enabled but onion hostname not yet available", "error", err)
		} else {
			a.logger.Infow("Tor hidden service active", "onion_address", onion)
		}
		apiServer.RegisterHandler("/api/tor/onion", api.Instrument("/api/tor/onion", func(w http.ResponseWriter, r *http.Request) {
			onion, err := tor.ReadOnionHostname(dataDir)
			if err != nil {
				http.Error(w, "onion address unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"onion_address": onion})
		}))
	}

	if err := apiServer.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start API Server", "error", err)
	}
	defer apiServer.Stop()

	// Initialize Services
	dnsService := dns.NewService(&a.cfg.Network.DNS, a.logger, pipeline)
	discoveryService := discovery.NewService(&a.cfg.Network.Discovery, a.logger, pipeline)

	// Tor outbound SOCKS5 client — used by future IOC/threat-intel
	// lookups so OWASAKA's own egress doesn't expose the host's real
	// address. Falls back to a direct (non-Tor) client if the dialer
	// can't be constructed; never fatal.
	torClient, err := tor.NewClient(&a.cfg.Network.Tor, a.logger)
	if err != nil {
		a.logger.Warnw("Tor SOCKS5 client unavailable, falling back to direct egress", "error", err)
		torClient, _ = tor.NewClient(&config.TorConfig{}, a.logger)
	}

	// Tor exit-node detection — local-file-first (air-gap-safe); only
	// fetches a live list if ExitNodeListURL is explicitly configured.
	torExitNodes := tor.NewExitNodeService(&a.cfg.Network.Tor, a.logger, torClient)
	if err := torExitNodes.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Tor exit-node list service", "error", err)
	}

	// Start Services
	if err := dnsService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start DNS service", "error", err)
		return err
	}

	if err := discoveryService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Discovery service", "error", err)
		// Don't return err here to allow app to run even if discovery fails (critical vs non-critical)
		// Actually, Service.Start already handles graceful failure for permissions, so this is safe.
	}

	// M2 Services
	attackSurface := attack_surface.NewService(&a.cfg.Discovery.AttackSurface, a.logger, pipeline, repository)
	if err := attackSurface.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Attack Surface Scanner", "error", err)
	}

	physicalService := physical.NewService(&a.cfg.Discovery.Physical, a.logger, pipeline)
	if err := physicalService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Physical Enumeration service", "error", err)
	}

	virtualService := virtual.NewService(&a.cfg.Discovery.Containers, &a.cfg.Discovery.Virtual, a.logger, pipeline)
	if err := virtualService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Virtual Discovery service", "error", err)
	}

	// Continuous Reconciliation Engine — drift detection
	reconEngine := reconciliation.NewEngine(&a.cfg.Discovery.Reconciliation, repository, pipeline, a.logger)
	if err := reconEngine.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Reconciliation Engine", "error", err)
	}

	// Transparent Proxy Engine — HTTP/HTTPS interception + DPI
	proxyService := proxy.NewService(&a.cfg.Network.Proxy, a.logger, pipeline, torExitNodes)
	if err := proxyService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Proxy service", "error", err)
	}
	defer proxyService.Stop()

	// eBPF host network monitor — watches local connect() syscalls for
	// Tor-port/Tor-exit-node egress. Requires CAP_BPF+CAP_PERFMON on
	// kernel >= 5.8; failure (unsupported kernel, missing capability)
	// is logged and non-fatal.
	ebpfService := ebpf.NewService(&a.cfg.EBPF, a.logger, pipeline, torExitNodes)
	if err := ebpfService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start eBPF host network monitor", "error", err)
	}
	defer ebpfService.Stop()

	// M2 Browser Hardening
	firefoxService := firefox.NewService(&a.cfg.Browser, a.logger)
	if err := firefoxService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Firefox service", "error", err)
	}

	// Browser Automation — CDP forensic logging
	autoService := automation.NewService(&a.cfg.Browser.Automation, a.logger, pipeline, a.cfg.Storage.Local.DataDir)
	if err := autoService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Browser Automation", "error", err)
	}

	// Integrity Verifier — Merkle trees + immutable audit log
	integrityService, err := integrity.NewService(&a.cfg.Storage.Integrity, repository, pipeline, a.logger)
	if err != nil {
		a.logger.Errorw("Failed to initialize Integrity Verifier", "error", err)
	} else {
		if err := integrityService.Start(ctx); err != nil {
			a.logger.Errorw("Failed to start Integrity Verifier", "error", err)
		}
		defer integrityService.Stop()
	}

	// NAS Connector — air-gapped NFS/SMB storage
	nasService := nas.NewService(&a.cfg.Storage.NAS, a.logger, pipeline)
	if err := nasService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start NAS Connector", "error", err)
	}
	defer nasService.Stop(ctx)

	// Every required subsystem has booted — flip /startupz from
	// "starting" to "ready". From this point on /readyz is the
	// authoritative probe for orchestrators.
	healthRegistry.MarkStartupComplete()

	a.logger.Info("System ready and waiting for signals (Press Ctrl+C to stop)")

	// Wait for termination signal
	select {
	case sig := <-sigChan:
		a.logger.Infow("Received shutdown signal", "signal", sig)
		// Perform cleanup here

		// Give services a moment to shut down gracefully
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		<-shutdownCtx.Done()

		a.logger.Info("Shutdown complete")
	case <-ctx.Done():
		a.logger.Info("Context cancelled, shutting down")
	}

	return nil
}

// transparencyLogAdapter bridges *transparency.Tree to the
// events.TransparencyLog interface. The tree exposes AppendBytes
// with the same signature; the adapter just renames it to satisfy
// the interface contract.
type transparencyLogAdapter struct{ t *transparency.Tree }

func (a transparencyLogAdapter) Append(ctx context.Context, kind, payload []byte, timestamp time.Time) error {
	return a.t.AppendBytes(ctx, kind, payload, timestamp)
}

// retentionLoggerAdapter satisfies retention.Logger (which is
// stdlib-agnostic) using the project's zap-backed logger.
type retentionLoggerAdapter struct{ l *logging.Logger }

func (a retentionLoggerAdapter) Infow(msg string, kv ...any) { a.l.Infow(msg, kv...) }
func (a retentionLoggerAdapter) Warnw(msg string, kv ...any) { a.l.Warnw(msg, kv...) }

// parseAgeRecipients best-effort parses the YAML-supplied age public
// keys into recipient values. Invalid entries are logged and skipped
// — the operator can fix the config and SIGHUP/restart, vs. losing
// the entire backup endpoint to a typo.
func parseAgeRecipients(logger *logging.Logger, keys []string) []age.Recipient {
	out := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		r, err := age.ParseX25519Recipient(k)
		if err != nil {
			logger.Warnw("backup recipient parse failed, skipping",
				"key_prefix", safePrefix(k), "error", err)
			continue
		}
		out = append(out, r)
	}
	return out
}

func safePrefix(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// seedAdmin creates the initial admin principal and credential so the
// operator can log in immediately after first boot.
//
// Default credentials (CHANGE AFTER FIRST LOGIN):
//
//	Username: admin
//	Password: owasaka-admin (set via OSWAKA_ADMIN_PASSWORD env var)
//	TOTP seed: printed to log on first boot; scan the QR URL to enroll.
//
// If the admin principal already exists, this is a no-op.
func seedAdmin(logger *logging.Logger, principals identity.PrincipalStore, creds identity.CredentialStore) {
	ctx := context.Background()

	// Skip if already seeded.
	if _, err := principals.Get(ctx, "principal-admin-001"); err == nil {
		return
	}

	password := os.Getenv("OSWAKA_ADMIN_PASSWORD")
	if password == "" {
		password = "owasaka-admin"
	}

	totpSecret, otpauthURL, err := identity.GenerateTOTPSecret("OWASAKA", "admin")
	if err != nil {
		logger.Errorw("Failed to generate TOTP secret for admin", "error", err)
		return
	}

	// Create the admin principal.
	adminPrincipal := &identity.Principal{
		ID:          "principal-admin-001",
		Type:        identity.PrincipalHuman,
		Subject:     "admin",
		DisplayName: "OWASAKA Administrator",
		Status:      identity.StatusActive,
		Roles:       []string{"admin"},
	}
	if err := principals.Save(ctx, adminPrincipal); err != nil {
		logger.Errorw("Failed to save admin principal", "error", err)
		return
	}

	// Create the password+TOTP credential.
	passwordCred, err := identity.NewPasswordTOTPCredential(
		adminPrincipal.ID, "admin", password, totpSecret, "OWASAKA")
	if err != nil {
		logger.Errorw("Failed to create admin credential", "error", err)
		return
	}
	if err := creds.Save(ctx, passwordCred); err != nil {
		logger.Errorw("Failed to save admin credential", "error", err)
		return
	}

	// Also create an API key for CI/automation.
	apiKey, plaintext, err := identity.NewAPIKey(adminPrincipal.ID, "default")
	if err != nil {
		logger.Errorw("Failed to create admin API key", "error", err)
		return
	}
	if err := creds.Save(ctx, apiKey); err != nil {
		logger.Errorw("Failed to save admin API key", "error", err)
		return
	}

	logger.Infow("==========================================================")
	logger.Infow("  ADMIN PRINCIPAL SEEDED")
	logger.Infow("  Username: admin")
	logger.Infow("  Password: (set via OSWAKA_ADMIN_PASSWORD env var)")
	logger.Infow("  TOTP QR:  " + otpauthURL)
	logger.Infow("  API Key:  " + plaintext)
	logger.Infow("  CHANGE THESE CREDENTIALS AFTER FIRST LOGIN")
	logger.Infow("==========================================================")
}
