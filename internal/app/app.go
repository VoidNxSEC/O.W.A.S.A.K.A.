package app

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/correlation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/ml"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/analytics/stream"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/api"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/authz"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/browser/automation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/browser/firefox"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/attack_surface"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/physical"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/reconciliation"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/discovery/virtual"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/events"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/discovery"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/dns"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/proxy"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/network/topology"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/integrity"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/nas"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
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

	// Connect to NATS event bus (optional — nil publisher disables event publishing)
	var pub *events.Publisher
	if a.cfg.NatsURL != "" {
		var err error
		pub, err = events.Connect(a.cfg.NatsURL)
		if err != nil {
			a.logger.Warnw("NATS unavailable, events disabled", "url", a.cfg.NatsURL, "error", err)
		} else {
			a.logger.Infow("NATS connected", "url", a.cfg.NatsURL)
			defer pub.Close()
		}
	}

	// Storage Engine
	database, err := db.New(&a.cfg.Storage.Local, a.logger)
	if err != nil {
		a.logger.Errorw("Failed to initialize database", "error", err)
		return err
	}
	defer database.Close()

	repository := db.NewRepository(database)

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

	// Hook Engine into Pipeline
	pipeline.SetEngine(engine)
	engine.SetAlertCallback(pipeline.PushNetworkEvent)
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

	if err := apiServer.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start API Server", "error", err)
	}
	defer apiServer.Stop()

	// Initialize Services
	dnsService := dns.NewService(&a.cfg.Network.DNS, a.logger, pipeline)
	discoveryService := discovery.NewService(&a.cfg.Network.Discovery, a.logger, pipeline)

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
	proxyService := proxy.NewService(&a.cfg.Network.Proxy, a.logger, pipeline)
	if err := proxyService.Start(ctx); err != nil {
		a.logger.Errorw("Failed to start Proxy service", "error", err)
	}
	defer proxyService.Stop()

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
