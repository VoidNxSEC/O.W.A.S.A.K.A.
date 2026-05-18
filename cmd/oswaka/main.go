// Command oswaka is the OWASAKA SIEM binary. With no arguments it
// boots the long-running server; with a subcommand it performs a
// one-shot operation (migrate, backup, restore) and exits.
//
// Subcommands intentionally use the same config file as the server
// so the operator does not pass the DB path twice; this keeps backup
// and restore aware of any encrypted-storage / data-dir overrides.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/app"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

var (
	// Build information (injected at build time).
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
	// Detect subcommand before flag.Parse so the global flagset
	// doesn't confiscate the subcommand-specific flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			os.Exit(runMigrate(os.Args[2:]))
		case "backup":
			os.Exit(runBackup(os.Args[2:]))
		case "restore":
			os.Exit(runRestore(os.Args[2:]))
		case "version", "--version", "-version":
			printVersion()
			return
		case "help", "--help", "-h":
			printHelp()
			return
		}
	}

	// Default: long-running server mode.
	configPath := flag.String("config", "configs/examples/default.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	cfg, logger, err := loadConfigAndLogger(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	logger.Infow("Initializing O.W.A.S.A.K.A.",
		"version", version,
		"commit", commit,
		"build_time", buildTime,
	)

	application := app.New(cfg, logger)
	if err := application.Run(); err != nil {
		logger.Fatalw("Application runtime error", "error", err)
	}
}

// loadConfigAndLogger is shared by every subcommand so all paths
// honour the same config file and logging behaviour.
func loadConfigAndLogger(configPath string) (*config.Config, *logging.Logger, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration %s: %w", configPath, err)
	}
	logger, err := logging.NewLogger(&cfg.Logging)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize logger: %w", err)
	}
	return cfg, logger, nil
}

func printVersion() {
	fmt.Printf("O.W.A.S.A.K.A. SIEM\nVersion: %s\nCommit: %s\nBuilt: %s\n", version, commit, buildTime)
}

func printHelp() {
	fmt.Print(`O.W.A.S.A.K.A. SIEM

Usage:
  oswaka [flags]                                            Run the SIEM server (default).
  oswaka migrate <up|status|down> [--config PATH]           Migrate the BoltDB schema.
  oswaka backup    [--config PATH] [--out DIR]              Take a hot encrypted backup.
  oswaka restore   [--config PATH] --in PATH [--allow-sth-mismatch]
                                                            Restore from an encrypted backup.
  oswaka version                                            Show build information.
  oswaka help                                               Show this help.

Server flags:
  --config PATH    Path to configuration YAML (default configs/examples/default.yaml).
  --version        Show version and exit.
`)
}
