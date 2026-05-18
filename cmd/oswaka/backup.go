package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/backup"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
)

// runBackup is the `oswaka backup` subcommand. Opens the DB at the
// configured data dir, runs the encrypted backup engine, writes the
// artifact to --out (or storage.backup.output_dir), and prints the
// artifact path on success.
//
// The operator MUST run this against a STOPPED server, OR the server
// is responsible for calling it via the admin endpoint (which holds
// the DB handle already). bbolt's Tx.WriteTo is concurrency-safe but
// opening a second writer with bolt.Open against a locked DB will
// time out — we accept the timeout as the operator's signal to stop
// the server first.
func runBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	configPath := fs.String("config", "configs/examples/default.yaml", "Path to configuration file")
	outDir := fs.String("out", "", "Output directory (overrides storage.backup.output_dir)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, logger, err := loadConfigAndLogger(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = logger.Sync() }()

	if len(cfg.Storage.Backup.Recipients) == 0 {
		fmt.Fprintln(os.Stderr, "backup: no age recipients in storage.backup.recipients")
		return 2
	}
	recipients, err := parseRecipients(cfg.Storage.Backup.Recipients)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: parse recipients: %v\n", err)
		return 1
	}

	dir := *outDir
	if dir == "" {
		dir = cfg.Storage.Backup.OutputDir
	}
	if dir == "" {
		dir = filepath.Join(cfg.Storage.Local.DataDir, "backups")
	}

	dbPath := filepath.Join(cfg.Storage.Local.DataDir, "owasaka.db")
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: open db %s: %v\n  (is the server running? stop it first or use the admin endpoint)\n", dbPath, err)
		return 1
	}
	defer db.Close()

	// Transparency tree is optional for the CLI — best-effort open
	// so the artifact carries its STH/root snapshot when available.
	tree, _ := transparency.Open(db)

	sink, err := backup.NewLocalSink(dir, cfg.Storage.Backup.KeepLast)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: sink init %s: %v\n", dir, err)
		return 1
	}
	engine, err := backup.NewEngine(
		backup.NewBoltSource(db, tree),
		[]backup.Sink{sink},
		recipients,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: engine init: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	art, err := engine.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: run failed: %v\n", err)
		return 1
	}
	fmt.Printf("Backup written: %s\n  tree_size=%d\n  output_dir=%s\n",
		art.Filename, art.TreeSize, dir)
	return 0
}

// parseRecipients turns YAML public-key strings into age.Recipient
// values. Accepts only X25519 (the default for `age-keygen`).
func parseRecipients(keys []string) ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		r, err := age.ParseX25519Recipient(k)
		if err != nil {
			return nil, fmt.Errorf("recipient %q: %w", abbrev(k), err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid recipients after parsing")
	}
	return out, nil
}

func abbrev(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:12] + "…" + s[len(s)-8:]
}
