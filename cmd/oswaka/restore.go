package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/backup"
)

// runRestore is the `oswaka restore` subcommand. Reads the encrypted
// artifact at --in, verifies the sidecar, decrypts with identities
// from --identities-file (default storage.backup.identities_file or
// SOPS_AGE_KEY_FILE env), and atomically swaps the live DB.
//
// The operator MUST run this against a STOPPED server. Restore opens
// the staged DB read-write to validate it (transparency.Open creates
// buckets), which would otherwise collide with the running binary's
// file lock.
func runRestore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	configPath := fs.String("config", "configs/examples/default.yaml", "Path to configuration file")
	in := fs.String("in", "", "Encrypted backup file (.age) to restore from (required)")
	identitiesPath := fs.String("identities-file", "", "Override storage.backup.identities_file")
	allowSTHMismatch := fs.Bool("allow-sth-mismatch", false, "Permit STH journal-record mismatch (DR exercise / forced rewind)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *in == "" {
		fmt.Fprintln(os.Stderr, "restore: --in PATH is required")
		return 2
	}

	cfg, logger, err := loadConfigAndLogger(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = logger.Sync() }()

	idPath := *identitiesPath
	if idPath == "" {
		idPath = cfg.Storage.Backup.IdentitiesFile
	}
	if idPath == "" {
		idPath = os.Getenv("SOPS_AGE_KEY_FILE")
	}
	if idPath == "" {
		fmt.Fprintln(os.Stderr, "restore: no identities file (set --identities-file, storage.backup.identities_file, or SOPS_AGE_KEY_FILE)")
		return 2
	}

	ids, err := loadIdentities(idPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: load identities %s: %v\n", idPath, err)
		return 1
	}

	target := filepath.Join(cfg.Storage.Local.DataDir, "owasaka.db")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	report, err := backup.Restore(ctx, backup.RestoreInput{
		EncryptedPath:    *in,
		Identities:       ids,
		TargetPath:       target,
		AllowSTHMismatch: *allowSTHMismatch,
		// ExpectedSTH is left nil; operators wanting STH journal
		// enforcement use the admin HTTP endpoint or a future
		// --expected-sth flag.
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: %v\n", err)
		return 1
	}
	fmt.Printf("Restore complete.\n")
	fmt.Printf("  target:      %s\n", report.NewDBPath)
	fmt.Printf("  swapped_at:  %s\n", report.SwappedAt.UTC().Format(time.RFC3339))
	fmt.Printf("  old_db:      %s\n", report.OldDBBackupPath)
	fmt.Printf("  backup_size: %d  root=%s\n", report.BackupTreeSize, report.BackupRootHex)
	if report.STHMismatchNote != "" {
		fmt.Printf("  sth_note:    %s\n", report.STHMismatchNote)
	}
	return 0
}

// loadIdentities parses an age key file (text, one or more X25519
// keys, comments allowed). filippo.io/age's ParseIdentities does the
// heavy lifting; we just open the file.
func loadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return age.ParseIdentities(f)
}
