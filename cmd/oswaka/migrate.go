package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/migrations"
)

// runMigrate is the `oswaka migrate` subcommand dispatcher. The first
// positional argument is the action (up|status|down); --config points
// at the YAML to locate the data dir.
func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configPath := fs.String("config", "configs/examples/default.yaml", "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oswaka migrate <up|status|down> [--config PATH]")
		return 2
	}

	cfg, _, err := loadConfigAndLogger(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	dbPath := filepath.Join(cfg.Storage.Local.DataDir, "owasaka.db")
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db %s: %v\n", dbPath, err)
		return 1
	}
	defer db.Close()

	switch rest[0] {
	case "status":
		st, err := migrations.CurrentStatus(db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "status: %v\n", err)
			return 1
		}
		fmt.Printf("Applied:  %d\nAvailable: %d\nPending:  %d\n",
			st.Applied, st.Available, len(st.Pending))
		for _, m := range st.Pending {
			fmt.Printf("  - %04d %s\n", m.ID, m.Description)
		}
		return 0
	case "up":
		applied, err := migrations.RunUp(db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate up: %v\n", err)
			return 1
		}
		fmt.Printf("Applied through migration %d.\n", applied)
		return 0
	case "down":
		// `oswaka migrate down` reverts ONE migration. We require an
		// explicit --confirm flag because down-migrations are rare,
		// destructive, and easy to fat-finger.
		confirm := false
		for _, a := range rest[1:] {
			if a == "--confirm" {
				confirm = true
			}
		}
		if !confirm {
			fmt.Fprintln(os.Stderr, "refusing to run down-migration without --confirm")
			return 2
		}
		reverted, err := migrations.RunDown(db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate down: %v\n", err)
			return 1
		}
		fmt.Printf("Reverted migration %d.\n", reverted)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown migrate action %q\n", rest[0])
		return 2
	}
}
