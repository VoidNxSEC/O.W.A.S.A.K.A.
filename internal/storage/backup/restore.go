package backup

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	bolt "go.etcd.io/bbolt"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/transparency"
)

// RestoreInput packages everything the restore primitive needs.
// Operators typically build it from CLI flags or the admin endpoint.
type RestoreInput struct {
	// EncryptedPath is the on-disk path of the .age backup file.
	EncryptedPath string

	// SidecarPath is the path of the .sha256 sidecar. When empty,
	// EncryptedPath + ".sha256" is used.
	SidecarPath string

	// Identities are the age private keys authorized to decrypt. At
	// least one must succeed. Typically loaded from
	// ~/.config/sops/age/keys.txt or the systemd LoadCredential path
	// (per ADR-0059 §"Secrets management").
	Identities []age.Identity

	// TargetPath is the path the restored owasaka.db should land at
	// after the swap. The current file at TargetPath is moved aside
	// (.bak.<timestamp>) before the restored file takes its place.
	TargetPath string

	// ExpectedSTH, if non-nil, is the operator's journal record of
	// the STH this backup should match. The restore primitive
	// compares against the STH captured at backup time and refuses
	// to swap on mismatch unless AllowSTHMismatch is true.
	ExpectedSTH *transparency.STH

	// AllowSTHMismatch bypasses the STH journal-record check. Set
	// only when the operator deliberately restores from an older
	// backup (DR exercise, suspected-tamper recovery).
	AllowSTHMismatch bool
}

// RestoreReport summarizes the outcome. Returned to callers for
// logging and audit-trail purposes.
type RestoreReport struct {
	BackupCreatedAt time.Time
	BackupTreeSize  uint64
	BackupRootHex   string
	SwappedAt       time.Time
	OldDBBackupPath string // where the previous live DB was moved
	NewDBPath       string // == TargetPath
	STHMatch        bool
	STHMismatchNote string // human-readable explanation when mismatched
}

// Restore decrypts an encrypted backup, verifies its sidecar, opens
// the resulting bolt file read-only to confirm validity, optionally
// cross-checks the captured STH against the operator's journal
// record, then atomically swaps the live DB with the restored file.
//
// The current TargetPath is moved aside (renamed with a .bak.<ts>
// suffix) before the restored file takes its place. The caller is
// responsible for restarting the binary so the new DB is picked up;
// in-flight bbolt handles to the old file MUST be closed before
// calling Restore.
//
// Returns ErrSTHMismatch when ExpectedSTH is set and the backup's
// STH disagrees, unless AllowSTHMismatch is true.
func Restore(ctx context.Context, in RestoreInput) (RestoreReport, error) {
	if err := ctx.Err(); err != nil {
		return RestoreReport{}, fmt.Errorf("%w: %v", ErrBackupCanceled, err)
	}
	if in.EncryptedPath == "" || in.TargetPath == "" {
		return RestoreReport{}, errors.New("restore: EncryptedPath and TargetPath required")
	}
	if len(in.Identities) == 0 {
		return RestoreReport{}, ErrNoRecipients
	}

	sidePath := in.SidecarPath
	if sidePath == "" {
		sidePath = in.EncryptedPath + ".sha256"
	}

	enc, err := os.ReadFile(in.EncryptedPath)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("restore: read encrypted: %w", err)
	}
	side, err := os.ReadFile(sidePath)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("restore: read sidecar: %w", err)
	}
	if err := VerifySidecar(enc, side); err != nil {
		return RestoreReport{}, fmt.Errorf("restore: sidecar verify: %w", err)
	}

	plain, err := DecryptArtifact(enc, in.Identities)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("restore: %w", err)
	}

	// Stage the decrypted bytes alongside the target so the rename is
	// always within the same filesystem (POSIX atomic).
	targetDir := filepath.Dir(in.TargetPath)
	staging, err := os.CreateTemp(targetDir, "restore-*.db")
	if err != nil {
		return RestoreReport{}, fmt.Errorf("restore: create staging: %w", err)
	}
	stagingPath := staging.Name()
	if _, err := staging.Write(plain); err != nil {
		_ = staging.Close()
		_ = os.Remove(stagingPath)
		return RestoreReport{}, fmt.Errorf("restore: write staging: %w", err)
	}
	if err := staging.Close(); err != nil {
		_ = os.Remove(stagingPath)
		return RestoreReport{}, fmt.Errorf("restore: close staging: %w", err)
	}

	// Validate the staged file actually opens as a BoltDB and pull
	// the transparency state out for the report + STH check.
	stagedTreeSize, stagedRootHex, stagedCreated, openErr := inspectStaged(stagingPath)
	if openErr != nil {
		_ = os.Remove(stagingPath)
		return RestoreReport{}, fmt.Errorf("restore: staged DB invalid: %w", openErr)
	}

	report := RestoreReport{
		BackupCreatedAt: stagedCreated,
		BackupTreeSize:  stagedTreeSize,
		BackupRootHex:   stagedRootHex,
		NewDBPath:       in.TargetPath,
	}

	if in.ExpectedSTH != nil {
		gotHex := stagedRootHex
		wantHex := hex.EncodeToString(in.ExpectedSTH.RootHash)
		match := uint64(in.ExpectedSTH.TreeSize) == stagedTreeSize && wantHex == gotHex
		report.STHMatch = match
		if !match {
			report.STHMismatchNote = fmt.Sprintf(
				"journal expected size=%d root=%s, backup carries size=%d root=%s",
				in.ExpectedSTH.TreeSize, wantHex, stagedTreeSize, gotHex)
			if !in.AllowSTHMismatch {
				_ = os.Remove(stagingPath)
				return report, fmt.Errorf("restore: %w (%s)", ErrSTHMismatch, report.STHMismatchNote)
			}
		}
	} else {
		// No expected STH supplied — restore succeeds, but the caller's
		// log line should make this visible.
		report.STHMatch = true
		report.STHMismatchNote = "no ExpectedSTH supplied — restored without journal-record comparison"
	}

	// Atomic swap. We rename the live file aside (if present) first,
	// then rename staging into its place.
	swapTime := time.Now().UTC()
	report.SwappedAt = swapTime

	if _, err := os.Stat(in.TargetPath); err == nil {
		bakSuffix := ".bak." + swapTime.Format("2006-01-02T15-04-05Z")
		bakPath := in.TargetPath + bakSuffix
		if rerr := os.Rename(in.TargetPath, bakPath); rerr != nil {
			_ = os.Remove(stagingPath)
			return report, fmt.Errorf("restore: rename current aside: %w", rerr)
		}
		report.OldDBBackupPath = bakPath
	}
	if rerr := os.Rename(stagingPath, in.TargetPath); rerr != nil {
		_ = os.Remove(stagingPath)
		return report, fmt.Errorf("restore: rename staging into place: %w", rerr)
	}

	return report, nil
}

// inspectStaged opens the staged file briefly, derives the
// transparency tree state from it, and returns it for the restore
// report + STH journal-record comparison.
//
// The open is read-write (not read-only) because transparency.Open
// creates the schema buckets if they're missing, which is correct
// behavior for restores: the staged file is about to become the live
// DB anyway. A read-only open would refuse the bucket bootstrap on
// backups taken before the transparency tables existed.
func inspectStaged(path string) (size uint64, rootHex string, createdAt time.Time, err error) {
	st, statErr := os.Stat(path)
	if statErr != nil {
		return 0, "", time.Time{}, statErr
	}
	createdAt = st.ModTime().UTC()

	db, openErr := bolt.Open(path, 0o600, &bolt.Options{
		Timeout: 2 * time.Second,
	})
	if openErr != nil {
		return 0, "", createdAt, openErr
	}
	defer db.Close()

	tree, terr := transparency.Open(db)
	if terr != nil {
		return 0, "", createdAt, terr
	}
	size = uint64(tree.Size())
	root := tree.Root()
	rootHex = hex.EncodeToString(root[:])
	return size, rootHex, createdAt, nil
}

// ErrSTHMismatch indicates the staged backup's transparency state
// disagrees with the journal-record STH the operator supplied. The
// restore primitive refuses to swap unless AllowSTHMismatch is true.
var ErrSTHMismatch = errors.New("restore: STH journal-record mismatch")
