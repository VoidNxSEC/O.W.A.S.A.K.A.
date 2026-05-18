// Package backup implements OWASAKA's hot-backup engine. Backups are
// written using BoltDB's native Tx.WriteTo primitive — bit-identical
// restoration with zero parsing — then encrypted with age using the
// same recipient set as the sops `secrets.yaml`. See ADR-0064.
//
// The package is composable: BackupEngine wires a backup Source (the
// BoltDB to back up) to one or more BackupSinks (filesystem / NAS /
// tee). Each backup produces an encrypted file plus a SHA-256 sidecar
// so operators can verify integrity before decrypting.
package backup

import (
	"context"
	"errors"
	"time"
)

// Artifact describes a written backup. Returned by Engine.Run and
// propagated to every Sink so the sidecar / journaling can attach.
type Artifact struct {
	// Filename is the suggested filename (no path), e.g.
	// "backup-2026-05-18T12-00-00Z-tree42.db.age".
	Filename string

	// Encrypted is the age-encrypted backup bytes. Sinks write
	// Encrypted to durable storage and Sidecar alongside it.
	Encrypted []byte

	// Sidecar is the SHA-256 hex digest of Encrypted as ASCII bytes
	// (trailing newline). Sinks write to <Filename>.sha256.
	Sidecar []byte

	// CreatedAt is the UTC timestamp captured at the start of the
	// backup transaction.
	CreatedAt time.Time

	// TreeSize is the transparency log tree size captured during the
	// backup. Zero if the log is empty or transparency is not wired.
	TreeSize uint64

	// RootHashHex is the hex-encoded Merkle root at TreeSize. Empty
	// when TreeSize is zero.
	RootHashHex string
}

// Source is the BoltDB-shaped thing a BackupEngine reads from. The
// production source is *bbolt.DB; tests can stub with anything that
// implements View + a Tx.WriteTo-equivalent.
type Source interface {
	// WriteTo runs a read transaction and copies the entire database
	// to the writer-like sink. Returns the number of bytes written.
	// Mirrors bbolt.DB.View + Tx.WriteTo.
	WriteTo(ctx context.Context, write func(p []byte) (int, error)) (int64, error)
}

// Sink receives a fully-formed Artifact and persists it. Implementations
// MUST handle Encrypted and Sidecar as a unit — partial writes (one but
// not the other) leave operators unable to verify.
type Sink interface {
	// Name is a short label used in logs and audit events.
	Name() string

	// Write persists the artifact. Returns an error if either the
	// encrypted body or the sidecar fails to write; the sink is
	// expected to clean up partial state before returning.
	Write(ctx context.Context, artifact Artifact) error
}

// MetadataProvider is an optional contract a Source can implement to
// surface transparency-log state at backup time. The engine asks for
// the current STH so the Artifact records what state the backup
// captured — letting operators detect "I restored an old backup" via
// the STH journal-record comparison.
type MetadataProvider interface {
	BackupMetadata(ctx context.Context) (treeSize uint64, rootHashHex string, err error)
}

// Sentinel errors.
var (
	ErrNoSinks        = errors.New("backup: at least one sink is required")
	ErrNoSource       = errors.New("backup: source is required")
	ErrNoRecipients   = errors.New("backup: at least one age recipient is required")
	ErrBackupCanceled = errors.New("backup: canceled")
)
