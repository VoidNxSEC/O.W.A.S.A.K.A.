package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
)

// Engine wires a Source (BoltDB) to one or more Sinks (filesystem,
// NAS, tee) with age encryption between the two. Build once at
// startup; Run is safe to call from a goroutine on a schedule and
// also from the HTTP admin endpoint and the CLI.
type Engine struct {
	source     Source
	sinks      []Sink
	recipients []age.Recipient
	clock      func() time.Time
}

// EngineOption configures the Engine. WithClock is the only one used
// in tests; production builds use the defaults.
type EngineOption func(*Engine)

// WithClock overrides the time source for deterministic filename
// generation in tests.
func WithClock(c func() time.Time) EngineOption {
	return func(e *Engine) { e.clock = c }
}

// NewEngine builds a configured Engine. recipients are the age
// public keys that will be able to decrypt the backup; in production
// these come from the same .sops.yaml that protects secrets.yaml.
// Returns errors if any input is missing.
func NewEngine(source Source, sinks []Sink, recipients []age.Recipient, opts ...EngineOption) (*Engine, error) {
	if source == nil {
		return nil, ErrNoSource
	}
	if len(sinks) == 0 {
		return nil, ErrNoSinks
	}
	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}
	e := &Engine{
		source:     source,
		sinks:      sinks,
		recipients: recipients,
		clock:      time.Now,
	}
	for _, o := range opts {
		o(e)
	}
	return e, nil
}

// Run produces a single backup artifact and writes it to every
// configured Sink. Returns the artifact for caller-side logging /
// auditing.
//
// Failures in any sink return immediately; partial sink success is
// surfaced via the error message (which sink failed) — the caller
// (admin endpoint / scheduler) decides whether to retry. The artifact
// produced is the same one passed to every sink, so retrying with a
// different sink set is straightforward.
func (e *Engine) Run(ctx context.Context) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrBackupCanceled, err)
	}

	now := e.clock().UTC()
	var raw bytes.Buffer
	if _, err := e.source.WriteTo(ctx, raw.Write); err != nil {
		return Artifact{}, fmt.Errorf("backup: source write: %w", err)
	}

	encrypted, err := encryptForRecipients(raw.Bytes(), e.recipients)
	if err != nil {
		return Artifact{}, fmt.Errorf("backup: encrypt: %w", err)
	}

	digest := sha256.Sum256(encrypted)
	sidecar := []byte(hex.EncodeToString(digest[:]) + "\n")

	treeSize := uint64(0)
	rootHex := ""
	if md, ok := e.source.(MetadataProvider); ok {
		ts, rh, mderr := md.BackupMetadata(ctx)
		if mderr == nil {
			treeSize = ts
			rootHex = rh
		}
	}

	artifact := Artifact{
		Filename:    formatFilename(now, treeSize),
		Encrypted:   encrypted,
		Sidecar:     sidecar,
		CreatedAt:   now,
		TreeSize:    treeSize,
		RootHashHex: rootHex,
	}

	for _, sink := range e.sinks {
		if err := sink.Write(ctx, artifact); err != nil {
			return artifact, fmt.Errorf("backup: sink %s: %w", sink.Name(), err)
		}
	}
	return artifact, nil
}

// formatFilename produces the canonical backup file name. The
// timestamp uses '-' separators (not ':' / '.') so the name is
// filesystem-safe across Windows / S3 / NFS variants. tree size is
// in the filename so a sort gives chronological + sized listing.
func formatFilename(t time.Time, treeSize uint64) string {
	stamp := t.Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("backup-%s-tree%d.db.age", stamp, treeSize)
}

// encryptForRecipients wraps the cleartext into an age envelope
// addressed to every recipient. Decrypting with any one of the
// matching identities recovers the original bytes.
func encryptForRecipients(cleartext []byte, recipients []age.Recipient) ([]byte, error) {
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(cleartext); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// DecryptArtifact reverses encryptForRecipients given any identity
// (age private key) authorized for the backup. Used by the restore
// flow (B12) and the integration test (B13).
func DecryptArtifact(encrypted []byte, identities []age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, ErrNoRecipients
	}
	r, err := age.Decrypt(bytes.NewReader(encrypted), identities...)
	if err != nil {
		return nil, fmt.Errorf("backup: decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("backup: read decrypted: %w", err)
	}
	return out, nil
}

// VerifySidecar checks the SHA-256 sidecar against the encrypted
// payload. Returns nil on match. Operators run this before
// attempting decryption — catches transport corruption or partial
// downloads from a NAS sink.
func VerifySidecar(encrypted, sidecar []byte) error {
	got := sha256.Sum256(encrypted)
	expectedHex := strings.TrimSpace(string(sidecar))
	gotHex := hex.EncodeToString(got[:])
	if expectedHex == "" {
		return fmt.Errorf("backup: empty sidecar")
	}
	if !strings.EqualFold(expectedHex, gotHex) {
		return fmt.Errorf("backup: sidecar mismatch (expected %s got %s)", expectedHex, gotHex)
	}
	return nil
}
