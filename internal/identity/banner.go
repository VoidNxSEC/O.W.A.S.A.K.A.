package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// BootBanner is the human-readable cryptographic identity card printed
// at startup. Per ADR-0059 §"Voidnxlabs flair" and ADR-0062/ADR-0063
// it surfaces the active key fingerprints so an operator comparing
// against an ops-record can detect a swapped Authority on first boot
// — well before any token or event leaves the binary.
//
// Sample output:
//
//	╔═══════════════════════════════════════════════════════════════════╗
//	║                 OWASAKA stands ready.                             ║
//	╚═══════════════════════════════════════════════════════════════════╝
//	  Root CA:        33:ba:47:f6:e8:b4:49:ec:…
//	  JWT signer:     716d:f935:…
//	  Event signer:   a1c4:23ee:…
//	  STH signer:     bb22:1199:…
//	  Current STH:    size=42  root=8f4a:2bc1:…  (2026-05-18T12:00:00Z)
//	  Trust this fingerprint? (compare to ops record)
//
// Each line is only printed if a key for that purpose actually exists;
// a fresh deployment with only the root CA still prints meaningfully.
type BootBanner struct {
	authority *pki.Authority
}

// NewBootBanner builds a BootBanner over a PKI Authority.
func NewBootBanner(authority *pki.Authority) *BootBanner {
	return &BootBanner{authority: authority}
}

// STHSnapshot is what callers pass to Render when they have an STH
// to display. The fields mirror transparency.STH; this struct exists
// so the identity package does not import internal/storage/transparency
// (which would create a dependency cycle).
type STHSnapshot struct {
	TreeSize  uint64
	RootHex   string
	Timestamp time.Time
}

// Render produces the banner as a single string. Callers print it
// via their logger or directly to stderr; the banner does not write
// anywhere itself so tests can assert on the rendered output.
//
// sth may be the zero value when the deployment has not yet appended
// any leaves; in that case the "Current STH" line is omitted.
func (b *BootBanner) Render(ctx context.Context, sth STHSnapshot) string {
	var sb strings.Builder
	border := strings.Repeat("═", 65)
	sb.WriteString(fmt.Sprintf("\n╔%s╗\n", border))
	sb.WriteString(fmt.Sprintf("║%s║\n", center("OWASAKA stands ready.", 65)))
	sb.WriteString(fmt.Sprintf("╚%s╝\n", border))

	b.renderPurpose(ctx, &sb, "Root CA",       pki.PurposeCA)
	b.renderPurpose(ctx, &sb, "JWT signer",    pki.PurposeJWTSigning)
	b.renderPurpose(ctx, &sb, "Event signer",  pki.PurposeEventSigning)
	b.renderPurpose(ctx, &sb, "STH signer",    pki.PurposeTransparencyLogSTH)

	if sth.TreeSize > 0 || sth.RootHex != "" {
		sb.WriteString(fmt.Sprintf("  Current STH:    size=%d  root=%s  (%s)\n",
			sth.TreeSize,
			truncateHex(sth.RootHex, 16),
			sth.Timestamp.UTC().Format(time.RFC3339)))
	}

	sb.WriteString("  Trust these fingerprints? (compare to ops record)\n")
	return sb.String()
}

// renderPurpose prints a single fingerprint line iff a key exists for
// the purpose. Silent on missing keys — the deployment may not have
// rotated/issued every purpose yet.
func (b *BootBanner) renderPurpose(ctx context.Context, sb *strings.Builder, label string, purpose pki.Purpose) {
	kp, err := b.authority.ActiveKey(ctx, purpose)
	if err != nil {
		return
	}
	fp := pki.Fingerprint(kp.Public)
	sb.WriteString(fmt.Sprintf("  %-16s%s\n", label+":", truncateFingerprint(fp, 6)))
}

// truncateFingerprint keeps the first `n` colon-separated bytes plus
// "…" — long enough for a quick visual compare, short enough that the
// banner stays one line per purpose.
func truncateFingerprint(fp string, n int) string {
	parts := strings.Split(fp, ":")
	if len(parts) <= n {
		return fp
	}
	return strings.Join(parts[:n], ":") + ":…"
}

// truncateHex shortens a hex string for display. Returns the original
// if it is already short enough.
func truncateHex(s string, keep int) string {
	if len(s) <= keep*2+1 {
		return s
	}
	return s[:keep] + "…" + s[len(s)-keep:]
}

func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	pad := width - len(s)
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
