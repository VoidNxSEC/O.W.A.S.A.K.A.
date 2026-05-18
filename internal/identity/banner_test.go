package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

func TestBootBanner_RendersAllAvailablePurposes(t *testing.T) {
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	ctx := context.Background()

	if _, err := a.EnsureRootCA(ctx, time.Hour); err != nil {
		t.Fatalf("ensure root: %v", err)
	}
	if _, err := a.GenerateKeyPair(ctx, pki.PurposeJWTSigning, time.Hour); err != nil {
		t.Fatalf("jwt key: %v", err)
	}
	if _, err := a.GenerateKeyPair(ctx, pki.PurposeEventSigning, time.Hour); err != nil {
		t.Fatalf("event key: %v", err)
	}
	if _, err := a.GenerateKeyPair(ctx, pki.PurposeTransparencyLogSTH, time.Hour); err != nil {
		t.Fatalf("sth key: %v", err)
	}

	banner := NewBootBanner(a).Render(ctx, STHSnapshot{
		TreeSize:  42,
		RootHex:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timestamp: time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	})

	for _, expected := range []string{
		"OWASAKA stands ready",
		"Root CA:",
		"JWT signer:",
		"Event signer:",
		"STH signer:",
		"Current STH:",
		"size=42",
		"2026-05-18T12:00:00Z",
		"Trust these fingerprints",
	} {
		if !strings.Contains(banner, expected) {
			t.Errorf("banner missing %q\n--- banner ---\n%s", expected, banner)
		}
	}
}

func TestBootBanner_SkipsMissingPurposes(t *testing.T) {
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	ctx := context.Background()

	// Only the root CA exists.
	if _, err := a.EnsureRootCA(ctx, time.Hour); err != nil {
		t.Fatalf("ensure root: %v", err)
	}

	banner := NewBootBanner(a).Render(ctx, STHSnapshot{})

	if !strings.Contains(banner, "Root CA:") {
		t.Fatal("Root CA must be present")
	}
	for _, missing := range []string{"JWT signer:", "Event signer:", "STH signer:", "Current STH:"} {
		if strings.Contains(banner, missing) {
			t.Errorf("banner should not include %q on fresh deployment\n%s", missing, banner)
		}
	}
}

func TestBootBanner_EmptySTHOmitted(t *testing.T) {
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	ctx := context.Background()
	_, _ = a.EnsureRootCA(ctx, time.Hour)

	banner := NewBootBanner(a).Render(ctx, STHSnapshot{})
	if strings.Contains(banner, "Current STH:") {
		t.Fatalf("zero-value STH must not render the STH line\n%s", banner)
	}
}

func TestTruncateFingerprint(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"aa:bb:cc:dd:ee:ff:00:11", 4, "aa:bb:cc:dd:…"},
		{"aa:bb", 4, "aa:bb"},
		{"", 4, ""},
	}
	for _, tc := range cases {
		if got := truncateFingerprint(tc.in, tc.n); got != tc.want {
			t.Errorf("truncateFingerprint(%q, %d) = %q; want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestTruncateHex(t *testing.T) {
	long := "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef" + "0123456789abcdef"
	short := truncateHex(long, 8)
	if !strings.Contains(short, "…") {
		t.Fatalf("expected ellipsis in truncated hex, got %q", short)
	}
	if truncateHex("abc", 8) != "abc" {
		t.Fatal("short input should pass through unchanged")
	}
}

func TestCenter(t *testing.T) {
	if got := center("hi", 6); got != "  hi  " {
		t.Fatalf("center: %q", got)
	}
	if got := center("toolong", 4); got != "toolong" {
		t.Fatalf("oversize input should pass through, got %q", got)
	}
}
