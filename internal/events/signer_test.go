package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

func bootstrappedAuthority(t *testing.T) *pki.Authority {
	t.Helper()
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	if _, err := a.GenerateKeyPair(context.Background(), pki.PurposeEventSigning, 24*time.Hour); err != nil {
		t.Fatalf("seed event signing key: %v", err)
	}
	return a
}

func sampleEvent() *models.NetworkEvent {
	return &models.NetworkEvent{
		ID:          "evt-1",
		Type:        models.EventDNS,
		Source:      "10.0.0.5",
		Destination: "1.1.1.1",
		Metadata:    map[string]any{"qname": "voidnxlabs.dev"},
		Timestamp:   time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	}
}

func TestSigner_RoundTripWithVerifier(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	verifier := NewVerifier(a)

	ev := sampleEvent()
	must(t, signer.Sign(context.Background(), ev), "Sign")

	if !ev.IsSigned() {
		t.Fatal("event must be signed after Sign")
	}
	if err := verifier.Verify(context.Background(), *ev); err != nil {
		t.Fatalf("verify round-trip: %v", err)
	}
}

func TestSigner_NilEventRejected(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	if err := signer.Sign(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil event")
	}
}

func TestSigner_NoActiveKey(t *testing.T) {
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	signer := NewSigner(a)
	if err := signer.Sign(context.Background(), sampleEvent()); !errors.Is(err, ErrSignerNoActiveKey) {
		t.Fatalf("expected ErrSignerNoActiveKey, got %v", err)
	}
}

func TestVerifier_UnsignedEventRejected(t *testing.T) {
	a := bootstrappedAuthority(t)
	v := NewVerifier(a)
	if err := v.Verify(context.Background(), *sampleEvent()); !errors.Is(err, ErrSignatureMissing) {
		t.Fatalf("expected ErrSignatureMissing, got %v", err)
	}
}

func TestVerifier_UnknownKey(t *testing.T) {
	a := bootstrappedAuthority(t)
	v := NewVerifier(a)
	ev := sampleEvent()
	ev.Signature = []byte("forged")
	ev.SignerKeyID = "no-such-key"
	if err := v.Verify(context.Background(), *ev); !errors.Is(err, ErrSignerKeyUnknown) {
		t.Fatalf("expected ErrSignerKeyUnknown, got %v", err)
	}
}

func TestVerifier_TamperedPayload(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	v := NewVerifier(a)

	ev := sampleEvent()
	must(t, signer.Sign(context.Background(), ev), "Sign")

	// Mutate after signing — should fail.
	ev.Destination = "8.8.8.8"
	if err := v.Verify(context.Background(), *ev); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid after tamper, got %v", err)
	}
}

func TestVerifier_TamperedSignature(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	v := NewVerifier(a)

	ev := sampleEvent()
	must(t, signer.Sign(context.Background(), ev), "Sign")

	// Flip one byte of the signature.
	ev.Signature[0] ^= 0xff
	if err := v.Verify(context.Background(), *ev); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for flipped signature, got %v", err)
	}
}

func TestVerifier_AcceptsRotatingKey(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	v := NewVerifier(a)

	ev := sampleEvent()
	must(t, signer.Sign(context.Background(), ev), "Sign")

	// Rotate: the signing key becomes "rotating" but should still verify.
	if _, err := a.Rotate(context.Background(), pki.PurposeEventSigning, 24*time.Hour); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := v.Verify(context.Background(), *ev); err != nil {
		t.Fatalf("rotating key should still verify historical events, got %v", err)
	}
}

func TestVerifier_RejectsRetiredKey(t *testing.T) {
	a := bootstrappedAuthority(t)
	signer := NewSigner(a)
	v := NewVerifier(a)

	ev := sampleEvent()
	must(t, signer.Sign(context.Background(), ev), "Sign")

	keyID := ev.SignerKeyID
	if err := a.Retire(context.Background(), keyID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := v.Verify(context.Background(), *ev); !errors.Is(err, ErrSignerKeyRetired) {
		t.Fatalf("expected ErrSignerKeyRetired, got %v", err)
	}
}

func TestVerifier_RejectsCrossPurposeKey(t *testing.T) {
	// Sign under one Authority + purpose; try to verify a forged
	// event whose kid resolves to a JWT signing key. Must refuse to
	// honor the cross-purpose match.
	a := pki.NewAuthority(pki.NewMemoryKeyStore())
	jwtKey, err := a.GenerateKeyPair(context.Background(), pki.PurposeJWTSigning, time.Hour)
	must(t, err, "seed jwt key")

	v := NewVerifier(a)
	ev := sampleEvent()
	ev.Signature = []byte("does-not-matter") // verify fails earlier with ErrSignerKeyUnknown
	ev.SignerKeyID = jwtKey.ID

	if err := v.Verify(context.Background(), *ev); !errors.Is(err, ErrSignerKeyUnknown) {
		t.Fatalf("expected ErrSignerKeyUnknown for cross-purpose, got %v", err)
	}
}

func TestSignerErrorIs_AllCategories(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrSignatureMissing, "missing"},
		{ErrSignatureInvalid, "invalid"},
		{ErrSignerKeyUnknown, "unknown_key"},
		{ErrSignerKeyRetired, "retired_key"},
		{ErrSignerNoActiveKey, "no_active_key"},
	}
	for _, tc := range cases {
		got, ok := SignerErrorIs(tc.err)
		if !ok || got != tc.want {
			t.Fatalf("category for %v: got (%q, %v), want (%q, true)", tc.err, got, ok, tc.want)
		}
	}
	if _, ok := SignerErrorIs(errors.New("unrelated")); ok {
		t.Fatal("unrelated error must not match a sentinel category")
	}
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}
