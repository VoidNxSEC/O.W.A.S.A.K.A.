package models

import (
	"bytes"
	"testing"
	"time"
)

func TestNetworkEvent_CanonicalBytes_ExcludesSignatureFields(t *testing.T) {
	e := NetworkEvent{
		ID:          "evt-1",
		Type:        EventDNS,
		Source:      "10.0.0.5",
		Destination: "1.1.1.1",
		Metadata:    map[string]any{"qname": "example.com"},
		Timestamp:   time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	}

	unsigned, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	e.Signature = []byte("forged-signature")
	e.SignerKeyID = "forged-key"
	signed, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical (signed): %v", err)
	}

	if !bytes.Equal(unsigned, signed) {
		t.Fatalf("canonical bytes must be identical before/after signature:\n  unsigned=%s\n  signed=%s",
			unsigned, signed)
	}
}

func TestNetworkEvent_CanonicalBytes_StableAcrossCallsWithMap(t *testing.T) {
	e := NetworkEvent{
		ID: "evt-2",
		Metadata: map[string]any{
			"z-key": 1,
			"a-key": 2,
			"m-key": 3,
		},
	}
	first, _ := e.CanonicalBytes()
	second, _ := e.CanonicalBytes()
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical bytes not stable across calls:\n  first =%s\n  second=%s", first, second)
	}
}

func TestNetworkEvent_IsSigned(t *testing.T) {
	cases := []struct {
		name string
		ev   NetworkEvent
		want bool
	}{
		{"unsigned", NetworkEvent{}, false},
		{"sig only", NetworkEvent{Signature: []byte{1}}, false},
		{"kid only", NetworkEvent{SignerKeyID: "k"}, false},
		{"both", NetworkEvent{Signature: []byte{1}, SignerKeyID: "k"}, true},
		{"empty sig + kid", NetworkEvent{Signature: []byte{}, SignerKeyID: "k"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ev.IsSigned(); got != tc.want {
				t.Fatalf("IsSigned() = %v, want %v", got, tc.want)
			}
		})
	}
}
