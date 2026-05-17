package identity

import (
	"testing"
	"time"
)

func TestPrincipal_IsActive(t *testing.T) {
	cases := []struct {
		name string
		p    *Principal
		want bool
	}{
		{"nil principal", nil, false},
		{"active", &Principal{Status: StatusActive}, true},
		{"suspended", &Principal{Status: StatusSuspended}, false},
		{"revoked", &Principal{Status: StatusRevoked}, false},
		{"zero value", &Principal{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.IsActive(); got != tc.want {
				t.Errorf("IsActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrincipal_Claim(t *testing.T) {
	now := time.Now()
	p := &Principal{
		ID:        "01HXXX",
		Type:      PrincipalHuman,
		Subject:   "marcos",
		Status:    StatusActive,
		CreatedAt: now,
		Claims: map[string]any{
			"email": "marcos@voidnxlabs.dev",
			"team":  "security",
			"age":   30, // non-string, should return empty
		},
	}

	if got := p.Claim("email"); got != "marcos@voidnxlabs.dev" {
		t.Errorf("Claim(email) = %q, want marcos@voidnxlabs.dev", got)
	}
	if got := p.Claim("missing"); got != "" {
		t.Errorf("Claim(missing) = %q, want empty", got)
	}
	if got := p.Claim("age"); got != "" {
		t.Errorf("Claim(age) non-string should return empty, got %q", got)
	}

	var nilP *Principal
	if got := nilP.Claim("anything"); got != "" {
		t.Errorf("nil Principal Claim should return empty, got %q", got)
	}

	noClaims := &Principal{ID: "x"}
	if got := noClaims.Claim("anything"); got != "" {
		t.Errorf("Principal without claims should return empty, got %q", got)
	}
}

func TestPrincipalType_Values(t *testing.T) {
	// Compile-time guarantee that the constants are non-empty and distinct.
	all := []PrincipalType{PrincipalHuman, PrincipalService, PrincipalAgent}
	seen := make(map[PrincipalType]bool)
	for _, v := range all {
		if v == "" {
			t.Errorf("PrincipalType constant is empty")
		}
		if seen[v] {
			t.Errorf("duplicate PrincipalType value: %q", v)
		}
		seen[v] = true
	}
}

func TestPrincipalStatus_Values(t *testing.T) {
	all := []PrincipalStatus{StatusActive, StatusSuspended, StatusRevoked}
	seen := make(map[PrincipalStatus]bool)
	for _, v := range all {
		if v == "" {
			t.Errorf("PrincipalStatus constant is empty")
		}
		if seen[v] {
			t.Errorf("duplicate PrincipalStatus value: %q", v)
		}
		seen[v] = true
	}
}
