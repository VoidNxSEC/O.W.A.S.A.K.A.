package authz

import "testing"

func TestConstantsAreNonEmpty(t *testing.T) {
	if Wildcard == "" {
		t.Fatal("Wildcard must not be empty")
	}
	if ActionAdmin == "" {
		t.Fatal("ActionAdmin must not be empty")
	}
	if ValueNotSelf == "" {
		t.Fatal("ValueNotSelf must not be empty")
	}
}

func TestRoleZeroValueIsUsable(t *testing.T) {
	var r Role
	if r.Name != "" || len(r.Permissions) != 0 {
		t.Fatal("zero-value Role must be empty but valid")
	}
}

func TestPolicyZeroValueIsUsable(t *testing.T) {
	var p Policy
	if p.Version != 0 || p.Roles != nil {
		t.Fatal("zero-value Policy must be empty but valid")
	}
}

func TestDecisionFieldsRoundTrip(t *testing.T) {
	d := Decision{
		Allowed:    true,
		Role:       "admin",
		Permission: &Permission{Resource: "*", Action: "admin"},
		Reason:     "matched admin:*:admin",
	}
	if !d.Allowed || d.Role != "admin" || d.Permission == nil {
		t.Fatalf("decision construction failed: %+v", d)
	}
}
