package identity

import (
	"crypto/x509"
	"strings"
)

// RolesFromCert extracts OWASAKA role names from an X.509 client cert.
//
// Convention: a cert's Subject OU entry of the form "role:<name>" binds
// the service principal to that role. Multiple OU entries with the
// `role:` prefix are unioned. Other OU entries (or none) are ignored.
//
// Examples:
//
//	Subject: CN=spectre,OU=role:service,O=voidnxlabs
//	  → ["service"]
//
//	Subject: CN=ops-relay,OU=role:service,OU=role:rule-author,O=voidnxlabs
//	  → ["service", "rule-author"]
//
// Returns nil for nil certs or certs without role-tagged OU entries.
// Callers typically assign the result to Principal.Roles after the
// mTLS handshake validates the chain.
func RolesFromCert(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	const prefix = "role:"
	var out []string
	for _, ou := range cert.Subject.OrganizationalUnit {
		if !strings.HasPrefix(ou, prefix) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(ou, prefix))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

// AssignRoles replaces the Principal's role set with the given names.
// Safe on nil Principal (no-op). De-duplicates while preserving the
// caller's input order; empty names are skipped.
//
// Use this at provisioning and on every successful login that derives
// roles from an external authority (mTLS cert, OIDC token).
func AssignRoles(p *Principal, names ...string) {
	if p == nil {
		return
	}
	seen := make(map[string]bool, len(names))
	roles := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		roles = append(roles, n)
	}
	p.Roles = roles
}
