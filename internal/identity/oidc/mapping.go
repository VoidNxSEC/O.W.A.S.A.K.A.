package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
)

// ClaimMapper resolves verified OIDC ID claims to an OWASAKA Principal.
//
// The default DefaultMapper looks up an existing principal by OIDC
// subject; if missing, it either auto-provisions (when configured) or
// returns ErrPrincipalUnknown.
type ClaimMapper interface {
	Map(ctx context.Context, claims IDClaims) (*identity.Principal, error)
}

// DefaultMapper is the canonical OIDC → Principal binding.
//
// It indexes principals by a "oidc:<issuer>:<sub>" Subject so multiple
// issuers can coexist without collision. When AutoProvision is on, the
// first login for an unknown OIDC subject creates a Human principal
// with claims pre-populated from the ID token. GroupRoleMap binds
// IdP-issued groups to OWASAKA roles on every login (so role changes
// in the IdP propagate without manual sync).
type DefaultMapper struct {
	Store         identity.PrincipalStore
	AutoProvision bool
	// GroupRoleMap binds IdP group names to OWASAKA role names.
	// Empty map means OIDC logins receive no roles by default —
	// operators must pre-assign roles via the principal store, or
	// provision the mapping here. See oidc.Config.GroupRoleMap.
	GroupRoleMap map[string]string
	Now          func() time.Time
}

// NewDefaultMapper builds a DefaultMapper. Pass autoProvision=false to
// require operators to be pre-provisioned (high-assurance deployments).
// groupRoleMap is the IdP group → OWASAKA role binding; nil/empty maps
// produce role-less Principals that fail every authorization check
// (compliant fail-closed behavior, callers should configure groups).
func NewDefaultMapper(store identity.PrincipalStore, autoProvision bool, groupRoleMap map[string]string) *DefaultMapper {
	return &DefaultMapper{
		Store:         store,
		AutoProvision: autoProvision,
		GroupRoleMap:  groupRoleMap,
		Now:           time.Now,
	}
}

// Map resolves the claims to a Principal.
//
// Returns ErrPrincipalUnknown if no matching principal exists and
// auto-provision is disabled; identity.ErrPrincipalInactive if the
// matched principal is not active.
func (m *DefaultMapper) Map(ctx context.Context, claims IDClaims) (*identity.Principal, error) {
	if claims.Subject == "" || claims.Issuer == "" {
		return nil, errors.New("oidc: ID claims missing sub or iss")
	}
	subject := PrincipalSubject(claims)

	existing, err := m.Store.FindBySubject(ctx, subject)
	if err == nil {
		if !existing.IsActive() {
			return nil, identity.ErrPrincipalInactive
		}
		// Refresh claims and roles on every login so IdP-side group /
		// email changes propagate without a separate sync job.
		existing.Claims = enrichClaims(existing.Claims, claims)
		identity.AssignRoles(existing, m.rolesForGroups(claims.Groups)...)
		_ = m.Store.Save(ctx, existing)
		return existing, nil
	}
	if !errors.Is(err, identity.ErrPrincipalNotFound) {
		return nil, err
	}

	if !m.AutoProvision {
		return nil, ErrPrincipalUnknown
	}

	now := m.Now()
	display := claims.Name
	if display == "" {
		display = claims.PreferredUsername
	}
	p := &identity.Principal{
		ID:          uuid.NewString(),
		Type:        identity.PrincipalHuman,
		Subject:     subject,
		DisplayName: display,
		Status:      identity.StatusActive,
		Claims:      enrichClaims(nil, claims),
		CreatedAt:   now,
	}
	identity.AssignRoles(p, m.rolesForGroups(claims.Groups)...)
	if err := m.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// rolesForGroups translates IdP-issued group names into OWASAKA role
// names via the configured GroupRoleMap. Unmapped groups are dropped
// silently — they may belong to other applications sharing the IdP.
func (m *DefaultMapper) rolesForGroups(groups []string) []string {
	if len(groups) == 0 || len(m.GroupRoleMap) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if role, ok := m.GroupRoleMap[g]; ok && role != "" {
			out = append(out, role)
		}
	}
	return out
}

// PrincipalSubject is the canonical store-indexed Subject for an OIDC
// identity. Format: "oidc:<issuer>:<sub>". Exposed so callers that
// pre-provision principals can register them under the same key.
func PrincipalSubject(claims IDClaims) string {
	return "oidc:" + claims.Issuer + ":" + claims.Subject
}

func enrichClaims(base map[string]any, c IDClaims) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	base["oidc_sub"] = c.Subject
	base["oidc_iss"] = c.Issuer
	if c.Email != "" {
		base["email"] = c.Email
		base["email_verified"] = c.EmailVerified
	}
	if c.Name != "" {
		base["name"] = c.Name
	}
	if c.PreferredUsername != "" {
		base["preferred_username"] = c.PreferredUsername
	}
	if len(c.Groups) > 0 {
		base["groups"] = c.Groups
	}
	return base
}
