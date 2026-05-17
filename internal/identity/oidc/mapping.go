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
// with claims pre-populated from the ID token.
type DefaultMapper struct {
	Store         identity.PrincipalStore
	AutoProvision bool
	Now           func() time.Time
}

// NewDefaultMapper builds a DefaultMapper. Pass autoProvision=false to
// require operators to be pre-provisioned (high-assurance deployments).
func NewDefaultMapper(store identity.PrincipalStore, autoProvision bool) *DefaultMapper {
	return &DefaultMapper{
		Store:         store,
		AutoProvision: autoProvision,
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
		// Refresh claims on every login so role/email changes upstream
		// propagate without a separate sync job.
		existing.Claims = enrichClaims(existing.Claims, claims)
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
	if err := m.Store.Save(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
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
