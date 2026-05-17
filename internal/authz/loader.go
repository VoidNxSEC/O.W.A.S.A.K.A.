package authz

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// yamlPolicy mirrors the on-disk YAML schema. Kept separate from the
// runtime `Policy` so the file format can evolve without disturbing
// the matcher.
type yamlPolicy struct {
	Version int                  `yaml:"version"`
	Roles   map[string]yamlRole  `yaml:"roles"`
}

type yamlRole struct {
	Description string           `yaml:"description"`
	Inherits    []string         `yaml:"inherits"`
	Permissions []yamlPermission `yaml:"permissions"`
}

type yamlPermission struct {
	Resource   string            `yaml:"resource"`
	Action     string            `yaml:"action"`
	Conditions map[string]string `yaml:"conditions"`
}

// Load reads a roles.yaml file from disk and returns a validated Policy.
// Errors are sentinel values from this package so callers can map them
// onto HTTP responses (admin reload endpoint) and audit-log reasons.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("authz: read %s: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses + validates an in-memory policy. Used by tests and
// by the admin reload endpoint when policy arrives via request body.
func LoadBytes(data []byte) (*Policy, error) {
	var raw yamlPolicy
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyMalformed, err)
	}

	policy := &Policy{
		Version: raw.Version,
		Roles:   make(map[string]*Role, len(raw.Roles)),
	}

	// Pass 1: hydrate roles (without expanding inherits yet).
	for name, yr := range raw.Roles {
		if name == "" {
			return nil, ErrPolicyEmptyRoleName
		}
		perms := make([]Permission, 0, len(yr.Permissions))
		for _, yp := range yr.Permissions {
			if yp.Resource == "" || yp.Action == "" {
				return nil, fmt.Errorf("%w: role %q", ErrPolicyEmptyPermission, name)
			}
			conds := make([]Condition, 0, len(yp.Conditions))
			// Stable iteration order for deterministic Reason strings.
			keys := make([]string, 0, len(yp.Conditions))
			for k := range yp.Conditions {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				conds = append(conds, Condition{Key: k, Value: yp.Conditions[k]})
			}
			perms = append(perms, Permission{
				Resource:   Resource(yp.Resource),
				Action:     Action(yp.Action),
				Conditions: conds,
			})
		}
		policy.Roles[name] = &Role{
			Name:        name,
			Description: yr.Description,
			Inherits:    append([]string{}, yr.Inherits...),
			Permissions: perms,
		}
	}

	// Pass 2: expand inherits with cycle detection.
	for _, role := range policy.Roles {
		seen := map[string]bool{role.Name: true}
		expanded, err := expandInherits(policy, role, seen)
		if err != nil {
			return nil, err
		}
		role.Permissions = dedupPermissions(append(role.Permissions, expanded...))
	}

	// Pass 3: structural validation.
	if err := validate(policy); err != nil {
		return nil, err
	}

	return policy, nil
}

// expandInherits returns the inherited permissions for a role,
// following the inherits chain depth-first. seen is the set of role
// names already on the visit stack — encountering one means a cycle.
func expandInherits(policy *Policy, role *Role, seen map[string]bool) ([]Permission, error) {
	var out []Permission
	for _, parent := range role.Inherits {
		if seen[parent] {
			return nil, fmt.Errorf("%w: %s -> %s", ErrPolicyInheritsCycle, role.Name, parent)
		}
		pr, ok := policy.Roles[parent]
		if !ok {
			return nil, fmt.Errorf("%w: %s inherits %s", ErrPolicyInheritsUnknown, role.Name, parent)
		}
		seen[parent] = true
		// First: copy parent's own permissions.
		out = append(out, pr.Permissions...)
		// Then: recurse for grandparents.
		grand, err := expandInherits(policy, pr, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, grand...)
		delete(seen, parent)
	}
	return out, nil
}

// dedupPermissions removes exact-duplicate entries (same resource,
// action, and conditions) introduced by overlapping inherits. Order
// of first appearance is preserved.
func dedupPermissions(perms []Permission) []Permission {
	seen := make(map[string]bool, len(perms))
	out := make([]Permission, 0, len(perms))
	for _, p := range perms {
		key := permissionKey(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func permissionKey(p Permission) string {
	// Conditions were sorted at load; safe to concatenate for key.
	key := string(p.Resource) + ":" + string(p.Action)
	for _, c := range p.Conditions {
		key += ";" + c.Key + "=" + c.Value
	}
	return key
}

// validate runs cross-role checks after roles are fully hydrated.
//
// - At least one role must grant `*:admin` (lockout protection).
// - Wildcard resource is only permitted on roles that also grant the
//   `admin` action — guards against accidental `*:read` typos.
func validate(policy *Policy) error {
	hasAdmin := false
	for _, role := range policy.Roles {
		roleHasWildcardAdmin := false
		for _, p := range role.Permissions {
			if string(p.Resource) == Wildcard && p.Action == ActionAdmin && len(p.Conditions) == 0 {
				roleHasWildcardAdmin = true
				hasAdmin = true
			}
			if string(p.Resource) == Wildcard && p.Action != ActionAdmin {
				return fmt.Errorf("%w: role %q has %s:%s", ErrPolicyWildcardOnNonAdmin, role.Name, p.Resource, p.Action)
			}
		}
		_ = roleHasWildcardAdmin
	}
	if !hasAdmin {
		return ErrPolicyNoAdmin
	}
	return nil
}
