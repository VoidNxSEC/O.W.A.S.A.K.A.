// Package authz implements OWASAKA's role-based access control with
// attribute enrichment ("RBAC + conditions"). It is the canonical
// authorization decision point for every protected handler. See
// ADR-0061 for design rationale, role model, and engine choice.
//
// The package is dependency-light by design: zero external policy
// engines, ~500 lines of legible Go that an auditor can read in one
// sitting. Decisions are pure functions over an immutable Policy
// snapshot; hot-reload swaps the snapshot atomically without ever
// holding a request behind a lock.
package authz

import "errors"

// Resource and Action are simple strings to keep the YAML readable.
// The engine matches them with exact equality plus a "*" wildcard.
type (
	Resource string
	Action   string
)

// Wildcard is the catch-all Resource or Action. Only the `admin` role
// uses it by convention; the validator refuses files that grant `*` to
// non-admin roles by accident.
const Wildcard = "*"

// ActionAdmin is the supremum action: holding `<resource>:admin` implies
// every other action on that resource. Modeled explicitly so the matcher
// can short-circuit without a special case in user policies.
const ActionAdmin Action = "admin"

// Policy is an immutable, in-memory snapshot of the loaded rule set.
//
// Construct via Load (or LoadBytes for in-memory testing). Once handed
// to an Engine the Policy is never mutated; reloads produce a new
// Policy and swap atomically.
type Policy struct {
	Version int
	Roles   map[string]*Role
}

// Role is a named bundle of permissions. Roles are flat at runtime —
// `Inherits` is a load-time aggregation aid that gets expanded into
// `Permissions` during Load. The runtime never walks an inheritance
// graph; auditors get readability, the matcher gets a flat list.
type Role struct {
	Name        string
	Description string
	// Inherits names other roles whose permissions should be unioned
	// into this role at load time. Cycles are detected and rejected.
	// After Load, this field is informational; Permissions is the
	// effective set.
	Inherits []string
	// Permissions is the effective permission set for the role after
	// Load. Stable order is not guaranteed; the matcher iterates and
	// short-circuits on first allow.
	Permissions []Permission
}

// Permission is one grant: a verb on a noun, optionally narrowed by
// conditions. Conditions are AND'd; a missing required attribute fails
// the condition closed.
type Permission struct {
	Resource Resource
	Action   Action
	// Conditions narrow the grant. Each entry is matched against the
	// request's attribute map (case-sensitive keys). Empty Conditions
	// means the grant applies unconditionally.
	Conditions []Condition
}

// Condition is one key/value constraint on a Permission.
//
// Values are evaluated as follows:
//   - The sentinel "not-self" on a key whose request attribute matches
//     the principal's ID is treated as a failure. Used for the
//     auditor role's `audit:read` to forbid self-erasure.
//   - Any other string is matched against the request attribute by
//     case-sensitive equality.
//
// Future versions may add list-membership, ranges, and time windows;
// keep new operators explicit and auditable rather than adding a
// general expression language (ADR-0061 §"Trade-offs").
type Condition struct {
	Key   string
	Value string
}

// Sentinel condition value: forbid the grant when the request's
// `Key` attribute equals the requesting principal's ID. Specifically
// powerful for the auditor role on `audit:read`.
const ValueNotSelf = "not-self"

// Sentinel errors returned by Load and Engine operations.
var (
	ErrPolicyMalformed         = errors.New("authz: malformed policy file")
	ErrPolicyNoAdmin           = errors.New("authz: policy has no role granting *:admin — refuses to load (lockout protection)")
	ErrPolicyInheritsCycle     = errors.New("authz: role inheritance cycle detected")
	ErrPolicyInheritsUnknown   = errors.New("authz: role inherits an undefined role")
	ErrPolicyEmptyRoleName     = errors.New("authz: role name must not be empty")
	ErrPolicyEmptyPermission   = errors.New("authz: permission must have non-empty resource and action")
	ErrPolicyWildcardOnNonAdmin = errors.New("authz: `*` resource permitted only on roles intended to be admin-class")
	ErrEngineNotInitialized    = errors.New("authz: engine not initialized with a policy")
	ErrRoleNotFound            = errors.New("authz: role not found in policy")
)

// Decision is the result of an Allowed call. Carries the audit reason
// so callers can log/explain without re-running the matcher.
type Decision struct {
	Allowed bool
	// Role and Permission identify which rule fired. Zero values when
	// Allowed is false ("no matching grant").
	Role         string
	Permission   *Permission
	// Reason is a human-readable explanation suitable for audit logs
	// and the Explain CLI output. Examples:
	//   "matched admin:*:admin"
	//   "matched analyst:events:acknowledge"
	//   "denied: no grant for events:override under role viewer"
	//   "denied: condition cn=cerebro not satisfied (got cn=spectre)"
	Reason string
}
