# OWASAKA Authorization (RBAC) Model

This document describes how the OWASAKA authorization layer works:
the role model, the policy file, the engine's decision flow, and the
day-to-day operations of editing and reloading policy. Architectural
rationale lives in [ADR-0061][adr]; this document is the operator
guide.

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0061.md

For the broader authentication context, read
[docs/auth/MODEL.md](MODEL.md) first.

---

## 30-second mental model

```
       request
          ↓
    ┌─────────────────┐
    │   RequireAuth   │  Sprint 1 — verify JWT/mTLS/API key,
    │ (identity/mw)   │  inject *identity.Principal into context.
    └────────┬────────┘
             ↓ Principal in ctx
    ┌─────────────────────────┐
    │ RequirePermission(      │  Sprint 2 — derive attrs from request,
    │   engine, resource,     │  ask the engine, audit-log the
    │   action, sink )        │  decision, 403 on deny.
    └────────┬────────────────┘
             ↓ allowed
       handler runs
```

A `Principal` carries its roles in `Claims["roles"]`. The engine
holds a `Policy` snapshot built from `configs/rbac/roles.yaml`. For
every request the engine answers:

> **Given this Principal's roles, may they perform `action` on
> `resource`, with these request attributes?**

Decisions are pure functions over an immutable Policy snapshot;
in-flight requests during a hot-reload see a consistent view.

---

## The baseline roles

Four roles ship with the binary. Their definitions live in
`configs/rbac/roles.yaml` — read that file alongside this doc.

| Role      | What it is for                                                                 | Highlights                                                                                            |
|-----------|--------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `viewer`  | Read-only operational access — dashboards, juniors, anyone who shouldn't mutate | `events:read`, `assets:read`, `rules:read`, `topology:read`, `ml:read`. **No** audit. **No** principal lifecycle. |
| `auditor` | Compliance review — external auditor, ISO/SOC 2/NIST evidence reviews          | `audit:read` (with `subject: not-self`), `principals:read`, `tokens:read`. **No** operational data.    |
| `admin`   | Owner / privileged operator                                                    | `*:admin` — full access. Required to provision principals, edit policy, rotate keys.                  |
| `service` | Ecosystem peers (Spectre, Cerebro, future ingestors)                           | Narrow event-bus access scoped by mTLS `cn`. Spectre writes; Cerebro reads.                           |

**Not** in the baseline: `analyst`, `responder`, `rule-author`, time-
limited break-glass. These are common additions documented in
[ROLE_RECIPES.md](ROLE_RECIPES.md). Adding them is a policy-file edit
plus a SIGHUP; no rebuild.

### Why `auditor` separate from `viewer`

ISO 27001 / SOC 2 / NIST audits want a role that reads the audit
trail and principal lifecycle but **not** operational data. The
`subject: not-self` condition prevents an auditor from reading their
own audit entries, closing the obvious self-erasure loophole. Cost of
keeping `auditor` defined even on solo deployments: ~6 lines of YAML.

### Why one `service` role instead of `service-publisher` + `service-consumer`

The meaningful distinction is *which ecosystem peer is on the other
end*, not the abstract direction. Express that with `conditions: { cn:
<peer> }` inside one role — the role list stays small, and new peers
add a single line to the `service` role.

---

## Permission shape

```yaml
- resource: events           # noun
  action:   write            # verb
  conditions:                # optional narrowing
    cn: spectre
```

**Resources** (initial set, extensible by usage): `events`, `assets`,
`rules`, `principals`, `tokens`, `audit`, `config`, `topology`, `ml`,
`proxy`, `dns`, `pki`.

**Actions** (verbs): `read`, `write`, `delete`, `acknowledge`,
`annotate`, `override`, `admin`.

**`admin` is the supremum**: holding `<resource>:admin` implies every
other action on that resource. So `*:admin` (wildcard resource, admin
action) is the canonical "everything" grant; only the `admin` role
uses it, and the loader refuses to let other roles use `*` for
anything other than `admin` (typo protection).

### Conditions

Conditions narrow a grant by matching request attributes:

```yaml
- resource: audit
  action:   read
  conditions:
    subject: not-self          # the sentinel — request's subject ≠ principal_id
- resource: events
  action:   write
  conditions:
    cn: spectre                # request's cn attribute must equal "spectre"
```

Conditions are **AND'd**. A missing required attribute **fails the
condition closed** — a permission with conditions never accidentally
allows because we didn't know.

The `not-self` sentinel compares the named attribute against the
principal's own ID; that's how `auditor:audit:read` blocks the
auditor from reading their own trail.

Where do attributes come from? `AttrsFromRequest(r)` in
`internal/authz/middleware.go` is the default deriver:

| Attribute      | Source                                             |
|----------------|----------------------------------------------------|
| `principal_id` | The Principal injected into context by RequireAuth |
| `cn`           | `r.TLS.PeerCertificates[0].Subject.CommonName` (mTLS only) |
| `subject`      | `?subject=` query parameter                        |

Handlers that need richer attributes can call `engine.Allowed(...)`
in-process with a custom attrs map — `RequirePermission` is the
middleware shortcut for the common case.

---

## Engine operations

```go
import "github.com/marcosfpina/O.W.A.S.A.K.A/internal/authz"

policy, err := authz.Load("/etc/owasaka/roles.yaml")
if err != nil { /* refuse to start */ }
engine := authz.NewEngine(policy)

// wire into HTTP:
mux.Handle("/api/rules", authMW.RequireAuth(
    authz.RequirePermission(engine, "rules", "write", auditSink)(
        rulesHandler)))

// in-process (background workers, event hooks):
allowed, err := authz.PrincipalAllowed(ctx, engine, p, "ml", "override", attrs, auditSink)
```

### `inherits`

`inherits:` is a **load-time aggregation** aid, not a runtime
hierarchy. At load, a role's `inherits` list is walked depth-first
(with cycle detection) and the parent roles' permissions are unioned
into the child's effective set. After load, every role has a flat
`Permissions` slice; the matcher never recurses.

```yaml
viewer:
  permissions: [{ resource: events, action: read }]

analyst:
  inherits: [viewer]
  permissions: [{ resource: events, action: acknowledge }]
# after load, analyst.Permissions == [events:read, events:acknowledge]
```

Why load-time only? Auditors find inherited permissions much harder
to reason about — "what can admin do?" should be a list, not a graph
walk. The YAML still reads naturally; the runtime stays simple.

---

## Editing and reloading policy

There are three reload mechanisms, intended for different contexts:

| Mechanism                                | Use when                                                        |
|------------------------------------------|------------------------------------------------------------------|
| **HTTP** `POST /api/admin/authz/reload`  | Operator using the admin UI/CLI. Returns a JSON diff in response. |
| **SIGHUP**                               | `systemctl reload owasaka` (NixOS module wires this).            |
| **fsnotify** (config-gated, OFF default) | Dev/test only. Accidental editor saves in prod cause flapping.   |

All three call the same `engine.ReloadFrom(path)` under the hood:

1. Read + parse the candidate policy.
2. Validate (admin-capable role present, no wildcard misuse, no
   inherits cycles).
3. **Only on success**: atomically swap the engine's snapshot.

If validation fails, the engine keeps the previous policy. The
operator (or the API response, or the audit log) sees the validation
error verbatim. There is no half-reloaded state.

### Inline reload (no file)

The admin endpoint accepts a `Content-Type: application/x-yaml` body
and reloads from it directly — useful for CI pipelines that build
policy from a higher-level source. The 1 MB body limit is a safety
bound, not a real constraint.

### Auditing reloads

Every reload emits a structured `AuditEvent` with `decision=allow`
(success) or `decision=deny` (validation failure) and a reason like
`reload: added=[ops] modified=[analyst]`. Same shape as per-request
authz events — your audit pipeline doesn't need a special case.

---

## Troubleshooting decisions

When a request unexpectedly returns 403:

1. **Check the audit log.** Every deny carries a `reason` like
   `denied: no grant for events:write under roles [viewer]` or
   `condition cn=spectre not satisfied (got cn=intruder)`.
2. **Run Explain in-process** (or via the future CLI):
   ```go
   d, err := engine.Explain(ctx, principal, "events", "write", attrs)
   ```
   Returns the same Decision as Allowed plus the reason — but skips
   the audit sink, so it's safe to call from a debugger or a test.
3. **Inspect the loaded policy**:
   ```go
   for name, role := range engine.Policy().Roles {
       fmt.Println(name, "→", role.Permissions)
   }
   ```
   `roles.yaml` on disk and the engine's snapshot can diverge only if
   a reload was skipped — check `systemctl reload owasaka` exit code.

Common gotchas:

- **Principal has no roles.** Verify `Principal.Claims["roles"]` was
  set during login. mTLS principals get roles from the cert subject;
  password+TOTP principals get them from the credential store.
- **Wrong condition key.** Conditions are case-sensitive. `subject`
  ≠ `Subject`.
- **`cn` missing for non-mTLS handlers.** The CN attribute only
  populates on mTLS connections. If you need it on a JWT-authenticated
  path, set it explicitly via a custom AttrsFromRequest.

---

## Adding a new role

1. Edit `configs/rbac/roles.yaml` — keep the baseline four intact.
2. Optionally `inherits:` from an existing role to compose
   permissions.
3. Decide whether the new role should appear in
   [ROLE_RECIPES.md](ROLE_RECIPES.md) for future reuse.
4. Save, commit, and reload:
   ```bash
   systemctl reload owasaka            # or
   curl -X POST .../api/admin/authz/reload
   ```
5. Verify in the audit log that the reload succeeded.

For common shapes (`analyst`, `responder`, `rule-author`, time-
limited break-glass) see [ROLE_RECIPES.md](ROLE_RECIPES.md) for
copy-paste-ready snippets.

---

## Adding a new resource or action

Resources and actions are just strings — there is no registry. To
add a new noun:

1. Decide the name. Singular nouns (`event`, `asset`) preferred over
   plurals. Lowercase. ASCII.
2. Use it in policy: `{ resource: webhooks, action: write }`.
3. Wire `RequirePermission(engine, "webhooks", "write", sink)` in
   the handler that touches it.

The engine doesn't know about the new resource ahead of time; it
just matches strings. The wildcard `*:admin` (held by `admin`)
already covers it.

---

## Compliance cross-reference

| Control                                  | Where satisfied                                                              |
|------------------------------------------|------------------------------------------------------------------------------|
| ISO 27001 A.9.4.1 (access restriction)   | `RequirePermission` enforces every protected endpoint                        |
| ISO 27001 A.9.4.4 (privileged management)| `admin` separated from operational roles; reloads audit-logged               |
| SOC 2 CC6.3 (logical access)             | Role assignment at provisioning; reviewable in `roles.yaml`                  |
| NIST 800-53 AC-3 (enforcement)           | Default-deny middleware; no handler escapes the matcher                      |
| NIST 800-53 AC-6 (least privilege)       | `viewer`/`auditor` strict subsets of `admin`                                  |
| NIST 800-53 AC-6(7) (periodic review)    | Quarterly checklist in [OPERATIONS.md](OPERATIONS.md)                         |
| NIST CSF PR.AC-4 (permissions managed)   | YAML-defined, git-tracked, hot-reloadable                                     |
| EU AI Act Art. 14 (human oversight)      | `responder.ml.override` (recipe in ROLE_RECIPES) is the hook                  |
| EU AI Act Art. 26 (deployer obligations) | `admin` is a natural person (per ADR-0059); reloads audit-logged              |

---

## See also

- [ADR-0061][adr] — design rationale and engine choice
- [docs/auth/MODEL.md](MODEL.md) — authentication model and wiring
- [docs/auth/OPERATIONS.md](OPERATIONS.md) — provisioning, rotation, revocation runbooks
- [docs/auth/ROLE_RECIPES.md](ROLE_RECIPES.md) — copy-paste role additions
- [docs/auth/ROTATION_RUNBOOK.md](ROTATION_RUNBOOK.md) — on-call rotation procedures
- `configs/rbac/roles.yaml` — the live policy
- `internal/authz/` — the engine source
