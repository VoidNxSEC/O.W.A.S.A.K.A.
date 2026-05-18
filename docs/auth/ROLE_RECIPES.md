# Role Recipes

Copy-paste-ready YAML snippets for roles beyond the four baseline.
Append any of these into `configs/rbac/roles.yaml` and reload the
engine (`systemctl reload owasaka` or
`POST /api/admin/authz/reload`).

Each recipe documents:

- **When to use it** — the operational situation the role fits.
- **What it grants** — the effective permission set in plain English.
- **Risk** — the obvious failure mode if you assign it carelessly.
- **YAML** — drop into `roles.yaml` under the existing `roles:` map.

For the model, conditions semantics, and how `inherits:` expansion
works see [AUTHZ.md](AUTHZ.md). For the design rationale of keeping
these *out* of the baseline see [ADR-0061][adr] §"Default roles".

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0061.md

---

## 1. `analyst` — day-to-day SOC operator

**When:** you have ≥2 humans regularly using OWASAKA, and the
distinction between "looks at the dashboard" (`viewer`) and "actively
triages" matters.

**Grants:** everything `viewer` has, plus the ability to
acknowledge events, annotate events/assets, and export reports.

**Risk:** an analyst can hide an alert by acknowledging it without
investigating. Mitigation: every acknowledge is audit-logged with
the principal id; periodic review of acknowledge volume per
analyst.

```yaml
analyst:
  description: "SOC operator — triage, acknowledge, annotate"
  inherits: [viewer]
  permissions:
    - { resource: events, action: acknowledge }
    - { resource: events, action: annotate }
    - { resource: assets, action: annotate }
    - { resource: reports, action: write }      # export reports
```

---

## 2. `responder` — incident on-call

**When:** you have someone who responds to incidents and needs
authority beyond an analyst's read+annotate — to override AI
verdicts (EU AI Act Art. 14), suspend principals, revoke tokens.

**Grants:** everything `analyst` has, plus override of correlation
and ML alerts, principal read (to know who's misbehaving), and
token write (revocation).

**Risk:** responder can revoke any operator's tokens. Use this for
incident commanders, not for daily triage. Pair with WebAuthn
opt-in for the principals that hold this role.

```yaml
responder:
  description: "Incident response on-call"
  inherits: [analyst]
  permissions:
    - { resource: events,     action: override }   # override correlation alert
    - { resource: ml,         action: override }   # override ML verdict (EU AI Act Art. 14)
    - { resource: principals, action: read }
    - { resource: tokens,     action: write }      # revoke tokens
```

---

## 3. `rule-author` — owns correlation rules

**When:** rules-writing has split off from general admin work. The
person who edits `configs/rules/*.yaml` has out-sized power
(silencing a rule = silencing a threat class) and benefits from
being a separately-named role.

**Grants:** read everything an analyst can; write to `rules`
specifically. Cannot touch principals, tokens, or config.

**Risk:** a bad rule can DOS the correlation engine or silently
silence a threat. Combine with mandatory PR review on the rules
directory; the role grants the *runtime* edit ability, not bypass
of git review.

```yaml
rule-author:
  description: "Edits correlation rules; analyst-level read on operational data"
  inherits: [analyst]
  permissions:
    - { resource: rules, action: write }
    - { resource: rules, action: delete }
```

---

## 4. `break-glass-admin` — short-lived elevated access

**When:** an incident requires admin-level action, but you do not
want to keep an admin session open day-to-day. Provisioning a
short-TTL credential under this role is safer than persistent
admin access.

**Grants:** identical to `admin`. The protection is *not* in the
permissions; it's in:

- The Principal that holds this role having a short token TTL
  (e.g., 1h instead of 15min/24h).
- Every break-glass session being audit-logged conspicuously.
- The Principal being de-provisioned at session end.

**Risk:** if you grant the role to a Principal that doesn't expire,
you've just made another admin. Tie the lifecycle to a calendar
event (incident ticket close).

```yaml
break-glass-admin:
  description: "Short-lived admin for incident response. Provisioned per-incident."
  permissions:
    - { resource: '*', action: admin }
```

Recommended operational discipline (Sprint 5 will codify this as
a runbook section in OPERATIONS.md):

1. Create the Principal at incident start with a 1h refresh TTL.
2. Audit-log the creation with the incident ticket id.
3. Suspend the Principal at incident close (`PrincipalStore.UpdateStatus`).
4. Quarterly review: list every break-glass Principal that ever
   existed, verify each pairs with a closed incident ticket.

---

## 5. `compliance-officer` — auditor + reports

**When:** internal/external compliance work demands the audit-read
that `auditor` provides AND the ability to export reports for an
assessor. The default `auditor` cannot write reports.

**Grants:** everything `auditor` has, plus report export.

**Risk:** reports may contain operational data the auditor base
role explicitly does not see. If you grant this role, your
report-export pipeline must respect the same `not-self` and
viewer-scoping discipline.

```yaml
compliance-officer:
  description: "Auditor + report export"
  inherits: [auditor]
  permissions:
    - { resource: reports, action: write }
```

---

## 6. `cerebro-extended` — RAG ingester with deeper read

**When:** Cerebro's RAG needs more than the baseline
`events:read` — e.g., access to topology and ML output for
embedding context.

**Grants:** `service` plus extra read scopes, gated by mTLS CN.

**Risk:** widening a service principal expands the blast radius
of a service compromise. Justify each expansion in an ADR before
landing.

```yaml
cerebro-extended:
  description: "Cerebro with RAG-context reads beyond baseline service"
  permissions:
    - { resource: events,   action: read,  conditions: { cn: cerebro } }
    - { resource: topology, action: read,  conditions: { cn: cerebro } }
    - { resource: ml,       action: read,  conditions: { cn: cerebro } }
```

Then in Cerebro's Principal: assign `cerebro-extended` instead of
the baseline `service`.

---

## 7. `readonly-investigator` — external IR firm, scoped time

**When:** an outside IR firm needs read access during an incident.
Same shape as `viewer`, but you'll provision a Principal with a
short token TTL and a name that makes the audit trail unambiguous.

**Grants:** identical to `viewer`. The constraint comes from the
Principal's lifecycle, not the role.

**Risk:** the role itself is safe; the risk is in forgetting to
de-provision the Principal after the engagement.

```yaml
readonly-investigator:
  description: "External IR firm scope — read-only, lifecycle-bound to engagement"
  inherits: [viewer]
  permissions: []
```

Yes, this is just `inherits: [viewer]` with a different name — the
point is the audit log says "readonly-investigator-acme" instead of
"viewer", making the trail readable months later.

---

## Anti-patterns

Things that look like recipes but aren't:

- **`super-admin` role.** No. `admin` already grants `*:admin`.
  Adding a higher tier signals you should rotate the existing admin
  and reduce the number of human admin Principals, not stack roles.
- **Role per resource type.** No. Roles are for *people and
  services*, not for resources. If `events-admin` and
  `assets-admin` show up as distinct roles, you've reinvented
  resource-class permissions — use them.
- **Roles with their own conditions duplicating Principal claims.**
  No. Conditions match request attributes (`cn`, `subject`,
  `principal_id`), not Principal claims. If you need to gate by a
  Principal property, encode it as a role assignment instead.
- **Inheriting from `admin`.** Refused by the loader (admin's
  `*:admin` would propagate uncontrollably). If you need
  admin-level for a specific case, use `break-glass-admin` with a
  short-lived Principal.

---

## When to write a new recipe

Add a recipe here when:

- You've used the same custom role across ≥2 deployments or
  incidents.
- The role has a non-obvious risk that a future operator should
  read before assigning.
- An auditor asked "what does X do" and the answer needed more than
  one sentence.

Otherwise leave it in your own `roles.yaml` — recipes are for
shared patterns, not for one-offs.
