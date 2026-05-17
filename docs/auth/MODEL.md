# OWASAKA Authentication Model

This document describes how authentication works inside OWASAKA. It is
the operational counterpart to [ADR-0059][adr] (which captures the
design rationale, threat model, and compliance posture). When the two
disagree, the ADR is the source of truth and this doc is the bug.

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md

---

## At a glance

```
                  ┌──────────────────────────────────────────────┐
                  │             internal/identity                │
                  │                                              │
   ┌─ Human ─┐    │   Principal {ID, Type, Subject, Status, …}   │
   │ pwd+TOTP│ ───┼──▶  ▲                                       │
   │ WebAuthn│    │     │                                        │
   └─────────┘    │   Credential                                 │
   ┌ Service ┐    │     ▲                                        │
   │   mTLS  │ ───┼──▶  │                                        │
   └─────────┘    │   AuthFactor  ──▶  Authenticator             │
   ┌  Agent  ┐    │                                              │
   │ API key │ ───┼──▶  │                                        │
   │  / mTLS │    │                                              │
   └─────────┘    │     │                                        │
   ┌  OIDC   ┐    │     ▼                                        │
   │ Zitadel │ ───┼──▶ DefaultMapper ──▶ identity.Principal     │
   └─────────┘    └──────────────────────────────────────────────┘
                                  │
                                  ▼
                  internal/identity/jwt
                  ├── Issuer:    Ed25519 sign, 15min/24h TTL
                  ├── Verifier:  parse + sig + revocation
                  └── JWKS:      /.well-known/jwks.json

                  internal/identity/middleware
                  ├── RequireAuth(handler)  — HTTP gate
                  ├── AuthorizeWS(req)      — WS upgrade gate
                  ├── WithDevMode(token, p) — escape hatch (env-gated)
                  └── PrincipalFromContext(ctx)

                  internal/identity/revocation
                  └── BoltDB-persisted JTI denylist + in-memory cache
```

---

## Principal types

| Type      | Typical actor                        | Default factor                                                                                |
|-----------|--------------------------------------|-----------------------------------------------------------------------------------------------|
| `Human`   | Security operator                    | Password + TOTP. WebAuthn is an opt-in upgrade. OIDC (Zitadel) optional, feature-flagged.     |
| `Service` | Spectre, Cerebro, future peers       | mTLS client cert chained to the internal CA.                                                  |
| `Agent`   | CLI, CI runner, automation script    | API key (`oswk_<keyID>_<secret>`). mTLS optional when an agent wants the stronger guarantee.  |

Every authenticated request carries a `*identity.Principal` in the
request context (see `middleware.PrincipalFromContext`). All audit
logs, signed events, and stored material reference that Principal's
stable ID — credentials may rotate, the ID does not.

---

## Token model (JWT)

| Property         | Value                                                                                       |
|------------------|---------------------------------------------------------------------------------------------|
| Algorithm        | EdDSA / Ed25519                                                                             |
| Access TTL       | 15 minutes (configurable via `jwt.WithAccessTTL`)                                           |
| Refresh TTL      | 24 hours (configurable via `jwt.WithRefreshTTL`)                                            |
| Signing key      | `pki.PurposeJWTSigning` keypair, rotated every 24h with a 1-hour verify-only overlap        |
| Issuer claim     | `owasaka`                                                                                   |
| Access audience  | `owasaka-api`                                                                               |
| Refresh audience | `owasaka-refresh` (rejected if presented as access)                                         |
| Public verification | `GET /.well-known/jwks.json` — JWKS over all currently-verifyable keys                  |
| Revocation       | Persistent denylist in BoltDB, indexed by JTI; cache primed at startup; O(1) hot path       |

### Claims emitted

```json
{
  "iss":   "owasaka",
  "sub":   "<principal.ID>",
  "aud":   ["owasaka-api"],
  "iat":   1716000000,
  "nbf":   1716000000,
  "exp":   1716000900,
  "jti":   "<uuid>",
  "ptype": "human|service|agent",
  "psub":  "<principal.Subject>",
  "ttype": "access|refresh"
}
```

Downstream consumers (Spectre, Cerebro) verify against the JWKS and
match `iss=owasaka` exactly. Audience gating prevents refresh tokens
from being used as access and vice versa.

---

## Wiring a service

The wiring lives in your application bootstrap (eventually
`internal/app/app.go`, but for now any test or harness can reproduce it):

```go
import (
    "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
    "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
    "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/middleware"
    "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/revocation"
    "github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/pki"
)

// 1. PKI authority + JWT signing key.
authority := pki.NewAuthority(keystore)
if _, err := authority.EnsureRootCA(ctx, 365*24*time.Hour); err != nil { ... }
if _, err := authority.GenerateKeyPair(ctx, pki.PurposeJWTSigning, 24*time.Hour); err != nil { ... }

// 2. Issuer + Verifier.
issuer := jwt.NewIssuer(authority)
revocations, _ := revocation.Open(boltDB)
verifier := jwt.NewVerifier(authority, jwt.WithRevocationChecker(revocations))

// 3. Middleware.
mw := middleware.New(verifier, principalStore, logger)
mux.Handle("/api/", mw.RequireAuth(apiHandler))
mux.Handle("/.well-known/jwks.json", jwt.Handler(authority, nil))
```

Add `middleware.WithDevMode(devToken, devPrincipal)` only when the
application has confirmed it is in development mode (e.g.
`OSWAKA_ENV=development`); production builds never call this option.

---

## Login flows

### Password + TOTP (default human)

```
client → POST /auth/login { username, password, totp }
        → identity.Authenticator verifies factors
        → jwt.Issuer.Issue(principal) -> { access, refresh, jti }
        → 200 OK with tokens (or HttpOnly cookies)
```

### API key (agent)

```
client → Authorization: Bearer oswk_<keyID>_<secret>
        → middleware splits via identity.ParseAPIKey
        → credentialStore.FindBySubject(CredentialAPIKey, keyID)
        → Credential.Verify against bcrypt hash
        → request enters handler with Principal in context
```

Agents typically receive a long-lived access token (or use the API key
directly as a bearer). Refresh is unnecessary; rotate the key itself
via `identity.NewAPIKey` and revoke the old key in the store.

### mTLS (service)

The TLS handshake at the connection layer validates the leaf cert
against `pki.Authority` root. Inside the handler, the cert's SPKI
fingerprint (`identity.SPKIFingerprint(cert)`) is looked up in the
`MTLSCredential` store to resolve the Principal.

### OIDC (Zitadel, opt-in)

```
client → GET /auth/oidc/login?return=/dashboard
       ← 302 to Zitadel /authorize with signed state
... user authenticates at Zitadel ...
       ← 302 back to /auth/oidc/callback?code=…&state=…
       → state cookie verified against query state
       → oauth code exchanged at Zitadel
       → ID token verified against Zitadel JWKS
       → DefaultMapper resolves claims → identity.Principal
       → identity/jwt.Issuer mints OWASAKA's own JWT pair
       ← Set-Cookie: owasaka_access, owasaka_refresh + 302 to /dashboard
```

The OIDC integration never accepts Zitadel's tokens as OWASAKA tokens;
it federates *identity proof*, then issues its own short-TTL JWTs that
the rest of the system understands.

---

## What lives where

| Concern                        | Package                                              |
|--------------------------------|------------------------------------------------------|
| Principal type, statuses       | `internal/identity` (principal.go)                   |
| Credential interface + factors | `internal/identity` (credential.go)                  |
| Password + TOTP, API key, mTLS | `internal/identity` (password_totp.go, apikey.go, mtls.go) |
| In-memory stores               | `internal/identity` (memory_store.go)                |
| JWT issuer / verifier / JWKS   | `internal/identity/jwt`                              |
| Revocation denylist            | `internal/identity/revocation` (BoltDB-backed)       |
| HTTP / WS middleware           | `internal/identity/middleware`                       |
| OIDC client                    | `internal/identity/oidc`                             |
| Root CA + Ed25519 keystore     | `internal/storage/pki`                               |

---

## Compliance cross-reference (recap from ADR-0059)

| Control area                       | Where implemented                                                 |
|------------------------------------|-------------------------------------------------------------------|
| LGPD Art. 46 (security measures)   | TLS layers, sops at-rest, audit-tagged Principal claims           |
| LGPD Art. 18 (subject rights)      | Principal lifecycle history retained; subject access via Principal.ID |
| ISO 27001 A.9.2 (user lifecycle)   | PrincipalStore + credential lifecycle (provision, rotate, revoke) |
| ISO 27001 A.9.4 (system access)    | RBAC (Sprint 2) + MFA + token TTL                                 |
| SOC 2 CC6.1 / CC6.6                | Mandatory auth on every endpoint, TTL, revocation                 |
| NIST 800-53 AC-2 (account mgmt)    | Principal type + status state machine                             |
| NIST 800-53 AC-3 (enforcement)     | `middleware.RequireAuth`                                          |
| NIST 800-53 IA-2 (multi-factor)    | Password+TOTP default; WebAuthn opt-in                            |
| NIST 800-53 IA-5 (authenticators)  | 24h key rotation, runbook in OPERATIONS.md                        |
| NIST CSF PR.AC-1                   | Principal abstraction unifies all credentialed actors             |
| NIST CSF PR.AC-7 (risk-tiered)     | TOTP standard, WebAuthn high-assurance, mTLS for services         |
| EU AI Act Art. 12 (record-keeping) | Identity-tagged events; persistent JTI revocation log             |
| EU AI Act Art. 14 (human oversight)| RBAC roles (Sprint 2) tied to verified Principal                  |
| EU AI Act Art. 26 (deployer)       | `admin` Principal is a natural person; WebAuthn recommended       |

---

## See also

- [docs/auth/OPERATIONS.md](OPERATIONS.md) — day-2 operations: provisioning, rotation, revocation
- [docs/secrets/BOOTSTRAP.md](../secrets/BOOTSTRAP.md) — first-time sops/age setup
- [docs/secrets/WORKFLOW.md](../secrets/WORKFLOW.md) — day-to-day secrets workflow
- [docs/deployment/NIXOS.md](../deployment/NIXOS.md) — wiring the NixOS module + LoadCredential
