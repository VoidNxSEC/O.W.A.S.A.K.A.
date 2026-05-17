# OWASAKA Authentication — Operations Runbook

Day-to-day procedures for the auth stack: provisioning principals,
rotating keys, revoking tokens, handling incidents. Read
[MODEL.md](MODEL.md) first for the architecture context.

> **Audience:** operators with shell access to the OWASAKA host. Many
> commands assume the application is reachable on `localhost` and the
> NixOS module is active (see [docs/deployment/NIXOS.md](../deployment/NIXOS.md)).

---

## 0. Conventions

- All cryptographic actions are logged to the audit trail; do not edit
  state directly unless this runbook explicitly says so.
- Time is UTC throughout. Use `date -u` when in doubt.
- The `oswk` CLI tooling that wraps these procedures lands in Sprint 2;
  until then, several steps use direct calls or in-process equivalents
  (demo script `scripts/auth-demo.sh` from T15).

---

## 1. Provisioning principals

### 1.1 Provision a new human operator (password + TOTP)

1. Generate the TOTP shared secret and otpauth URL (rendered as a QR
   code for the operator's authenticator app):

   ```go
   secret, otpauth, err := identity.GenerateTOTPSecret("OWASAKA", "alice")
   ```

2. Create the Principal and persist:

   ```go
   p := &identity.Principal{
       ID:          uuid.NewString(),
       Type:        identity.PrincipalHuman,
       Subject:     "alice",
       DisplayName: "Alice Anderson",
       Status:      identity.StatusActive,
       CreatedAt:   time.Now(),
   }
   _ = principalStore.Save(ctx, p)
   ```

3. Bind the credential:

   ```go
   cred, _ := identity.NewPasswordTOTPCredential(p.ID, "alice", "<initial-password>", secret, "OWASAKA")
   _ = credentialStore.Save(ctx, cred)
   ```

4. Hand the operator the QR (otpauth URL) and a one-time password they
   must change at first login.

### 1.2 Upgrade an operator to WebAuthn

WebAuthn is an opt-in **additional** factor (not a replacement for
password+TOTP yet). The current flow keeps both registered so a lost
hardware key falls back to TOTP.

(Procedure depends on the frontend enrollment UI — lands with
Sprint 9. Until then, WebAuthn registration is manual via the
`go-webauthn/webauthn` library against the existing Principal.)

### 1.3 Provision a service (mTLS)

Issue the cert from the internal CA, then bind the fingerprint:

```go
issued, err := authority.IssueServiceCert(ctx, "spectre", 30*24*time.Hour)
cred, _   := identity.NewMTLSCredential(p.ID, "spectre", issued.Certificate)
_ = credentialStore.Save(ctx, cred)
```

Deliver the leaf cert + key to the service operator over a secure
channel (sops-encrypted file or systemd LoadCredential). Rotate every
30 days; the 7-day overlap window allows graceful redeploys.

### 1.4 Provision an API key (agent)

```go
cred, plaintext, _ := identity.NewAPIKey(p.ID, "ci-runner-01")
_ = credentialStore.Save(ctx, cred)
// Display plaintext exactly once to the operator.
fmt.Println(plaintext)  // oswk_<keyID>_<secret>
```

Never log `plaintext`; it cannot be recovered after generation. If the
operator loses it, mint a new key and revoke the old (§3.2).

---

## 2. Rotating keys

### 2.1 JWT signing key (every 24h)

In-process automation should call `authority.Rotate(...)` on schedule.
Manual rotation:

```go
new, _ := authority.Rotate(ctx, pki.PurposeJWTSigning, 24*time.Hour)
log.Printf("new signing key id=%s fingerprint=%s", new.ID, pki.Fingerprint(new.Public))
```

After rotation:

- New tokens are signed by `new`.
- In-flight tokens signed by the previous key continue to verify
  (`StatusKeyRotating`) for 1 hour.
- After the overlap, retire the previous key:

  ```go
  _ = authority.Retire(ctx, oldKeyID)
  ```

The JWKS endpoint reflects the change immediately; downstream
consumers (Spectre, Cerebro) pick up the new key on their next JWKS
refresh.

### 2.2 Root CA (yearly or on compromise)

Root rotation invalidates every issued service cert. Plan downtime or
do a phased re-issuance:

1. Generate the new root:

   ```go
   _, _ = authority.GenerateKeyPair(ctx, pki.PurposeCA, 365*24*time.Hour)
   // The new root becomes active; mark the old "rotating" deliberately:
   _ = authority.store.UpdateStatus(ctx, oldRootID, pki.StatusKeyRotating)
   ```

2. Re-issue every service cert under the new root.
3. Distribute the new leaf certs to each service.
4. After all services confirm rollover, retire the old root.

For an emergency (suspected compromise), short-circuit: generate new
root, re-issue all leaves, then **immediately** retire the old root,
accepting the brief outage.

### 2.3 sops/age recipient rotation

See [docs/secrets/WORKFLOW.md §"Rotating a recipient"](../secrets/WORKFLOW.md).

---

## 3. Revocation

### 3.1 Revoke a token (single JTI)

```go
_ = revocations.Revoke(ctx, revocation.Entry{
    JTI:       "<from the claim>",
    Reason:    "operator request",
    RevokedBy: "<admin-principal-id>",
    ExpiresAt: claims.ExpiresAt.Time, // optional: lets GC drop it later
})
```

The verifier picks this up on the next call — the bloom-style cache
is in-memory and updated synchronously.

### 3.2 Revoke a credential (all tokens derived from it)

```go
_ = credentialStore.Revoke(ctx, identity.CredentialAPIKey, "<keyID>")
// or:
_ = credentialStore.Revoke(ctx, identity.CredentialMTLS, "<fingerprint>")
```

Active tokens already issued under that credential remain valid until
expiry — revoke each token's JTI explicitly (§3.1) if you need
immediate cutoff. Alternatively, suspend the Principal (§3.3) to deny
all tokens regardless of credential.

### 3.3 Suspend or revoke a Principal

```go
_ = principalStore.UpdateStatus(ctx, principalID, identity.StatusSuspended)
// or, permanent:
_ = principalStore.UpdateStatus(ctx, principalID, identity.StatusRevoked)
```

Suspended/revoked Principals fail `Principal.IsActive()` so every
token (existing or freshly verified) is rejected with
`identity.ErrPrincipalInactive`. The middleware returns HTTP 403 for
these cases.

### 3.4 Mass revocation (signing-key compromise)

If a JWT signing key leaks, every token signed by it is suspect:

1. Retire the key immediately:
   ```go
   _ = authority.Retire(ctx, compromisedKeyID)
   ```
   Verification fails for any token bearing this `kid`.
2. Generate a new signing key:
   ```go
   _, _ = authority.GenerateKeyPair(ctx, pki.PurposeJWTSigning, 24*time.Hour)
   ```
3. Notify Spectre/Cerebro to refresh JWKS.
4. Force re-authentication (in practice this happens naturally as
   users hit 401s).

### 3.5 Garbage-collect expired revocations

```go
n, _ := revocations.GC(ctx, time.Now())
log.Printf("revocation GC dropped %d expired entries", n)
```

Entries without `ExpiresAt` are kept indefinitely (long-term audit of
compromised credentials).

---

## 4. Incident response

| Signal                                | First response                                                  |
|---------------------------------------|-----------------------------------------------------------------|
| Suspected stolen access token         | Revoke JTI (§3.1) + check token issuance audit trail            |
| Suspected stolen refresh token        | Revoke refresh JTI + force re-auth + investigate user device    |
| Lost age private key                  | sops `updatekeys` excluding the lost recipient; re-encrypt      |
| Hardware key (WebAuthn) lost          | Remove WebAuthn credential; user falls back to password+TOTP    |
| Suspected JWT signing-key compromise  | §3.4 (mass revocation playbook)                                 |
| Suspected root CA compromise          | §2.2 emergency path                                             |
| Compromised operator workstation      | Suspend Principal (§3.3) + revoke all their JTIs + investigate  |

For every incident: open an ADR (`adr_new`) describing the event,
response, and follow-up actions. Audit log captures the mechanics;
the ADR captures the *why* and *what we changed*.

---

## 5. Dev-mode escape hatch

`middleware.WithDevMode(token, principal)` accepts a static bearer
token for development only. The middleware emits a loud warning every
60 seconds while the mode is active:

```
WARN  DEV MODE: static auth token is active — DO NOT USE IN PRODUCTION
```

If you see this in production logs, immediately:

1. Stop the service.
2. Confirm `OSWAKA_ENV=production` (or unset).
3. Verify the binary was built without the `dev` tag.
4. Open a sev-1 ADR documenting the exposure.

---

## 6. Audit queries

Every authentication decision and credential lifecycle event is
captured in the audit log (BoltDB `audit.api.access.v1` bucket, plus
the transparency log once Sprint 3 lands).

```bash
# Stream recent auth events (placeholder until the CLI lands):
# oswk audit tail --type=auth --since=1h
```

For LGPD subject access requests, query by `Principal.ID` — the
ledger stores all events tagged with the principal that produced them.

---

## 7. Verifying the deployment

After any of the changes above:

```bash
# 1. JWKS responds and lists currently-verifyable keys.
curl -fsSL https://owasaka.example/.well-known/jwks.json | jq '.keys | length'

# 2. Unauthenticated API request is rejected with 401 and WWW-Authenticate.
curl -i https://owasaka.example/api/topology | head -3

# 3. Authenticated API request succeeds.
curl -i -H "Authorization: Bearer <access>" https://owasaka.example/api/topology | head -3

# 4. WebSocket auth via subprotocol works.
websocat -H "Sec-WebSocket-Protocol: owasaka.v1,bearer.<access>" wss://owasaka.example/ws

# 5. Revoked token is rejected immediately.
oswk auth revoke <jti>   # (Sprint 2 CLI)
curl -i -H "Authorization: Bearer <access-with-that-jti>" https://owasaka.example/api/topology
```

Expect step 5 to return 401 immediately — the verifier's denylist is
checked on every call.

---

## 8. References

- [ADR-0059][adr] — design rationale, threat model, compliance
- [docs/auth/MODEL.md](MODEL.md) — architecture and wiring
- [docs/secrets/BOOTSTRAP.md](../secrets/BOOTSTRAP.md)
- [docs/secrets/WORKFLOW.md](../secrets/WORKFLOW.md)
- [docs/deployment/NIXOS.md](../deployment/NIXOS.md)

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md
