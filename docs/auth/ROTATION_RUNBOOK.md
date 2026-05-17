# Key Rotation Runbook

A focused, copy-paste-friendly procedure for every key OWASAKA owns.
Use this when on-call. The architectural why lives in [ADR-0059][adr]
and [docs/auth/MODEL.md](MODEL.md); the broader operational context in
[docs/auth/OPERATIONS.md](OPERATIONS.md). This page is intentionally
terse.

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md

---

## Decision table: when to rotate which key

| Trigger                            | JWT signing | Root CA | Service leaf | API key | age recipient | sops file |
|------------------------------------|:-----------:|:-------:|:------------:|:-------:|:-------------:|:---------:|
| Scheduled (cadence)                | 24h         | 1y      | 30d          | yearly  | on-change     | n/a       |
| Operator leaves                    |             |         |              |    ✓    |       ✓       |     ✓     |
| Suspected token theft              |      ✓      |         |              |         |               |           |
| Suspected key compromise           |      ✓      |    ✓ (emergency) |    ✓     |    ✓    |       ✓       |     ✓     |
| Cert expiring < 7 days             |             |    ✓    |      ✓       |         |               |           |
| Recipient lost device              |             |         |              |         |       ✓       |     ✓     |
| Lost/stolen API key plaintext      |             |         |              |    ✓    |               |           |

---

## R1. JWT signing key (scheduled, 24h)

```go
new, err := authority.Rotate(ctx, pki.PurposeJWTSigning, 24*time.Hour)
if err != nil { return err }
log.Infow("rotated", "kid", new.ID, "fingerprint", pki.Fingerprint(new.Public))

// 1h later (overlap window over):
_ = authority.Retire(ctx, previousKeyID)
```

**Pre-flight:** nothing. Rotation is non-disruptive thanks to the
1-hour overlap window.

**Post-flight:**
- `curl /.well-known/jwks.json | jq '.keys | length'` returns ≥ 2 during overlap.
- `journalctl -u owasaka | grep rotated` shows the new `kid`.
- After 1h, `keys | length` drops back to 1.

**If something goes wrong:** the previous key is still in BoltDB; mark
it active again via `authority.store.UpdateStatus(ctx, oldID,
pki.StatusKeyActive)` and investigate before retrying.

---

## R2. Root CA (yearly or emergency)

**Scheduled (planned, low-risk):**

1. Notify Spectre + Cerebro of a planned root rotation.
2. Generate the new root:
   ```go
   _, _ = authority.GenerateKeyPair(ctx, pki.PurposeCA, 365*24*time.Hour)
   ```
3. Re-issue every active service cert under the new root.
4. Distribute leaf certs to each service (sops-encrypted delivery).
5. Confirm Spectre + Cerebro reach OWASAKA with new certs.
6. Retire the old root:
   ```go
   _ = authority.Retire(ctx, oldRootID)
   ```

**Emergency (suspected compromise, downtime acceptable):**

```go
_ = authority.Retire(ctx, compromisedRootID)
new, _ := authority.GenerateKeyPair(ctx, pki.PurposeCA, 365*24*time.Hour)
// Re-issue all leaves now. Until they redeploy, mTLS fails closed.
```

**Post-flight:** boot banner shows the new root fingerprint. Update
peer trust stores (Spectre, Cerebro deployment configs) with the new
fingerprint.

---

## R3. Service leaf certificate (30d, or on demand)

```go
issued, err := authority.IssueServiceCert(ctx, "spectre", 30*24*time.Hour)
if err != nil { return err }
// Persist the leaf cert + private key, deliver to the service.
// Update the bound mTLSCredential's fingerprint:
new, _ := identity.NewMTLSCredential(p.ID, "spectre", issued.Certificate)
_ = credentialStore.Save(ctx, new)
// Old fingerprint can be revoked after the consumer redeploys:
_ = credentialStore.Revoke(ctx, identity.CredentialMTLS, oldFingerprint)
```

**Overlap window:** 7 days during which both old and new certs are
accepted. Set a calendar reminder to revoke the old after rollout.

---

## R4. API key (yearly or on loss)

```go
new, plaintext, _ := identity.NewAPIKey(p.ID, "ci-runner-01")
_ = credentialStore.Save(ctx, new)
// Hand `plaintext` to the operator out-of-band.

// Once they confirm rollover:
_ = credentialStore.Revoke(ctx, identity.CredentialAPIKey, oldKeyID)
```

If the key was lost / leaked, **revoke first**, mint second. The
agent fails authenticated calls until the new key is in place — which
is the desired behavior under suspected compromise.

---

## R5. age recipient (operator leaves or device lost)

See [docs/secrets/WORKFLOW.md §"Rotating a recipient"](../secrets/WORKFLOW.md).
TL;DR:

```bash
# 1. Remove the recipient from .sops.yaml. Commit.
# 2. Re-encrypt every sops-managed file:
sops updatekeys secrets.yaml
sops updatekeys secrets.dev.yaml  # if you have per-env files
# 3. Commit the re-encrypted files.
```

This **does not** revoke past access — anything the operator
decrypted while authorized is theirs. If the removal was triggered by
compromise, also rotate any secrets they could have read.

---

## R6. Sops-encrypted secret rotation (suspected leak)

1. Edit `secrets.yaml` with `sops secrets.yaml` and replace the
   compromised value.
2. Commit + push.
3. Restart consumers so they pick up the new value (NixOS:
   `systemctl restart owasaka`).
4. If the secret was a credential (DB password, OIDC client secret),
   also rotate that credential at the source (Zitadel admin console,
   etc.).

---

## R7. Mass JWT revocation (signing-key leak)

```go
_ = authority.Retire(ctx, leakedSigningKeyID)
_, _ = authority.GenerateKeyPair(ctx, pki.PurposeJWTSigning, 24*time.Hour)
```

Every token signed by the leaked key now fails verification. Users
hit 401 and re-authenticate. The denylist is not used here because the
key itself is retired — verification fails earlier (no usable public
key for that `kid`).

Notify Spectre and Cerebro to re-pull JWKS immediately rather than
wait for their normal refresh cadence.

---

## Rotation log template

Append to `docs/auth/ROTATION_LOG.md` (create on first rotation):

```markdown
## 2026-XX-XX — <key kind> rotated
- Trigger: <scheduled | incident | operator change | …>
- Previous: <kid or fingerprint>
- New:      <kid or fingerprint>
- Overlap:  <duration, if any>
- By:       <admin principal id>
- Notes:    <free text>
```

The transparency log (Sprint 3) will eventually consume these
machine-readably; until then, the markdown trail is the audit record.
