# OWASAKA — Incident Response Playbook

On-call playbook for "something is on fire". Triage first, then act.
For data loss / restore see [DR.md](DR.md); for known failure modes
with root-cause notes see [COMMON_FAILURES.md](COMMON_FAILURES.md);
for log-triage commands see [LOG_ANALYSIS.md](LOG_ANALYSIS.md).

---

## First 5 minutes

Run these in order. Each should take under 30s.

```bash
# 1. Liveness — is the process up at all?
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/healthz
# 200 → process alive. Non-200 / connect refused → service dead.

# 2. Readiness — is every required subsystem operational?
curl -sS http://127.0.0.1:8080/readyz | jq .
# 200 + required_status="healthy" → fine.
# 503 → body enumerates which subsystem is unhealthy/degraded.

# 3. systemd verdict — what does the supervisor think?
systemctl status owasaka --no-pager
# Active: active (running) → process is up.
# Active: failed          → check journalctl below.

# 4. Recent logs — last 100 lines, errors only.
journalctl -u owasaka -n 100 --no-pager -p err
# Anything at err/crit/alert level should be triaged below.

# 5. Disk — is the data dir or log dir full?
df -h /var/lib/owasaka /var/log/oswaka
# >95% used on either is an immediate cause of failure.
```

If `/readyz` is green and disk is fine but users report failures,
move to the triage matrix.

---

## Triage matrix

| Symptom                                | Likely cause                                                  | First action                                                                 |
|----------------------------------------|---------------------------------------------------------------|------------------------------------------------------------------------------|
| API returns 500 on every request       | Unhandled panic / DB unreachable / authz engine load failure  | `journalctl -u owasaka -n 200 -p err`; look for `Failed to ...` lines       |
| `/readyz` returns 503                  | A required probe is unhealthy (boltdb today; nats is optional) | `curl /readyz \| jq .subsystems` → drill into the failing subsystem          |
| WebSocket clients disconnect repeatedly| Auth failure on upgrade / hub overload / network flap         | `grep "WebSocket client" /var/log/oswaka/oswaka.log`; check client tokens   |
| NATS publish failures in logs          | NATS unreachable (graceful — events stay local)               | `curl /readyz \| jq '.subsystems[] \| select(.name=="nats")'` — degraded is expected when down |
| BoltDB lock contention / open fails    | Stale lock from crash / second process / disk failing         | `lsof /var/lib/owasaka/owasaka.db`; see [COMMON_FAILURES.md](COMMON_FAILURES.md#boltdb-locked-or-corrupted) |
| Transparency log size growing fast     | High append rate or attacker spam — never delete leaves       | `curl /api/transparency/sth`; compare growth rate to baseline               |
| Signed events failing verification     | Key retired before consumer refreshed, OR genuine tampering   | `journalctl -u owasaka \| grep -E "ErrSignerKey(Unknown\|Retired)\|ErrSignatureInvalid"` |
| Login 401 storm                        | TOTP clock skew / password rotation / brute force             | `journalctl -u owasaka \| grep "login rejected"`; correlate by username     |
| `/startupz` stays 503                  | Required subsystem failed init (DB open, root CA, JWT key)    | `journalctl -u owasaka` from boot; look for first `Errorw` line             |

Cross-reference the row's "First action" output against the matching
section in [COMMON_FAILURES.md](COMMON_FAILURES.md) for remediation.

---

## Escalation criteria

Stop self-driving and page another operator (or the on-call architect)
if **any** of these are true:

- **Transparency log tamper-evident proof FAILED.** A signed event
  returns `ErrSignatureInvalid`, or `/api/transparency/consistency`
  reports `ok=false`, or the boot banner's STH root differs from the
  paper journal at the same tree size. Treat as suspected tampering;
  follow [DR.md §"Scenario 2 — Suspected tampering"](DR.md).
- **Signed event with unknown signer kid.** A `kid` appears that
  does not resolve in the local PKI. Either upstream is signing with a
  key OWASAKA never issued (impossible if isolation holds) or the
  Authority's keystore is missing entries — both are major.
- **Restore needed.** Disk loss, corrupted DB, or you intentionally
  rolled back state. Hand off to whoever owns DR before restoring;
  evidence is fragile.
- **STH regression at boot.** Banner reports a tree size or root
  that is smaller / different than the previous boot's record without
  a corresponding restore having been performed.
- **Audit log integrity violation.** The Merkle verifier (see
  `internal/storage/integrity`) logs `AUDIT LOG INTEGRITY VIOLATION`.
  This is not subtle — it is a hard failure of the immutable audit
  bucket.

Anything else (NATS down, NAS unreachable, ML model not loading) is
on-call-tier and should be remediated, not escalated.

---

## Evidence collection

Before you restart or roll anything back, capture state. The act of
restarting is destructive to in-memory diagnostics. Run all of the
below **first**, even if the service is already crashlooping.

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
EV=/var/lib/owasaka/incidents/${TS}
mkdir -p "${EV}"

# 1. Full journal for the unit, untruncated.
journalctl -u owasaka --no-pager > "${EV}/journal.log"

# 2. The current BoltDB file. Do NOT use `cp` while the service is
#    running — it locks the file. Either stop the service first
#    (preferred when crashlooping) or use the snapshot procedure:
#       oswaka backup --out="${EV}/snapshot.db.age"
#    which uses bbolt's read tx (safe with a running process).
sudo systemctl stop owasaka
cp /var/lib/owasaka/owasaka.db "${EV}/owasaka.db"
sha256sum "${EV}/owasaka.db" > "${EV}/owasaka.db.sha256"

# 3. The current STH (and the previous one if you have it on paper).
curl -sS http://127.0.0.1:8080/api/transparency/sth > "${EV}/sth.json" 2>/dev/null || true
# If the service is down, the STH is whatever the paper journal says.

# 4. Health snapshot at time of incident.
curl -sS http://127.0.0.1:8080/readyz > "${EV}/readyz.json" 2>/dev/null || true

# 5. Process state if the binary was still running.
ps -ef | grep -i oswaka > "${EV}/processes.txt"
df -h > "${EV}/disk.txt"

# 6. Lock files at incident time (may reveal stale-lock cause).
ls -la /var/lib/owasaka/ > "${EV}/datadir.ls"

tar czf "${EV}.tar.gz" -C /var/lib/owasaka/incidents "${TS}"
```

Keep the evidence bundle (`${EV}.tar.gz`) at least 90 days. For
tampering incidents, keep indefinitely.

---

## Stand-down checklist

Do not declare "incident resolved" until every box ticks:

- [ ] `/healthz` returns 200.
- [ ] `/readyz` returns 200 and `required_status == "healthy"`.
- [ ] `/startupz` returns 200.
- [ ] `systemctl status owasaka` shows `active (running)` with no
      recent restarts (`systemctl show owasaka -p NRestarts`).
- [ ] Boot banner's STH matches the paper journal (size + root). If
      you restored, the journal record was updated to the new STH
      and you have a written note explaining the divergence.
- [ ] No `Errorw` log lines in the last 5 minutes
      (`journalctl -u owasaka --since "5 min ago" -p err`).
- [ ] A handful of recent signed events verify cleanly. Smoke test:
      pull the latest 10 alerts, run them through the verifier path
      (the API does this implicitly on read; absence of
      `ErrSignatureInvalid` in fresh logs is sufficient).
- [ ] If NATS was involved, Spectre is receiving events again
      (check the Spectre side; OWASAKA's view is "publisher
      reconnected").
- [ ] Evidence bundle archived. Operator who ran the incident
      writes a one-paragraph post-mortem (timeline, suspected
      cause, action taken, follow-ups) and files it alongside the
      evidence.
- [ ] If keys were rotated or principals revoked during triage,
      `docs/auth/ROTATION_RUNBOOK.md` post-flight steps complete.

---

## See also

- [DR.md](DR.md) — disaster recovery (lost disk, suspected tampering, failover)
- [COMMON_FAILURES.md](COMMON_FAILURES.md) — known failure modes and remediation
- [LOG_ANALYSIS.md](LOG_ANALYSIS.md) — log triage cheatsheet
- [docs/auth/OPERATIONS.md](../auth/OPERATIONS.md) — provisioning, rotation, revocation
- [docs/auth/TRANSPARENCY_LOG.md](../auth/TRANSPARENCY_LOG.md) — STH semantics, proofs
