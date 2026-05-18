# OWASAKA — Common Failure Modes

Catalogue of recurring failure modes with symptom, root cause,
diagnostic, remediation, and prevention. Linked from
[INCIDENT.md](INCIDENT.md)'s triage matrix. For log search patterns
see [LOG_ANALYSIS.md](LOG_ANALYSIS.md); for data-loss scenarios see
[DR.md](DR.md).

Each entry follows the same shape; skim the symptom column when you
arrive here from a paging.

---

## NATS unreachable

**Symptom.** Logs repeat `[owasaka/publisher] NATS disconnected: ...`
and `NATS reconnected to ...`. `/readyz` shows
`subsystems[].name=="nats"` with `status=="degraded"` and message
`"nats status: DISCONNECTED"`. Events still ingest and persist; the
WebSocket hub still pushes to UI clients. The NATS probe is
**optional**, not required — so `/readyz` overall stays **200**.

**Root cause.** Spectre's NATS broker is down, the NKey changed, TLS
cert expired, or the network path between OWASAKA and the broker
broke. The publisher is configured with infinite reconnect
(`nats.MaxReconnects(-1)`), so transient outages self-heal.

**Diagnostic.**
```bash
# What does OWASAKA think of NATS right now?
curl -sS http://127.0.0.1:8080/readyz | jq '.subsystems[] | select(.name=="nats")'

# Can we reach the broker at all?
nc -vz <nats-host> 4222   # or 4443 for tls://

# Per-reconnect attempt log lines (one per disconnect).
journalctl -u owasaka --since "1 hour ago" | grep -E "NATS (disconnected|reconnected|connection closed)"
```

**Remediation.** This is graceful, not critical. If the broker
recovers and OWASAKA reconnects, no operator action is needed —
events that arrived while disconnected stayed local (BoltDB + WS)
and are queryable normally. If NATS stays down indefinitely, either
fix Spectre's broker or set `nats_url: ""` in config to silence the
probe.

**Prevention.** Keep the NATS NKey / TLS cert rotation calendar in
sync with Spectre's. Run the broker behind a watchdog. Set TLS cert
expiry alerts at T-30d.

---

## BoltDB locked or corrupted

**Symptom.** Startup fails with `failed to open boltdb at ...:
timeout`. Or `/readyz` flips to 503 with `boltdb` subsystem
`unhealthy`. Or the binary exits with `database not initialized` on
the next request.

**Root cause.** bbolt holds an exclusive file lock on the DB file.
A previous OWASAKA process crashed without releasing it, a second
process is trying to open the same file (compose + systemd both
running it), or the underlying disk is failing.

**Diagnostic.**
```bash
# Who holds the lock?
sudo lsof /var/lib/owasaka/owasaka.db

# Two PIDs → kill the rogue one. Zero PIDs → the lock is stale or
# the file is corrupt (different failure mode).

# bbolt page count + freelist; corruption usually surfaces as
# "page X: invalid checksum".
file /var/lib/owasaka/owasaka.db   # should report "data" — not "empty" or "truncated"
ls -la /var/lib/owasaka/owasaka.db # size: 0 → corrupted/truncated
```

**Remediation.**
- **Stale lock, no other process:** stop the service, remove only if
  you're certain (`sudo systemctl stop owasaka`; bbolt cleans up its
  own lock on a clean exit — the file lock is held via flock, not a
  separate `.lock` file; if it persists, the kernel will release on
  process death).
- **Two processes:** kill the rogue (`systemctl stop` whichever is
  not the intended supervisor).
- **Corrupted file:** see [DR.md §"Scenario 1 — Lost disk / corrupted
  DB"](DR.md#scenario-1--lost-disk--corrupted-db). Restore from the
  latest backup.

**Prevention.** Run exactly one OWASAKA per host. Use the NixOS
module's systemd unit (which sets `Type=simple` and a single
`ExecStart`) rather than ad-hoc launches. Monitor disk SMART.

---

## Disk full (data dir or log dir)

**Symptom.** Backups fail with `no space left on device`. Retention
sweep logs `compaction failed`. BoltDB writes start returning errors
mid-transaction. Lumberjack stops rotating because it cannot write
the next file.

**Root cause.** `/var/lib/owasaka` filled by event ingest outpacing
retention sweeps, by an unbounded transparency log, or by stale
backups under `/var/lib/owasaka/backups/`. `/var/log/oswaka` filled
because `max_backups`/`max_age_days` are too generous (or never
applied — `compress: true` in `default.yaml`).

**Diagnostic.**
```bash
df -h /var/lib/owasaka /var/log/oswaka
du -sh /var/lib/owasaka/* /var/log/oswaka/* | sort -h | tail
# Top consumers usually: owasaka.db, backups/, oswaka.log*
```

**Remediation.**
- **Data dir:** stop running backups for now (they need space to
  write). Manually rotate the local backup dir down to a smaller
  `local_keep_last`. Run `oswaka migrate status` to confirm no
  in-flight migration. If retention has been on but the DB still
  grew, compaction has not run — lower
  `compaction_freelist_threshold` and trigger one manual sweep.
  **Never** delete `owasaka.db` or any `transparency.*` bucket
  contents directly.
- **Log dir:** delete rotated `.gz` files older than your retention
  window; lumberjack rotates on next write.

**Prevention.** Monitor disk at 70% / 85% / 95%. Tune
`storage.local.retention.events_default_days` and
`storage.backup.local_keep_last` for the host's actual capacity. Send
backups to NAS so the host data dir is bounded.

---

## TOTP clock skew on admin login

**Symptom.** Operator reports `POST /auth/login` returns 401
`authentication failed` with correct password + correct-looking
authenticator code. Logs show `login rejected ... reason=...`. Tests
with a freshly-generated code also fail.

**Root cause.** TOTP validates a 6-digit code derived from the
current 30-second window. If the OWASAKA host's clock and the
operator's phone disagree by more than ±1 window, every code fails.
`Verify` errors are deliberately undifferentiated so callers cannot
tell whether the password or the TOTP failed.

**Diagnostic.**
```bash
# Host clock vs NTP reference.
timedatectl status | grep -E "Local time|NTP|synchronized"
# `System clock synchronized: yes` is required.

# Compare to a known good source (operator's phone, a second host).
date -u

# How recent are login rejections?
journalctl -u owasaka --since "10 min ago" | grep "login rejected"
```

**Remediation.** Re-sync NTP (`sudo systemctl restart
systemd-timesyncd` or equivalent). Have the operator re-sync their
phone's automatic time. Retry login.

**Prevention.** Enforce NTP on every OWASAKA host (the NixOS module
inherits `services.timesyncd`). Operators should keep "automatic
date & time" on for their authenticator's host device.

---

## JWT signing key rotation gap

**Symptom.** Downstream services (Spectre, Cerebro) start rejecting
tokens issued by OWASAKA with `unknown kid` or `signature invalid`.
OWASAKA's own JWT verifier is fine — the gap is on the consumer
side.

**Root cause.** A JWT signing key was retired (`authority.Retire`)
before downstream verifiers refreshed their JWKS snapshot. The
intended flow is: rotate → 1h overlap → retire. If the overlap
window is skipped, in-flight tokens fail to verify on consumers that
cached the old JWKS.

**Diagnostic.**
```bash
# How many keys are currently in the JWKS? During overlap should be ≥ 2.
curl -sS http://127.0.0.1:8080/.well-known/jwks.json | jq '.keys | length'

# Which kid is currently active in OWASAKA?
journalctl -u owasaka | grep "JWT signing key generated" | tail -3

# On the consumer side: check whether the kid in a failing token
# matches anything in the consumer's cached JWKS. If not, the
# consumer is stale.
```

**Remediation.** Re-publish the previous key as active in OWASAKA
(`authority.store.UpdateStatus(ctx, oldID, pki.StatusKeyActive)` —
see [docs/auth/ROTATION_RUNBOOK.md §R1](../auth/ROTATION_RUNBOOK.md)).
Force consumers to refresh their JWKS cache. Then redo the rotation
with a proper 1h overlap.

**Prevention.** Always honour the overlap window
([ROTATION_RUNBOOK.md](../auth/ROTATION_RUNBOOK.md) "1h later" step).
Consumers should refresh JWKS every 5–10 minutes, not on token
failure.

---

## Transparency log STH mismatch with operator journal

**Symptom.** Boot banner reports an STH (size + root) that differs
from the paper journal record. Or
`GET /api/transparency/consistency?first=<old>&second=<new>` returns
`ok=false`.

**Root cause.** Either the DB was restored from an older backup
(intentional during DR), or someone modified leaves directly in
BoltDB, or the journal record is stale. The transparency log is
append-only by design and any divergence is significant.

**Diagnostic.** See [DR.md §"Scenario 5 — STH regression at boot"](DR.md#scenario-5--sth-regression-at-boot)
for the full triage tree.

**Remediation.** Decision flow is in DR.md. Summary:
- Restore was intentional → update the journal to the new banner.
- Restore was unintentional → forensic capture per
  [INCIDENT.md "Evidence collection"](INCIDENT.md#evidence-collection)
  then DR §2.
- Journal stale → update journal from boot banner if you trust the
  intervening signing chain.

**Prevention.** Snapshot the boot banner daily into an offline
record. Run the monthly `oswaka backup --verify-restore` drill — a
broken transparency journal usually surfaces there first.

---

## Backup encryption fails (age recipients mismatch)

**Symptom.** `oswaka backup` fails with `backup: encrypt: ...` or
`age: invalid recipient`. Alternatively, a backup succeeds but
`oswaka restore` (or `--verify-restore`) fails with `age: no
identity matched any of the recipients`.

**Root cause.** `.sops.yaml`'s recipient list and the age key the
operator (or systemd `LoadCredential`) is using have drifted. A new
operator joined and was added to sops but not to the backup engine's
recipient list, or vice versa. Old backups remain encrypted to their
original recipients — adding a recipient does not retroactively
re-key them.

**Diagnostic.**
```bash
# What does sops think the recipients are?
grep -A20 "age:" .sops.yaml

# What is the operator's public key?
age-keygen -y ~/.config/sops/age/keys.txt

# Is that pubkey in the recipient list? If not, this operator
# cannot decrypt new backups produced after they were dropped.
```

**Remediation.** Edit `.sops.yaml` to include the missing
recipient. Re-run `sops updatekeys secrets.yaml`. Take a fresh
backup — it will be encrypted to the corrected recipient list.
**Existing backups remain decryptable only by their original
recipients**; if those keys are lost, those backups are
unrecoverable. Keep an offline breakglass age key in the recipient
list as standing policy ([BACKUP.md](../auth/BACKUP.md) §"Recipients").

**Prevention.** Treat the breakglass key as non-optional. Add new
operators **before** off-boarding old ones. Monthly restore drill
catches recipient drift before a real disaster.

---

## Migration pending at boot blocking startup

**Symptom.** Startup fails with `migrations: pending (have N
pending: ...)`. `/startupz` never flips to 200. systemd marks the
unit `failed`.

**Root cause.** The migration runner refuses to start with pending
schema migrations unless `--auto-migrate` is set
(`internal/storage/migrations/runner.go:CheckBoot`). Production
deployments deliberately keep this **off** so operators apply
migrations consciously and can take a pre-migration backup.

**Diagnostic.**
```bash
# What's pending?
oswaka migrate status
# applied: 1
# available: 3
# pending: 2  (ID 2 "...", ID 3 "...")
```

**Remediation.**
```bash
# Always take a fresh backup BEFORE applying migrations.
oswaka backup

# Apply forward.
oswaka migrate up

# Then restart.
sudo systemctl start owasaka
```

If `oswaka migrate status` reports `applied > available`, the binary
is older than the DB — you are downgrading. The runner returns
`ErrDowngradeDetected` and refuses. Use the matching (newer) binary
version.

**Prevention.** Migrations run during planned maintenance windows,
not during incident-driven restarts. Always backup before `migrate
up`. Pin the binary version in the NixOS module so a binary
downgrade is intentional, not accidental.

---

## Circuit breaker stuck open (NATS / NAS)

**Symptom.** Operations against the protected dependency fail fast
with `circuit breaker open` even though the dependency itself
recovered. The breaker is supposed to attempt a half-open probe
after `Timeout` (default 30s) — if that probe keeps failing the
breaker re-opens.

**Root cause.** The dependency is still failing every probe (so the
breaker correctly stays open), OR the wrapped operation has a
timeout longer than the breaker's `Timeout`, OR the probe call uses
a context that times out faster than the operation can succeed.
Context-cancellation errors are excluded from failure counts
(`IsExcluded` in `internal/reliability/breaker.go`), so a
`ctx.Canceled` should not trip the breaker.

**Diagnostic.**
```bash
# State-change log lines (the OnStateChange hook writes one per
# transition; closed→open is the alert).
journalctl -u owasaka | grep -E "breaker.*(open|half-open|closed)"

# Reach the dependency directly, bypassing OWASAKA:
nc -vz <nats-host> 4222
mount | grep <nas-mountpoint>
```

**Remediation.** Fix the dependency first. The breaker self-heals
when a half-open probe succeeds. If you must force-close (the
dependency is verifiably healthy and the breaker is mis-tripped),
there is **no operator-facing force-close API** — restart the
OWASAKA service to reset breaker state in memory. This is heavy;
prefer letting the breaker observe a successful half-open probe.

**Prevention.** Tune `BreakerConfig.Timeout` to match the upstream's
real recovery cadence. Tune `FailureThreshold` (default 5) high
enough that transient blips do not trip. Do not wrap operations
whose own timeout exceeds the breaker's `Timeout` — the breaker will
fight the operation.

---

## See also

- [INCIDENT.md](INCIDENT.md) — first-five-minutes triage and escalation
- [DR.md](DR.md) — restore, suspected-tamper, failover playbooks
- [LOG_ANALYSIS.md](LOG_ANALYSIS.md) — search patterns for the logs cited above
- [docs/auth/BACKUP.md](../auth/BACKUP.md) — backup + retention + migrations operations
- [docs/auth/ROTATION_RUNBOOK.md](../auth/ROTATION_RUNBOOK.md) — key rotation procedures
- [docs/auth/OPERATIONS.md](../auth/OPERATIONS.md) — provisioning, rotation, revocation
