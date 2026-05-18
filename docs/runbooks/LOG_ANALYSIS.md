# OWASAKA — Log Triage Cheatsheet

One-page reference. Patterns assume the default JSON log format
(`logging.format: "json"` in `configs/examples/default.yaml`). For
incident response context see [INCIDENT.md](INCIDENT.md); for
specific failure modes see [COMMON_FAILURES.md](COMMON_FAILURES.md).

---

## Where logs live

```
/var/log/oswaka/oswaka.log       # primary log file, lumberjack-rotated
/var/log/oswaka/oswaka.log.*.gz  # rotated, compressed (max_backups=5, max_age_days=30)
journalctl -u owasaka            # systemd journal (whatever stdout produced)
```

Rotation is governed by `logging.{max_size_mb, max_backups,
max_age_days, compress}` in the config. The journal is always
available even when the file sink is broken (e.g., disk full on
`/var/log`).

Output sink is set by `logging.output` (`stdout`, `file`, or
`both`). The NixOS module defaults to `stdout`, which means
`journalctl` is your primary view; standalone deployments often run
`both`.

---

## Common log fields

OWASAKA uses zap's structured logging. The base fields you'll see:

| Field           | Where it appears                                 | What it means                                                |
|-----------------|--------------------------------------------------|--------------------------------------------------------------|
| `level`         | every line                                       | `debug` / `info` / `warn` / `error`                          |
| `ts`            | every line                                       | RFC 3339 timestamp                                           |
| `msg`           | every line                                       | the human message                                            |
| `principal_id`  | authz decisions, login flows                     | the authenticated subject id (e.g., `principal-admin-001`)   |
| `username`      | login attempts                                   | the subject string the user typed                            |
| `remote`        | auth-related                                     | the client's `RemoteAddr`                                    |
| `kid`           | JWT issuance, event signing, STH                 | the key id involved (truncate prefix for compact display)    |
| `resource`/`action`/`decision`/`reason` | authz audit lines       | RBAC decision shape (see `internal/authz/middleware.go`)     |
| `error`         | any failure path                                 | the underlying Go error string                               |
| `subsystem`     | health-probe responses, app start lines          | which OWASAKA module emitted the line                        |

`trace_id` is **not** currently emitted as a structured field —
correlation across services is by `principal_id` + timestamp window.

---

## Key search patterns

### Authentication failures

```bash
# Rejected logins (wrong password, wrong TOTP, missing factor).
journalctl -u owasaka --since "1 hour ago" | grep "login rejected"

# Rejected at middleware (bad/missing Authorization header).
journalctl -u owasaka | grep "auth rejected"

# In the rotated file:
grep -E "login rejected|auth rejected" /var/log/oswaka/oswaka.log
```

A short burst of `login rejected` from one `username` against one
`remote` is interesting (brute force, stuck client). A flood across
many usernames from many remotes is an attack.

### RBAC denials

```bash
# Every authz decision is logged via LogAuditSink; filter to denies.
journalctl -u owasaka | grep '"decision":"deny"'

# Group by resource+action to spot a misconfigured role.
journalctl -u owasaka | grep '"decision":"deny"' \
  | jq -r '"\(.resource)/\(.action) \(.principal_id) \(.reason)"' \
  | sort | uniq -c | sort -rn
```

A burst of denies on the same `resource`/`action` after a roles
hot-reload usually means the YAML diff dropped a permission — check
`RBAC policy reloaded` for the diff.

### NATS reconnects

```bash
# Disconnect / reconnect / closed lifecycle.
journalctl -u owasaka | grep -E "NATS (disconnected|reconnected|connection closed)"

# Are we currently connected? Check the health probe.
curl -sS http://127.0.0.1:8080/readyz | jq '.subsystems[] | select(.name=="nats")'
```

One disconnect-reconnect cycle per blip is normal. Continuous
flapping means the broker side is unstable.

### Retention sweep summaries

```bash
# Each sweep writes one structured "sweep complete" line.
journalctl -u owasaka | grep "retention: sweep complete"

# Failures.
journalctl -u owasaka | grep -E "retention:.*(failed|compaction failed)"
```

The complete line carries `events_removed`, `alerts_removed`,
`assets_removed`, `compaction_ran`, `duration_ms`. Sudden zero
removals when the sweep used to remove thousands is a yellow flag —
verify the clock has not jumped.

### Backup runs

```bash
# Successful backup writes emit at info level via the admin endpoint
# or scheduler. Failed runs surface the sink that failed.
journalctl -u owasaka | grep -E "backup: (sink|encrypt|source write)"

# On-disk artifact survey:
ls -lh /var/lib/owasaka/backups/ | tail
sha256sum -c /var/lib/owasaka/backups/backup-*.db.age.sha256 | grep -v OK
```

### Breaker state changes

```bash
# The OnStateChange hook logs one line per transition. Pattern
# depends on caller wiring; grep generously.
journalctl -u owasaka | grep -iE "breaker|circuit"

# Stuck-open detection: many "closed -> open" with no subsequent
# "open -> half-open -> closed" inside the configured Timeout.
```

### STH and transparency-log activity

```bash
# Boot banner — the STH at startup.
journalctl -u owasaka | grep -E "Current STH|stands ready" | tail -5

# Signature verification failures.
journalctl -u owasaka | grep -E "ErrSignatureInvalid|ErrSignerKeyUnknown|ErrSignerKeyRetired"

# Audit log integrity (Merkle verifier — see internal/storage/integrity).
journalctl -u owasaka | grep -i "AUDIT LOG INTEGRITY VIOLATION"
```

`AUDIT LOG INTEGRITY VIOLATION` is the loudest line OWASAKA emits.
Treat as an immediate page (see [INCIDENT.md "Escalation criteria"](INCIDENT.md#escalation-criteria)).

### Migrations at boot

```bash
journalctl -u owasaka | grep -iE "migration|migrate|pending|downgrade"
```

`pending` at boot means [COMMON_FAILURES.md "Migration pending at boot"](COMMON_FAILURES.md#migration-pending-at-boot-blocking-startup).

### Dev-mode warnings

```bash
# This must NEVER appear in production logs.
journalctl -u owasaka | grep -E "DEV MODE: static auth token"
```

If it does, `OSWAKA_ENV=development` slipped into a production
environment. Page the deploy owner.

---

## Quick aggregations

```bash
# Error-rate over the last hour, bucketed per minute.
journalctl -u owasaka --since "1 hour ago" -p err -o short-iso \
  | awk '{print substr($1,1,16)}' | sort | uniq -c

# Top 10 noisiest error messages today.
journalctl -u owasaka --since today -p err \
  | jq -r .msg 2>/dev/null | sort | uniq -c | sort -rn | head

# Login attempts per username (last 24h).
journalctl -u owasaka --since "24 hours ago" \
  | jq -r 'select(.msg | test("login (rejected|succeeded)")) | .username' \
  | sort | uniq -c | sort -rn
```

`jq` only works when `logging.format: "json"`. For text format,
substitute `awk`/`grep` on the printable representation.

---

## See also

- [INCIDENT.md](INCIDENT.md) — incident response playbook (first 5
  minutes, triage matrix, evidence collection)
- [COMMON_FAILURES.md](COMMON_FAILURES.md) — known failure modes
  with diagnostic commands matching the searches above
- [DR.md](DR.md) — disaster recovery (lost disk, suspected
  tampering, failover, STH-regression triage)
- [docs/auth/OPERATIONS.md](../auth/OPERATIONS.md) — provisioning
  and revocation procedures
