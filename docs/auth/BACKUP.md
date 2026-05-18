# Backup & Retention — Operator Guide

Day-to-day operations of OWASAKA's data layer: backup schedule,
retention tuning, migration workflow, restore drill cadence. For DR
playbooks see [docs/runbooks/DR.md](../runbooks/DR.md); for design
rationale see [ADR-0064][adr].

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0064.md

---

## 30-second mental model

```
                          BoltDB
                            │
                            ▼
              ┌───────────────────────────┐
              │  internal/storage/backup  │
              │  Engine.Run(ctx)          │
              │    ├ Tx.WriteTo (hot)     │
              │    ├ age.Encrypt (recip)  │
              │    └ SHA-256 sidecar       │
              └─────────────┬─────────────┘
                            ▼
              ┌─── Sink fan-out ─────────┐
              │  LocalSink (rotate N)    │
              │  NASSink  (offsite)      │
              │  MultiSink (tee)          │
              └───────────────────────────┘

                          BoltDB
                            │
                            ▼
              ┌──────────────────────────────┐
              │ internal/storage/retention   │
              │ daily sweep:                  │
              │   • events  > 90d  → DELETE   │
              │   • alerts  > 365d → DELETE   │
              │   • assets  > 30d  → DELETE   │
              │   • transparency log → NEVER  │
              │ if freelist > threshold:      │
              │   • Tx.CopyFile + rename     │
              └──────────────────────────────┘
```

---

## Configuration

Add to `configs/examples/default.yaml` (operator-tuned):

```yaml
storage:
  local:
    data_dir: /var/lib/owasaka
    retention:
      events_default_days: 90
      events_alerts_days: 365
      assets_stale_days: 30
      sweep_interval_hours: 24
      compaction_freelist_threshold: 1024   # pages; 0 disables
  backup:
    schedule_interval_hours: 6
    local_dir: /var/lib/owasaka/backups
    local_keep_last: 14            # 14 * 6h ≈ 84h retained on host
    nas:
      enabled: true
      mount_point: /mnt/owasaka-nas
      subdir: backups               # appended to mount_point
    age_recipients_file: .sops.yaml  # same age recipients as sops
```

Defaults are baked in; everything is overridable.

---

## Scheduled backups

Wired into the binary via the Sprint 5 ops slice (B3 in ADR-0064).
Until then, run from cron:

```cron
# /etc/cron.d/owasaka-backup
0 */6 * * * owasaka oswaka backup --quiet
```

Or, post-Sprint-5:

```yaml
services.owasaka = {
  enable = true;
  backup.scheduleIntervalHours = 6;
};
```

---

## On-demand backup

```bash
oswaka backup
# writes to the configured local_dir; the NAS sink (if enabled)
# also receives a copy synchronously.

oswaka backup --out=/tmp/adhoc.db.age
# overrides local sink only; the NAS sink still runs if configured

oswaka backup --verify-restore
# dry-run: takes a backup, decrypts it into a sandbox, verifies the
# STH against the live journal, then deletes the sandbox. Use this
# during monthly drills.
```

The HTTP admin endpoint mirrors the CLI:

```bash
curl -X POST https://owasaka.example/api/admin/backup \
  -H "Authorization: Bearer <admin token>"
```

Returns JSON with: `filename`, `tree_size`, `root_hash`, `created_at`,
and the path on each sink where the artifact landed.

---

## Backup naming + rotation

Filenames embed an RFC 3339-ish UTC timestamp and the tree size at
backup time so a lexicographic `ls | sort` is chronological:

```
backup-2026-05-18T12-00-00Z-tree42.db.age
backup-2026-05-18T12-00-00Z-tree42.db.age.sha256
```

`LocalSink` rotates by file count: `local_keep_last=14` retains the
14 most recent pairs. `NASSink` does not rotate automatically — the
NAS is "long-term archive" and operators run rotation policy on the
NAS itself.

---

## Recipients (who can decrypt)

Backups are encrypted with **age** to the same recipient set as
`secrets.yaml`. Edit `.sops.yaml`:

```yaml
keys:
  - &alice age1pndp7g...               # alice's operator key
  - &bob   age1qd0xul...               # bob's operator key
  - &break age1z2lqmj...               # paper breakglass key, offline

creation_rules:
  - path_regex: secrets\.yaml$
    age:
      - *alice
      - *bob
      - *break
```

The backup engine reads the same recipient list. Add a new operator's
recipient BEFORE letting them off-board — once removed, they can no
longer decrypt backups (or secrets).

**Multi-recipient is non-negotiable in production**: a single-key
deployment is one lost laptop away from permanent backup
unreadability.

---

## Retention tuning

Defaults assume a SOC-style workload:

- **events_default_days=90** — routine telemetry. Matches typical
  SIEM hot-storage windows.
- **events_alerts_days=365** — high-severity alerts. Auditors want
  alerts long after routine events have aged out.
- **assets_stale_days=30** — assets not seen for 30d are GC-eligible.
  The transparency log retains any historical record; the live
  asset view stays current.

**Never** prune the transparency log. The retention engine
deliberately skips `transparency.*` buckets — that would defeat the
tamper-evidence guarantee. If your disk fills up, increase capacity
or add a compaction trigger; do not delete log leaves.

### Reading the sweep report

Each sweep emits a structured log line:

```
retention: sweep complete events_removed=1247 alerts_removed=0
  assets_removed=12 compaction_ran=true duration_ms=183
```

`alerts_removed > 0` in routine operations is a yellow flag —
verify your auditor compliance window before complaining.

---

## Compaction

BoltDB does not reclaim disk space when buckets shrink — freed pages
go on a freelist for reuse. After heavy retention pruning the
freelist can grow large (megabytes); compaction copies the live
data to a fresh file and renames it into place.

`compaction_freelist_threshold` (in pages) gates this. 0 disables
compaction entirely; production deployments set a non-zero threshold
(default 1024 pages ≈ 4 MB on most systems).

Compaction is **expensive**: it takes a read lock for the duration
of the copy and rewrites the entire DB. Operators schedule it
during quiet windows or skip it (the freelist is functional space,
just not visible disk space).

---

## Migrations

```bash
oswaka migrate status
# applied: 1
# available: 3
# pending: 2  (ID 2 "add foo bucket", ID 3 "add bar index")

oswaka migrate up
# pre-migration backup written to /var/lib/owasaka/backups/...
# applying ID 2 "add foo bucket"... ok
# applying ID 3 "add bar index"... ok
# applied: 3

oswaka migrate down --force
# requires --force because BoltDB downgrades are fragile
```

The binary refuses to start if migrations are pending unless
`--auto-migrate` is set. Production deployments keep `--auto-migrate`
**off** so operators run migrations deliberately and inspect the
diff first.

A downgrade (applied > available) is always fatal — the operator
must use a matching binary version.

---

## Restore drill cadence

Monthly:

```bash
oswaka backup --verify-restore
```

This takes a fresh backup and dry-run-restores it into a sandbox,
reporting whether the STH matches the live journal. A failure here
means your backups are broken — investigate immediately, not next
DR.

Quarterly:

Full DR exercise (Scenario 4 in [DR.md](../runbooks/DR.md)) — stop
the live host, restore from the previous backup onto a clean host,
verify, then resume the live host. Some teams will skip this; the
ones that don't are the ones that survive disk failures cleanly.

---

## Common operational questions

### "Where do I find the age key?"

`~/.config/sops/age/keys.txt` for operator use, or the systemd
`LoadCredential` path (see Sprint 1 T10 / NixOS module) for the
service principal. The sops setup uses the same file.

### "Can I encrypt to a hardware key (YubiKey)?"

age supports `age-plugin-yubikey`. Add the YubiKey-stub recipient
to `.sops.yaml` and re-encrypt secrets + future backups. Existing
backups remain decryptable by the original recipients.

### "How big are backups?"

Roughly the live DB size, plus age envelope overhead (~200 bytes).
A SIEM ingesting at 10k events/sec with 90-day retention typically
ends up in the low gigabytes; the age compression-free format
means backup size tracks DB size linearly.

### "What if the NAS sink fails?"

The `MultiSink` returns the first failure; local sink writes
complete first by ordering convention. Operator sees the error in
logs and investigates the NAS. The latest local backup remains
available.

### "How do I rotate backup encryption?"

Same as sops rotation: edit `.sops.yaml`, run `sops updatekeys
secrets.yaml`, take a fresh backup. Old backups remain decryptable
by their original recipients.

---

## See also

- [DR.md](../runbooks/DR.md) — disaster recovery playbooks
- [MODEL.md](MODEL.md) — authentication / identity architecture
- [TRANSPARENCY_LOG.md](TRANSPARENCY_LOG.md) — STH semantics
- [docs/secrets/BOOTSTRAP.md](../secrets/BOOTSTRAP.md) — first-time
  age + sops setup
- [ADR-0064][adr] — backup + retention + migrations design
