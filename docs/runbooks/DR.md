# OWASAKA — Disaster Recovery Runbook

On-call playbook for the day everything breaks. Each scenario is a
numbered list of commands; copy-paste-runnable. Architectural why
lives in [ADR-0064][adr]; operational discipline (rotation, backup
cadence, journal cadence) lives in [BACKUP.md](../auth/BACKUP.md).

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0064.md

---

## Pre-flight: things you need

Have these to hand before any DR procedure:

- **age private key** (`~/.config/sops/age/keys.txt` or systemd
  credential path) — the one that decrypts both `secrets.yaml` and
  the encrypted backup files.
- **STH journal** — your operational record of the most recent
  trusted Signed Tree Head (size, root_hash, timestamp). The boot
  banner prints the current STH on every restart; you should be
  snapshotting it daily into a paper or offline log.
- **Encrypted backup** — the most recent `.db.age` file from the
  local backup dir or NAS, plus its `.sha256` sidecar.
- **Matching OWASAKA binary** — the version that originally created
  the backup. Downgrades are refused (ADR-0064 §"Migrations").

If any of those are missing, **stop** and recover them before
proceeding. Restoring from a corrupted backup or signing a new STH
with a forged key is worse than the original disaster.

---

## Scenario 1 — Lost disk / corrupted DB

The host's `owasaka.db` is unreadable. Backups exist on the NAS or
local backup dir.

### Steps

```bash
# 1. Stop the OWASAKA service on the affected host.
sudo systemctl stop owasaka

# 2. Pick the most recent backup. Verify the sidecar BEFORE
#    decrypting anything.
cd /var/lib/owasaka/backups
LATEST=$(ls -1 backup-*.db.age | sort | tail -n1)
sha256sum -c "${LATEST}.sha256"   # must succeed

# 3. Restore. The STH journal-record check is REQUIRED here — if
#    it fails, you are about to silently roll back state that the
#    transparency log claims existed.
oswaka restore \
  --from="${LATEST}" \
  --target=/var/lib/owasaka/owasaka.db \
  --expected-sth-size=<from-journal> \
  --expected-sth-root=<from-journal>

# 4. Start the service. The boot banner prints the restored STH.
sudo systemctl start owasaka
journalctl -u owasaka -f
```

### Verify

- Banner shows tree size + root matching the journal record (within
  the backup-cadence window — slightly older is normal, newer means
  the wrong backup).
- `curl /api/transparency/sth` returns the same.
- A handful of recent alerts read back via the API and verify their
  signatures.

### If verification fails

The restored DB diverges from the journal. **Do not signal "DR
complete"**. Restore from a different backup (older if necessary)
until journal alignment is achieved, then catch up the gap manually
from upstream sources if any (Spectre's NATS retention, syslog
forwarder, etc.).

---

## Scenario 2 — Suspected tampering

You observe a consistency-proof failure (`/api/transparency/consistency`
returns `ok=false`), an STH regression at boot, or a signed event
that fails verification.

### Steps

```bash
# 1. Capture forensic state IMMEDIATELY before touching anything.
sudo systemctl stop owasaka
cp /var/lib/owasaka/owasaka.db /var/lib/owasaka/forensic-$(date -u +%Y%m%dT%H%M%SZ).db

# 2. Inspect the boot banner from journalctl history. Look for the
#    last STH whose root matches your daily journal record.
journalctl -u owasaka | grep 'Current STH' | tail -20

# 3. Find the last backup whose .age filename embeds the trusted
#    tree size. Backup filenames are `backup-<UTC>-tree<N>.db.age`.
LATEST_TRUSTED=$(ls -1 /var/lib/owasaka/backups/backup-*-tree<N>.db.age | sort | tail -n1)

# 4. Restore from the trusted backup. The STH journal-record check
#    will succeed only against the trusted backup.
oswaka restore \
  --from="${LATEST_TRUSTED}" \
  --target=/var/lib/owasaka/owasaka.db \
  --expected-sth-size=<trusted-size> \
  --expected-sth-root=<trusted-root>

# 5. Open an ADR documenting the incident: timeline, suspected vector,
#    forensic DB path, restored-from backup, journal record at restore.
#    See docs/auth/OPERATIONS.md §"Incident response" for the template.

sudo systemctl start owasaka
```

### Don't

- **Don't** restart OWASAKA before forensic capture. The current
  state is evidence.
- **Don't** delete the suspected-tampered DB. Keep the
  `forensic-*.db` file at least 90 days for investigation.
- **Don't** sign a fresh STH over the tampered state — that
  legitimizes the tamper.

---

## Scenario 3 — Fail over to new hardware

Planned migration to a fresh host.

### Steps

```bash
# On the old host:
oswaka backup --out=/tmp/cutover.db.age
ls /tmp/cutover.db.age /tmp/cutover.db.age.sha256

# Transport encrypted file + sidecar via your air-gap-approved
# channel (sneakernet, NAS, encrypted USB). Both files must arrive
# intact; verify the sidecar on receipt.

# On the new host (which already has the same age key under
# ~/.config/sops/age/keys.txt and the same OWASAKA binary version):
sha256sum -c /tmp/cutover.db.age.sha256

oswaka restore \
  --from=/tmp/cutover.db.age \
  --target=/var/lib/owasaka/owasaka.db \
  --expected-sth-size=<current-on-old-host> \
  --expected-sth-root=<current-on-old-host>

sudo systemctl start owasaka

# Verify on new host
curl https://new-host/api/transparency/sth
```

### Don't

- **Don't** start the new host's OWASAKA service before restore.
  An empty DB on a host with the same age key would cheerfully accept
  events and write a competing STH; restoring afterward then
  triggers a journal mismatch.
- **Don't** keep the old host running concurrently. Two OWASAKA
  instances with the same identity is incoherent.

---

## Scenario 4 — Validate backups (drill)

Run this **monthly**. A backup you have never restored is not a
backup.

### Steps

```bash
# Pick the most recent backup.
LATEST=$(ls -1 /var/lib/owasaka/backups/backup-*.db.age | sort | tail -n1)

# Dry-run restore into a sandbox; the binary opens the file
# read-only, derives the STH, and reports without swapping anything.
oswaka backup --verify-restore --from="${LATEST}"

# Expected output:
#   Backup created:  2026-05-18T08:00:00Z
#   Tree size:       42
#   Root hash:       8f4a2bc1…
#   STH:             matches journal record  ✓
```

### If it fails

A failed drill means the backup or the encryption is broken —
**before** an actual disaster. Investigate immediately:

1. Wrong age key? Cross-check with `age-keygen -y
   ~/.config/sops/age/keys.txt` against `.sops.yaml`.
2. Sidecar mismatch? Backup was corrupted in transit. Re-pull from
   the source sink.
3. Bolt-open failure? Backup was taken with a different binary
   version; downgrade refused. Use the matching binary.

---

## Scenario 5 — STH regression at boot

The boot banner reports a tree size or root that does not match
your daily journal record.

### Triage tree

```
Banner size < journal size            → restore was from older backup
                                         (intentional? if not → §2 tamper)
Banner size > journal size            → journal record is stale
                                         (update from boot banner; investigate
                                         if you missed a daily snapshot)
Banner root mismatches, size matches  → tree was modified at the leaf level
                                         post-snapshot → §2 tamper
```

### Action per branch

- **Restore from older backup, intentional** (e.g., you did §1 or
  §2): update the journal to the new banner values.
- **Restore from older, unintentional**: stop the service, run §2
  with the trusted-tree journal record.
- **Journal stale**: take the boot banner as authoritative if you
  trust the chain since the last snapshot. Schedule a daily journal
  snapshot via cron / paper-and-safe.
- **Root mismatch with size match**: §2 tamper. Forensic capture
  before touching state.

---

## Operational discipline reminders

- **Backups happen automatically** every 6h (configurable). On-demand
  `oswaka backup` adds a snapshot whenever you want.
- **The STH journal is the trust anchor.** Without it you cannot
  distinguish a restored-from-old-backup boot from a tampered one.
  Snapshot the boot banner daily; store offline.
- **Multi-recipient age** means losing one operator's age key is
  not catastrophic. Add new recipients before letting an operator
  off-board.
- **`make test-integration`** runs the backup → wipe → restore
  cycle in CI on every PR that touches storage. If it fails,
  storage has drifted; do **not** ship until the cycle is green.

---

## See also

- [docs/auth/BACKUP.md](../auth/BACKUP.md) — day-to-day operations
- [docs/auth/MODEL.md](../auth/MODEL.md) — authentication architecture
- [docs/auth/OPERATIONS.md](../auth/OPERATIONS.md) — provisioning,
  rotation, revocation
- [docs/auth/TRANSPARENCY_LOG.md](../auth/TRANSPARENCY_LOG.md) — STH
  semantics, inclusion / consistency proof reading
- [ADR-0064][adr] — design rationale + threat model
