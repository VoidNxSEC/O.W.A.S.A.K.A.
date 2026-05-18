# Transparency Log

OWASAKA's RFC 6962-inspired Merkle log captures critical events
(high-severity alerts at v1; principal/policy/key lifecycle entries
land via dedicated call sites) into a tamper-evident, sequentially
append-only structure with public inclusion + consistency proofs.

For architectural rationale and the threat model see [ADR-0063][adr].
For the per-event signing layer this log sits on top of see
[EVENT_SIGNING.md](EVENT_SIGNING.md).

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0063.md

---

## Mental model

```
                     critical event (sig'd per ADR-0062)
                                   │
                                   ▼
                  internal/storage/transparency.Tree
                       Append(leaf) → leafIndex
                                   │
                                   ▼
                       compute Merkle root over leaves
                                   │
                                   ▼
              STHSigner.SignSTH(size, root) → STH (Ed25519)
                                   │
                                   ▼
                            PersistSTH (BoltDB)
                                   │
                                   ▼
                  /api/transparency/{sth,inclusion,consistency,leaf}
                                   │
                                   ▼
                       external auditor / Spectre / Cerebro
                pins latest STH, verifies inclusion + consistency
```

The log lives in BoltDB (`transparency.leaves`, `transparency.nodes`,
`transparency.sth`, `transparency.sth.history` buckets) alongside the
existing event store. Single-host durability is a known limitation;
Sprint 4 backup ADR covers it. Replication is deferred to v2.

---

## What goes in the log

V1 scope is deliberately narrow:

| Source                                | Why                                                       |
|---------------------------------------|-----------------------------------------------------------|
| `EventAlert` (severity ≥ high)        | Auditors examine these; volume manageable                 |
| Principal lifecycle (provision, status change, role change) | Compliance-mandated trail (LGPD, ISO 27001 A.9.4) |
| Token lifecycle (issue/revoke, JTI only) | Non-repudiation for revocation audits                 |
| Policy lifecycle (RBAC reload, rule edits) | Auditor question: "what changed and when"           |
| Key lifecycle (PKI rotation, retirement) | Forensic chain after a suspected compromise           |
| Backup / restore events (Sprint 4)    | Detects unintended restore-from-old-backup as STH regression |
| Operator override of AI verdict       | EU AI Act Art. 14 human-oversight evidence               |

Routine telemetry (DNS, ARP, port-scan results) is **not** logged.
It carries its own per-event signature; auditors sample it from the
event store without burning Merkle real estate.

The pipeline (`internal/events/pipeline.go`) automatically appends
`EventAlert` events. Other categories are appended at their call
sites — e.g., the RBAC reload handler appends a leaf for every
successful reload diff.

---

## Reading proofs

### Inclusion: "this event was in the log at size N"

A consumer that holds a signed event at log position `m` and knows
the latest STH of size `n`:

```
GET /api/transparency/inclusion?leaf_index=m&tree_size=n
→ 200 OK
   {
     "tree_size": n,
     "leaf_index": m,
     "audit_path": ["<hex32>", "<hex32>", ...]
   }
```

To verify:

1. Compute `leaf_hash = SHA256(0x00 || canonical_event_bytes)` from
   the event the consumer holds.
2. Walk the audit path bottom-up (RFC 6962 §2.1.1) to reproduce the
   tree root.
3. Compare the reproduced root against the `root_hash` in the latest
   STH (`GET /api/transparency/sth`).

`internal/storage/transparency.VerifyInclusion` is the Go reference
implementation; Spectre/Cerebro mirror the algorithm.

### Consistency: "the log of size n is an extension of size m"

A consumer that previously pinned an STH at size `m` and now sees
an STH at size `n > m`:

```
GET /api/transparency/consistency?first=m&second=n
→ 200 OK
   {
     "tree_size": n,
     "first_size": m,
     "second_size": n,
     "audit_path": ["<hex32>", ...]
   }
```

To verify:

1. Take the pinned root for size `m` and the audit path.
2. Walk the algorithm (RFC 6962 §2.1.2 / `VerifyConsistency`) — when
   `m` is a power of 2, the algorithm uses pinned `root_m` as the
   starting hash; otherwise it re-derives `root_m` from the proof
   (forgery detection happens at the algorithm level in that case).
3. Compare the reproduced `root_n` against the new STH's root.

A mismatch on the reproduced root **proves the log was retroactively
edited** — an alarm-worthy event.

---

## Signed Tree Head (STH)

```
GET /api/transparency/sth
→ 200 OK
   {
     "tree_size": 42,
     "root_hash": "<hex32>",
     "timestamp_ns": 1747522800000000000,
     "signature": "<hex64>",
     "signer_key_id": "<uuid>"
   }
```

The signature covers a fixed-width byte string:

```
[8 bytes BE TreeSize][32 bytes RootHash][8 bytes BE UnixNano]
```

No JSON ambiguity, no canonicalization drift between Go versions.
Verifiers reproduce the same bytes from the response fields and check
the Ed25519 signature against the `signer_key_id` public key fetched
from `/.well-known/jwks.json` (`owasaka_purpose=transparency-sth`).

The STH signing key (`pki.PurposeTransparencyLogSTH`) is **distinct
from** the event signing key. Compromise of one does not invalidate
the other; STH rotates on a slower cadence (weekly) since issuance
volume is orders of magnitude lower than event signing.

---

## Operational discipline

### Daily STH snapshot

Operators record the current STH (`size`, `root_hash`, `timestamp`)
to an ops journal at least daily. The boot banner prints the current
STH on every restart:

```
  Current STH:    size=42  root=8f4a:…:2bc1  (2026-05-18T12:00:00Z)
```

A surprise STH **regression** at boot — size went down, or root
mismatches the recorded value — indicates rollback / restore-from-
backup. Expected during DR exercises; alarming otherwise.

### Periodic consistency verification

Spectre/Cerebro should pin the latest STH they observed and run a
consistency check on every fresh fetch. A failed consistency proof
is irrecoverable: the log has been edited, and trust in the producer
must be re-established out-of-band (compare with operator's journal).

### Reloads, key rotations, and policy edits

Each emits a leaf at the call site (RBAC reload handler, key rotation
flow, etc.). Inclusion proofs let an auditor answer "did this change
ever make it into the log?" without trusting the BoltDB events bucket.

---

## Failure modes and their meaning

| Failure                                         | Meaning                                                                                                  |
|-------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `503` from `/api/transparency/sth`              | Log initialized but no critical events have happened yet. Not alarming on fresh deployments.            |
| Inclusion proof reproduces wrong root           | The event the consumer holds has been tampered with OR the consumer's pinned STH is stale.              |
| Consistency proof fails (`ok=false`)            | The log was retroactively edited. **Alarming.** Compare boot-banner STH against journal records.        |
| STH signature invalid                           | STH signer key compromised or wrong key resolved. Check JWKS, rotate STH key, alert operations.         |
| `ErrCorruptedTree` at startup                   | BoltDB write was interrupted mid-append. Restore from backup; the STH history bucket allows partial reconstruction. |

---

## Threat-to-control matrix

| Threat                                     | Detection                                                                                              |
|--------------------------------------------|--------------------------------------------------------------------------------------------------------|
| Insider with BoltDB write access edits log | Consistency proof against pinned STH fails (history rewriting breaks the Merkle chain).               |
| Backdated entries inserted post-hoc        | Inclusion proof for the entry reproduces a root that doesn't match the STH at the entry's claimed time.|
| STH signer key compromise                  | Boot banner fingerprint mismatch; rotate STH key, invalidate STHs bearing the compromised kid.        |
| BoltDB corruption                          | Sprint 4 backup ADR + STH history bucket cross-check; restored backup's STH must match journal record. |

---

## See also

- [EVENT_SIGNING.md](EVENT_SIGNING.md) — per-event provenance this log builds on
- [OPERATIONS.md](OPERATIONS.md) — rotation runbooks
- [ADR-0063][adr] — design rationale, alternatives, trade-offs
- RFC 6962 — Certificate Transparency v1 (data structure inspiration)
- Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging", USENIX Security 2009
