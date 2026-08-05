# Architecture

## System Purpose

O.W.A.S.A.K.A. is an air-gapped, zero-trust Security Information and Event Management (SIEM)
system designed to run on dedicated hardware with no dependency on external services. It
performs its own network observation — down to an eBPF kernel probe — its own DNS resolution,
its own asset discovery, and stores everything on NAS-backed encrypted storage.

The design constraint that shapes everything else: it must work with no internet connection,
at install time and at run time. Dependencies are vendored deliberately for this reason.

## High-Level Overview

```
┌───────────────────────────────────────────────────────────┐
│ network/          eBPF probe (kernel), transparent proxy, │
│                   DNS resolver                            │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌───────────────────────────────────────────────────────────┐
│ discovery/  asset discovery      events/  event pipeline  │
│ analytics/  detection + analysis metrics/ instrumentation │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌───────────────────────────────────────────────────────────┐
│ identity/ + authz/   zero-trust identity and authorization│
│ reliability/         degradation and recovery             │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌───────────────────────────────────────────────────────────┐
│ storage/   NAS-backed encrypted persistence               │
└──────────────────────────┬────────────────────────────────┘
                           ▼
        api/  ──▶  web/ + frontend/  ──▶  cmd/ binaries
```

## Components

Go, with `internal/` holding the implementation:

| Package | Files | Responsibility |
|---|---|---|
| `internal/storage/` | 42 | Encrypted, NAS-backed persistence |
| `internal/analytics/` | 34 | Detection logic and analysis |
| `internal/identity/` | 28 | Zero-trust identity |
| `internal/network/` | 25 | eBPF probe, transparent proxy, DNS resolver |
| `internal/authz/` | 12 | Authorization |
| `internal/discovery/` | 11 | Asset discovery |
| `internal/api/` | 11 | API surface |
| `internal/events/` | 8 | Event pipeline |
| `internal/browser/` | 6 | Browser automation (CDP) |
| `internal/reliability/` | 5 | Graceful degradation |
| `internal/models/` | 5 | Domain types |
| `internal/metrics/` | 5 | Instrumentation |

Binaries under `cmd/`: `oswaka`, `oswaka-ui`, `owasaka-bar`, `owasaka-notify`.
Interfaces: `web/` (backend-served) and `frontend/`.

### eBPF probe

`internal/network/ebpf/bpf/probe.c` is a kernel-space eBPF program for network observation.
It ships alongside `vmlinux.h`, the generated kernel BTF type header — that file is machine
output, not authored code, and should not be read as such.

## Data Flow

1. The eBPF probe observes network activity in kernel space.
2. The transparent proxy and DNS resolver capture application-level traffic and name
   resolution.
3. `discovery/` builds and maintains the asset inventory.
4. `events/` normalises observations into a pipeline.
5. `analytics/` applies detection logic.
6. `storage/` persists to encrypted NAS-backed storage.
7. `api/` serves `web/` and `frontend/`; `owasaka-notify` raises alerts.

## Trust Boundaries

| Boundary | Control |
|---|---|
| Network → probe | kernel-space eBPF; observation only |
| Client → API | zero-trust identity (`identity/`) plus `authz/` |
| Service → storage | encryption at rest on NAS-backed volumes |
| System → internet | **none by design** — air-gapped operation |

## Runtime Model

Go, multi-binary. The eBPF probe runs in kernel space and requires elevated privileges to
load. Dedicated-hardware deployment is the intended model, not shared hosting.

## Configuration

`configs/`, plus `deploy/` for deployment assets. Secrets managed with SOPS (`.sops.yaml`).

## Storage

NAS-backed encrypted storage. `internal/storage/` is the largest package in the codebase (42
files), reflecting that retention and integrity are core concerns rather than an afterthought.

## External Integrations

None required at runtime — that is the point. Optional integration with the wider platform
happens through the event mesh when the deployment is not fully isolated.

## Security Model

- Air-gapped by design; no outbound dependency.
- Zero-trust identity and authorization on every request.
- Encryption at rest.
- **Dependencies vendored** (`vendor/`, ~1.18M lines of Go) so that builds are reproducible
  without network access. This is a deliberate architectural decision, not repository bloat.
- SOPS for secret management.
- Security posture 73/100.

## Testing Model

47 test files. `go test ./...`. The flake exposes `checks` and `overlays`.

## Operational Notes

- Container restart policy, metrics endpoint, tracing, graceful shutdown and health probes are
  present (operability 68/100).
- `Makefile` drives the common tasks; `pnpm-workspace.yaml` covers the frontends.
- Runs from `deploy/docker-compose.master.yml`.

## Known Architectural Risks

1. **Zero release tags against 36,569 lines of authored Go.** Release discipline scores 0/100.
   This is the largest untagged asset in the ecosystem — there is no version anyone can
   reference, pin or roll back to.
2. **No `SECURITY.md` or threat model** for a security product. The tool does not currently
   meet the documentation bar it exists to enforce on others.
3. **No operational runbook**, which matters more here than elsewhere: an air-gapped system
   cannot be debugged by pulling a container image.
4. **No HTTP endpoints detected by static analysis** despite an `internal/api/` package —
   routing is likely constructed dynamically, which also means it is not statically auditable.
5. **Architecture depth scores 18/100.** Twelve packages, no recorded module contracts, no ADRs.
6. **eBPF probe requires privileged load** and there is no documented fallback for
   environments where that is unavailable.
7. **Two separate frontends** (`web/` and `frontend/`) with no recorded rationale for the split.
