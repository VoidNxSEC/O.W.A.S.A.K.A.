# O.W.A.S.A.K.A. systemd unit

This directory ships a production-grade systemd unit for installing
`oswaka` on non-NixOS distributions (Debian, Ubuntu, RHEL/Rocky/Alma,
Arch, openSUSE). NixOS users should consume `nixosModules.default` from
the flake instead — see the project root `flake.nix`.

## Installation

### 1. Place the binary

Either install the package from your distribution's repo (when
available), or copy a release build:

```bash
sudo install -m 0755 ./bin/oswaka /usr/bin/oswaka
```

### 2. Create the `oswaka` system user and group

```bash
sudo groupadd --system oswaka
sudo useradd  --system --gid oswaka \
              --home-dir /var/lib/oswaka \
              --shell /usr/sbin/nologin \
              oswaka
```

`StateDirectory=oswaka` and `LogsDirectory=oswaka` in the unit cause
systemd to create `/var/lib/oswaka` and `/var/log/oswaka` automatically
on first start, chowned to `oswaka:oswaka`.

### 3. Drop the configuration in place

```bash
sudo install -d -m 0755 -o root -g root /etc/oswaka
sudo install -m 0644 configs/examples/default.yaml /etc/oswaka/config.yaml
```

Tune the file for your deployment. The most common knobs:

| Key                          | Default                       |
|------------------------------|-------------------------------|
| `server.port`                | `8080`                        |
| `storage.local.data_dir`     | set to `/var/lib/oswaka`      |
| `logging.file_path`          | `/var/log/oswaka/oswaka.log`  |

### 4. Provision the age key (required for sops-encrypted secrets)

The unit ships with `LoadCredential=age-key:/etc/oswaka/age.key`. systemd
reads the file as root **before** dropping privileges and exposes it
inside the unit at `%d/age-key` (mode 0400, readable only by the
service). Place the key as root and lock it down:

```bash
sudo install -m 0400 -o root -g root /path/to/age.key /etc/oswaka/age.key
```

If you are not using sops-encrypted secrets yet, you may either:

* drop a placeholder key (the binary tolerates a missing
  `OWASAKA_SECRETS_FILE`), or
* remove the `LoadCredential=` and `Environment=SOPS_AGE_KEY_FILE=`
  lines from the unit before enabling it.

See `docs/secrets/BOOTSTRAP.md` for the full bootstrap procedure.

### 5. Install and enable the unit

```bash
sudo install -m 0644 packaging/systemd/oswaka.service \
                     /etc/systemd/system/oswaka.service
sudo systemctl daemon-reload
sudo systemctl enable --now oswaka.service
```

## Verifying

```bash
systemctl status oswaka.service
journalctl -u oswaka.service -f
curl -fsS http://localhost:8080/healthz   # liveness
curl -fsS http://localhost:8080/readyz    # readiness (all subsystems ok)
curl -fsS http://localhost:8080/startupz  # startup probe
```

The three health endpoints follow the Kubernetes liveness/readiness/
startup-probe convention. Use `/startupz` until the operator marks the
service ready, then switch over to `/readyz`.

## Hardening notes

The unit applies aggressive hardening out of the box:

* `ProtectSystem=strict` — the entire filesystem is read-only except
  `/var/lib/oswaka`, `/var/log/oswaka`, and `/tmp` (via `PrivateTmp`).
* `NoNewPrivileges`, `LockPersonality`, `MemoryDenyWriteExecute` —
  standard kill-chain mitigations.
* `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM`
  — block exotic syscalls; surface failures as `EPERM` rather than
  killing the process.
* `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` — only the two caps
  the packet-capture pipeline genuinely needs.

If you add a hypervisor scanner or anything else that needs broader
permissions, edit `CapabilityBoundingSet` and `AmbientCapabilities`
*together* — they intentionally match.

## Type=simple vs Type=notify

`oswaka` does not currently emit `sd_notify(READY=1)` at end-of-startup,
so the unit uses `Type=simple`. The HTTP `/startupz` endpoint plays the
role of "I am up" for external orchestrators. If the Go binary ever
gains sdnotify support, switch `Type=` to `notify` and add
`NotifyAccess=main`.
