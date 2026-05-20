# Deploying OWASAKA on NixOS

This guide deploys the OWASAKA SIEM via the flake's `nixosModules.default`.
Covers: enabling the service, wiring sops-encrypted secrets through
systemd credentials, and verifying the running unit.

For first-time secret bootstrap see [docs/secrets/BOOTSTRAP.md](../secrets/BOOTSTRAP.md).
For the design rationale see [ADR-0059][adr] §"Secrets management".

[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md

---

## Minimal configuration (no secrets)

Suitable for development hosts and air-gapped first-boot.

```nix
{ inputs, ... }:
{
  imports = [ inputs.owasaka.nixosModules.default ];

  services.owasaka = {
    enable     = true;
    configFile = ./owasaka.yaml;
  };
}
```

`systemctl status owasaka` should show the unit running, capabilities
`CAP_NET_RAW` and `CAP_NET_ADMIN` granted, state under
`/var/lib/owasaka`, logs in `/var/log/owasaka`.

---

## Recommended configuration (with sops-encrypted secrets)

The age private key never lives in the Nix store. It is materialized at
boot by [sops-nix][sops-nix], [agenix][agenix], or
`systemd-creds`, then handed to the OWASAKA unit via systemd
`LoadCredential`.

[sops-nix]: https://github.com/Mic92/sops-nix
[agenix]: https://github.com/ryantm/agenix

### With sops-nix (recommended)

```nix
{ inputs, config, ... }:
{
  imports = [
    inputs.owasaka.nixosModules.default
    inputs.sops-nix.nixosModules.sops
  ];

  # sops-nix decrypts ~/.sops-nix.yaml managed material at boot.
  sops.defaultSopsFile = ./secrets/host.yaml;
  sops.age.keyFile     = "/var/lib/sops-nix/key.txt";

  sops.secrets."owasaka/age-key" = {
    mode  = "0400";
    owner = config.users.users.owasaka.name;
  };

  services.owasaka = {
    enable      = true;
    configFile  = ./owasaka.yaml;
    secretsFile = ./secrets/owasaka-secrets.yaml; # sops-encrypted, in git
    ageKeyFile  = config.sops.secrets."owasaka/age-key".path;
  };
}
```

What this produces at runtime:

- `LoadCredential = "age-key:/run/secrets/owasaka/age-key"` copies the
  decrypted age key into `$CREDENTIALS_DIRECTORY/age-key` (mode 0400,
  readable only by the unit's user).
- `SOPS_AGE_KEY_FILE=%d/age-key` is exported into the unit environment.
- `OWASAKA_SECRETS_FILE=<path>` points the application at the encrypted
  secrets file.

> **State of the contract (Sprint 1):** the NixOS module establishes the
> env-var contract and credential loading. The Go-side consumer that
> reads `OWASAKA_SECRETS_FILE` and decrypts via sops lands when the
> first runtime-secret consumer needs it (e.g., NATS authentication in
> Sprint 8, or OIDC client secret in T11). Until then, the binary
> ignores both env vars without error and operators can deploy with the
> `secretsFile`/`ageKeyFile` options left null.

When the consumer lands, the application opens the encrypted secrets
file at startup and decrypts using the loaded age key. The plaintext
never touches the filesystem — `LoadCredential` keeps it as a
file-descriptor scoped to the unit.

### With agenix

```nix
{ inputs, config, ... }:
{
  imports = [
    inputs.owasaka.nixosModules.default
    inputs.agenix.nixosModules.default
  ];

  age.secrets.owasaka-age = {
    file  = ./secrets/owasaka-age.age;
    mode  = "0400";
    owner = "owasaka";
  };

  services.owasaka = {
    enable      = true;
    configFile  = ./owasaka.yaml;
    secretsFile = ./secrets/owasaka-secrets.yaml;
    ageKeyFile  = config.age.secrets.owasaka-age.path;
  };
}
```

### With systemd-creds (no third-party module)

```nix
# /etc/credstore.encrypted/owasaka-age contains the encrypted age key,
# produced with `systemd-creds encrypt --pretty <key>`.
services.owasaka = {
  enable      = true;
  configFile  = ./owasaka.yaml;
  secretsFile = "/etc/owasaka/secrets.yaml";
  ageKeyFile  = "/etc/credstore.encrypted/owasaka-age";
};
```

systemd decrypts the credential transparently before exposing it under
`$CREDENTIALS_DIRECTORY`.

---

## Verifying the deployment

```bash
systemctl status owasaka
journalctl -u owasaka --since "5 min ago"

# Confirm the credential made it in but cannot be read outside the unit:
sudo systemd-creds list --unit owasaka
sudo cat $(systemctl show owasaka -p RuntimeDirectory --value)/...  # should fail

# Confirm env wiring inside the unit:
sudo systemctl show owasaka -p Environment | grep -E 'SOPS|OWASAKA'
```

Expected env (when secrets are wired):

```
Environment=SOPS_AGE_KEY_FILE=%d/age-key OWASAKA_SECRETS_FILE=/etc/owasaka/secrets.yaml
```

---

## Threat model recap (per ADR-0059)

| Threat                     | What the module does                                                    |
| -------------------------- | ----------------------------------------------------------------------- |
| Age key on disk            | `LoadCredential` keeps it under systemd's purview, mode 0400, unit-only |
| Privilege escalation       | `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`  |
| Lateral movement via creds | Credential dir is per-unit; other units cannot read                     |
| Supply-chain dep stealing  | Capabilities boundary set to `CAP_NET_RAW` + `CAP_NET_ADMIN` only       |
| Insider with shell access  | Combined with sops-encrypted at-rest secrets; rotation per WORKFLOW.md  |

---

## Removing the legacy Wazuh stack

The legacy `docker-compose.yml` is retained only for cutover. Once
historical events have been migrated:

```bash
make docker-down
rm docker-compose.yml custom-rules wazuh-manager.sh
```

(Removal lands as part of Sprint 4 data-layer hardening.)
