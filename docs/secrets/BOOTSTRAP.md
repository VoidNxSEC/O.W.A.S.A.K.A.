# Secrets Bootstrap — sops + age

OWASAKA encrypts every plaintext secret out of git via [sops][sops] with
[age][age] recipients. This document walks an operator through the
first-time setup on a fresh machine.

See [ADR-0059][adr] §"Secrets management" for the design rationale and
threat model.

[sops]: https://github.com/getsops/sops
[age]: https://github.com/FiloSottile/age
[adr]: https://github.com/marcosfpina/adr-ledger/blob/main/adr/proposed/ADR-0059.md

## Quick path

```bash
nix develop                     # ensures sops + age are available
./scripts/bootstrap-secrets.sh
# Follow the printed instructions to register your age recipient,
# then edit secrets.yaml:
sops secrets.yaml
```

That's it for most operators. The rest of this document explains what
the script does and how to handle edge cases.

---

## Manual walkthrough

### 1. Generate an age keypair

Each operator and each service that needs to decrypt secrets gets its
own keypair. **Never share private keys.**

```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
chmod 600 ~/.config/sops/age/keys.txt
```

The file contains:
- Your private key (`AGE-SECRET-KEY-1...`) — keep secret.
- A comment line with the public recipient (`# public key: age1...`).

To print the recipient on demand:

```bash
age-keygen -y ~/.config/sops/age/keys.txt
```

### 2. Register the recipient in `.sops.yaml`

Open `.sops.yaml` at the repo root and add your `age1...` recipient to
the appropriate `creation_rules` entry. Multiple recipients are
comma-separated.

```yaml
creation_rules:
  - path_regex: ^secrets\.yaml$
    age: >-
      age1qy3rrjkxr5d3z2lz7eajrqkpdv2mhxq2hd6scnumgj97vp0p55sqp4lqsr,age1q9...
```

Commit the change. New encryptions will use all listed recipients.

If `secrets.yaml` already exists with different recipients, re-key it:

```bash
sops updatekeys secrets.yaml
```

### 3. Author `secrets.yaml`

Copy the template and fill in values:

```bash
cp secrets.example.yaml secrets.yaml
sops secrets.yaml               # opens $EDITOR; sops re-encrypts on save
```

Or encrypt an existing plaintext in place:

```bash
sops --encrypt --in-place secrets.yaml
```

Commit `secrets.yaml` — it is encrypted at rest, safe in git.

### 4. Verify

```bash
sops -d secrets.yaml | head -5  # should print the YAML content
```

---

## Multi-recipient pattern

For team operations, register **every** operator's recipient plus at
least one **breakglass** recipient stored offline (printed and locked).
If a primary operator's machine is lost, the breakglass recipient
recovers access.

```yaml
creation_rules:
  - path_regex: ^secrets\.yaml$
    age: >-
      age1alice...,age1bob...,age1charlie...,age1BREAKGLASS_OFFLINE...
```

Rotate recipients with `sops updatekeys secrets.yaml` after any team
change.

---

## Runtime decryption

The application binary decrypts at startup via the sops library — you
do **not** decrypt to a file on disk. The NixOS module wires the age
private key in via `LoadCredential` so the running process is the only
reader.

For ad-hoc CLI use (debugging, exporting to docker-compose):

```bash
sops -d secrets.yaml > secrets.dec.yaml   # NEVER commit
# ... use it ...
shred -u secrets.dec.yaml
```

`secrets.dec.yaml` and `secrets.dec.*.yaml` are explicitly gitignored.

---

## Threat model recap

Per ADR-0059 §"Threat model (defense surface)":

- **Supply chain**: age private key lives outside the build, loaded at
  runtime via systemd credential. Compromised dependencies cannot read it
  unless they also achieve process injection.
- **Insider**: every read of `secrets.yaml` is auditable via git history
  (the encrypted blob changes when re-encrypted). Combine with the
  transparency log (Sprint 3) for full attestation.
- **Network-adjacent**: secrets never leave the host in plaintext.
- **Credential theft**: rotate via `sops updatekeys` immediately on
  suspicion. Pull encrypted file again after rotation.

---

## Common operations

```bash
# Edit
sops secrets.yaml

# Rotate recipients (after `.sops.yaml` change)
sops updatekeys secrets.yaml

# Decrypt one-off
sops -d secrets.yaml

# Encrypt a new file from plaintext
sops --encrypt --in-place secrets.staging.yaml

# Verify which recipients can decrypt
sops --decrypt --extract '[]' secrets.yaml >/dev/null && echo OK
```
