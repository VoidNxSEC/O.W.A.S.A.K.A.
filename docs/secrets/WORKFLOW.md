# Secrets Workflow — Day-to-day reference

Quick reference card for working with sops-encrypted secrets. Assumes
the operator has already completed [BOOTSTRAP.md](BOOTSTRAP.md).

---

## Adding a new secret

1. **Add the shape** to `secrets.example.yaml`. Keep it in version
   control so other operators know the schema.
2. **Edit the live file**: `sops secrets.yaml` and add the same key with
   a real value.
3. **Commit both** in one PR — template and encrypted file move together.

## Adding a new consumer

When new Go code needs a secret:

1. Read the secret at startup via the sops library, never at request
   time. The decrypted value lives in memory only.
2. Surface it through `pkg/config` so tests can inject without sops.
3. Add the secret name to `secrets.example.yaml` so operators know it
   exists.

## Rotating a secret

```bash
sops secrets.yaml               # change the value
# ... commit, push, redeploy the consumers that read it ...
```

The previous value remains in git history (encrypted). If the rotation
was forced by suspected compromise, **also** revoke any derived material
(JWTs signed by an Ed25519 key derived from the secret, etc.) — see
`docs/auth/OPERATIONS.md` for revocation procedures.

## Rotating a recipient (operator leaves)

```bash
# Remove their age recipient from .sops.yaml, commit.
sops updatekeys secrets.yaml
# Commit the re-encrypted secrets.yaml.
```

This re-encrypts the *current* contents under the new recipient set. It
does NOT revoke past access — anything they decrypted while authorized
is theirs.

## Onboarding a new operator

1. New operator generates their age keypair (see BOOTSTRAP.md §1).
2. They share **only the public recipient** (`age1...`) with the team.
3. An existing operator adds the recipient to `.sops.yaml` and runs
   `sops updatekeys secrets.yaml`.
4. New operator pulls and can now decrypt.

## Anti-patterns

- **Don't** `sops -d secrets.yaml > secrets.dec.yaml` and leave the
  decrypted file around. Use process substitution: `<(sops -d ...)`.
- **Don't** edit the encrypted blob directly. Use `sops <file>`.
- **Don't** echo a decrypted secret. Pipe into the consumer:
  `sops -d secrets.yaml | yq '.nats.password' | container exec ...`
- **Don't** commit `.env` files alongside `secrets.yaml` — single source
  of truth. `.env` is gitignored and stays per-machine.

## CI / non-interactive use

For automation, set `SOPS_AGE_KEY_FILE` to point at the private key:

```bash
export SOPS_AGE_KEY_FILE=/secrets/age-ci.txt
sops -d secrets.yaml | feed-into-tool
```

In NixOS, the systemd unit uses `LoadCredentialEncrypted` so the file
never leaves systemd's purview.
