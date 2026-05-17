#!/usr/bin/env bash
# OWASAKA — sops/age bootstrap helper.
#
# First-time setup of the encrypted secrets workflow for a new operator
# or a new machine. Generates an age keypair, registers the public key
# (recipient) in `.sops.yaml`, and produces an encrypted `secrets.yaml`
# from the template if none exists yet.
#
# Re-running is safe: existing keys and encrypted secrets are not touched.
#
# See ADR-0059 §"Secrets management" and docs/secrets/BOOTSTRAP.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOPS_CONFIG="${REPO_ROOT}/.sops.yaml"
SECRETS_FILE="${REPO_ROOT}/secrets.yaml"
TEMPLATE="${REPO_ROOT}/secrets.example.yaml"

AGE_KEY_DIR="${SOPS_AGE_KEY_DIR:-${HOME}/.config/sops/age}"
AGE_KEY_FILE="${AGE_KEY_DIR}/keys.txt"

red()  { printf '\033[0;31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[0;33m%s\033[0m\n' "$*"; }
cyan() { printf '\033[0;36m%s\033[0m\n' "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || {
    red "Missing dependency: $1"
    echo "Enter the Nix devShell: nix develop"
    exit 1
  }
}

require sops
require age
require age-keygen

cyan "==> Bootstrapping OWASAKA secrets workflow"

# 1. age keypair
if [[ -f "${AGE_KEY_FILE}" ]]; then
  ylw "age keypair already exists at ${AGE_KEY_FILE}; keeping it"
else
  mkdir -p "${AGE_KEY_DIR}"
  chmod 700 "${AGE_KEY_DIR}"
  age-keygen -o "${AGE_KEY_FILE}" 2>/dev/null
  chmod 600 "${AGE_KEY_FILE}"
  grn "Generated age keypair at ${AGE_KEY_FILE}"
fi

RECIPIENT="$(age-keygen -y "${AGE_KEY_FILE}")"
cyan "==> Your age public recipient:"
echo "    ${RECIPIENT}"

# 2. .sops.yaml recipient registration
if grep -Fq "${RECIPIENT}" "${SOPS_CONFIG}"; then
  ylw ".sops.yaml already lists this recipient"
else
  cat <<EOF

$(red 'ACTION REQUIRED:') Add this recipient to .sops.yaml under the
relevant creation_rule. Example:

  creation_rules:
    - path_regex: ^secrets\.yaml\$
      age: >-
        ${RECIPIENT}

If you already have other recipients, comma-separate them.
EOF
fi

# 3. secrets.yaml encryption
if [[ -f "${SECRETS_FILE}" ]]; then
  ylw "secrets.yaml already exists; not overwriting"
else
  if [[ ! -f "${TEMPLATE}" ]]; then
    red "Template missing: ${TEMPLATE}"
    exit 1
  fi
  cp "${TEMPLATE}" "${SECRETS_FILE}"
  echo ""
  cyan "==> secrets.yaml created from template; edit it now (sops will"
  cyan "    auto-encrypt on save):"
  echo "      sops ${SECRETS_FILE}"
  echo ""
  echo "Run again once .sops.yaml has your recipient AND sops has"
  echo "encrypted the file."
fi

echo ""
grn "Bootstrap complete."
echo ""
echo "Day-to-day usage:"
echo "  sops secrets.yaml                  # edit (auto-encrypts on save)"
echo "  sops -d secrets.yaml               # one-off decrypt to stdout"
echo "  sops updatekeys secrets.yaml       # re-key when recipients change"
echo ""
echo "Runtime decryption is handled by the application or NixOS module;"
echo "operators do not normally decrypt the file at the CLI."
