# OWASAKA SIEM - Nix Development Guide

## Overview

This project uses Nix Flakes for reproducible development environments. The `flake.nix` provides all necessary tools, dependencies, and scripts for O.W.A.S.A.K.A. development.

---

## Prerequisites

### Install Nix with Flakes

```bash
# Install Nix (multi-user installation recommended)
sh <(curl -L https://nixos.org/nix/install) --daemon

# Enable flakes (add to ~/.config/nix/nix.conf or /etc/nix/nix.conf)
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

---

## Quick Start

### Enter Development Shell

```bash
# From project root
nix develop

# Or for a pure environment (no system PATH pollution)
nix develop --pure

# First run might take a while (downloads all dependencies)
```

You'll see the O.W.A.S.A.K.A. welcome banner and a fully configured development environment!

---

## Development Environment

### Included Tools

#### Core Development

- **Go 1.22+** - Latest stable Go compiler
- **gotools** - godoc, goimports, etc.
- **gopls** - Go language server (LSP)
- **delve** - Go debugger

#### Go Development Tools

- **golangci-lint** - Comprehensive Go linter
- **air** - Hot reload for Go applications
- **gotest** - Enhanced testing
- **gotestsum** - Pretty test output

#### Build Tools

- **Make** - Build automation
- **GCC** - C compiler (for cgo)
- **pkg-config** - Package configuration

#### Frontend Development

- **Node.js 20 LTS** - JavaScript runtime
- **npm** - Package manager
- **pnpm** - Fast package manager alternative

#### Browser Integration

- **Firefox ESR** - For browser integration testing

#### Network Analysis (PHASE 1)

- **nmap** - Network scanner
- **tcpdump** - Packet capture
- **tshark** - Terminal Wireshark
- **dig, host, nslookup** - DNS tools
- **ip** - Network configuration
- **netcat** - Network debugging
- **socat** - Socket relay
- **iperf3** - Network performance testing

#### Container Tools (PHASE 2)

- **Docker** - Container runtime
- **docker-compose** - Multi-container orchestration

#### Security Tools

- **OpenSSL** - SSL/TLS toolkit
- **GnuPG** - Cryptographic signing

#### Documentation

- **mdbook** - Markdown documentation generator
- **graphviz** - Graph/diagram generation

#### Utilities

- **jq** - JSON processor
- **yq** - YAML processor
- **ripgrep (rg)** - Fast text search
- **fd** - Fast file finder
- **bat** - Enhanced cat with syntax highlighting
- **htop** - Process monitor
- **bottom (btm)** - Modern resource monitor

---

## Custom Development Commands

The development environment provides `oswaka-dev` wrapper for common tasks:

### Build & Run

```bash
oswaka-dev build          # Build the project
oswaka-dev run            # Build and run
oswaka-dev watch          # Hot reload development mode
```

### Testing

```bash
oswaka-dev test           # Run all tests
oswaka-dev test-coverage  # Tests with coverage report
oswaka-dev bench          # Run benchmarks
```

### Code Quality

```bash
oswaka-dev lint           # Run linters
oswaka-dev fmt            # Format code
oswaka-dev check          # Run all checks
```

### Network Tools

```bash
oswaka-dev scan-network   # Quick network scan
oswaka-dev capture        # Start packet capture
oswaka-dev dns-test       # Test DNS resolution
```

### Documentation

```bash
oswaka-dev docs           # Serve documentation
```

### Utilities

```bash
oswaka-dev clean          # Clean build artifacts
oswaka-dev info           # Show project info
oswaka-dev help           # Show all commands
```

---

## Aliases

The development shell provides convenient aliases:

### Build Aliases

```bash
dev           # oswaka-dev wrapper
build         # make build
run           # make run
test          # make test
lint          # make lint
```

### Network Analysis

```bash
scan          # sudo nmap -sn (network scan)
capture       # sudo tcpdump -i any (packet capture)
dns           # dig @8.8.8.8 (DNS query)
```

### Navigation

```bash
docs          # cd docs
internal      # cd internal
configs       # cd configs
```

### Git Helpers

```bash
git-status    # git status -sb (short format)
git-log       # git log --oneline --graph -10
```

### Testing

```bash
gotest        # go test -v -race -coverprofile=coverage.out
```

---

## Environment Variables

The development shell sets up:

### Go Configuration

```bash
GOPATH="$HOME/go"
GOBIN="$GOPATH/bin"
GOCACHE="$PWD/.cache/go-build"
GOMODCACHE="$PWD/.cache/go-mod"
GO111MODULE=on
GOMAXPROCS=$(nproc)
```

### Project Configuration

```bash
OSWAKA_ENV="development"
OSWAKA_CONFIG="$PWD/configs/examples/default.yaml"
```

### Node.js Configuration

```bash
NODE_ENV="development"
NPM_CONFIG_PREFIX="$PWD/.npm-global"
```

### Privacy (Telemetry Disabled)

```bash
CHECKPOINT_DISABLE=1
DO_NOT_TRACK=1
HOMEBREW_NO_ANALYTICS=1
```

---

## Hot Reload with Air

Air is pre-configured for automatic rebuilds on file changes:

```bash
# Start hot reload
oswaka-dev watch

# Or directly
air

# Configuration in .air.toml
```

**Watched files:**

- `*.go` (except tests)
- `*.yaml`, `*.yml`
- `*.html`, `*.tpl`, `*.tmpl`

**Excluded:**

- `*_test.go`
- `tmp/`, `vendor/`, `.git/`, `.cache/`
- `web/node_modules/`

---

## Building with Nix

### Build the Package

```bash
# Build oswaka using Nix
nix build

# Result in ./result/bin/oswaka
./result/bin/oswaka --version
```

### Run Directly

```bash
# Run without building
nix run

# With arguments
nix run . -- --config configs/examples/default.yaml
```

---

## IDE Integration

### VSCode / VSCodium

Install the Nix Environment Selector extension:

```bash
code --install-extension arrterian.nix-env-selector
```

Add to `.vscode/settings.json`:

```json
{
  "nix.enableLanguageServer": true,
  "nix.serverPath": "nil",
  "go.toolsManagement.autoUpdate": true,
  "go.useLanguageServer": true,
  "go.alternateTools": {
    "gopls": "gopls"
  }
}
```

### Neovim

With `direnv` integration:

```bash
# Install direnv
nix-env -iA nixpkgs.direnv

# Create .envrc
echo "use flake" > .envrc
direnv allow
```

### Emacs

Install `nix-mode` and `direnv-mode`:

```elisp
(use-package nix-mode
  :mode "\\.nix\\'")

(use-package direnv
  :config
  (direnv-mode))
```

---

## Troubleshooting

### Flake is Too Old

```bash
# Update flake inputs
nix flake update

# Re-enter shell
exit
nix develop
```

### Missing Permissions for Network Tools

Some tools require elevated privileges:

```bash
# For nmap, tcpdump, etc.
sudo -E oswaka-dev scan-network
sudo -E oswaka-dev capture
```

### Go Module Issues

```bash
# Clean Go cache
rm -rf .cache/go-build .cache/go-mod

# Re-download modules
go mod download
go mod tidy
```

### Shell Hook Not Running

```bash
# Force reload
nix develop --command bash
```

---

## Advanced Usage

### Customize the Environment

Fork `flake.nix` and modify `buildInputs`:

```nix
buildInputs = with pkgs; [
  # Add your custom tools here
  my-custom-tool
];
```

### Add More Scripts

Extend `devScripts` in `flake.nix`:

```nix
devScripts = pkgs.writeScriptBin "oswaka-dev" ''
  #!${pkgs.bash}/bin/bash

  function my-new-command() {
    echo "Custom command"
  }

  # Add to case statement
  case "$1" in
    my-command) my-new-command ;;
    # ...
  esac
'';
```

### Override Go Version

```nix
buildInputs = with pkgs; [
  go_1_23  # Use Go 1.23 instead
  # ...
];
```

---

## Pinning Specific Versions

The flake uses `nixos-unstable` for latest packages. To pin specific versions:

```nix
inputs = {
  nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";  # Pin to 23.11
  # ...
};
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: cachix/install-nix-action@v22
        with:
          extra_nix_config: |
            experimental-features = nix-command flakes
      - run: nix build
      - run: nix develop --command make test
```

---

## Clean Up

### Exit Development Shell

```bash
exit
```

### Garbage Collect Nix Store

```bash
# Remove unused packages
nix-collect-garbage

# Aggressive cleanup (remove old generations)
nix-collect-garbage -d
```

---

## Resources

- [Nix Manual](https://nixos.org/manual/nix/stable/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [Go Development with Nix](https://nixos.wiki/wiki/Go)
- [Air (Hot Reload)](https://github.com/cosmtrek/air)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-25
**Status**: Production Ready
