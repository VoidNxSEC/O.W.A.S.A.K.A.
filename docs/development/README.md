# OWASAKA SIEM - Development Documentation

This directory contains development guides and documentation for contributors.

---

## Contents

- **[NIX_GUIDE.md](NIX_GUIDE.md)** - Complete guide for Nix Flakes development environment

---

## Development Workflow

### 1. Environment Setup

**Recommended: Nix Flakes**

```bash
nix develop
```

**Alternative: Manual**

```bash
make deps
```

### 2. Development Cycle

```bash
# Hot reload (auto-rebuild on file changes)
oswaka-dev watch  # or: air

# Manual build and run
oswaka-dev build
oswaka-dev run
```

### 3. Testing

```bash
# Run tests
oswaka-dev test

# With coverage
oswaka-dev test-coverage

# Benchmarks
oswaka-dev bench
```

### 4. Code Quality

```bash
# Format code
oswaka-dev fmt

# Lint
oswaka-dev lint

# All checks
oswaka-dev check
```

---

## Tools and Scripts

### oswaka-dev Command

Custom wrapper for common development tasks:

```bash
oswaka-dev help           # Show all commands
oswaka-dev build          # Build project
oswaka-dev run            # Build and run
oswaka-dev watch          # Hot reload mode
oswaka-dev test           # Run tests
oswaka-dev lint           # Run linters
oswaka-dev scan-network   # Network scan
oswaka-dev capture        # Packet capture
oswaka-dev dns-test       # DNS testing
oswaka-dev docs           # Serve docs
oswaka-dev clean          # Clean artifacts
oswaka-dev info           # Project info
```

### Make Targets

See `Makefile` for all targets:

```bash
make help
```

Common targets:

- `make build` - Build binary
- `make test` - Run tests
- `make lint` - Run linters
- `make clean` - Clean artifacts

---

## Network Analysis Tools

Available in Nix environment:

### Scanning

```bash
# Network discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -p 1-65535 192.168.1.1

# Service detection
nmap -sV -p 80,443 192.168.1.1
```

### Packet Capture

```bash
# Capture all traffic
sudo tcpdump -i any -w capture.pcap

# Capture specific port
sudo tcpdump -i any port 53 -w dns.pcap

# Analyze with tshark
tshark -r capture.pcap
```

### DNS Analysis

```bash
# Query DNS
dig @8.8.8.8 google.com

# Reverse lookup
dig -x 8.8.8.8

# DNS over HTTPS test
curl -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=google.com&type=A'
```

---

## IDE Configuration

### VSCode

Recommended extensions:

- Go (golang.go)
- Nix Environment Selector (arrterian.nix-env-selector)
- EditorConfig (editorconfig.editorconfig)

Settings (`.vscode/settings.json`):

```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.formatTool": "goimports",
  "nix.enableLanguageServer": true
}
```

### Neovim

With direnv:

```bash
echo "use flake" > .envrc
direnv allow
```

LSP configuration:

```lua
require('lspconfig').gopls.setup{}
require('lspconfig').nil_ls.setup{}  -- Nix LSP
```

---

## Debugging

### Delve (Go Debugger)

```bash
# Debug main package
dlv debug ./cmd/oswaka

# Debug tests
dlv test ./internal/network/dns

# Attach to running process
dlv attach <pid>
```

In Delve:

```
(dlv) break main.main
(dlv) continue
(dlv) print variable
(dlv) next
```

### VSCode Debugging

`.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug oswaka",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/oswaka",
      "args": ["--config", "configs/examples/default.yaml"]
    }
  ]
}
```

---

## Performance Profiling

### CPU Profiling

```bash
# Build with profiling
go build -o oswaka ./cmd/oswaka

# Run with CPU profile
./oswaka --cpuprofile=cpu.prof

# Analyze
go tool pprof cpu.prof
```

### Memory Profiling

```bash
# Run with memory profile
./oswaka --memprofile=mem.prof

# Analyze
go tool pprof mem.prof
```

### Live Profiling (pprof)

If debug.pprof is enabled in config:

```bash
# CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile

# Heap profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine
```

---

## Git Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Code refactoring
- `docs/description` - Documentation only
- `test/description` - Test improvements

### Commit Messages

Follow Conventional Commits:

```
feat: Add DNS resolver with query logging
fix: Resolve memory leak in packet capture
refactor: Simplify topology graph construction
docs: Update API documentation
test: Add integration tests for discovery engine
```

### Before Committing

```bash
# Format code
make fmt

# Run checks
make check

# Run tests
make test
```

---

## Continuous Integration

GitHub Actions workflow (`.github/workflows/ci.yml`):

```yaml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: cachix/install-nix-action@v22
      - run: nix develop --command make check
      - run: nix develop --command make test
```

---

## Resources

### O.W.A.S.A.K.A. Documentation

- [Architecture Overview](../architecture/OVERVIEW.md)
- [Data Model](../architecture/DATA_MODEL.md)
- [Development Phases](../architecture/DEVELOPMENT_PHASES.md)
- [API Documentation](../api/README.md)
- [Deployment Guide](../deployment/README.md)

### External Resources

- [Go Documentation](https://go.dev/doc/)
- [Nix Manual](https://nixos.org/manual/nix/stable/)
- [Air (Hot Reload)](https://github.com/cosmtrek/air)
- [golangci-lint](https://golangci-lint.run/)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-25
**Status**: Active Development - PHASE 0 Complete
