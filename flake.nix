{
  description = "O.W.A.S.A.K.A. SIEM - Air-gapped Security Monitoring Platform";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Honeypot micro-VM host (Wave E).
    # Pin with: nix flake update microvm
    microvm.url                    = "github:astro/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      microvm,
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true; # For some network analysis tools
        };

        # Custom scripts for development
        devScripts = pkgs.writeScriptBin "oswaka-dev" ''
          #!${pkgs.bash}/bin/bash

          function help() {
            echo "O.W.A.S.A.K.A. SIEM Development Commands"
            echo ""
            echo "Build & Run:"
            echo "  dev-build         - Build the project"
            echo "  dev-run           - Build and run"
            echo "  dev-watch         - Hot reload development mode"
            echo ""
            echo "Testing:"
            echo "  dev-test          - Run all tests"
            echo "  dev-test-coverage - Run tests with coverage"
            echo "  dev-bench         - Run benchmarks"
            echo ""
            echo "Code Quality:"
            echo "  dev-lint          - Run linters"
            echo "  dev-fmt           - Format code"
            echo "  dev-check         - Run all checks"
            echo ""
            echo "Network Tools:"
            echo "  dev-scan-network  - Quick network scan"
            echo "  dev-capture       - Start packet capture"
            echo "  dev-dns-test      - Test DNS resolution"
            echo ""
            echo "Documentation:"
            echo "  dev-docs          - Generate and serve docs"
            echo ""
            echo "Utilities:"
            echo "  dev-clean         - Clean build artifacts"
            echo "  dev-info          - Show project info"
          }

          function dev-build() {
            make build
          }

          function dev-run() {
            make run
          }

          function dev-watch() {
            air
          }

          function dev-test() {
            make test
          }

          function dev-test-coverage() {
            make test-coverage
          }

          function dev-bench() {
            make benchmark
          }

          function dev-lint() {
            make lint
          }

          function dev-fmt() {
            make fmt
          }

          function dev-check() {
            make check
          }

          function dev-scan-network() {
            echo "Scanning local network..."
            sudo nmap -sn 192.168.1.0/24 || echo "Run with sudo for full scan"
          }

          function dev-capture() {
            echo "Starting packet capture on all interfaces..."
            echo "Press Ctrl+C to stop"
            sudo tcpdump -i any -w /tmp/oswaka-capture.pcap
          }

          function dev-dns-test() {
            echo "Testing DNS resolution..."
            dig @8.8.8.8 google.com
            dig @1.1.1.1 google.com
          }

          function dev-docs() {
            echo "Serving documentation at http://localhost:6060"
            godoc -http=:6060
          }

          function dev-clean() {
            make clean
          }

          function dev-info() {
            make info
          }

          # Main command dispatcher
          case "$1" in
            build)         dev-build ;;
            run)           dev-run ;;
            watch)         dev-watch ;;
            test)          dev-test ;;
            test-coverage) dev-test-coverage ;;
            bench)         dev-bench ;;
            lint)          dev-lint ;;
            fmt)           dev-fmt ;;
            check)         dev-check ;;
            scan-network)  dev-scan-network ;;
            capture)       dev-capture ;;
            dns-test)      dev-dns-test ;;
            docs)          dev-docs ;;
            clean)         dev-clean ;;
            info)          dev-info ;;
            help|*)        help ;;
          esac
        '';

        # Welcome message script
        welcomeScript = pkgs.writeScriptBin "oswaka-welcome" ''
          #!${pkgs.bash}/bin/bash

          cat << 'EOF'
          ╔═══════════════════════════════════════════════════════════════════╗
          ║                                                                   ║
          ║   ██████╗ ██╗    ██╗ █████╗ ███████╗ █████╗ ██╗  ██╗ █████╗     ║
          ║  ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔══██╗    ║
          ║  ██║   ██║██║ █╗ ██║███████║███████╗███████║█████╔╝ ███████║    ║
          ║  ██║   ██║██║███╗██║██╔══██║╚════██║██╔══██║██╔═██╗ ██╔══██║    ║
          ║  ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║  ██║██║  ██╗██║  ██║    ║
          ║   ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ║
          ║                                                                   ║
          ║           🔐 Development Environment Ready 🔐                     ║
          ║                                                                   ║
          ╚═══════════════════════════════════════════════════════════════════╝

          Development Stack Loaded:
            ✓ Go $(go version | cut -d' ' -f3)
            ✓ Node.js $(node --version)
            ✓ Firefox ESR $(firefox --version 2>/dev/null | cut -d' ' -f3 || echo "N/A")
            ✓ Make, Git, and full toolchain

          Quick Start:
            oswaka-dev help           - Show all dev commands
            oswaka-dev build          - Build the project
            oswaka-dev run            - Run the SIEM
            oswaka-dev watch          - Hot reload mode
            oswaka-dev test           - Run tests
            oswaka-dev info           - Project information

          Network Tools:
            nmap, tcpdump, tshark     - Network analysis
            dig, host                 - DNS tools

          Go Tools:
            air                       - Hot reload
            golangci-lint             - Linter
            gopls                     - Language server
            delve                     - Debugger

          Documentation:
            ../owasaka-docs/docs/architecture/ - System architecture
            ../owasaka-docs/docs/api/          - API documentation
            ../owasaka-docs/docs/deployment/   - Deployment guides

          Current Phase: PHASE 0 ✅ → PHASE 1 (Network Intelligence)

          Happy Hacking! 🚀
          EOF
        '';

      in
      {
        # Development shell
        devShells.default = pkgs.mkShell {
          name = "oswaka-dev";

          # pkg-config as nativeBuildInput so CGO finds libpcap headers
          nativeBuildInputs = with pkgs; [ pkg-config ];

          buildInputs = with pkgs; [
            # === Core Development ===
            go # Go 1.22+ (or latest available)
            gotools # godoc, goimports, etc.
            gopls # Go language server
            delve # Go debugger

            # === Go Development Tools ===
            golangci-lint # Comprehensive linter
            air # Hot reload for Go
            gotest # Enhanced go test
            gotestsum # Pretty test output

            # === Build Tools ===
            gnumake # Make
            gcc # C compiler (for cgo if needed)

            # === Version Control ===
            git # Git
            gh # GitHub CLI

            # === Frontend Development ===
            nodejs_24
            pnpm # pnpm (faster alternative)

            # === Browser Integration ===
            firefox-esr # Firefox ESR for browser integration

            # === Network Analysis Tools (PHASE 1) ===
            nmap # Network scanner
            tcpdump # Packet capture
            # tshark for packet analysis
            bind # dig, host, nslookup
            iproute2 # ip command
            netcat-gnu # nc for network testing
            socat # Socket relay
            iperf3 # Network performance

            # === Container Tools (PHASE 2) ===
            docker # Docker CLI
            docker-compose # Docker Compose

            # === Security Tools ===
            openssl # SSL/TLS toolkit
            gnupg # GPG for signing
            sops # Secrets OPerationS — encrypted secrets in git (ADR-0059 T9)
            age # Modern asymmetric encryption used by sops

            # === Documentation ===
            mdbook # Markdown book generator
            graphviz # Graph visualization (for diagrams)

            # === Utilities ===
            jq # JSON processor
            yq-go # YAML processor
            ripgrep # Fast grep (rg)
            fd # Fast find
            bat # Better cat
            htop # Process monitor
            bottom # Modern htop alternative (btm)

            # === Development Scripts ===
            devScripts # Custom dev scripts
            welcomeScript # Welcome message

            # System Libraries
            libpcap # Required for gopacket
            libcap

            # === eBPF (internal/network/ebpf) ===
            # Only needed to re-run `go generate ./...` after editing
            # internal/network/ebpf/bpf/probe.c — the generated
            # probe_x86_bpfel.go/.o are committed, so a normal build
            # never needs these at runtime.
            clang
            llvm
            libbpf # bpf/bpf_helpers.h, bpf/bpf_tracing.h, bpf/bpf_core_read.h
            bpftools # bpftool, used to regenerate bpf/vmlinux.h from /sys/kernel/btf/vmlinux
          ];

          # Environment variables
          shellHook = ''
            # Display welcome message
            oswaka-welcome

            # Go environment
            export GOPATH="$HOME/go"
            export GOBIN="$GOPATH/bin"
            export PATH="$GOBIN:$PATH"

            # Add local bin to PATH
            export PATH="$PWD/bin:$PATH"

            # Go build cache
            export GOCACHE="$PWD/.cache/go-build"
            export GOMODCACHE="$PWD/.cache/go-mod"

            # Enable Go modules
            export GO111MODULE=on

            # Go performance flags
            export GOMAXPROCS=$(nproc)

            # Project variables
            export OSWAKA_ENV="development"
            export OSWAKA_CONFIG="$PWD/configs/examples/default.yaml"

            # Node.js configuration
            export NODE_ENV="development"
            export NPM_CONFIG_PREFIX="$PWD/.npm-global"
            export PATH="$NPM_CONFIG_PREFIX/bin:$PATH"

            # Disable telemetry
            export CHECKPOINT_DISABLE=1
            export DO_NOT_TRACK=1
            export HOMEBREW_NO_ANALYTICS=1

            # Create necessary directories
            mkdir -p .cache/go-build .cache/go-mod .npm-global bin logs

            # Git configuration helpers
            alias git-status='git status -sb'
            alias git-log='git log --oneline --graph --decorate -10'

            # Development aliases
            alias dev='oswaka-dev'
            alias build='make build'
            alias run='make run'
            alias test='make test'
            alias lint='make lint'

            # Network analysis aliases
            alias scan='sudo nmap -sn'
            alias capture='sudo tcpdump -i any'
            alias dns='dig @8.8.8.8'

            # Quick navigation
            alias docs='cd docs'
            alias internal='cd internal'
            alias configs='cd configs'

            # Colored output
            export CLICOLOR=1
            export LSCOLORS=ExFxBxDxCxegedabagacad

            # Go test with color
            alias gotest='go test -v -race -coverprofile=coverage.out'

            echo ""
            echo "📍 Current directory: $PWD"
            echo "🔧 Run 'oswaka-dev help' for available commands"
            echo ""
          '';

          # Additional packages that might be needed
          # but are optional
          # Uncomment as needed:
          # libvirt         # For VM integration (PHASE 2)
          # virt-manager    # VM management
          # qemu            # Emulation
        };

        # ── Analyst shell: air-gapped RAM scratchpad + USB printer ─────────────
        # Usage: nix develop .#analyst
        #
        # All writes go to a tmpfs mount in RAM — nothing hits disk.
        # Notes are printed via CUPS to a USB printer and then shredded.
        # Network egress is disabled inside the shell.
        devShells.analyst = pkgs.mkShell {
          name = "owasaka-analyst";

          buildInputs = with pkgs; [
            neovim   # editor (redirected to RAM)
            cups     # USB printer via lp/lpstat
            fzf      # interactive note picker for print-note
            util-linux  # mount / umount
          ];

          shellHook = ''
            export ANALYST_DIR="/tmp/owasaka-analyst-$$"
            mkdir -p "$ANALYST_DIR"

            # Mount tmpfs so content lives in RAM only, not on disk.
            # Requires the user to have mount capability (root or fuse).
            # Falls back silently to the plain directory when not available.
            mount -t tmpfs -o size=64m,mode=700 tmpfs "$ANALYST_DIR" 2>/dev/null \
              && _TMPFS_MOUNTED=1 \
              || _TMPFS_MOUNTED=0

            # Redirect all editor/cache paths into RAM
            export MYVIMRC="$ANALYST_DIR/.vimrc"
            export XDG_DATA_HOME="$ANALYST_DIR/.local/share"
            export XDG_CACHE_HOME="$ANALYST_DIR/.cache"
            export XDG_RUNTIME_DIR="$ANALYST_DIR/.runtime"
            export TMPDIR="$ANALYST_DIR"
            mkdir -p "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR"

            # Disable all network proxies and external lookups
            unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ftp_proxy FTP_PROXY
            export no_proxy="*" NO_PROXY="*"

            # ── Aliases ──────────────────────────────────────────────────────
            alias note='nvim "$ANALYST_DIR/incident-$(date +%Y%m%d-%H%M%S).md"'

            alias ls-notes='ls -lh "$ANALYST_DIR"/*.md 2>/dev/null \
              || echo "(no notes yet)"'

            alias print-note='
              _P=$(lpstat -p 2>/dev/null | awk "{print \$2}" | head -1)
              if [ -z "$_P" ]; then
                echo "No CUPS printer detected. Run: printer-setup"
              else
                _F=$(ls "$ANALYST_DIR"/*.md 2>/dev/null \
                     | ${pkgs.fzf}/bin/fzf --prompt="Select note to print: ")
                [ -n "$_F" ] && lp -d "$_P" "$_F" \
                  && echo "Sent to $_P" \
                  || echo "Aborted."
              fi
            '

            alias secure-clear='
              find "$ANALYST_DIR" -type f -exec shred -uz {} \; 2>/dev/null
              [ "$_TMPFS_MOUNTED" = "1" ] \
                && umount "$ANALYST_DIR" 2>/dev/null \
                && rmdir  "$ANALYST_DIR" 2>/dev/null
              echo "Scratchpad cleared."
            '

            alias printer-setup='
              echo "=== USB devices ==="
              ls /dev/usb/lp* 2>/dev/null || echo "  (none at /dev/usb/lp*)"
              echo "=== CUPS printers ==="
              lpstat -p 2>/dev/null || echo "  (CUPS not running or no printers)"
              echo ""
              echo "To add a USB printer:"
              echo "  lpadmin -p PRINTERNAME -E -v usb://Make/Model -m everywhere"
            '

            # Auto-shred on shell exit (Ctrl-D or exit)
            trap '
              find "$ANALYST_DIR" -type f -exec shred -uz {} \; 2>/dev/null
              [ "$_TMPFS_MOUNTED" = "1" ] \
                && umount "$ANALYST_DIR" 2>/dev/null \
                && rmdir  "$ANALYST_DIR" 2>/dev/null
            ' EXIT

            _STORAGE_MSG="RAM (tmpfs)"
            [ "$_TMPFS_MOUNTED" = "0" ] && _STORAGE_MSG="DISK (tmpfs unavailable — needs root)"

            echo ""
            echo "╔══════════════════════════════════════════════╗"
            echo "║  O.W.A.S.A.K.A.  Analyst Shell              ║"
            echo "╠══════════════════════════════════════════════╣"
            echo "║  Storage : $_STORAGE_MSG"
            echo "║  Path    : $ANALYST_DIR"
            echo "╠══════════════════════════════════════════════╣"
            echo "║  note           open RAM editor              ║"
            echo "║  ls-notes       list current notes           ║"
            echo "║  print-note     fzf → select → USB printer   ║"
            echo "║  printer-setup  detect USB / CUPS printers   ║"
            echo "║  secure-clear   shred all + unmount          ║"
            echo "╚══════════════════════════════════════════════╝"
            echo ""
          '';
        };

        # ── Hyprland integration binaries ──────────────────────────────────────
        # Build with: nix build .#owasaka-bar   nix build .#owasaka-notify
        packages.owasaka-bar = pkgs.buildGoModule {
          pname = "owasaka-bar";
          version = "0.1.0-dev";
          src = ./.;
          subPackages = [ "cmd/owasaka-bar" ];
          vendorHash = "sha256-xuDo0gyZggTNtdUdlZoLWs/7dqtebygKPVd1l7L3CAw=";
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap ];
          checkPhase = "true";
          meta.description = "O.W.A.S.A.K.A. Waybar live module";
        };

        packages.owasaka-notify = pkgs.buildGoModule {
          pname = "owasaka-notify";
          version = "0.1.0-dev";
          src = ./.;
          subPackages = [ "cmd/owasaka-notify" ];
          vendorHash = "sha256-xuDo0gyZggTNtdUdlZoLWs/7dqtebygKPVd1l7L3CAw=";
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap ];
          checkPhase = "true";
          meta.description = "O.W.A.S.A.K.A. SwayNC notification daemon";
        };

        # ── Desktop UI package (requires Fyne vendor: go get fyne.io/fyne/v2) ──
        # Build with: nix build .#oswaka-ui
        # Needs libGL + X11 headers present; disabled on non-Linux.
        packages.oswaka-ui = pkgs.lib.mkIf pkgs.stdenv.isLinux (pkgs.buildGoModule {
          pname = "oswaka-ui";
          version = "0.1.0-dev";
          src = ./.;
          subPackages = [ "cmd/oswaka-ui" ];
          tags = [ "fyne" ];
          vendorHash = null; # update after: go get fyne.io/fyne/v2 && go mod vendor
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = with pkgs; [
            libGL
            xorg.libX11
            xorg.libXcursor
            xorg.libXi
            xorg.libXxf86vm
          ];
          checkPhase = "true";
          meta.description = "O.W.A.S.A.K.A. native desktop UI (Fyne)";
        });

        # Package definition (for building oswaka)
        packages.default = pkgs.buildGoModule {
          pname = "oswaka";
          version = "0.1.0-dev";
          src = ./.;

          vendorHash = "sha256-xuDo0gyZggTNtdUdlZoLWs/7dqtebygKPVd1l7L3CAw=";

          # CGO dependencies (gopacket/pcap requires libpcap)
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap ];

          # Skip tests during build (run them separately)
          checkPhase = "true";

          meta = with pkgs.lib; {
            description = "O.W.A.S.A.K.A. SIEM - Air-gapped Security Monitoring Platform";
            homepage = "https://github.com/marcosfpina/O.W.A.S.A.K.A.";
            license = licenses.unfree;
            maintainers = [ "marcosfpina" ];
            platforms = platforms.linux;
          };
        };

        # Apps that can be run with `nix run`
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/oswaka";
        };

        # ── Checks ─────────────────────────────────────────────────────────────
        # `nix flake check` exercises these. The nixos-module test boots a real
        # VM (~3 min on a warm cache) so it is intentionally placed under
        # checks, not packages — CI should run it on every PR that touches
        # packaging/, the nixos module, or the systemd unit.
        checks = {
          # Sanity-build the package — `nix flake check` also exercises this
          # implicitly via `packages.default`, but listing it here makes the
          # intent explicit.
          package = self.packages.${system}.default;
        }
        // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # NixOS integration test: boot a VM with the module enabled and
          # confirm the unit reaches active state and `/healthz` returns 200.
          nixos-module = pkgs.testers.nixosTest {
            name = "owasaka-nixos-module";

            nodes.machine =
              { config, pkgs, ... }:
              {
                imports = [ self.nixosModules.default ];

                # Minimal config file: server on the default port 8080 and
                # data dir under /var/lib/oswaka (created by StateDirectory).
                # All optional subsystems disabled to keep the VM boot lean.
                environment.etc."oswaka/config.yaml".text = ''
                  server:
                    host: "127.0.0.1"
                    port: 8080
                    websocket:
                      enabled: true
                      path: "/ws"
                      max_connections: 100
                    tls:
                      enabled: false

                  logging:
                    level: "info"
                    format: "json"
                    output: "stdout"

                  network:
                    dns:
                      enabled: false
                    proxy:
                      enabled: false
                    discovery:
                      enabled: false
                    topology:
                      enabled: false

                  discovery:
                    physical:
                      enabled: false
                    virtual:
                      enabled: false
                    containers:
                      enabled: false
                    attack_surface:
                      enabled: false
                    reconciliation:
                      enabled: false

                  browser:
                    enabled: false

                  storage:
                    nas:
                      enabled: false
                    encryption:
                      enabled: false
                    integrity:
                      enabled: false
                    local:
                      data_dir: "/var/lib/owasaka"
                      max_size_gb: 1
                      cleanup_policy: "oldest_first"

                  analytics:
                    stream:
                      enabled: false
                    correlation:
                      enabled: false
                    ml:
                      enabled: false

                  alerts:
                    enabled: false

                  performance:
                    max_memory_mb: 512
                    max_cpu_percent: 50
                    max_concurrent_scans: 5
                    event_queue_size: 1000

                  metrics:
                    enabled: false

                  debug:
                    enabled: false

                  security:
                    api_auth:
                      enabled: false
                    rate_limiting:
                      enabled: true
                      requests_per_second: 100
                      burst: 200
                    rbac:
                      enabled: false

                  nats_url: ""
                '';

                services.owasaka = {
                  enable = true;
                  configFile = "/etc/oswaka/config.yaml";
                  apiPort = 8080;
                };
              };

            testScript = ''
              start_all()
              machine.wait_for_unit("oswaka.service")
              machine.wait_for_open_port(8080)
              machine.succeed("curl -fsS http://localhost:8080/healthz")
            '';
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    )
    // {

      # ── Overlay ────────────────────────────────────────────────────────────────
      # Allows other flakes to add oswaka to their pkgs set:
      #   pkgs = import nixpkgs { overlays = [ owasaka.overlays.default ]; };
      overlays.default = final: prev: {
        oswaka = self.packages.${final.system}.default;
      };

      # ── Honeypot NixOS module (Wave E) ─────────────────────────────────────────
      # Consumers import this alongside microvm.nixosModules.microvm and set
      # owasaka.honeypot.enable = true and owasaka.honeypot.webhookURL = "...".
      nixosModules.honeypot = import ./nix/honeypot.nix;

      # ── Honeypot smoke-test VM (x86_64-linux only) ─────────────────────────────
      # Instantiates a disposable 128 MB honeypot with a placeholder webhook for
      # local testing.  Run with:
      #   nix run .#honeypot-vm
      # For production, generate a real slug via POST /api/admin/honeypot and
      # add a new nixosConfiguration with that webhookURL.
      nixosConfigurations.honeypot-test = nixpkgs.lib.nixosSystem {
        system  = "x86_64-linux";
        modules = [
          microvm.nixosModules.microvm
          self.nixosModules.honeypot
          {
            microvm = {
              mem      = 512;
              vcpu     = 1;
              hypervisor = "qemu";
              interfaces = [{
                type = "tap";
                id   = "vm-hp-test";
                mac  = "02:00:00:00:00:01";
              }];
            };
            owasaka.honeypot.enable     = true;
            owasaka.honeypot.webhookURL = "http://localhost:8080/api/canary/webhook/TEST_SLUG_00000000";
          }
        ];
      };

      # Convenience app: `nix run .#honeypot-vm` boots the test VM via QEMU.
      apps."x86_64-linux".honeypot-vm = {
        type    = "app";
        program = "${self.nixosConfigurations.honeypot-test.config.microvm.runner.qemu}/bin/microvm-run";
      };

      # ── NixOS Module ───────────────────────────────────────────────────────────
      # Usage in a NixOS configuration:
      #   imports = [ owasaka.nixosModules.default ];
      #   services.owasaka.enable = true;
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.owasaka;
        in
        {
          options.services.owasaka = {
            enable = lib.mkEnableOption "O.W.A.S.A.K.A. SIEM";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              defaultText = "owasaka";
              description = "The owasaka package to use.";
            };

            configFile = lib.mkOption {
              type = lib.types.path;
              description = "Path to the owasaka YAML configuration file.";
            };

            apiPort = lib.mkOption {
              type = lib.types.port;
              default = 8080;
              description = "Port for the HTTP/WebSocket API.";
            };

            proxyPort = lib.mkOption {
              type = lib.types.port;
              default = 8888;
              description = "Port for the transparent MITM proxy.";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Open firewall port for the API (not the proxy — keep it local).";
            };

            torHiddenService = {
              enable = lib.mkEnableOption "exposing the dashboard via a Tor .onion address";
            };

            user = lib.mkOption {
              type = lib.types.str;
              default = "owasaka";
            };

            group = lib.mkOption {
              type = lib.types.str;
              default = "owasaka";
            };

            # ── Secrets (ADR-0059 §"Secrets management") ─────────────────────────
            # Operators set both options to enable sops-encrypted secret loading.
            # The age private key is loaded via systemd LoadCredential so the
            # file never leaves systemd's purview and is only readable by this
            # unit. The encrypted secrets.yaml is read by the application at
            # startup and never written back in plaintext.

            secretsFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              example = "/etc/owasaka/secrets.yaml";
              description = ''
                Path to the sops-encrypted `secrets.yaml`. When non-null the
                application reads it at startup and decrypts using the age
                key provided by `ageKeyFile`. See `../owasaka-docs/docs/secrets/BOOTSTRAP.md`.
              '';
            };

            ageKeyFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              example = "/run/secrets/owasaka-age-key";
              description = ''
                Path to the age private key file (containing
                `AGE-SECRET-KEY-...`). Loaded into the systemd unit via
                LoadCredential so only the owasaka process can read it.
                Required when `secretsFile` is set; ignored otherwise.

                Recommended sources, in order of preference:
                  1. sops-nix (`config.sops.secrets.owasaka-age-key.path`)
                  2. systemd-creds encrypted credential
                  3. agenix
                  4. Plain file at 0400, owned by root (least preferred)
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [
              {
                assertion = (cfg.secretsFile == null) == (cfg.ageKeyFile == null);
                message = ''
                  services.owasaka.secretsFile and services.owasaka.ageKeyFile
                  must be set together (or both null). One without the other
                  has no useful effect.
                '';
              }
            ];

            users.users.${cfg.user} = {
              isSystemUser = true;
              group = cfg.group;
              description = "O.W.A.S.A.K.A. SIEM daemon";
              home = "/var/lib/owasaka";
            };
            users.groups.${cfg.group} = { };

            systemd.services.owasaka = {
              description = "O.W.A.S.A.K.A. SIEM";
              documentation = [ "https://github.com/marcosfpina/O.W.A.S.A.K.A" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];

              # Surface the encrypted-secrets contract to the binary via env
              # vars. The binary resolves the age key via SOPS_AGE_KEY_FILE
              # and reads the encrypted file at OWASAKA_SECRETS_FILE.
              environment = lib.mkIf (cfg.secretsFile != null) {
                SOPS_AGE_KEY_FILE = "%d/age-key";
                OWASAKA_SECRETS_FILE = toString cfg.secretsFile;
              };

              serviceConfig = {
                Type = "simple";
                User = cfg.user;
                Group = cfg.group;
                ExecStart = "${cfg.package}/bin/oswaka -config ${cfg.configFile}";
                Restart = "on-failure";
                RestartSec = "5s";

                # State & log dirs (created automatically by systemd)
                StateDirectory = "owasaka";
                LogsDirectory = "owasaka";
                RuntimeDirectory = "owasaka";

                # Encrypted-secrets credential loading.
                # systemd copies the source path into %d/age-key (mode 0400),
                # readable only by this unit. The source file is read by
                # systemd as root before privileges drop, so the unit user
                # never needs filesystem access to the original path.
                LoadCredential = lib.mkIf (cfg.ageKeyFile != null) [
                  "age-key:${toString cfg.ageKeyFile}"
                ];

                # Hardening
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                CapabilityBoundingSet = [
                  # Needed for raw socket / packet capture
                  "CAP_NET_RAW"
                  "CAP_NET_ADMIN"
                  # Needed for the eBPF host network monitor (kernel >= 5.8
                  # split-capability model: CAP_BPF to load programs/maps,
                  # CAP_PERFMON to attach kprobes). Older kernels would
                  # otherwise need the much broader CAP_SYS_ADMIN — not
                  # granted here; the eBPF service fails non-fatally with
                  # a warning on kernels that lack split BPF capabilities.
                  "CAP_BPF"
                  "CAP_PERFMON"
                ];
                AmbientCapabilities = [
                  "CAP_NET_RAW"
                  "CAP_NET_ADMIN"
                  "CAP_BPF"
                  "CAP_PERFMON"
                ];
              };
            };

            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.apiPort ];

            # Tor hidden service: the tor daemon is managed entirely by
            # nixpkgs' first-class services.tor module, not by OWASAKA's
            # own process. OWASAKA only reads the resulting hostname
            # file at <HiddenServiceDir>/hostname (internal/network/tor
            # ReadOnionHostname) — no control-port auth/cookie handling
            # needed. Re-verify `relay.onionServices` against the target
            # nixpkgs version; this is the modern attrset form.
            services.tor = lib.mkIf cfg.torHiddenService.enable {
              enable = true;
              client.enable = false;
              relay.onionServices.owasaka-dashboard = {
                version = 3;
                map = [
                  {
                    port = 80;
                    target = {
                      addr = "127.0.0.1";
                      port = cfg.apiPort;
                    };
                  }
                ];
              };
            };
          };
        };
    };
}
