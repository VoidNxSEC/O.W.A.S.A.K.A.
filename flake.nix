{
  description = "O.W.A.S.A.K.A. SIEM - Air-gapped Security Monitoring Platform";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
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
            docs/architecture/        - System architecture
            docs/api/                 - API documentation
            docs/deployment/          - Deployment guides

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

        # Package definition (for building oswaka)
        packages.default = pkgs.buildGoModule {
          pname = "oswaka";
          version = "0.1.0-dev";
          src = ./.;

          vendorHash = "sha256-WVWZxhWBXmt3kZGljQKdXBf2RdMfL0lXMtja3S3CUWw=";

          # CGO dependencies (gopacket/pcap requires libpcap)
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.libpcap ];

          # Skip tests during build (run them separately)
          checkPhase = "true";

          meta = with pkgs.lib; {
            description = "O.W.A.S.A.K.A. SIEM - Air-gapped Security Monitoring Platform";
            homepage = "https://github.com/marcosfpina/O.W.A.S.A.K.A";
            license = licenses.proprietary;
            maintainers = [ "marcosfpina" ];
            platforms = platforms.linux;
          };
        };

        # Apps that can be run with `nix run`
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/oswaka";
        };
      }
    )
    // {

      # ── Overlay ────────────────────────────────────────────────────────────────
      # Allows other flakes to add oswaka to their pkgs set:
      #   pkgs = import nixpkgs { overlays = [ owasaka.overlays.default ]; };
      overlays.default = final: prev: {
        oswaka = self.packages.${final.system}.default;
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

            user = lib.mkOption {
              type = lib.types.str;
              default = "owasaka";
            };

            group = lib.mkOption {
              type = lib.types.str;
              default = "owasaka";
            };
          };

          config = lib.mkIf cfg.enable {
            users.users.${cfg.user} = {
              isSystemUser = true;
              group = cfg.group;
              description = "O.W.A.S.A.K.A. SIEM daemon";
              home = "/var/lib/owasaka";
            };
            users.groups.${cfg.group} = { };

            systemd.services.owasaka = {
              description = "O.W.A.S.A.K.A. SIEM";
              documentation = [ "https://github.com/VoidNxSEC/O.W.A.S.A.K.A" ];
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];

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
                ];
                AmbientCapabilities = [
                  "CAP_NET_RAW"
                  "CAP_NET_ADMIN"
                ];
              };
            };

            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.apiPort ];
          };
        };
    };
}
