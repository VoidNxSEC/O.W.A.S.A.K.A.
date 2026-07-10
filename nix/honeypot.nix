# OWASAKA Honeypot micro-VM — NixOS module.
#
# Requires microvm.nix (github:astro/microvm.nix) to be imported
# alongside this module in the caller's nixosConfiguration:
#
#   modules = [
#     microvm.nixosModules.microvm   # from microvm.nix input
#     owasaka.nixosModules.honeypot  # this file
#     {
#       owasaka.honeypot.enable = true;
#       owasaka.honeypot.webhookURL = "<URL from POST /api/admin/honeypot>";
#     }
#   ];
#
# The VM is 512 MB RAM, 1 vCPU, with SSH :22 and HTTP :80 as decoys.
# Every inbound probe is forwarded to the OWASAKA canary webhook, which
# fires a CANARY event → TemporalCorrelator → CANARY_THEN_SCAN kill chain
# → CRITICAL alert if a port scan follows within 15 minutes.
{ config, lib, pkgs, ... }:
let
  cfg = config.owasaka.honeypot;
in {
  options.owasaka.honeypot = {
    enable = lib.mkEnableOption "OWASAKA honeypot micro-VM decoy services";

    webhookURL = lib.mkOption {
      type    = lib.types.str;
      default = "";
      example = "https://siem.internal/api/canary/webhook/deadbeef01020304";
      description = ''
        OWASAKA canary webhook URL returned by POST /api/admin/honeypot.
        The reporter sends a JSON payload to this URL for every SSH or
        HTTP probe, triggering a CANARY event in the SIEM pipeline.
      '';
    };

    sshPort = lib.mkOption {
      type    = lib.types.port;
      default = 22;
      description = "SSH decoy listen port.";
    };

    httpPort = lib.mkOption {
      type    = lib.types.port;
      default = 80;
      description = "HTTP decoy listen port.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = cfg.webhookURL != "";
      message   = "owasaka.honeypot.webhookURL must be set (get it from POST /api/admin/honeypot).";
    }];

    # ── Network ─────────────────────────────────────────────────────────
    networking = {
      hostName       = "owasaka-honeypot";
      # Accept everything — every attempt is a signal.
      firewall.enable = false;
    };

    # ── SSH decoy ────────────────────────────────────────────────────────
    # Permit password auth so scanners advance further and generate richer
    # journal events before the connection is logged and closed.
    services.openssh = {
      enable = true;
      ports  = [ cfg.sshPort ];
      settings = {
        PermitRootLogin          = "yes";
        PasswordAuthentication   = true;
        MaxAuthTries             = 6;
        LoginGraceTime           = 30;
      };
    };
    # Intentionally weak — this is a decoy, not a real system.
    users.users.root.password = "honeypot";

    # ── HTTP decoy (nginx) ────────────────────────────────────────────────
    services.nginx = {
      enable = true;
      virtualHosts.honeypot = {
        listen = [{ addr = "0.0.0.0"; port = cfg.httpPort; }];
        locations."/" = {
          return      = "200 'OK'";
          extraConfig = ''
            add_header Content-Type text/plain;
            access_log /var/log/nginx/honeypot-access.log combined;
          '';
        };
      };
    };

    # ── Reporter: journal → OWASAKA canary webhook ────────────────────────
    #
    # Tails sshd + nginx journal entries in JSON format. For each line it
    # extracts the MESSAGE field and POSTs it to the webhook. curl is
    # fire-and-forget (-f -s -m 5 || true) so a dead SIEM never blocks
    # decoy service availability.
    systemd.services.honeypot-reporter = {
      description = "OWASAKA honeypot activity reporter";
      wantedBy    = [ "multi-user.target" ];
      after       = [ "network-online.target" "sshd.service" "nginx.service" ];
      wants       = [ "network-online.target" ];

      environment.WEBHOOK_URL = cfg.webhookURL;

      path = with pkgs; [ curl jq systemd coreutils ];

      script = ''
        journalctl -f -o json -u sshd -u nginx \
          | while IFS= read -r line; do
              msg=$(printf '%s' "$line" \
                    | jq -r '.MESSAGE // "unknown"' 2>/dev/null \
                    || echo "parse-error")
              src=$(printf '%s' "$line" \
                    | jq -r '._SYSTEMD_UNIT // "unknown"' 2>/dev/null \
                    || echo "unknown")
              payload=$(jq -cn \
                --arg source "honeypot-vm" \
                --arg unit   "$src" \
                --arg detail "$msg" \
                '{source:$source, unit:$unit, detail:$detail}')
              curl -sf -m 5 -X POST "$WEBHOOK_URL" \
                -H "Content-Type: application/json" \
                -d "$payload" \
              || true
            done
      '';

      serviceConfig = {
        Restart    = "always";
        RestartSec = "5s";
        # Minimal privileges — the reporter only needs network egress.
        NoNewPrivileges = true;
        PrivateTmp      = true;
        ProtectSystem   = "strict";
        StandardError   = "journal";
      };
    };

    system.stateVersion = "24.11";
  };
}
