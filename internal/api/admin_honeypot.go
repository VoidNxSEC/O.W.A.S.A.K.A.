package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/canary"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// HoneypotAdminHandler mints honeypot VM canary tokens and returns a
// ready-to-use NixOS configuration snippet for wiring the reporter.
type HoneypotAdminHandler struct {
	Repo   *db.Repository
	Cfg    *config.CanaryConfig
	Logger *logging.Logger
}

type honeypotResponse struct {
	Slug            string `json:"slug"`
	WebhookURL      string `json:"webhook_url"`
	VMConfigSnippet string `json:"vm_config_snippet"`
}

// CreateHoneypot handles POST /api/admin/honeypot.
func (h *HoneypotAdminHandler) CreateHoneypot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req createCanaryRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	t, err := canary.GenerateHoneypotToken(h.Repo, h.Cfg.WebhookBaseURL, h.Cfg.WebhookPath, req.Label)
	if err != nil {
		h.Logger.Errorw("Failed to generate honeypot token", "error", err)
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	resp := honeypotResponse{
		Slug:            t.Token,
		WebhookURL:      t.URL,
		VMConfigSnippet: honeypotVMSnippet(t.URL, t.Token),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// honeypotVMSnippet returns a NixOS flake snippet that wires the
// honeypot reporter to this specific canary webhook URL.
func honeypotVMSnippet(webhookURL, slug string) string {
	return fmt.Sprintf(`# Add to your NixOS flake and run: nix run .#honeypot-%s
nixosConfigurations."honeypot-%s" = nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    microvm.nixosModules.microvm
    owasaka.nixosModules.honeypot
    {
      owasaka.honeypot.enable = true;
      owasaka.honeypot.webhookURL = "%s";
    }
  ];
};
# Runner (add to apps):
# apps."x86_64-linux"."honeypot-%s" = {
#   type = "app";
#   program = "${nixosConfigurations."honeypot-%s".config.microvm.runner.qemu}/bin/microvm-run";
# };`, slug[:8], slug[:8], webhookURL, slug[:8], slug[:8])
}
