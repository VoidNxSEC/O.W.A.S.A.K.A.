package tor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadOnionHostname reads the .onion address Tor wrote to
// <dataDir>/hostname when it created the hidden service. This avoids
// any control-port authentication dance — Tor writes this file once
// the service is published and keeps it in sync across restarts.
// dataDir must match the tor daemon's HiddenServiceDir (managed
// externally, e.g. via NixOS services.tor — see flake.nix).
func ReadOnionHostname(dataDir string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("tor: hidden service data dir not configured")
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "hostname"))
	if err != nil {
		return "", fmt.Errorf("tor: read onion hostname: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
