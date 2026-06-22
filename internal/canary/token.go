package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
)

// randomSlug returns a short hex token used as the public, grep-friendly
// identifier embedded in canary subdomains/URLs (mirrors the random-byte
// pattern used by internal/identity.NewAPIKey).
func randomSlug() (string, error) {
	b := make([]byte, 8) // 64 bits, plenty for a non-guessable decoy slug
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("canary: read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateDNSToken mints a unique canary subdomain under zone (which
// must contain ".canary." for configs/rules/dns_canary_trigger.yaml to
// match it) and persists it.
func GenerateDNSToken(repo *db.Repository, zone, label string) (*models.CanaryToken, error) {
	slug, err := randomSlug()
	if err != nil {
		return nil, err
	}
	t := &models.CanaryToken{
		ID:        uuid.NewString(),
		Token:     slug,
		Type:      models.CanaryDNS,
		Label:     label,
		Subdomain: slug + "." + zone,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveCanaryToken(t); err != nil {
		return nil, fmt.Errorf("canary: save token: %w", err)
	}
	return t, nil
}
