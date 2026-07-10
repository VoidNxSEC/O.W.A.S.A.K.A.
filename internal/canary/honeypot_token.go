package canary

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
)

// GenerateHoneypotToken mints a canary token for a honeypot micro-VM
// deployment. The slug is embedded in the VM reporter's webhook URL so
// every SSH/HTTP probe fires a CANARY event in the SIEM pipeline.
func GenerateHoneypotToken(repo *db.Repository, baseURL, webhookPath, label string) (*models.CanaryToken, error) {
	slug, err := randomSlug()
	if err != nil {
		return nil, err
	}
	webhookURL := strings.TrimRight(baseURL, "/") + "/" + strings.Trim(webhookPath, "/") + "/" + slug
	t := &models.CanaryToken{
		ID:        uuid.NewString(),
		Token:     slug,
		Type:      models.CanaryHoneypotVM,
		Label:     label,
		URL:       webhookURL,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveCanaryToken(t); err != nil {
		return nil, fmt.Errorf("canary: save honeypot token: %w", err)
	}
	return t, nil
}
