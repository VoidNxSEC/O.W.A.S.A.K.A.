package canary

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/storage/db"
)

// GenerateHTTPToken mints a unique decoy URL (baseURL + webhookPath +
// "/" + slug) for planting in a user's own apps/websites, and persists
// it. The slug itself is the secret — anyone who POSTs it to the
// webhook is treated as having triggered the canary.
func GenerateHTTPToken(repo *db.Repository, baseURL, webhookPath, label string) (*models.CanaryToken, error) {
	slug, err := randomSlug()
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(baseURL, "/") + "/" + strings.Trim(webhookPath, "/") + "/" + slug
	t := &models.CanaryToken{
		ID:        uuid.NewString(),
		Token:     slug,
		Type:      models.CanaryHTTP,
		Label:     label,
		URL:       url,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.SaveCanaryToken(t); err != nil {
		return nil, fmt.Errorf("canary: save token: %w", err)
	}
	return t, nil
}
