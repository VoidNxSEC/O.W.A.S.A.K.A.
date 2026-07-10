package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/models"
	bolt "go.etcd.io/bbolt"
)

// Repository manages structural interaction with BoltDB schema
type Repository struct {
	db *Database
}

// NewRepository creates a new DAO
func NewRepository(db *Database) *Repository {
	return &Repository{db: db}
}

// SaveAsset upserts network/physical assets by string ID
func (r *Repository) SaveAsset(a *models.Asset) error {
	return r.db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAssets))
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put([]byte(a.ID), data)
	})
}

// GetAsset reads a single asset resolving it off json
func (r *Repository) GetAsset(id string) (*models.Asset, error) {
	var a models.Asset
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAssets))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("asset not found")
		}
		return json.Unmarshal(data, &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListAssets returns all stored assets.
func (r *Repository) ListAssets() ([]models.Asset, error) {
	var assets []models.Asset
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAssets))
		return b.ForEach(func(k, v []byte) error {
			var a models.Asset
			if err := json.Unmarshal(v, &a); err != nil {
				return nil // skip corrupt entries
			}
			assets = append(assets, a)
			return nil
		})
	})
	return assets, err
}

// GetEvent reads a single persisted event by ID.
func (r *Repository) GetEvent(id string) (*models.NetworkEvent, error) {
	var e models.NetworkEvent
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketEvents))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("event not found")
		}
		return json.Unmarshal(data, &e)
	})
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// LogEvent streams a forensic event to BoltDB mapping an ID to structure
func (r *Repository) LogEvent(e *models.NetworkEvent) error {
	return r.db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketEvents))
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put([]byte(e.ID), data)
	})
}

// SaveCanaryToken upserts a planted DNS/HTTP decoy token by ID.
func (r *Repository) SaveCanaryToken(t *models.CanaryToken) error {
	return r.db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketCanaryTokens))
		data, err := json.Marshal(t)
		if err != nil {
			return err
		}
		return b.Put([]byte(t.ID), data)
	})
}

// GetCanaryToken reads a single canary token by ID.
func (r *Repository) GetCanaryToken(id string) (*models.CanaryToken, error) {
	var t models.CanaryToken
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketCanaryTokens))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("canary token not found")
		}
		return json.Unmarshal(data, &t)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListCanaryTokens returns all stored canary tokens.
func (r *Repository) ListCanaryTokens() ([]models.CanaryToken, error) {
	var tokens []models.CanaryToken
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketCanaryTokens))
		return b.ForEach(func(k, v []byte) error {
			var t models.CanaryToken
			if err := json.Unmarshal(v, &t); err != nil {
				return nil // skip corrupt entries
			}
			tokens = append(tokens, t)
			return nil
		})
	})
	return tokens, err
}

// ── Alert lifecycle ───────────────────────────────────────────────────────────

// SaveAlert upserts an alert into BucketAlerts keyed by its ID.
func (r *Repository) SaveAlert(a *models.Alert) error {
	return r.db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAlerts))
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put([]byte(a.ID), data)
	})
}

// GetAlert reads a single alert by ID.
func (r *Repository) GetAlert(id string) (*models.Alert, error) {
	var a models.Alert
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAlerts))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("alert not found")
		}
		return json.Unmarshal(data, &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpdateAlert patches status and/or note on an existing alert.
// UpdatedAt is always refreshed. Returns the updated alert.
func (r *Repository) UpdateAlert(id string, status models.AlertStatus, note string) (*models.Alert, error) {
	var updated models.Alert
	err := r.db.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAlerts))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("alert not found")
		}
		if err := json.Unmarshal(data, &updated); err != nil {
			return err
		}
		if status != "" {
			updated.Status = status
		}
		if note != "" {
			updated.Note = note
		}
		updated.UpdatedAt = time.Now()
		out, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), out)
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// AlertFilter constrains a ListAlerts scan.
type AlertFilter struct {
	Status   models.AlertStatus // empty = all
	Severity string             // empty = all
	Limit    int                // 0 = default 50
}

// ListAlerts scans BucketAlerts with optional filters. Results are
// newest-first (reverse BoltDB key order).
func (r *Repository) ListAlerts(f AlertFilter) ([]models.Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	var alerts []models.Alert
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketAlerts))
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if len(alerts) >= f.Limit {
				break
			}
			var a models.Alert
			if err := json.Unmarshal(v, &a); err != nil {
				continue
			}
			if f.Status != "" && a.Status != f.Status {
				continue
			}
			if f.Severity != "" && !strings.EqualFold(a.Severity, f.Severity) {
				continue
			}
			alerts = append(alerts, a)
		}
		return nil
	})
	return alerts, err
}

// ListEventsByType scans BucketEvents returning up to limit events
// that match the given type and were recorded at or after `since`.
// Pass zero time to skip the time filter. Results newest-first.
func (r *Repository) ListEventsByType(eventType string, since time.Time, limit int) ([]models.NetworkEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []models.NetworkEvent
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketEvents))
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			if len(out) >= limit {
				break
			}
			var e models.NetworkEvent
			if err := json.Unmarshal(v, &e); err != nil {
				continue
			}
			if eventType != "" && string(e.Type) != eventType {
				continue
			}
			if !since.IsZero() && e.Timestamp.Before(since) {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// FindCanaryTokenByToken looks up a canary token by its public slug
// (used by the HTTP webhook handler, which only knows the slug).
func (r *Repository) FindCanaryTokenByToken(token string) (*models.CanaryToken, error) {
	var found *models.CanaryToken
	err := r.db.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketCanaryTokens))
		return b.ForEach(func(k, v []byte) error {
			var t models.CanaryToken
			if err := json.Unmarshal(v, &t); err != nil {
				return nil
			}
			if t.Token == token {
				found = &t
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("canary token not found")
	}
	return found, nil
}
