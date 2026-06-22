package db

import (
	"encoding/json"
	"fmt"

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
