package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// APIKeyCredential authenticates an Agent (CLI, CI runner, automation)
// via a long-lived bearer token. The plaintext value is shown to the
// operator exactly once at issuance; only a bcrypt hash is persisted.
//
// Keys are formatted as `oswk_<keyID>_<secret>`:
//   - `oswk_` makes leaked keys grep-friendly in logs and secret scanners.
//   - `<keyID>` is the public, short id used to look up the credential.
//   - `<secret>` is 32 random bytes base64-url-encoded.
type APIKeyCredential struct {
	principalID string
	keyID       string // short public id ("subject" for store indexing)
	hash        []byte // bcrypt hash of the secret part
	label       string // operator-supplied label for identification
}

// APIKeyPrefix is the human-recognizable prefix of every OWASAKA key.
const APIKeyPrefix = "oswk_"

// NewAPIKey mints a fresh API key for a principal. Returns the
// credential (safe to persist) and the plaintext value (to display
// exactly once to the operator).
func NewAPIKey(principalID, label string) (*APIKeyCredential, string, error) {
	if principalID == "" {
		return nil, "", errors.New("identity: principal id required")
	}

	keyIDBytes := make([]byte, 8) // 64 bits of public id
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, "", fmt.Errorf("identity: read random: %w", err)
	}
	secretBytes := make([]byte, 32) // 256 bits of secret
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, "", fmt.Errorf("identity: read random: %w", err)
	}

	keyID := hex.EncodeToString(keyIDBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcryptCost)
	if err != nil {
		return nil, "", fmt.Errorf("identity: bcrypt: %w", err)
	}

	plaintext := APIKeyPrefix + keyID + "_" + secret
	cred := &APIKeyCredential{
		principalID: principalID,
		keyID:       keyID,
		hash:        hash,
		label:       label,
	}
	return cred, plaintext, nil
}

// LoadAPIKey reconstructs an APIKeyCredential from persisted material.
func LoadAPIKey(principalID, keyID string, hash []byte, label string) *APIKeyCredential {
	return &APIKeyCredential{
		principalID: principalID,
		keyID:       keyID,
		hash:        hash,
		label:       label,
	}
}

// ParseAPIKey splits a presented key into its public id and secret. Used
// by the authenticator to look up the right credential before bcrypt
// comparison.
func ParseAPIKey(presented string) (keyID, secret string, err error) {
	if !strings.HasPrefix(presented, APIKeyPrefix) {
		return "", "", ErrCredentialInvalid
	}
	body := presented[len(APIKeyPrefix):]
	parts := strings.SplitN(body, "_", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", ErrCredentialInvalid
	}
	return parts[0], parts[1], nil
}

// Kind implements Credential.
func (c *APIKeyCredential) Kind() CredentialKind { return CredentialAPIKey }

// PrincipalID implements Credential.
func (c *APIKeyCredential) PrincipalID() string { return c.principalID }

// Subject returns the key's public id — what the store indexes against.
func (c *APIKeyCredential) Subject() string { return c.keyID }

// Label returns the operator-friendly label assigned at issuance.
func (c *APIKeyCredential) Label() string { return c.label }

// Verify checks the presented secret against the stored bcrypt hash.
//
// The caller is expected to have already split the presented key into
// keyID + secret via ParseAPIKey, looked up the matching credential, and
// passed only the secret in Proof.
func (c *APIKeyCredential) Verify(_ context.Context, factor AuthFactor) error {
	if factor.Kind != CredentialAPIKey {
		return ErrUnsupportedFactor
	}
	if err := bcrypt.CompareHashAndPassword(c.hash, factor.Proof); err != nil {
		return ErrCredentialInvalid
	}
	return nil
}
