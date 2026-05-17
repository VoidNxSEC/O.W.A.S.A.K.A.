package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// PasswordTOTPCredential combines a bcrypt-hashed password with a TOTP
// secret. Both factors are required to authenticate (see ADR-0059:
// "Password + TOTP (default)"). This is the default human credential.
//
// The TOTP secret is stored alongside the password hash on the same
// record. Stronger setups bind TOTP to a hardware key (WebAuthn) — see
// the WebAuthnCredential type for the opt-in upgrade path.
type PasswordTOTPCredential struct {
	principalID  string
	subject      string // username — what the user types at login
	passwordHash []byte // bcrypt-cost-12 hash
	totpSecret   string // base32-encoded shared secret
	issuer       string // TOTP issuer string (shown in authenticator apps)
}

// NewPasswordTOTPCredential creates a fresh credential. Plaintext
// password is hashed with bcrypt before storage; only the hash is kept.
//
// The TOTP secret is opaque to the caller; it should be enrolled by
// rendering the otpauth URL into a QR code for the user.
func NewPasswordTOTPCredential(principalID, subject, plaintextPassword, totpSecret, issuer string) (*PasswordTOTPCredential, error) {
	if principalID == "" || subject == "" {
		return nil, errors.New("identity: principal id and subject required")
	}
	if plaintextPassword == "" {
		return nil, errors.New("identity: password required")
	}
	if totpSecret == "" {
		return nil, errors.New("identity: totp secret required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("identity: bcrypt: %w", err)
	}
	if issuer == "" {
		issuer = "OWASAKA"
	}
	return &PasswordTOTPCredential{
		principalID:  principalID,
		subject:      subject,
		passwordHash: hash,
		totpSecret:   totpSecret,
		issuer:       issuer,
	}, nil
}

// LoadPasswordTOTPCredential reconstructs a credential from already-hashed
// material. Used when reading from persistence.
func LoadPasswordTOTPCredential(principalID, subject string, passwordHash []byte, totpSecret, issuer string) *PasswordTOTPCredential {
	if issuer == "" {
		issuer = "OWASAKA"
	}
	return &PasswordTOTPCredential{
		principalID:  principalID,
		subject:      subject,
		passwordHash: passwordHash,
		totpSecret:   totpSecret,
		issuer:       issuer,
	}
}

// bcryptCost is the cost factor for password hashing. Cost 12 ≈ 250ms on
// modern hardware — slow enough to deter offline brute-force, fast enough
// for an interactive login.
const bcryptCost = 12

// Kind implements Credential.
func (c *PasswordTOTPCredential) Kind() CredentialKind { return CredentialPassword }

// PrincipalID implements Credential.
func (c *PasswordTOTPCredential) PrincipalID() string { return c.principalID }

// Subject returns the username this credential authenticates.
func (c *PasswordTOTPCredential) Subject() string { return c.subject }

// TOTPSecret returns the shared secret. Exposed for re-rendering the
// enrollment QR; callers must treat it as sensitive.
func (c *PasswordTOTPCredential) TOTPSecret() string { return c.totpSecret }

// Issuer returns the TOTP issuer string.
func (c *PasswordTOTPCredential) Issuer() string { return c.issuer }

// Verify checks both factors. The AuthFactor must carry the password in
// Proof and the 6-digit TOTP code in Extra["totp"].
//
// Returns ErrCredentialInvalid on any mismatch. Errors are deliberately
// undifferentiated to avoid leaking which factor failed.
func (c *PasswordTOTPCredential) Verify(_ context.Context, factor AuthFactor) error {
	if factor.Kind != CredentialPassword {
		return ErrUnsupportedFactor
	}
	if err := bcrypt.CompareHashAndPassword(c.passwordHash, factor.Proof); err != nil {
		return ErrCredentialInvalid
	}
	code, _ := factor.Extra["totp"].(string)
	if code == "" {
		return ErrInsufficientFactor
	}
	if !totp.Validate(code, c.totpSecret) {
		return ErrCredentialInvalid
	}
	return nil
}

// GenerateTOTPSecret produces a fresh shared secret for enrollment.
// Returns the secret and the otpauth URL for QR encoding.
func GenerateTOTPSecret(issuer, accountName string) (secret string, otpauthURL string, err error) {
	if issuer == "" {
		issuer = "OWASAKA"
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("identity: totp generate: %w", err)
	}
	return key.Secret(), key.URL(), nil
}
