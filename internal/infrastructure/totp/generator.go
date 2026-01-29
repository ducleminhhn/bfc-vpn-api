package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	Digits     = otp.DigitsSix // 6 digits
	Period     = 30            // 30 seconds
	SecretSize = 20            // 160 bits (32 chars base32)
	Skew       = 1             // ±1 time step (90 second window)
	Algorithm  = otp.AlgorithmSHA1
)

// GenerateResult contains TOTP setup information
type GenerateResult struct {
	Secret      string // Base32-encoded secret
	OTPAuthURL  string // otpauth:// URI for QR code
	Issuer      string
	AccountName string
}

// Generate creates a new TOTP key for the given issuer and account
func Generate(issuer, accountName string) (*GenerateResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      Period,
		SecretSize:  SecretSize,
		Digits:      Digits,
		Algorithm:   Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}
	return &GenerateResult{
		Secret:      key.Secret(),
		OTPAuthURL:  key.URL(),
		Issuer:      issuer,
		AccountName: accountName,
	}, nil
}

// ValidateCode validates a TOTP code against the secret using current time
func ValidateCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// ValidateCodeWithSkew validates with custom time and skew
func ValidateCodeWithSkew(secret, code string, t time.Time, skew uint) bool {
	opts := totp.ValidateOpts{
		Period:    Period,
		Skew:      skew,
		Digits:    Digits,
		Algorithm: Algorithm,
	}
	valid, _ := totp.ValidateCustom(code, secret, t, opts)
	return valid
}

// GenerateCode generates a TOTP code for the current time
func GenerateCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// GenerateCodeAt generates a TOTP code for a specific time
func GenerateCodeAt(secret string, t time.Time) (string, error) {
	return totp.GenerateCode(secret, t)
}
