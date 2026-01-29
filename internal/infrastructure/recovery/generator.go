package recovery

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const (
	CodeLength  = 8  // 8 characters total (without hyphen)
	CodeCount   = 10
	// Charset excludes I, O, 0, 1 for readability
	CodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// GenerateCodes generates 10 unique recovery codes in XXXX-XXXX format
func GenerateCodes() ([]string, error) {
	codes := make([]string, CodeCount)
	for i := 0; i < CodeCount; i++ {
		code, err := generateSingleCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func generateSingleCode() (string, error) {
	bytes := make([]byte, CodeLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	var sb strings.Builder
	sb.Grow(9) // 8 chars + 1 hyphen
	for i, b := range bytes {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(CodeCharset[int(b)%len(CodeCharset)])
	}
	return sb.String(), nil // Format: XXXX-XXXX (9 chars with hyphen)
}

// NormalizeCode removes hyphen and converts to uppercase for comparison
func NormalizeCode(code string) string {
	return strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(code)), "-", "")
}

// FormatCode adds hyphen for display
func FormatCode(code string) string {
	normalized := NormalizeCode(code)
	if len(normalized) != 8 {
		return code
	}
	return normalized[:4] + "-" + normalized[4:]
}

// IsRecoveryCodeFormat checks if input looks like recovery code (not TOTP)
// TOTP is 6 digits, recovery code is 8 alphanumeric chars
func IsRecoveryCodeFormat(code string) bool {
	normalized := NormalizeCode(code)
	if len(normalized) != 8 {
		return false
	}
	for _, c := range normalized {
		if !strings.ContainsRune(CodeCharset, c) {
			return false
		}
	}
	return true
}

// IsTOTPFormat checks if input looks like TOTP code (6 digits)
func IsTOTPFormat(code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
