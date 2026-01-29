package recovery_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/infrastructure/recovery"
)

func TestGenerateCodes_Count(t *testing.T) {
	codes, err := recovery.GenerateCodes()
	require.NoError(t, err)
	assert.Len(t, codes, 10, "should generate exactly 10 codes")
}

func TestGenerateCodes_Uniqueness(t *testing.T) {
	codes, err := recovery.GenerateCodes()
	require.NoError(t, err)

	seen := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, seen[code], "duplicate code found: %s", code)
		seen[code] = true
	}
}

func TestGenerateCodes_Format(t *testing.T) {
	codes, err := recovery.GenerateCodes()
	require.NoError(t, err)

	for _, code := range codes {
		// Check format XXXX-XXXX (9 chars with hyphen)
		assert.Len(t, code, 9, "code should be 9 chars including hyphen")
		assert.Regexp(t, `^[A-Z0-9]{4}-[A-Z0-9]{4}$`, code)

		// Check no ambiguous characters (I, O, 0, 1)
		for _, c := range code {
			if c != '-' {
				assert.NotContains(t, "IOoi01", string(c), "code should not contain ambiguous characters")
			}
		}
	}
}

func TestIsRecoveryCodeFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid with hyphen", "ABCD-EFGH", true},
		{"valid without hyphen", "ABCDEFGH", true},
		{"valid lowercase", "abcd-efgh", true},
		{"valid alphanumeric", "A2B3-C4D5", true},
		{"TOTP format 6 digits", "123456", false},
		{"TOTP format all zeros", "000000", false},
		{"too short", "ABC", false},
		{"too long", "ABCD-EFGH-IJKL", false},
		{"contains ambiguous I", "ABCI-EFGH", false},
		{"contains ambiguous O", "ABCO-EFGH", false},
		{"contains ambiguous 0", "ABC0-EFGH", false},
		{"contains ambiguous 1", "ABC1-EFGH", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, recovery.IsRecoveryCodeFormat(tt.input))
		})
	}
}

func TestIsTOTPFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid TOTP", "123456", true},
		{"valid TOTP all zeros", "000000", true},
		{"valid TOTP all nines", "999999", true},
		{"too short", "12345", false},
		{"too long", "1234567", false},
		{"contains letters", "12345A", false},
		{"recovery code format", "ABCD-EFGH", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, recovery.IsTOTPFormat(tt.input))
		})
	}
}

func TestNormalizeCode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABCD-EFGH", "ABCDEFGH"},
		{"abcd-efgh", "ABCDEFGH"},
		{"  ABCD-EFGH  ", "ABCDEFGH"},
		{"ABCDEFGH", "ABCDEFGH"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, recovery.NormalizeCode(tt.input))
		})
	}
}

func TestFormatCode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ABCDEFGH", "ABCD-EFGH"},
		{"abcdefgh", "ABCD-EFGH"},
		{"ABC", "ABC"}, // Too short, return as-is
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, recovery.FormatCode(tt.input))
		})
	}
}
