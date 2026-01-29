package totp

import (
	"strings"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	result, err := Generate("BFC-VPN", "test@example.com")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check secret length (32 chars base32 = 160 bits)
	if len(result.Secret) != 32 {
		t.Errorf("expected secret length 32, got %d", len(result.Secret))
	}

	// Check OTPAuth URL format
	if !strings.HasPrefix(result.OTPAuthURL, "otpauth://totp/") {
		t.Errorf("invalid otpauth URL: %s", result.OTPAuthURL)
	}

	// Check issuer and account in URL
	if !strings.Contains(result.OTPAuthURL, "BFC-VPN") {
		t.Errorf("issuer not found in URL: %s", result.OTPAuthURL)
	}
	if !strings.Contains(result.OTPAuthURL, "test%40example.com") && !strings.Contains(result.OTPAuthURL, "test@example.com") {
		t.Errorf("account not found in URL: %s", result.OTPAuthURL)
	}
}

func TestValidateCode(t *testing.T) {
	result, _ := Generate("BFC-VPN", "test@example.com")

	// Generate a valid code
	code, err := GenerateCode(result.Secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Validate the code
	if !ValidateCode(result.Secret, code) {
		t.Error("ValidateCode should accept current code")
	}

	// Invalid code should fail
	if ValidateCode(result.Secret, "000000") {
		t.Error("ValidateCode should reject invalid code")
	}
}

func TestValidateCodeWithSkew(t *testing.T) {
	result, _ := Generate("BFC-VPN", "test@example.com")
	now := time.Now()

	// Generate code for current time
	currentCode, _ := GenerateCodeAt(result.Secret, now)

	// Generate code for 30 seconds ago (previous step)
	prevCode, _ := GenerateCodeAt(result.Secret, now.Add(-30*time.Second))

	// Generate code for 30 seconds in future (next step)
	nextCode, _ := GenerateCodeAt(result.Secret, now.Add(30*time.Second))

	// Generate code for 60 seconds ago (2 steps ago)
	oldCode, _ := GenerateCodeAt(result.Secret, now.Add(-60*time.Second))

	tests := []struct {
		name  string
		code  string
		skew  uint
		want  bool
	}{
		{"current code with skew 1", currentCode, 1, true},
		{"previous code with skew 1", prevCode, 1, true},
		{"next code with skew 1", nextCode, 1, true},
		{"2 steps old code with skew 1", oldCode, 1, false},
		{"current code with skew 0", currentCode, 0, true},
		{"previous code with skew 0", prevCode, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateCodeWithSkew(result.Secret, tt.code, now, tt.skew)
			if got != tt.want {
				t.Errorf("ValidateCodeWithSkew() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateCode(t *testing.T) {
	result, _ := Generate("BFC-VPN", "test@example.com")

	code, err := GenerateCode(result.Secret)
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	// Check code is 6 digits
	if len(code) != 6 {
		t.Errorf("expected 6 digit code, got %d digits", len(code))
	}

	// Check code is numeric
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("code contains non-numeric character: %c", c)
		}
	}
}

func TestGenerateCodeAt(t *testing.T) {
	result, _ := Generate("BFC-VPN", "test@example.com")
	fixedTime := time.Date(2026, 1, 29, 12, 0, 0, 0, time.UTC)

	// Same time should produce same code
	code1, _ := GenerateCodeAt(result.Secret, fixedTime)
	code2, _ := GenerateCodeAt(result.Secret, fixedTime)

	if code1 != code2 {
		t.Error("same time should produce same code")
	}

	// Different time step should produce different code
	code3, _ := GenerateCodeAt(result.Secret, fixedTime.Add(30*time.Second))
	if code1 == code3 {
		t.Error("different time step should produce different code")
	}
}

func TestMultipleGenerateUnique(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 10; i++ {
		result, err := Generate("BFC-VPN", "test@example.com")
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if secrets[result.Secret] {
			t.Error("duplicate secret generated")
		}
		secrets[result.Secret] = true
	}
}
