package crypto

import (
	"bytes"
	"testing"
)

func TestNewAESEncryptor_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	enc, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encryptor")
	}
}

func TestNewAESEncryptor_InvalidKeyLength(t *testing.T) {
	testCases := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"too short", 16, true},
		{"too long", 64, true},
		{"empty", 0, true},
		{"valid", 32, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			_, err := NewAESEncryptor(key)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	enc, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("Hello, World!")},
		{"empty", []byte("")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}},
		{"totp secret", []byte("JBSWY3DPEHPK3PXP")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decrypted) {
				t.Errorf("decrypted text mismatch: got %v, want %v", decrypted, tc.plaintext)
			}
		})
	}
}

func TestEncrypt_UniqueNonce(t *testing.T) {
	key := make([]byte, 32)
	enc, _ := NewAESEncryptor(key)

	plaintext := []byte("test")
	results := make(map[string]bool)

	for i := 0; i < 100; i++ {
		ciphertext, _ := enc.Encrypt(plaintext)
		if results[ciphertext] {
			t.Error("duplicate ciphertext detected, nonce not unique")
		}
		results[ciphertext] = true
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	enc, _ := NewAESEncryptor(key)

	testCases := []struct {
		name       string
		ciphertext string
	}{
		{"invalid base64", "not-valid-base64!!!"},
		{"too short", "YWJjZA=="}, // "abcd" in base64
		{"tampered", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enc.Decrypt(tc.ciphertext)
			if err == nil {
				t.Error("expected error for invalid ciphertext")
			}
		})
	}
}
