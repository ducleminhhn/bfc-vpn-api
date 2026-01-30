package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sample private key PEM for testing
const testPrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILOdmx3PvVxW6xxSHa6cYLmMBBz1hR0eRDKdpq3MKBkmoAcGBSuBBAAK
oUQDQgAEcR1vA0Uc3F+JWp7Fl7nUiLwxBWJ/kVXZPvGM1Y8ckxKAHQoqLvFhJuKT
oNKvKGJ9pJvHN0VkShzPP1CKrL0Xug==
-----END EC PRIVATE KEY-----`

func TestEncryptDecryptPrivateKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	require.NoError(t, err)

	plaintext := []byte(testPrivateKeyPEM)

	// Encrypt
	encrypted, err := EncryptPrivateKey(plaintext, key)
	require.NoError(t, err)

	// Encrypted should be longer than plaintext (nonce + tag overhead)
	assert.Greater(t, len(encrypted), len(plaintext))

	// Decrypt
	decrypted, err := DecryptPrivateKey(encrypted, key)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptPrivateKey_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"empty key", 0},
		{"16 bytes", 16},
		{"31 bytes", 31},
		{"33 bytes", 33},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := EncryptPrivateKey([]byte(testPrivateKeyPEM), key)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecryptPrivateKey_InvalidKeySize(t *testing.T) {
	// First encrypt with valid key
	validKey, err := GenerateEncryptionKey()
	require.NoError(t, err)

	encrypted, err := EncryptPrivateKey([]byte(testPrivateKeyPEM), validKey)
	require.NoError(t, err)

	// Try to decrypt with invalid key sizes
	invalidKey := make([]byte, 16)
	_, err = DecryptPrivateKey(encrypted, invalidKey)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestDecryptPrivateKey_WrongKey(t *testing.T) {
	key1, err := GenerateEncryptionKey()
	require.NoError(t, err)

	key2, err := GenerateEncryptionKey()
	require.NoError(t, err)

	// Encrypt with key1
	encrypted, err := EncryptPrivateKey([]byte(testPrivateKeyPEM), key1)
	require.NoError(t, err)

	// Try to decrypt with key2
	_, err = DecryptPrivateKey(encrypted, key2)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptPrivateKey_TamperedData(t *testing.T) {
	key, err := GenerateEncryptionKey()
	require.NoError(t, err)

	encrypted, err := EncryptPrivateKey([]byte(testPrivateKeyPEM), key)
	require.NoError(t, err)

	// Tamper with the ciphertext
	encrypted[len(encrypted)/2] ^= 0xFF

	_, err = DecryptPrivateKey(encrypted, key)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestDecryptPrivateKey_TooShort(t *testing.T) {
	key, err := GenerateEncryptionKey()
	require.NoError(t, err)

	// Try to decrypt data that's too short
	shortData := make([]byte, GCMNonceSize+GCMTagSize-1)
	_, err = DecryptPrivateKey(shortData, key)
	assert.ErrorIs(t, err, ErrCiphertextTooShort)
}

func TestNonceUniqueness(t *testing.T) {
	key, err := GenerateEncryptionKey()
	require.NoError(t, err)

	plaintext := []byte(testPrivateKeyPEM)

	// Encrypt multiple times
	encrypted1, err := EncryptPrivateKey(plaintext, key)
	require.NoError(t, err)

	encrypted2, err := EncryptPrivateKey(plaintext, key)
	require.NoError(t, err)

	// Nonces should be different (first 12 bytes)
	nonce1 := encrypted1[:GCMNonceSize]
	nonce2 := encrypted2[:GCMNonceSize]

	assert.False(t, bytes.Equal(nonce1, nonce2), "nonces should be unique")

	// Both should decrypt correctly
	decrypted1, err := DecryptPrivateKey(encrypted1, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted1)

	decrypted2, err := DecryptPrivateKey(encrypted2, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted2)
}

func TestValidateEncryptionKey(t *testing.T) {
	tests := []struct {
		name      string
		keySize   int
		expectErr bool
	}{
		{"valid 32 bytes", 32, false},
		{"invalid 16 bytes", 16, true},
		{"invalid 31 bytes", 31, true},
		{"invalid 33 bytes", 33, true},
		{"invalid empty", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			err := ValidateEncryptionKey(key)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecodeEncryptionKey(t *testing.T) {
	// Generate a valid key
	originalKey, err := GenerateEncryptionKey()
	require.NoError(t, err)

	// Encode it
	encoded := EncodeEncryptionKey(originalKey)

	// Decode it back
	decoded, err := DecodeEncryptionKey(encoded)
	require.NoError(t, err)

	assert.Equal(t, originalKey, decoded)
}

func TestDecodeEncryptionKey_InvalidBase64(t *testing.T) {
	_, err := DecodeEncryptionKey("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecodeEncryptionKey_WrongSize(t *testing.T) {
	// Encode a 16-byte key
	shortKey := make([]byte, 16)
	encoded := EncodeEncryptionKey(shortKey)

	_, err := DecodeEncryptionKey(encoded)
	assert.Error(t, err)
}

func TestGenerateEncryptionKey(t *testing.T) {
	key1, err := GenerateEncryptionKey()
	require.NoError(t, err)

	key2, err := GenerateEncryptionKey()
	require.NoError(t, err)

	// Keys should be 32 bytes
	assert.Len(t, key1, AES256KeySize)
	assert.Len(t, key2, AES256KeySize)

	// Keys should be different
	assert.False(t, bytes.Equal(key1, key2), "generated keys should be unique")
}

func TestEncryptedDataOverhead(t *testing.T) {
	key, err := GenerateEncryptionKey()
	require.NoError(t, err)

	plaintext := []byte(testPrivateKeyPEM)

	encrypted, err := EncryptPrivateKey(plaintext, key)
	require.NoError(t, err)

	// Overhead should be nonce (12) + tag (16) = 28 bytes
	expectedLen := len(plaintext) + GCMNonceSize + GCMTagSize
	assert.Equal(t, expectedLen, len(encrypted))
}
