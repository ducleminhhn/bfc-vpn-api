package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Certificate private key encryption using AES-256-GCM
// Format: nonce(12 bytes) || ciphertext || tag(16 bytes)

const (
	// AES256KeySize is the required key size for AES-256
	AES256KeySize = 32
	// GCMNonceSize is the nonce size for GCM mode
	GCMNonceSize = 12
	// GCMTagSize is the authentication tag size for GCM mode
	GCMTagSize = 16
)

var (
	// ErrInvalidKeySize indicates the encryption key is not 32 bytes
	ErrInvalidKeySize = errors.New("encryption key must be 32 bytes for AES-256")
	// ErrCiphertextTooShort indicates the ciphertext is too short to contain nonce
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	// ErrDecryptionFailed indicates decryption failed (wrong key or tampered data)
	ErrDecryptionFailed = errors.New("decryption failed")
)

// EncryptPrivateKey encrypts a private key PEM using AES-256-GCM
// Returns: nonce(12 bytes) || ciphertext || tag(16 bytes)
func EncryptPrivateKey(privateKeyPEM []byte, encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != AES256KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal prepends nonce to ciphertext
	// Result: nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, privateKeyPEM, nil)
	return ciphertext, nil
}

// DecryptPrivateKey decrypts an encrypted private key using AES-256-GCM
// Expects: nonce(12 bytes) || ciphertext || tag(16 bytes)
func DecryptPrivateKey(encrypted []byte, encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != AES256KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize+GCMTagSize {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ValidateEncryptionKey validates that the encryption key is the correct size
func ValidateEncryptionKey(key []byte) error {
	if len(key) != AES256KeySize {
		return fmt.Errorf("encryption key must be %d bytes, got %d", AES256KeySize, len(key))
	}
	return nil
}

// DecodeEncryptionKey decodes a base64-encoded encryption key
func DecodeEncryptionKey(encodedKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("decode base64 key: %w", err)
	}
	if err := ValidateEncryptionKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateEncryptionKey generates a new random 32-byte encryption key
// This is used for testing or initial setup
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// EncodeEncryptionKey encodes a key to base64 for storage/display
func EncodeEncryptionKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
