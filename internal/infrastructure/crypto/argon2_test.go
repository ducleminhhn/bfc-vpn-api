package crypto_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/infrastructure/crypto"
)

func TestHashPassword(t *testing.T) {
	hash, err := crypto.HashPassword("test-password-123", nil)
	require.NoError(t, err)

	// Check format starts with $argon2id$v=19$m=65536,t=3,p=4$
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$"), "hash should have correct prefix: %s", hash)

	// Check parts count
	parts := strings.Split(hash, "$")
	assert.Len(t, parts, 6)
}

func TestHashPassword_DifferentSalts(t *testing.T) {
	password := "same-password-123"
	hash1, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)

	hash2, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)

	// Same password should produce different hashes (different salts)
	assert.NotEqual(t, hash1, hash2)
}

func TestVerifyPassword_Success(t *testing.T) {
	password := "correct-password-123"
	hash, err := crypto.HashPassword(password, nil)
	require.NoError(t, err)

	valid, err := crypto.VerifyPassword(password, hash)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := crypto.HashPassword("correct-password", nil)
	require.NoError(t, err)

	valid, err := crypto.VerifyPassword("wrong-password", hash)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	_, err := crypto.VerifyPassword("password", "invalid-hash")
	assert.Error(t, err)
}

func TestVerifyPassword_WrongAlgorithm(t *testing.T) {
	// bcrypt-style hash
	_, err := crypto.VerifyPassword("password", "$2a$10$abcdefghijklmnopqrstuvwxyz")
	assert.Error(t, err)
}

func TestNeedsRehash_OutdatedParams(t *testing.T) {
	// Hash with old parameters
	oldParams := &crypto.Argon2idParams{
		Memory:      32 * 1024, // Lower than default
		Time:        2,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
	hash, err := crypto.HashPassword("password", oldParams)
	require.NoError(t, err)

	// Should need rehash with default (higher) params
	assert.True(t, crypto.NeedsRehash(hash, nil))
}

func TestNeedsRehash_CurrentParams(t *testing.T) {
	// Hash with current parameters should not need rehash
	currentHash, err := crypto.HashPassword("password", nil)
	require.NoError(t, err)

	assert.False(t, crypto.NeedsRehash(currentHash, nil))
}

func TestNeedsRehash_InvalidHash(t *testing.T) {
	// Invalid hash should return true (needs rehash)
	assert.True(t, crypto.NeedsRehash("invalid-hash", nil))
}

func TestDefaultParams_MeetsRequirements(t *testing.T) {
	params := crypto.DefaultParams()

	// AC requirement: cost factor >= 3
	assert.GreaterOrEqual(t, params.Time, uint32(3))

	// OWASP/RFC recommendation: 64 MiB
	assert.Equal(t, uint32(64*1024), params.Memory)

	// Default parallelism
	assert.Equal(t, uint8(4), params.Parallelism)
}

func TestHashPassword_CustomParams(t *testing.T) {
	customParams := &crypto.Argon2idParams{
		Memory:      32 * 1024,
		Time:        2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := crypto.HashPassword("password", customParams)
	require.NoError(t, err)

	// Should have custom params in hash
	assert.Contains(t, hash, "m=32768,t=2,p=2")

	// Should still be verifiable
	valid, err := crypto.VerifyPassword("password", hash)
	require.NoError(t, err)
	assert.True(t, valid)
}

func BenchmarkHashPassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = crypto.HashPassword("benchmark-password-123", nil)
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, _ := crypto.HashPassword("benchmark-password-123", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = crypto.VerifyPassword("benchmark-password-123", hash)
	}
}
