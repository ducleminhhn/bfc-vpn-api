package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams holds the parameters for Argon2id hashing
// OWASP recommended: m=46 MiB, t=1, p=1
// RFC 9106 recommended: m=64 MiB, t=3, p=4
type Argon2idParams struct {
	Memory      uint32 // Memory usage in KiB (default: 64*1024 = 64 MiB)
	Time        uint32 // Number of iterations (default: 3)
	Parallelism uint8  // Degree of parallelism (default: 4)
	SaltLength  uint32 // Salt length in bytes (default: 16)
	KeyLength   uint32 // Hash length in bytes (default: 32)
}

// DefaultParams returns OWASP/RFC 9106 recommended parameters
func DefaultParams() *Argon2idParams {
	return &Argon2idParams{
		Memory:      64 * 1024, // 64 MiB
		Time:        3,         // 3 iterations (cost factor >= 3 per AC)
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword generates an Argon2id hash for the given password
// Returns format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
func HashPassword(password string, params *Argon2idParams) (string, error) {
	if params == nil {
		params = DefaultParams()
	}

	// Generate cryptographically secure random salt
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate hash using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Encode to standard PHC string format
	// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Time,
		params.Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

// VerifyPassword checks if the password matches the hash
// Uses constant-time comparison to prevent timing attacks
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	params, salt, hash, err := parseHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Constant-time comparison (timing-safe)
	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// parseHash extracts parameters from encoded hash string
func parseHash(encodedHash string) (*Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version: %w", err)
	}

	params := &Argon2idParams{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&params.Memory, &params.Time, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt: %w", err)
	}
	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash: %w", err)
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}

// NeedsRehash checks if hash needs upgrading to current parameters
func NeedsRehash(encodedHash string, params *Argon2idParams) bool {
	if params == nil {
		params = DefaultParams()
	}

	current, _, _, err := parseHash(encodedHash)
	if err != nil {
		return true // Invalid hash, needs rehash
	}

	return current.Memory != params.Memory ||
		current.Time != params.Time ||
		current.Parallelism != params.Parallelism
}
