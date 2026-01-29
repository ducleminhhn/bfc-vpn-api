package totp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository"
)

// RedisClient defines the Redis operations needed by TOTP service
type RedisClient interface {
	// MFA Token operations
	GetMFAToken(ctx context.Context, token string) (string, error)
	SetMFAToken(ctx context.Context, token, data string) error
	DeleteMFAToken(ctx context.Context, token string) error

	// TOTP Pending setup operations
	SetTOTPPending(ctx context.Context, userID, data string) error
	GetTOTPPending(ctx context.Context, userID string) (string, error)
	DeleteTOTPPending(ctx context.Context, userID string) error

	// Replay protection
	MarkTOTPCodeUsed(ctx context.Context, userID, code string) (bool, error)

	// Brute force protection
	IsAccountLocked(ctx context.Context, userID string) (bool, time.Duration, error)
	GetTOTPFailedCount(ctx context.Context, userID string) (int64, error)
	IncrementTOTPFailed(ctx context.Context, userID string) (int64, error)
	ResetTOTPFailed(ctx context.Context, userID string) error
}

// UserRepository defines the user operations needed by TOTP service
type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	EnableTOTP(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error
	DisableTOTP(ctx context.Context, userID uuid.UUID) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
}

// AuditRepository defines the audit operations needed by TOTP service
type AuditRepository interface {
	LogEvent(ctx context.Context, event repository.AuditEvent) error
}

// Encryptor defines encryption operations
type Encryptor interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(ciphertextBase64 string) ([]byte, error)
}

// TOTPGenerator defines TOTP generation operations
type TOTPGenerator interface {
	Generate(issuer, accountName string) (*GenerateResult, error)
	ValidateCode(secret, code string) bool
}

// GenerateResult contains TOTP setup information (for interface)
type GenerateResult struct {
	Secret      string
	OTPAuthURL  string
	Issuer      string
	AccountName string
}

// RecoveryService defines recovery codes generation operations
type RecoveryService interface {
	GenerateAndStore(ctx context.Context, userID uuid.UUID, email, clientIP, userAgent string) (*GenerateRecoveryResponse, error)
}

// GenerateRecoveryResponse contains generated recovery codes
type GenerateRecoveryResponse struct {
	Codes []string `json:"codes"`
}
