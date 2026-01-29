package recovery

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository"
)

// RecoveryRepository defines recovery codes data operations
type RecoveryRepository interface {
	CreateCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	GetUnusedCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error)
	GetAllCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error)
	MarkCodeUsed(ctx context.Context, userID, codeID uuid.UUID) (bool, error)
	DeleteAllCodes(ctx context.Context, userID uuid.UUID) error
	CountUnusedCodes(ctx context.Context, userID uuid.UUID) (int64, error)
}

// UserRepository defines user operations needed by recovery service
type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// AuditRepository defines audit logging operations
type AuditRepository interface {
	LogEvent(ctx context.Context, event repository.AuditEvent) error
}

// TOTPService defines TOTP validation operations (used for regenerate)
type TOTPService interface {
	ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error)
}

// RedisClient defines Redis operations for recovery service
type RedisClient interface {
	// Basic operations
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, key string) error

	// Counter operations
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, expiration time.Duration) error
	TTL(ctx context.Context, key string) (time.Duration, error)
}
