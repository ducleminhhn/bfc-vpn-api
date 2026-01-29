package localauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserRepository interface for user operations
type UserRepository interface {
	GetByEmailForLocalAuth(ctx context.Context, email string) (*UserForLocalAuth, error)
	IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error
	ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error
	LockUserAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error
	UnlockUserAccount(ctx context.Context, userID uuid.UUID) error
	IsUserLocked(ctx context.Context, userID uuid.UUID) (bool, error)
	UpdatePasswordHash(ctx context.Context, userID uuid.UUID, hash string) error
	Ping(ctx context.Context) error
}

// UserForLocalAuth represents user data needed for local authentication
type UserForLocalAuth struct {
	ID                   uuid.UUID
	TenantID             uuid.UUID
	Email                string
	PasswordHash         string
	TOTPEnabled          bool
	TOTPSecretEncrypted  []byte
	Status               string
	LocalAuthEnabled     bool
	LockedAt             *time.Time
	LockedUntil          *time.Time
	FailedAttempts       int
	LastFailedAt         *time.Time
}

// TOTPService interface for TOTP verification
type TOTPService interface {
	ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error)
}

// RecoveryService interface for recovery codes
type RecoveryService interface {
	Verify(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) // returns (valid, remaining, error)
}

// TokenService interface for JWT token generation
type TokenService interface {
	GenerateAccessToken(ctx context.Context, userID, email, tenantID string) (string, int, error)
	GenerateRefreshToken(ctx context.Context, userID string) (string, error)
	GenerateMFAToken(ctx context.Context, userID, email, clientIP, userAgent string) (string, error)
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogEvent(ctx context.Context, event AuditEvent) error
}

// AuditEvent represents an audit log entry
type AuditEvent struct {
	EventType     string
	ActorID       string
	ActorEmail    string
	TenantID      string
	ClientIP      string
	UserAgent     string
	Success       bool
	FailureReason string
	AuthMethod    string // "local", "keycloak"
	Metadata      map[string]interface{}
}

// RedisClient interface for Redis operations
type RedisClient interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, expiration time.Duration) error
	TTL(ctx context.Context, key string) (time.Duration, error)
	Delete(ctx context.Context, key string) error
	SAdd(ctx context.Context, key string, member interface{}) error
	SCard(ctx context.Context, key string) (int64, error)
	Ping(ctx context.Context) error
}
