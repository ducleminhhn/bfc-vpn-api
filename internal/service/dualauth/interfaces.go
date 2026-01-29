package dualauth

import (
	"context"
	"time"
)

// RedisClient interface for Redis operations
type RedisClient interface {
	GetInt(ctx context.Context, key string) (int, error)
	Incr(ctx context.Context, key string, ttl time.Duration) error
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	Log(ctx context.Context, event string, data map[string]interface{}) error
}

// PasswordSyncer interface for password synchronization
type PasswordSyncer interface {
	SyncPassword(ctx context.Context, userID string, passwordHash string) error
	SyncOnLogin(ctx context.Context, userID string, password string) error
	SyncAllActiveUsers(ctx context.Context) error
	GetSyncStatus(ctx context.Context) (*SyncStatus, error)
}

// SyncStatus represents the current sync status
type SyncStatus struct {
	Status      string    `json:"status"` // "synced", "syncing", "out_of_sync"
	LastSyncAt  time.Time `json:"last_sync_at"`
	NextSyncAt  time.Time `json:"next_sync_at"`
	PendingSync int       `json:"pending_sync"`
	LastError   string    `json:"last_error,omitempty"`
}

// Notifier interface for sending alerts
type Notifier interface {
	SendAlert(ctx context.Context, config AlertConfig) error
}

// AlertConfig represents an alert configuration
type AlertConfig struct {
	Level   string   `json:"level"`   // "INFO", "WARNING", "CRITICAL"
	Title   string   `json:"title"`
	Message string   `json:"message"`
	Channel []string `json:"channel"` // "email", "slack", "webhook"
}
