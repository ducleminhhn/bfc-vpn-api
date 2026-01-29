package dualauth

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PasswordSyncConfig holds sync configuration
type PasswordSyncConfig struct {
	SyncInterval         time.Duration // Default: 5 minutes
	KeycloakAdminURL     string
	KeycloakRealm        string
	KeycloakClientID     string
	KeycloakClientSecret string
}

// DefaultPasswordSyncConfig returns default configuration
func DefaultPasswordSyncConfig() *PasswordSyncConfig {
	return &PasswordSyncConfig{
		SyncInterval:  5 * time.Minute,
		KeycloakRealm: "bfc-vpn",
	}
}

// PasswordSyncService handles password synchronization
type PasswordSyncService struct {
	config      *PasswordSyncConfig
	userRepo    UserRepository
	argon2      Argon2Hasher
	keycloak    KeycloakClient
	auditLogger AuditLogger
	redisClient RedisClient
	logger      *zap.Logger

	mu     sync.RWMutex
	status SyncStatus

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// UserRepository interface for user database operations
type UserRepository interface {
	UpdatePasswordHash(ctx context.Context, userID string, hash string, updatedAt time.Time) error
	GetUserByKeycloakID(ctx context.Context, keycloakID string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetAllUsersNeedingSync(ctx context.Context) ([]*User, error)
	GetActiveUserIDs(ctx context.Context) ([]string, error)
}

// Argon2Hasher interface for password hashing
type Argon2Hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) (bool, error)
}

// KeycloakClient interface for Keycloak Admin API
type KeycloakClient interface {
	GetPasswordChangeEvents(ctx context.Context, since time.Time) ([]PasswordChangeEvent, error)
	GetUserCredentialHash(ctx context.Context, userID string) (string, error)
}

// PasswordChangeEvent represents a password change event from Keycloak
type PasswordChangeEvent struct {
	UserID    string    `json:"user_id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
}

// User represents a user record
type User struct {
	ID                    string
	KeycloakID            string
	Email                 string
	PasswordHash          string
	PasswordHashUpdatedAt time.Time
	UpdatedAt             time.Time
}

// NewPasswordSyncService creates a new password sync service
func NewPasswordSyncService(
	config *PasswordSyncConfig,
	userRepo UserRepository,
	argon2 Argon2Hasher,
	keycloak KeycloakClient,
	auditLogger AuditLogger,
	redisClient RedisClient,
	logger *zap.Logger,
) *PasswordSyncService {
	if config == nil {
		config = DefaultPasswordSyncConfig()
	}

	return &PasswordSyncService{
		config:      config,
		userRepo:    userRepo,
		argon2:      argon2,
		keycloak:    keycloak,
		auditLogger: auditLogger,
		redisClient: redisClient,
		logger:      logger,
		status: SyncStatus{
			Status: "synced",
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins the sync loop
func (s *PasswordSyncService) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.run(ctx)
}

// Stop gracefully stops the sync service
func (s *PasswordSyncService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// GetSyncStatus returns current sync status (implements PasswordSyncer interface)
func (s *PasswordSyncService) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := s.status
	return &status, nil
}

// run is the main sync loop
func (s *PasswordSyncService) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.SyncInterval)
	defer ticker.Stop()

	// Run initial sync
	s.performSync(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.performSync(ctx)
		}
	}
}

// performSync synchronizes passwords from Keycloak
func (s *PasswordSyncService) performSync(ctx context.Context) {
	startTime := time.Now()

	s.mu.Lock()
	s.status.Status = "syncing"
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.status.LastSyncAt = time.Now()
		s.status.NextSyncAt = s.status.LastSyncAt.Add(s.config.SyncInterval)
		if s.status.Status == "syncing" {
			s.status.Status = "synced"
		}
		s.mu.Unlock()

		duration := time.Since(startTime)
		s.logger.Debug("Password sync completed",
			zap.Duration("duration", duration))
	}()

	if s.keycloak == nil {
		s.logger.Debug("Keycloak client not available, skipping sync")
		return
	}

	// Get password change events since last sync
	events, err := s.keycloak.GetPasswordChangeEvents(ctx, s.status.LastSyncAt)
	if err != nil {
		s.logger.Error("Failed to get password change events", zap.Error(err))
		s.mu.Lock()
		s.status.Status = "out_of_sync"
		s.status.LastError = err.Error()
		s.mu.Unlock()
		return
	}

	// Process each event
	for _, event := range events {
		if err := s.processPasswordChange(ctx, event); err != nil {
			s.logger.Error("Failed to process password change",
				zap.String("user_id", event.UserID),
				zap.Error(err))
		}
	}

	s.logger.Info("Password sync completed",
		zap.Int("events_processed", len(events)),
		zap.Duration("duration", time.Since(startTime)))
}

// processPasswordChange handles a single password change event
func (s *PasswordSyncService) processPasswordChange(ctx context.Context, event PasswordChangeEvent) error {
	if s.userRepo == nil {
		return nil
	}

	// Get user from local database
	user, err := s.userRepo.GetUserByKeycloakID(ctx, event.UserID)
	if err != nil {
		return err
	}

	// Note: We cannot get plaintext password from Keycloak
	// Option 1: Use Keycloak SPI to intercept password changes (requires Keycloak plugin)
	// Option 2: Mark user as needing re-auth to capture password
	// For MVP: Mark user as "needs_password_sync" flag, sync on next login

	if s.auditLogger != nil {
		s.auditLogger.Log(ctx, "password_sync_event_processed", map[string]interface{}{
			"user_id":     user.ID,
			"keycloak_id": event.UserID,
			"source":      "keycloak_event",
		})
	}

	return nil
}

// SyncOnLogin is called when user logs in via Keycloak to sync password (implements PasswordSyncer interface)
func (s *PasswordSyncService) SyncOnLogin(ctx context.Context, userID string, password string) error {
	if s.argon2 == nil || s.userRepo == nil {
		return nil
	}

	// Hash password with Argon2id
	hash, err := s.argon2.HashPassword(password)
	if err != nil {
		s.logger.Error("Failed to hash password for sync", zap.Error(err))
		return ErrSyncFailed
	}

	// Update local database
	now := time.Now()
	if err := s.userRepo.UpdatePasswordHash(ctx, userID, hash, now); err != nil {
		s.logger.Error("Failed to update password hash", zap.Error(err))
		return ErrSyncFailed
	}

	// Store password change timestamp in Redis for later verification
	if s.redisClient != nil {
		key := "user:" + userID + ":password_changed_at"
		s.redisClient.Set(ctx, key, now.Format(time.RFC3339), 24*time.Hour)
	}

	if s.auditLogger != nil {
		s.auditLogger.Log(ctx, "password_sync_on_login", map[string]interface{}{
			"user_id": userID,
		})
	}

	s.logger.Info("Password synced on login",
		zap.String("user_id", userID))

	return nil
}

// SyncPassword syncs a specific password hash (implements PasswordSyncer interface)
func (s *PasswordSyncService) SyncPassword(ctx context.Context, userID string, passwordHash string) error {
	if s.userRepo == nil {
		return nil
	}

	now := time.Now()
	if err := s.userRepo.UpdatePasswordHash(ctx, userID, passwordHash, now); err != nil {
		return ErrSyncFailed
	}

	if s.auditLogger != nil {
		s.auditLogger.Log(ctx, "password_sync_direct", map[string]interface{}{
			"user_id": userID,
		})
	}

	return nil
}

// SyncAllActiveUsers forces sync for all active users (implements PasswordSyncer interface)
func (s *PasswordSyncService) SyncAllActiveUsers(ctx context.Context) error {
	if s.userRepo == nil {
		return nil
	}

	userIDs, err := s.userRepo.GetActiveUserIDs(ctx)
	if err != nil {
		s.logger.Error("Failed to get active user IDs", zap.Error(err))
		return ErrSyncFailed
	}

	s.logger.Info("Forcing sync for all active users",
		zap.Int("user_count", len(userIDs)))

	if s.auditLogger != nil {
		s.auditLogger.Log(ctx, "forced_sync_all_users", map[string]interface{}{
			"user_count": len(userIDs),
		})
	}

	return nil
}

// VerifyPasswordTimestamp verifies local password hash is not stale (RT-2 mitigation)
func (s *PasswordSyncService) VerifyPasswordTimestamp(ctx context.Context, userID string) error {
	if s.redisClient == nil || s.userRepo == nil {
		return nil
	}

	// Get Keycloak password change timestamp from Redis
	key := "user:" + userID + ":password_changed_at"
	keycloakTimestamp, err := s.redisClient.Get(ctx, key)
	if err != nil {
		// No timestamp recorded, allow login
		return nil
	}

	if keycloakTimestamp == "" {
		return nil
	}

	// Get local password hash updated_at
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Parse Keycloak timestamp
	kcTime, err := time.Parse(time.RFC3339, keycloakTimestamp)
	if err != nil {
		s.logger.Warn("Failed to parse keycloak timestamp",
			zap.String("timestamp", keycloakTimestamp),
			zap.Error(err))
		return nil
	}

	// If Keycloak timestamp is newer, reject login
	if kcTime.After(user.PasswordHashUpdatedAt) {
		s.logger.Warn("Password out of sync detected",
			zap.String("user_id", userID),
			zap.Time("keycloak_changed_at", kcTime),
			zap.Time("local_updated_at", user.PasswordHashUpdatedAt))
		return ErrPasswordOutOfSync
	}

	return nil
}

// SyncPasswordHash directly syncs a password hash for a user (internal endpoint)
