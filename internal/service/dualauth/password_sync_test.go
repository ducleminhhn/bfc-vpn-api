package dualauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	users       map[string]*User
	passwordErr error
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: map[string]*User{
			"user-1": {
				ID:                    "user-1",
				KeycloakID:            "kc-user-1",
				Email:                 "test@example.com",
				PasswordHash:          "",
				PasswordHashUpdatedAt: time.Now().Add(-time.Hour),
			},
		},
	}
}

func (m *MockUserRepository) UpdatePasswordHash(ctx context.Context, userID string, hash string, updatedAt time.Time) error {
	if m.passwordErr != nil {
		return m.passwordErr
	}
	if user, ok := m.users[userID]; ok {
		user.PasswordHash = hash
		user.PasswordHashUpdatedAt = updatedAt
	}
	return nil
}

func (m *MockUserRepository) GetUserByKeycloakID(ctx context.Context, keycloakID string) (*User, error) {
	for _, user := range m.users {
		if user.KeycloakID == keycloakID {
			return user, nil
		}
	}
	return nil, nil
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, nil
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, nil
}

func (m *MockUserRepository) GetAllUsersNeedingSync(ctx context.Context) ([]*User, error) {
	var users []*User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MockUserRepository) GetActiveUserIDs(ctx context.Context) ([]string, error) {
	var ids []string
	for id := range m.users {
		ids = append(ids, id)
	}
	return ids, nil
}

// MockArgon2Hasher is a mock implementation of Argon2Hasher
type MockArgon2Hasher struct {
	hashErr error
}

func NewMockArgon2Hasher() *MockArgon2Hasher {
	return &MockArgon2Hasher{}
}

func (m *MockArgon2Hasher) HashPassword(password string) (string, error) {
	if m.hashErr != nil {
		return "", m.hashErr
	}
	return "mock-hash-" + password, nil
}

func (m *MockArgon2Hasher) VerifyPassword(password, hash string) (bool, error) {
	return hash == "mock-hash-"+password, nil
}

// MockKeycloakClient is a mock implementation of KeycloakClient
type MockKeycloakClient struct {
	events []PasswordChangeEvent
	err    error
}

func NewMockKeycloakClient() *MockKeycloakClient {
	return &MockKeycloakClient{
		events: []PasswordChangeEvent{},
	}
}

func (m *MockKeycloakClient) GetPasswordChangeEvents(ctx context.Context, since time.Time) ([]PasswordChangeEvent, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.events, nil
}

func (m *MockKeycloakClient) GetUserCredentialHash(ctx context.Context, userID string) (string, error) {
	return "", nil
}

func TestPasswordSyncService_SyncOnLogin(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// Sync password on login
	err := sync.SyncOnLogin(ctx, "user-1", "password123")
	require.NoError(t, err)

	// Verify password hash was updated
	user := userRepo.users["user-1"]
	assert.Equal(t, "mock-hash-password123", user.PasswordHash)

	// Verify audit event was logged
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "password_sync_on_login", events[0].Event)

	// Verify Redis timestamp was set
	key := "user:user-1:password_changed_at"
	timestamp, _ := redis.Get(ctx, key)
	assert.NotEmpty(t, timestamp)
}

func TestPasswordSyncService_ForcedSyncOnFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// Sync all active users
	err := sync.SyncAllActiveUsers(ctx)
	require.NoError(t, err)

	// Verify audit event was logged
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "forced_sync_all_users", events[0].Event)
}

func TestPasswordSyncService_TimestampVerification(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// Set Keycloak timestamp NEWER than local
	keycloakTime := time.Now().Add(time.Hour)
	key := "user:user-1:password_changed_at"
	redis.Set(ctx, key, keycloakTime.Format(time.RFC3339), 24*time.Hour)

	// Verify should fail because Keycloak password is newer
	err := sync.VerifyPasswordTimestamp(ctx, "user-1")
	assert.Equal(t, ErrPasswordOutOfSync, err)
}

func TestPasswordSyncService_TimestampVerification_NoTimestamp(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// No timestamp in Redis - should allow login
	err := sync.VerifyPasswordTimestamp(ctx, "user-1")
	assert.NoError(t, err)
}

func TestPasswordSyncService_TimestampVerification_LocalNewer(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// Update user's local password timestamp to now
	userRepo.users["user-1"].PasswordHashUpdatedAt = time.Now()

	// Set Keycloak timestamp OLDER than local
	keycloakTime := time.Now().Add(-2 * time.Hour)
	key := "user:user-1:password_changed_at"
	redis.Set(ctx, key, keycloakTime.Format(time.RFC3339), 24*time.Hour)

	// Verify should pass because local password is up to date
	err := sync.VerifyPasswordTimestamp(ctx, "user-1")
	assert.NoError(t, err)
}

func TestPasswordSyncService_GetSyncStatus(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	status, err := sync.GetSyncStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, "synced", status.Status)
}

func TestPasswordSyncService_SyncPassword(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx := context.Background()

	// Direct sync password hash
	err := sync.SyncPassword(ctx, "user-1", "direct-hash-value")
	require.NoError(t, err)

	// Verify password hash was updated
	user := userRepo.users["user-1"]
	assert.Equal(t, "direct-hash-value", user.PasswordHash)

	// Verify audit event was logged
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "password_sync_direct", events[0].Event)
}

func TestPasswordSyncService_StartAndStop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := &PasswordSyncConfig{
		SyncInterval:  50 * time.Millisecond,
		KeycloakRealm: "bfc-vpn",
	}

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the sync service
	sync.Start(ctx)

	// Wait for a few syncs
	time.Sleep(150 * time.Millisecond)

	// Stop the sync service
	sync.Stop()

	// Should have updated status
	status, _ := sync.GetSyncStatus(ctx)
	assert.NotNil(t, status)
}

func TestPasswordSyncService_WithNilConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	// Pass nil config - should use defaults
	sync := NewPasswordSyncService(nil, userRepo, argon2, keycloak, audit, redis, logger)
	
	assert.NotNil(t, sync)
}

func TestPasswordSyncService_NilDependencies(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := DefaultPasswordSyncConfig()

	// Create with nil user repo and argon2
	sync := NewPasswordSyncService(config, nil, nil, nil, audit, redis, logger)
	ctx := context.Background()

	// These should handle nil gracefully
	err := sync.SyncOnLogin(ctx, "user-1", "password")
	assert.NoError(t, err)

	err = sync.SyncPassword(ctx, "user-1", "hash")
	assert.NoError(t, err)

	err = sync.SyncAllActiveUsers(ctx)
	assert.NoError(t, err)
}

func TestPasswordSyncService_ContextCancellation(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := &PasswordSyncConfig{
		SyncInterval:  100 * time.Millisecond,
		KeycloakRealm: "bfc-vpn",
	}

	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, redis, logger)
	ctx, cancel := context.WithCancel(context.Background())

	// Start the sync service
	sync.Start(ctx)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for goroutine to finish
	time.Sleep(50 * time.Millisecond)
}

func TestPasswordSyncService_NilRedisClient(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	audit := NewMockAuditLogger()
	userRepo := NewMockUserRepository()
	argon2 := NewMockArgon2Hasher()
	keycloak := NewMockKeycloakClient()

	config := DefaultPasswordSyncConfig()

	// Create with nil redis
	sync := NewPasswordSyncService(config, userRepo, argon2, keycloak, audit, nil, logger)
	ctx := context.Background()

	// SyncOnLogin should work without redis
	err := sync.SyncOnLogin(ctx, "user-1", "password")
	assert.NoError(t, err)

	// VerifyPasswordTimestamp should return nil without redis
	err = sync.VerifyPasswordTimestamp(ctx, "user-1")
	assert.NoError(t, err)
}
