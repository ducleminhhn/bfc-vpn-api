package dualauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)
// MockKeycloakAuthService is a mock implementation of KeycloakAuthService
type MockKeycloakAuthService struct {
	loginResult        *AuthResult
	loginErr           error
	verifyTOTPResult   *AuthResult
	verifyTOTPErr      error
	verifyRecoveryResult *AuthResult
	verifyRecoveryErr  error
}

func NewMockKeycloakAuthService() *MockKeycloakAuthService {
	return &MockKeycloakAuthService{
		loginResult: &AuthResult{
			Success: true,
			UserID:  "user-1",
		},
	}
}

func (m *MockKeycloakAuthService) Login(ctx context.Context, email, password string) (*AuthResult, error) {
	if m.loginErr != nil {
		return nil, m.loginErr
	}
	return m.loginResult, nil
}

func (m *MockKeycloakAuthService) VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*AuthResult, error) {
	if m.verifyTOTPErr != nil {
		return nil, m.verifyTOTPErr
	}
	return m.verifyTOTPResult, nil
}

func (m *MockKeycloakAuthService) VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*AuthResult, error) {
	if m.verifyRecoveryErr != nil {
		return nil, m.verifyRecoveryErr
	}
	return m.verifyRecoveryResult, nil
}

// MockLocalAuthService is a mock implementation of LocalAuthService
type MockLocalAuthService struct {
	loginResult        *AuthResult
	loginErr           error
	verifyTOTPResult   *AuthResult
	verifyTOTPErr      error
	verifyRecoveryResult *AuthResult
	verifyRecoveryErr  error
}

func NewMockLocalAuthService() *MockLocalAuthService {
	return &MockLocalAuthService{
		loginResult: &AuthResult{
			Success: true,
			UserID:  "user-1",
		},
	}
}

func (m *MockLocalAuthService) Login(ctx context.Context, email, password string) (*AuthResult, error) {
	if m.loginErr != nil {
		return nil, m.loginErr
	}
	return m.loginResult, nil
}

func (m *MockLocalAuthService) VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*AuthResult, error) {
	if m.verifyTOTPErr != nil {
		return nil, m.verifyTOTPErr
	}
	return m.verifyTOTPResult, nil
}

func (m *MockLocalAuthService) VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*AuthResult, error) {
	if m.verifyRecoveryErr != nil {
		return nil, m.verifyRecoveryErr
	}
	return m.verifyRecoveryResult, nil
}

func TestDualAuthManager_RoutesToKeycloakByDefault(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Default mode should be Keycloak
	assert.Equal(t, AuthModeKeycloak, manager.GetCurrentMode())

	// Login should use Keycloak
	result, err := manager.Login(ctx, "test@example.com", "password")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "keycloak", result.AuthMode)
}

func TestDualAuthManager_RoutesToLocalAfterFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Trigger manual failover
	err := manager.ManualFailover(ctx, "admin-1", "Testing")
	require.NoError(t, err)

	// Mode should be Local now
	assert.Equal(t, AuthModeLocal, manager.GetCurrentMode())

	// Login should use Local
	result, err := manager.Login(ctx, "test@example.com", "password")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "local", result.AuthMode)
}

func TestDualAuthManager_ManualFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Manual failover
	err := manager.ManualFailover(ctx, "admin-1", "Testing manual failover")
	require.NoError(t, err)

	assert.Equal(t, AuthModeLocal, manager.GetCurrentMode())

	// Second failover should fail
	err = manager.ManualFailover(ctx, "admin-1", "Another test")
	assert.Equal(t, ErrAlreadyInLocalMode, err)
}

func TestDualAuthManager_ManualRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// First failover to Local
	err := manager.ManualFailover(ctx, "admin-1", "Testing")
	require.NoError(t, err)

	// Then recover to Keycloak
	err = manager.ManualRecovery(ctx, "admin-1")
	require.NoError(t, err)

	assert.Equal(t, AuthModeKeycloak, manager.GetCurrentMode())

	// Second recovery should fail
	err = manager.ManualRecovery(ctx, "admin-1")
	assert.Equal(t, ErrAlreadyInKeycloakMode, err)
}

func TestDualAuthManager_GetStatus(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	status := manager.GetStatus(ctx)
	
	assert.Equal(t, "keycloak", status.CurrentMode)
	assert.Equal(t, "healthy", status.KeycloakStatus)
	assert.Equal(t, "synced", status.SyncStatus)
	assert.False(t, status.FlappingDetected)
}

func TestDualAuthManager_VerifyTOTP(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	keycloakAuth.verifyTOTPResult = &AuthResult{
		Success:     true,
		AccessToken: "test-token",
		UserID:      "user-1",
	}
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Verify TOTP via Keycloak
	result, err := manager.VerifyTOTP(ctx, "mfa-token", "123456")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "keycloak", result.AuthMode)
}

func TestDualAuthManager_VerifyRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	keycloakAuth.verifyRecoveryResult = &AuthResult{
		Success:     true,
		AccessToken: "test-token",
		UserID:      "user-1",
	}
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Verify recovery via Keycloak
	result, err := manager.VerifyRecovery(ctx, "mfa-token", "recovery-code")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "keycloak", result.AuthMode)
}

func TestDualAuthManager_ResetFlapping(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Reset flapping
	err := manager.ResetFlapping(ctx, "admin-1")
	require.NoError(t, err)
}

func TestCompleteOutageResponse(t *testing.T) {
	status, response := CompleteOutageResponse()
	
	assert.Equal(t, 503, status)
	assert.Equal(t, "Service Unavailable", response["title"])
	assert.NotEmpty(t, response["message_vi"])
}

func TestDualAuthManager_StartAndStop(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()

	config := &DualAuthManagerConfig{
		KeycloakURL:              "localhost:8080",
		HealthCheckIntervalSecs:  1,
		FailureThreshold:         3,
		RecoveryThreshold:        3,
		MaxFailoversPerHour:      3,
		HealthCheckTimeoutSecs:   5,
		PasswordSyncIntervalMins: 1,
		KeycloakRealm:            "bfc-vpn",
	}
	
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start
	manager.Start(ctx)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Stop
	manager.Stop()
}

func TestDualAuthManager_NilAuthServices(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := DefaultDualAuthManagerConfig()
	
	// Create with nil auth services
	manager := NewDualAuthManager(config, nil, nil, redis, audit, logger)
	ctx := context.Background()

	// Login with nil Keycloak should handle gracefully
	result, err := manager.Login(ctx, "test@example.com", "password")
	assert.NoError(t, err)
	assert.False(t, result.Success)

	// Failover and try Local
	manager.ManualFailover(ctx, "admin", "testing")
	result, err = manager.Login(ctx, "test@example.com", "password")
	assert.NoError(t, err)
	assert.False(t, result.Success)

	// VerifyTOTP with nil services
	result, err = manager.VerifyTOTP(ctx, "token", "123456")
	assert.NoError(t, err)
	assert.Nil(t, result)

	// VerifyRecovery with nil services
	result, err = manager.VerifyRecovery(ctx, "token", "code")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestDualAuthManager_LoginError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	keycloakAuth.loginErr = assert.AnError
	localAuth := NewMockLocalAuthService()

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Login should return error
	_, err := manager.Login(ctx, "test@example.com", "password")
	assert.Error(t, err)
}

func TestDualAuthManager_VerifyTOTPInLocalMode(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()
	localAuth.verifyTOTPResult = &AuthResult{
		Success:     true,
		AccessToken: "local-token",
		UserID:      "user-1",
	}

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Failover to Local
	manager.ManualFailover(ctx, "admin", "testing")

	// Verify TOTP via Local
	result, err := manager.VerifyTOTP(ctx, "mfa-token", "123456")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "local", result.AuthMode)
}

func TestDualAuthManager_VerifyRecoveryInLocalMode(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	keycloakAuth := NewMockKeycloakAuthService()
	localAuth := NewMockLocalAuthService()
	localAuth.verifyRecoveryResult = &AuthResult{
		Success:     true,
		AccessToken: "local-token",
		UserID:      "user-1",
	}

	config := DefaultDualAuthManagerConfig()
	manager := NewDualAuthManager(config, keycloakAuth, localAuth, redis, audit, logger)

	ctx := context.Background()

	// Failover to Local
	manager.ManualFailover(ctx, "admin", "testing")

	// Verify Recovery via Local
	result, err := manager.VerifyRecovery(ctx, "mfa-token", "recovery-code")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "local", result.AuthMode)
}
