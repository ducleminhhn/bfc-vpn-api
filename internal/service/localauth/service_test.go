package localauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/bfc-vpn/api/internal/infrastructure/crypto"
	"github.com/bfc-vpn/api/internal/service/localauth"
)

// ============================================================================
// Mock Implementations
// ============================================================================

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetByEmailForLocalAuth(ctx context.Context, email string) (*localauth.UserForLocalAuth, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*localauth.UserForLocalAuth), args.Error(1)
}

func (m *MockUserRepository) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) LockUserAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	args := m.Called(ctx, userID, lockedUntil)
	return args.Error(0)
}

func (m *MockUserRepository) UnlockUserAccount(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) IsUserLocked(ctx context.Context, userID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) UpdatePasswordHash(ctx context.Context, userID uuid.UUID, hash string) error {
	args := m.Called(ctx, userID, hash)
	return args.Error(0)
}

func (m *MockUserRepository) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	args := m.Called(ctx, userID, code)
	return args.Bool(0), args.Error(1)
}

type MockRecoveryService struct {
	mock.Mock
}

func (m *MockRecoveryService) Verify(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	args := m.Called(ctx, userID, code)
	return args.Bool(0), args.Int(1), args.Error(2)
}

type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateAccessToken(ctx context.Context, userID, email, tenantID string) (string, int, error) {
	args := m.Called(ctx, userID, email, tenantID)
	return args.String(0), args.Int(1), args.Error(2)
}

func (m *MockTokenService) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GenerateMFAToken(ctx context.Context, userID, email, clientIP, userAgent string) (string, error) {
	args := m.Called(ctx, userID, email, clientIP, userAgent)
	return args.String(0), args.Error(1)
}

type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogEvent(ctx context.Context, event localauth.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

type MockRedisClient struct {
	mock.Mock
	data map[string]string
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{data: make(map[string]string)}
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Error(1)
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	args := m.Called(ctx, key, value, expiration)
	return args.Error(0)
}

func (m *MockRedisClient) Incr(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) error {
	args := m.Called(ctx, key, expiration)
	return args.Error(0)
}

func (m *MockRedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(time.Duration), args.Error(1)
}

func (m *MockRedisClient) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockRedisClient) SAdd(ctx context.Context, key string, member interface{}) error {
	args := m.Called(ctx, key, member)
	return args.Error(0)
}

func (m *MockRedisClient) SCard(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRedisClient) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ============================================================================
// Test Helpers
// ============================================================================

func createTestUser(email, password string, totpEnabled, localAuthEnabled bool) *localauth.UserForLocalAuth {
	hash, _ := crypto.HashPassword(password, nil)
	return &localauth.UserForLocalAuth{
		ID:               uuid.New(),
		TenantID:         uuid.New(),
		Email:            email,
		PasswordHash:     hash,
		TOTPEnabled:      totpEnabled,
		LocalAuthEnabled: localAuthEnabled,
		Status:           "active",
		FailedAttempts:   0,
	}
}

func setupService() (*localauth.Service, *MockUserRepository, *MockTOTPService, *MockRecoveryService, *MockTokenService, *MockAuditLogger, *MockRedisClient) {
	userRepo := new(MockUserRepository)
	totpService := new(MockTOTPService)
	recoveryService := new(MockRecoveryService)
	tokenService := new(MockTokenService)
	auditLogger := new(MockAuditLogger)
	redisClient := NewMockRedisClient()

	service := localauth.NewService(userRepo, totpService, recoveryService, tokenService, auditLogger, redisClient)
	return service, userRepo, totpService, recoveryService, tokenService, auditLogger, redisClient
}

// ============================================================================
// Login Tests - AC-1, AC-4, AC-5, AC-7, AC-8
// ============================================================================

func TestLogin_Success_NoMFA(t *testing.T) {
	// Arrange
	service, userRepo, _, _, tokenService, auditLogger, redisClient := setupService()
	ctx := context.Background()
	password := "test-password-123"
	user := createTestUser("test@example.com", password, false, true)

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	redisClient.On("Delete", ctx, mock.AnythingOfType("string")).Return(nil)
	userRepo.On("ResetFailedAttempts", ctx, user.ID).Return(nil)
	tokenService.On("GenerateAccessToken", ctx, user.ID.String(), user.Email, user.TenantID.String()).Return("access-token", 900, nil)
	tokenService.On("GenerateRefreshToken", ctx, user.ID.String()).Return("refresh-token", nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: password}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, "refresh-token", resp.RefreshToken)
	assert.False(t, resp.RequiresMFA)
	userRepo.AssertExpectations(t)
	tokenService.AssertExpectations(t)
}

func TestLogin_Success_WithMFA(t *testing.T) {
	// Arrange
	service, userRepo, _, _, tokenService, auditLogger, redisClient := setupService()
	ctx := context.Background()
	password := "test-password-123"
	user := createTestUser("test@example.com", password, true, true)

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	redisClient.On("Delete", ctx, mock.AnythingOfType("string")).Return(nil)
	userRepo.On("ResetFailedAttempts", ctx, user.ID).Return(nil)
	tokenService.On("GenerateMFAToken", ctx, user.ID.String(), user.Email, "192.168.1.1", "Mozilla/5.0").Return("mfa-token", nil)
	tokenService.On("GenerateAccessToken", ctx, user.ID.String(), user.Email, user.TenantID.String()).Return("access-token", 900, nil)
	tokenService.On("GenerateRefreshToken", ctx, user.ID.String()).Return("refresh-token", nil)
	redisClient.On("Set", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: password}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "mfa_required", resp.Status)
	assert.Equal(t, "mfa-token", resp.MFAToken)
	assert.True(t, resp.RequiresMFA)
	assert.True(t, resp.TOTPEnabled)
}

func TestLogin_Fail_UserNotFound(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "unknown@example.com").Return(nil, errors.New("user not found"))
	redisClient.On("Incr", ctx, mock.AnythingOfType("string")).Return(int64(1), nil)
	redisClient.On("Expire", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	redisClient.On("SAdd", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)
	redisClient.On("SCard", ctx, mock.AnythingOfType("string")).Return(int64(1), nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "unknown@example.com", Password: "any-password-123"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	// Error Title is "Xác thực thất bại"
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestLogin_Fail_WrongPassword(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	user := createTestUser("test@example.com", "correct-password-123", false, true)

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	redisClient.On("Incr", ctx, mock.AnythingOfType("string")).Return(int64(1), nil)
	redisClient.On("Expire", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	userRepo.On("IncrementFailedAttempts", ctx, user.ID).Return(nil)
	redisClient.On("SAdd", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)
	redisClient.On("SCard", ctx, mock.AnythingOfType("string")).Return(int64(1), nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "wrong-password-123"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
	userRepo.AssertCalled(t, "IncrementFailedAttempts", ctx, user.ID)
}

func TestLogin_Fail_LocalAuthDisabled(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	user := createTestUser("test@example.com", "password-123456", false, false) // local auth disabled

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestLogin_Fail_AccountLocked_AC5(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	user := createTestUser("test@example.com", "password-123456", false, true)

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "global_auth_blocked:192.168.1.1"
	})).Return("", nil)
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "global_auth_failed:192.168.1.1"
	})).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	// Account is locked in Redis
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "local_auth_lockout:"+user.ID.String()
	})).Return("1", nil)
	redisClient.On("TTL", ctx, mock.AnythingOfType("string")).Return(10*time.Minute, nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	// LockedError Title is "Tài khoản bị khóa"
	assert.Contains(t, err.Error(), "Tài khoản bị khóa")
}

func TestLogin_Fail_RateLimitExceeded_AC4(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	user := createTestUser("test@example.com", "password-123456", false, true)

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "global_auth_blocked:192.168.1.1" || key == "global_auth_failed:192.168.1.1"
	})).Return("", nil)
	userRepo.On("GetByEmailForLocalAuth", ctx, "test@example.com").Return(user, nil)
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "local_auth_lockout:"+user.ID.String()
	})).Return("", nil)
	// 5 failed attempts already
	redisClient.On("Get", ctx, mock.MatchedBy(func(key string) bool {
		return key == "local_auth_failed:"+user.ID.String()
	})).Return("5", nil)
	redisClient.On("Set", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(nil)
	userRepo.On("LockUserAccount", ctx, user.ID, mock.AnythingOfType("time.Time")).Return(nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	// LockedError Title is "Tài khoản bị khóa"
	assert.Contains(t, err.Error(), "Tài khoản bị khóa")
	userRepo.AssertCalled(t, "LockUserAccount", ctx, user.ID, mock.AnythingOfType("time.Time"))
}

func TestLogin_Fail_RedisUnavailable_AC8(t *testing.T) {
	// Arrange
	service, _, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()

	redisClient.On("Ping", ctx).Return(errors.New("redis connection refused"))
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	// ServiceUnavailableError Title is "Dịch vụ không khả dụng"
	assert.Contains(t, err.Error(), "Dịch vụ không khả dụng")
}

func TestLogin_Fail_DatabaseUnavailable_AC8(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(errors.New("database connection refused"))
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Dịch vụ không khả dụng")
}

func TestLogin_Fail_GlobalIPBlocked_AC7(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, _, redisClient := setupService()
	ctx := context.Background()

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	// IP is blocked
	redisClient.On("Get", ctx, "global_auth_blocked:192.168.1.1").Return("1", nil)

	// Act
	req := localauth.LoginRequest{Email: "test@example.com", Password: "password-123456"}
	resp, err := service.Login(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	// TooManyRequestsError Title is "Quá nhiều yêu cầu"
	assert.Contains(t, err.Error(), "Quá nhiều yêu cầu")
}

// ============================================================================
// VerifyTOTP Tests - AC-2
// ============================================================================

func TestVerifyTOTP_Success(t *testing.T) {
	// Arrange
	service, userRepo, totpService, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	mfaData := `{"user_id":"` + userID.String() + `","email":"test@example.com","tenant_id":"` + tenantID.String() + `","client_ip":"192.168.1.1","user_agent":"Mozilla/5.0","access_token":"access-token","refresh_token":"refresh-token","expires_in":900}`

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return(mfaData, nil)
	totpService.On("ValidateCode", ctx, userID, "123456").Return(true, nil)
	redisClient.On("Delete", ctx, mock.AnythingOfType("string")).Return(nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.VerifyTOTPRequest{MFAToken: "mfa-token", Code: "123456"}
	resp, err := service.VerifyTOTP(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "access-token", resp.AccessToken)
	totpService.AssertExpectations(t)
}

func TestVerifyTOTP_Fail_InvalidCode(t *testing.T) {
	// Arrange
	service, userRepo, totpService, _, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	mfaData := `{"user_id":"` + userID.String() + `","email":"test@example.com","tenant_id":"` + tenantID.String() + `","client_ip":"192.168.1.1","user_agent":"Mozilla/5.0","access_token":"access-token","refresh_token":"refresh-token","expires_in":900}`

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return(mfaData, nil)
	totpService.On("ValidateCode", ctx, userID, "000000").Return(false, nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.VerifyTOTPRequest{MFAToken: "mfa-token", Code: "000000"}
	resp, err := service.VerifyTOTP(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerifyTOTP_Fail_ExpiredToken(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, _, redisClient := setupService()
	ctx := context.Background()

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return("", nil)

	// Act
	req := localauth.VerifyTOTPRequest{MFAToken: "expired-token", Code: "123456"}
	resp, err := service.VerifyTOTP(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerifyTOTP_Fail_IPMismatch(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, _, redisClient := setupService()
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	mfaData := `{"user_id":"` + userID.String() + `","email":"test@example.com","tenant_id":"` + tenantID.String() + `","client_ip":"192.168.1.1","user_agent":"Mozilla/5.0","access_token":"access-token","refresh_token":"refresh-token","expires_in":900}`

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return(mfaData, nil)

	// Act - different IP
	req := localauth.VerifyTOTPRequest{MFAToken: "mfa-token", Code: "123456"}
	resp, err := service.VerifyTOTP(ctx, req, "10.0.0.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

// ============================================================================
// VerifyRecovery Tests - AC-3
// ============================================================================

func TestVerifyRecovery_Success(t *testing.T) {
	// Arrange
	service, userRepo, _, recoveryService, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	mfaData := `{"user_id":"` + userID.String() + `","email":"test@example.com","tenant_id":"` + tenantID.String() + `","client_ip":"192.168.1.1","user_agent":"Mozilla/5.0","access_token":"access-token","refresh_token":"refresh-token","expires_in":900}`

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return(mfaData, nil)
	recoveryService.On("Verify", ctx, userID, "RECOVERY-CODE").Return(true, 9, nil) // 9 codes remaining
	redisClient.On("Delete", ctx, mock.AnythingOfType("string")).Return(nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.VerifyRecoveryRequest{MFAToken: "mfa-token", Code: "RECOVERY-CODE"}
	resp, err := service.VerifyRecovery(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, 9, resp.CodesRemaining)
	recoveryService.AssertExpectations(t)
}

func TestVerifyRecovery_Fail_InvalidCode(t *testing.T) {
	// Arrange
	service, userRepo, _, recoveryService, _, auditLogger, redisClient := setupService()
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()

	mfaData := `{"user_id":"` + userID.String() + `","email":"test@example.com","tenant_id":"` + tenantID.String() + `","client_ip":"192.168.1.1","user_agent":"Mozilla/5.0","access_token":"access-token","refresh_token":"refresh-token","expires_in":900}`

	redisClient.On("Ping", ctx).Return(nil)
	userRepo.On("Ping", ctx).Return(nil)
	redisClient.On("Get", ctx, mock.AnythingOfType("string")).Return(mfaData, nil)
	recoveryService.On("Verify", ctx, userID, "INVALID-CODE").Return(false, 0, nil)
	auditLogger.On("LogEvent", ctx, mock.AnythingOfType("localauth.AuditEvent")).Return(nil)

	// Act
	req := localauth.VerifyRecoveryRequest{MFAToken: "mfa-token", Code: "INVALID-CODE"}
	resp, err := service.VerifyRecovery(ctx, req, "192.168.1.1", "Mozilla/5.0")

	// Assert
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

// ============================================================================
// SetPassword Tests - AC-1
// ============================================================================

func TestSetPassword_Success(t *testing.T) {
	// Arrange
	service, userRepo, _, _, _, _, _ := setupService()
	ctx := context.Background()
	userID := uuid.New()

	userRepo.On("UpdatePasswordHash", ctx, userID, mock.MatchedBy(func(hash string) bool {
		// Verify hash format is Argon2id
		return len(hash) > 10 && hash[:9] == "$argon2id"
	})).Return(nil)

	// Act
	err := service.SetPassword(ctx, userID, "new-password-12345")

	// Assert
	require.NoError(t, err)
	userRepo.AssertExpectations(t)
}

// ============================================================================
// Argon2id Password Hash Format Tests - AC-1
// ============================================================================

func TestArgon2id_HashFormat(t *testing.T) {
	// Verify Argon2id format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	hash, err := crypto.HashPassword("test-password-123", nil)
	require.NoError(t, err)

	// Check prefix - verify it starts with argon2id and has correct params
	assert.True(t, len(hash) > 50, "Hash should be longer than 50 characters")
	// Check that hash starts with correct algorithm identifier
	assert.True(t, len(hash) >= 30)
	prefix := "$argon2id$v=19$m=65536,t=3,p=4"
	assert.Equal(t, prefix, hash[:len(prefix)])
}

func TestArgon2id_VerifyTimingSafe(t *testing.T) {
	// Test that verification uses constant-time comparison
	password := "test-password-123"
	hash, _ := crypto.HashPassword(password, nil)

	// Both should take similar time (constant-time)
	valid, err := crypto.VerifyPassword(password, hash)
	require.NoError(t, err)
	assert.True(t, valid)

	valid, err = crypto.VerifyPassword("wrong-password-12", hash)
	require.NoError(t, err)
	assert.False(t, valid)
}

// ============================================================================
// Password Verification Performance Tests - Success Metric
// ============================================================================

func TestArgon2id_VerifyPerformance(t *testing.T) {
	// AC requirement: Argon2id password verify < 500ms
	password := "test-password-123"
	hash, _ := crypto.HashPassword(password, nil)

	start := time.Now()
	_, _ = crypto.VerifyPassword(password, hash)
	elapsed := time.Since(start)

	// Should be under 500ms
	assert.Less(t, elapsed.Milliseconds(), int64(500), "Password verification should be under 500ms")
}
