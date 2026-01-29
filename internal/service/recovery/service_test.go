package recovery_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"github.com/bfc-vpn/api/internal/domain"
	recoveryGen "github.com/bfc-vpn/api/internal/infrastructure/recovery"
	"github.com/bfc-vpn/api/internal/service/recovery"
)

func TestGenerateAndStore_Success(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mocks
	recoveryRepo.On("DeleteAllCodes", mock.Anything, userID).Return(nil)
	recoveryRepo.On("CreateCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).Return(nil)
	redisClient.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("LogEvent", mock.Anything, mock.Anything).Return(nil)

	// Execute
	resp, err := service.GenerateAndStore(context.Background(), userID, "test@example.com", "127.0.0.1", "test-ua")

	// Assert
	require.NoError(t, err)
	assert.Len(t, resp.Codes, 10, "should generate 10 codes")
	for _, code := range resp.Codes {
		assert.Regexp(t, `^[A-Z0-9]{4}-[A-Z0-9]{4}$`, code, "code format should be XXXX-XXXX")
	}
	recoveryRepo.AssertExpectations(t)
	auditRepo.AssertExpectations(t)
}

func TestVerify_ValidCode(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()
	codeID := uuid.New()
	plainCode := "ABCD-EFGH"
	normalized := recoveryGen.NormalizeCode(plainCode)
	hashedCode, _ := bcrypt.GenerateFromPassword([]byte(normalized), 10)

	// Setup MFA token data
	mfaData := map[string]interface{}{
		"user_id":       userID.String(),
		"email":         "test@example.com",
		"client_ip":     "127.0.0.1",
		"user_agent":    "test-ua",
		"access_token":  "access-token-123",
		"refresh_token": "refresh-token-123",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return key != "mfa_token:valid-token"
	})).Return("", nil) // No lockout

	recoveryRepo.On("GetUnusedCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{
		{ID: codeID, UserID: userID, CodeHash: string(hashedCode), CodeIndex: 0},
	}, nil)
	recoveryRepo.On("MarkCodeUsed", mock.Anything, userID, codeID).Return(true, nil)
	recoveryRepo.On("CountUnusedCodes", mock.Anything, userID).Return(int64(9), nil)
	redisClient.On("Delete", mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("LogEvent", mock.Anything, mock.Anything).Return(nil)

	// Execute
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: plainCode}
	resp, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "access-token-123", resp.AccessToken)
	assert.Equal(t, "refresh-token-123", resp.RefreshToken)
	assert.Equal(t, 9, resp.CodesRemaining)
}

func TestVerify_InvalidCode(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()
	codeID := uuid.New()
	hashedCode, _ := bcrypt.GenerateFromPassword([]byte("WRONGCODE"), 10)

	// Setup MFA token data
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "127.0.0.1",
		"user_agent": "test-ua",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return key != "mfa_token:valid-token"
	})).Return("", nil)

	recoveryRepo.On("GetUnusedCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{
		{ID: codeID, UserID: userID, CodeHash: string(hashedCode), CodeIndex: 0},
	}, nil)
	redisClient.On("Incr", mock.Anything, mock.Anything).Return(int64(1), nil)
	redisClient.On("Expire", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	auditRepo.On("LogEvent", mock.Anything, mock.Anything).Return(nil)

	// Execute
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert - AppError.Error() returns Title
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerify_BruteForceLockout(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup MFA token data
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "127.0.0.1",
		"user_agent": "test-ua",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks - 5 failed attempts (locked out)
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return key != "mfa_token:valid-token"
	})).Return("5", nil)
	redisClient.On("TTL", mock.Anything, mock.Anything).Return(10*time.Minute, nil)

	// Execute
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert - AppError.Error() returns Title
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerify_InvalidFormat_TOTP(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup MFA token data
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "127.0.0.1",
		"user_agent": "test-ua",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return key != "mfa_token:valid-token"
	})).Return("", nil)

	// Execute - using TOTP format (6 digits)
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "123456"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert - AppError.Error() returns Title "Dữ liệu không hợp lệ"
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Dữ liệu không hợp lệ")
}

func TestRegenerate_RequiresTOTP(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mocks - TOTP validation fails
	totpService.On("ValidateCode", mock.Anything, userID, "123456").Return(false, nil)
	auditRepo.On("LogEvent", mock.Anything, mock.Anything).Return(nil)

	// Execute
	req := recovery.RegenerateRequest{TOTPCode: "123456"}
	_, err := service.Regenerate(context.Background(), userID, req, "test@example.com", "127.0.0.1", "test-ua")

	// Assert - AppError.Error() returns Title
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestRegenerate_Success(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mocks - TOTP validation succeeds
	totpService.On("ValidateCode", mock.Anything, userID, "123456").Return(true, nil)
	auditRepo.On("LogEvent", mock.Anything, mock.Anything).Return(nil)
	recoveryRepo.On("DeleteAllCodes", mock.Anything, userID).Return(nil)
	recoveryRepo.On("CreateCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).Return(nil)
	redisClient.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// Execute
	req := recovery.RegenerateRequest{TOTPCode: "123456"}
	resp, err := service.Regenerate(context.Background(), userID, req, "test@example.com", "127.0.0.1", "test-ua")

	// Assert
	require.NoError(t, err)
	assert.Len(t, resp.Codes, 10)
}

func TestGetTemporaryCodes_Success(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mock
	codes := []string{"ABCD-EFGH", "IJKL-MNOP"}
	codesJSON, _ := json.Marshal(codes)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return true
	})).Return(string(codesJSON), nil)

	// Execute
	result, err := service.GetTemporaryCodes(context.Background(), userID)

	// Assert
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestGetTemporaryCodes_NotFound(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mock - key not found
	redisClient.On("Get", mock.Anything, mock.Anything).Return("", assert.AnError)

	// Execute
	_, err := service.GetTemporaryCodes(context.Background(), userID)

	// Assert
	require.Error(t, err)
}

func TestGetCodesStatus(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	usedAt := time.Now()
	// Setup mock - 2 codes, 1 used
	recoveryRepo.On("GetAllCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{
		{ID: uuid.New(), CodeIndex: 0, UsedAt: nil},
		{ID: uuid.New(), CodeIndex: 1, UsedAt: &usedAt},
	}, nil)

	// Execute
	status, err := service.GetCodesStatus(context.Background(), userID)

	// Assert
	require.NoError(t, err)
	assert.Len(t, status, 2)
	assert.False(t, status[0], "first code should not be used")
	assert.True(t, status[1], "second code should be used")
}

func TestValidateCode_Success(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()
	codeID := uuid.New()
	plainCode := "ABCD-EFGH"
	normalized := recoveryGen.NormalizeCode(plainCode)
	hashedCode, _ := bcrypt.GenerateFromPassword([]byte(normalized), 10)

	// Setup mocks
	recoveryRepo.On("GetUnusedCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{
		{ID: codeID, UserID: userID, CodeHash: string(hashedCode), CodeIndex: 0},
	}, nil)

	// Execute
	valid, err := service.ValidateCode(context.Background(), userID, plainCode)

	// Assert
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateCode_InvalidFormat(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()

	// Execute - TOTP format
	valid, err := service.ValidateCode(context.Background(), userID, "123456")

	// Assert
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestValidateCode_NoMatch(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()
	codeID := uuid.New()
	hashedCode, _ := bcrypt.GenerateFromPassword([]byte("DIFFERENTCODE"), 10)

	// Setup mocks
	recoveryRepo.On("GetUnusedCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{
		{ID: codeID, UserID: userID, CodeHash: string(hashedCode), CodeIndex: 0},
	}, nil)

	// Execute
	valid, err := service.ValidateCode(context.Background(), userID, "ABCD-EFGH")

	// Assert
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestVerify_NoCodesRemaining(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()

	// Setup MFA token data
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "127.0.0.1",
		"user_agent": "test-ua",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)
	redisClient.On("Get", mock.Anything, mock.MatchedBy(func(key string) bool {
		return key != "mfa_token:valid-token"
	})).Return("", nil)

	// No codes remaining
	recoveryRepo.On("GetUnusedCodes", mock.Anything, userID).Return([]*domain.RecoveryCode{}, nil)

	// Execute
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerify_ExpiredMFAToken(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	// Setup mocks - MFA token not found
	redisClient.On("Get", mock.Anything, "mfa_token:expired-token").Return("", assert.AnError)

	// Execute
	req := recovery.VerifyRequest{MFAToken: "expired-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerify_IPBindingFailure(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()

	// Setup MFA token data with different IP
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "192.168.1.1", // Different IP
		"user_agent": "test-ua",
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)

	// Execute with different IP
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestVerify_UABindingFailure(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)

	userID := uuid.New()

	// Setup MFA token data with different UA
	mfaData := map[string]interface{}{
		"user_id":    userID.String(),
		"email":      "test@example.com",
		"client_ip":  "127.0.0.1",
		"user_agent": "different-browser", // Different UA
	}
	mfaJSON, _ := json.Marshal(mfaData)

	// Setup mocks
	redisClient.On("Get", mock.Anything, "mfa_token:valid-token").Return(string(mfaJSON), nil)

	// Execute with different UA
	req := recovery.VerifyRequest{MFAToken: "valid-token", Code: "ABCD-EFGH"}
	_, err := service.Verify(context.Background(), req, "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Xác thực thất bại")
}

func TestClearTemporaryCodes(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mock
	redisClient.On("Delete", mock.Anything, mock.Anything).Return(nil)

	// Execute - should not panic
	service.ClearTemporaryCodes(context.Background(), userID)

	// Assert
	redisClient.AssertExpectations(t)
}

func TestRegenerate_TOTPServiceNil(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	redisClient := new(MockRedisClient)

	// Create service without TOTP service
	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, nil, redisClient)
	userID := uuid.New()

	// Execute
	req := recovery.RegenerateRequest{TOTPCode: "123456"}
	_, err := service.Regenerate(context.Background(), userID, req, "test@example.com", "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Lỗi hệ thống")
}

func TestGenerateAndStore_CreateCodesError(t *testing.T) {
	recoveryRepo := new(MockRecoveryRepository)
	userRepo := new(MockUserRepository)
	auditRepo := new(MockAuditRepository)
	totpService := new(MockTOTPService)
	redisClient := new(MockRedisClient)

	service := recovery.NewService(recoveryRepo, userRepo, auditRepo, totpService, redisClient)
	userID := uuid.New()

	// Setup mocks - CreateCodes fails
	recoveryRepo.On("DeleteAllCodes", mock.Anything, userID).Return(nil)
	recoveryRepo.On("CreateCodes", mock.Anything, userID, mock.AnythingOfType("[]string")).Return(assert.AnError)

	// Execute
	_, err := service.GenerateAndStore(context.Background(), userID, "test@example.com", "127.0.0.1", "test-ua")

	// Assert
	require.Error(t, err)
}
