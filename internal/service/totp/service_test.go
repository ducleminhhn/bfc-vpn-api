package totp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/domain"
	totpGen "github.com/bfc-vpn/api/internal/infrastructure/totp"
)

func createTestService() (*Service, *MockRedisClient, *MockUserRepository, *MockAuditRepository) {
	cfg := config.TOTPConfig{
		Issuer:        "BFC-VPN-Test",
		EncryptionKey: "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
	}
	
	mockRedis := NewMockRedisClient()
	mockUserRepo := NewMockUserRepository()
	mockAuditRepo := &MockAuditRepository{}
	mockEncryptor := &MockEncryptor{}
	
	svc := NewServiceWithDeps(cfg, mockEncryptor, mockUserRepo, mockAuditRepo, mockRedis)
	return svc, mockRedis, mockUserRepo, mockAuditRepo
}

func setupMFAToken(mockRedis *MockRedisClient, token, userID, email, clientIP, userAgent string) {
	mfaData := MFATokenData{
		UserID:       userID,
		Email:        email,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		CreatedAt:    time.Now().Unix(),
	}
	mfaJSON, _ := json.Marshal(mfaData)
	mockRedis.MFATokens[token] = string(mfaJSON)
}

// === NewService Tests ===

func TestNewService_ValidKey(t *testing.T) {
	cfg := config.TOTPConfig{
		Issuer:        "BFC-VPN",
		EncryptionKey: "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
	}
	svc, err := NewService(cfg, nil, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewService_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"too short", "short"},
		{"invalid base64", "not-valid-base64!!!"},
		{"empty", ""},
		{"valid base64 wrong length", "YWJjZA=="}, // "abcd" = 4 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.TOTPConfig{
				Issuer:        "BFC-VPN",
				EncryptionKey: tt.key,
			}
			_, err := NewService(cfg, nil, nil, nil)
			assert.Error(t, err)
		})
	}
}

func TestNewServiceWithDeps(t *testing.T) {
	cfg := config.TOTPConfig{Issuer: "Test"}
	svc := NewServiceWithDeps(cfg, &MockEncryptor{}, nil, nil, nil)
	assert.NotNil(t, svc)
	assert.Equal(t, "Test", svc.cfg.Issuer)
}

// === Setup Tests ===

func TestSetup_Success(t *testing.T) {
	svc, mockRedis, mockUserRepo, mockAuditRepo := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		TOTPEnabled: false,
	}
	
	req := SetupRequest{MFAToken: mfaToken}
	resp, err := svc.Setup(ctx, req, clientIP, userAgent)
	
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Secret)
	assert.Contains(t, resp.OTPAuthURL, "otpauth://totp/")
	assert.Contains(t, mockRedis.PendingTOTP, userID.String())
	assert.Len(t, mockAuditRepo.Events, 1)
	assert.Equal(t, "totp_setup_initiated", mockAuditRepo.Events[0].EventType)
}

func TestSetup_InvalidMFAToken(t *testing.T) {
	svc, _, _, _ := createTestService()
	ctx := context.Background()
	
	req := SetupRequest{MFAToken: "invalid-token"}
	resp, err := svc.Setup(ctx, req, "192.168.1.1", "Mozilla/5.0")
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestSetup_TOTPAlreadyEnabled(t *testing.T) {
	svc, mockRedis, mockUserRepo, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		TOTPEnabled: true,
	}
	
	req := SetupRequest{MFAToken: mfaToken}
	resp, err := svc.Setup(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestSetup_IPMismatch(t *testing.T) {
	svc, mockRedis, _, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", "192.168.1.1", "Mozilla/5.0")
	
	req := SetupRequest{MFAToken: mfaToken}
	resp, err := svc.Setup(ctx, req, "10.0.0.1", "Mozilla/5.0")
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestSetup_UAMismatch(t *testing.T) {
	svc, mockRedis, _, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, "Mozilla/5.0")
	
	req := SetupRequest{MFAToken: mfaToken}
	resp, err := svc.Setup(ctx, req, clientIP, "curl/7.68.0")
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestSetup_UserNotFound(t *testing.T) {
	svc, mockRedis, _, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	
	req := SetupRequest{MFAToken: mfaToken}
	resp, err := svc.Setup(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

// === Verify Tests ===

func TestVerify_Success_ExistingTOTP(t *testing.T) {
	svc, mockRedis, mockUserRepo, mockAuditRepo := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	result, _ := totpGen.Generate("BFC-VPN-Test", "test@example.com")
	code, _ := totpGen.GenerateCode(result.Secret)
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:                   userID,
		Email:                "test@example.com",
		TOTPEnabled:          true,
		TOTPSecretEncrypted:  []byte("encrypted:" + result.Secret),
	}
	
	req := VerifyRequest{MFAToken: mfaToken, Code: code}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "test-access-token", resp.AccessToken)
	assert.Equal(t, 900, resp.ExpiresIn)
	
	assert.Greater(t, len(mockAuditRepo.Events), 0)
	lastEvent := mockAuditRepo.Events[len(mockAuditRepo.Events)-1]
	assert.Equal(t, "totp_verify_success", lastEvent.EventType)
}

func TestVerify_Success_SetupFlow(t *testing.T) {
	svc, mockRedis, mockUserRepo, mockAuditRepo := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	result, _ := totpGen.Generate("BFC-VPN-Test", "test@example.com")
	code, _ := totpGen.GenerateCode(result.Secret)
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		TOTPEnabled: false,
	}
	
	pendingData := map[string]interface{}{
		"encrypted_secret": "encrypted:" + result.Secret,
		"created_at":       time.Now().Unix(),
	}
	pendingJSON, _ := json.Marshal(pendingData)
	mockRedis.PendingTOTP[userID.String()] = string(pendingJSON)
	
	req := VerifyRequest{MFAToken: mfaToken, Code: code}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "success", resp.Status)
	assert.True(t, mockUserRepo.Users[userID].TOTPEnabled)
	
	_, exists := mockRedis.PendingTOTP[userID.String()]
	assert.False(t, exists)
	
	found := false
	for _, event := range mockAuditRepo.Events {
		if event.EventType == "totp_setup_completed" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestVerify_InvalidCode(t *testing.T) {
	svc, mockRedis, mockUserRepo, mockAuditRepo := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	result, _ := totpGen.Generate("BFC-VPN-Test", "test@example.com")
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:                   userID,
		Email:                "test@example.com",
		TOTPEnabled:          true,
		TOTPSecretEncrypted:  []byte("encrypted:" + result.Secret),
	}
	
	req := VerifyRequest{MFAToken: mfaToken, Code: "000000"}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.Equal(t, int64(1), mockRedis.FailedCounts[userID.String()])
	
	found := false
	for _, event := range mockAuditRepo.Events {
		if event.EventType == "totp_verify_failed" {
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestVerify_ReplayAttack(t *testing.T) {
	svc, mockRedis, mockUserRepo, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	result, _ := totpGen.Generate("BFC-VPN-Test", "test@example.com")
	code, _ := totpGen.GenerateCode(result.Secret)
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:                   userID,
		Email:                "test@example.com",
		TOTPEnabled:          true,
		TOTPSecretEncrypted:  []byte("encrypted:" + result.Secret),
	}
	
	mockRedis.UsedCodes[userID.String()+":"+code] = true
	
	req := VerifyRequest{MFAToken: mfaToken, Code: code}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestVerify_AccountLocked(t *testing.T) {
	svc, mockRedis, mockUserRepo, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		TOTPEnabled: true,
	}
	
	mockRedis.FailedCounts[userID.String()] = 5
	
	req := VerifyRequest{MFAToken: mfaToken, Code: "123456"}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

func TestVerify_PendingExpired(t *testing.T) {
	svc, mockRedis, mockUserRepo, _ := createTestService()
	ctx := context.Background()
	
	userID := uuid.New()
	mfaToken := "valid-mfa-token"
	clientIP := "192.168.1.1"
	userAgent := "Mozilla/5.0"
	
	setupMFAToken(mockRedis, mfaToken, userID.String(), "test@example.com", clientIP, userAgent)
	mockUserRepo.Users[userID] = &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		TOTPEnabled: false,
	}
	
	req := VerifyRequest{MFAToken: mfaToken, Code: "123456"}
	resp, err := svc.Verify(ctx, req, clientIP, userAgent)
	
	assert.Nil(t, resp)
	assert.Error(t, err)
}

// === Helper Function Tests ===

func TestCalculateBackoffDelay(t *testing.T) {
	tests := []struct {
		failedCount int64
		expected    time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 8 * time.Second},
		{6, 8 * time.Second},
		{10, 8 * time.Second},
	}
	
	for _, tt := range tests {
		delay := CalculateBackoffDelay(tt.failedCount)
		assert.Equal(t, tt.expected, delay, "failedCount=%d", tt.failedCount)
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123456", true},
		{"000000", true},
		{"999999", true},
		{"0", true},
		{"", true},
		{"12345a", false},
		{"a12345", false},
		{"12 34", false},
		{"12.34", false},
		{"-123", false},
		{"+123", false},
	}
	
	for _, tt := range tests {
		got := IsNumeric(tt.input)
		assert.Equal(t, tt.want, got, "input=%q", tt.input)
	}
}

// === Struct Tests ===

func TestSetupRequest_Fields(t *testing.T) {
	req := SetupRequest{MFAToken: "test-token"}
	assert.Equal(t, "test-token", req.MFAToken)
}

func TestVerifyRequest_Fields(t *testing.T) {
	req := VerifyRequest{MFAToken: "token", Code: "123456"}
	assert.Equal(t, "token", req.MFAToken)
	assert.Equal(t, "123456", req.Code)
}

func TestSetupResponse_Fields(t *testing.T) {
	resp := SetupResponse{
		Secret:     "JBSWY3DPEHPK3PXP",
		OTPAuthURL: "otpauth://totp/Test:user@example.com",
		QRCodeData: "base64data",
	}
	assert.NotEmpty(t, resp.Secret)
	assert.Contains(t, resp.OTPAuthURL, "otpauth://")
}

func TestVerifyResponse_Fields(t *testing.T) {
	resp := VerifyResponse{
		Status:       "success",
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresIn:    900,
		UserID:       "user-123",
	}
	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, 900, resp.ExpiresIn)
}

func TestMFATokenData_Fields(t *testing.T) {
	data := MFATokenData{
		UserID:       "user-123",
		Email:        "test@example.com",
		ClientIP:     "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		AccessToken:  "access",
		RefreshToken: "refresh",
		CreatedAt:    time.Now().Unix(),
	}
	assert.NotEmpty(t, data.UserID)
	assert.NotEmpty(t, data.Email)
	assert.Greater(t, data.CreatedAt, int64(0))
}

func TestGetFailedCount(t *testing.T) {
	svc, mockRedis, _, _ := createTestService()
	ctx := context.Background()
	
	userID := "test-user"
	mockRedis.FailedCounts[userID] = 3
	
	count, err := svc.GetFailedCount(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}
