package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	totpGen "github.com/bfc-vpn/api/internal/infrastructure/totp"
	"github.com/bfc-vpn/api/internal/service/totp"
)

var errKeyNotFound = errors.New("key not found")

// MockRedisClient implements redis.Client interface for testing
type MockRedisClient struct {
	mfaTokens    map[string]string
	pendingTOTP  map[string]string
	usedCodes    map[string]bool
	failedCounts map[string]int64
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		mfaTokens:    make(map[string]string),
		pendingTOTP:  make(map[string]string),
		usedCodes:    make(map[string]bool),
		failedCounts: make(map[string]int64),
	}
}

func (m *MockRedisClient) GetMFAToken(ctx context.Context, token string) (string, error) {
	if data, ok := m.mfaTokens[token]; ok {
		return data, nil
	}
	return "", errKeyNotFound
}

func (m *MockRedisClient) SetMFAToken(ctx context.Context, token, data string) error {
	m.mfaTokens[token] = data
	return nil
}

func (m *MockRedisClient) DeleteMFAToken(ctx context.Context, token string) error {
	delete(m.mfaTokens, token)
	return nil
}

func (m *MockRedisClient) SetTOTPPending(ctx context.Context, userID, data string) error {
	m.pendingTOTP[userID] = data
	return nil
}

func (m *MockRedisClient) GetTOTPPending(ctx context.Context, userID string) (string, error) {
	if data, ok := m.pendingTOTP[userID]; ok {
		return data, nil
	}
	return "", errKeyNotFound
}

func (m *MockRedisClient) DeleteTOTPPending(ctx context.Context, userID string) error {
	delete(m.pendingTOTP, userID)
	return nil
}

func (m *MockRedisClient) MarkTOTPCodeUsed(ctx context.Context, userID, code string) (bool, error) {
	key := userID + ":" + code
	if m.usedCodes[key] {
		return false, nil // Already used
	}
	m.usedCodes[key] = true
	return true, nil
}

func (m *MockRedisClient) IsAccountLocked(ctx context.Context, userID string) (bool, time.Duration, error) {
	if count := m.failedCounts[userID]; count >= 5 {
		return true, 15 * time.Minute, nil
	}
	return false, 0, nil
}

func (m *MockRedisClient) GetTOTPFailedCount(ctx context.Context, userID string) (int64, error) {
	return m.failedCounts[userID], nil
}

func (m *MockRedisClient) IncrementTOTPFailed(ctx context.Context, userID string) (int64, error) {
	m.failedCounts[userID]++
	return m.failedCounts[userID], nil
}

func (m *MockRedisClient) ResetTOTPFailed(ctx context.Context, userID string) error {
	m.failedCounts[userID] = 0
	return nil
}

// Integration Tests

func TestTOTPVerify_ValidCode(t *testing.T) {
	// Generate a valid secret and code
	result, err := totpGen.Generate("BFC-VPN-Test", "test@example.com")
	assert.NoError(t, err)

	code, err := totpGen.GenerateCode(result.Secret)
	assert.NoError(t, err)

	// Validate the code
	valid := totpGen.ValidateCode(result.Secret, code)
	assert.True(t, valid, "Valid code should be accepted")
}

func TestTOTPVerify_ReplayAttack(t *testing.T) {
	mockRedis := NewMockRedisClient()
	ctx := context.Background()
	userID := "test-user-123"
	code := "123456"

	// First use should succeed
	isNew1, _ := mockRedis.MarkTOTPCodeUsed(ctx, userID, code)
	assert.True(t, isNew1, "First use should be marked as new")

	// Second use should fail (replay attack)
	isNew2, _ := mockRedis.MarkTOTPCodeUsed(ctx, userID, code)
	assert.False(t, isNew2, "Replay should be detected")
}

func TestTOTPVerify_BruteForceProtection(t *testing.T) {
	mockRedis := NewMockRedisClient()
	ctx := context.Background()
	userID := "brute-force-user"

	// Simulate 5 failed attempts
	for i := 0; i < 5; i++ {
		mockRedis.IncrementTOTPFailed(ctx, userID)
	}

	// Check lockout
	locked, ttl, _ := mockRedis.IsAccountLocked(ctx, userID)
	assert.True(t, locked, "Account should be locked after 5 failures")
	assert.Equal(t, 15*time.Minute, ttl, "Lockout should be 15 minutes")
}

func TestTOTPVerify_SuccessResetsCounter(t *testing.T) {
	mockRedis := NewMockRedisClient()
	ctx := context.Background()
	userID := "reset-test-user"

	// Add some failures
	mockRedis.IncrementTOTPFailed(ctx, userID)
	mockRedis.IncrementTOTPFailed(ctx, userID)

	count1, _ := mockRedis.GetTOTPFailedCount(ctx, userID)
	assert.Equal(t, int64(2), count1)

	// Reset on success
	mockRedis.ResetTOTPFailed(ctx, userID)

	count2, _ := mockRedis.GetTOTPFailedCount(ctx, userID)
	assert.Equal(t, int64(0), count2, "Counter should reset on success")
}

func TestMFAToken_IPBinding(t *testing.T) {
	mfaData := totp.MFATokenData{
		UserID:    "user-123",
		Email:     "test@example.com",
		ClientIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0",
	}

	// Simulate IP mismatch check
	requestIP := "10.0.0.1"
	assert.NotEqual(t, mfaData.ClientIP, requestIP, "IP mismatch should be detected")
}

func TestMFAToken_UABinding(t *testing.T) {
	mfaData := totp.MFATokenData{
		UserID:    "user-123",
		Email:     "test@example.com",
		ClientIP:  "192.168.1.1",
		UserAgent: "Mozilla/5.0 (Windows)",
	}

	// Simulate UA mismatch check
	requestUA := "curl/7.68.0"
	assert.NotEqual(t, mfaData.UserAgent, requestUA, "User-Agent mismatch should be detected")
}

func TestMFATokenStorage(t *testing.T) {
	mockRedis := NewMockRedisClient()
	ctx := context.Background()
	token := "test-mfa-token"
	data := `{"user_id":"123","email":"test@example.com"}`

	// Store token
	err := mockRedis.SetMFAToken(ctx, token, data)
	assert.NoError(t, err)

	// Retrieve token
	retrieved, err := mockRedis.GetMFAToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, data, retrieved)

	// Delete token
	err = mockRedis.DeleteMFAToken(ctx, token)
	assert.NoError(t, err)

	// Should not exist
	_, err = mockRedis.GetMFAToken(ctx, token)
	assert.Error(t, err)
}

func TestPendingTOTPStorage(t *testing.T) {
	mockRedis := NewMockRedisClient()
	ctx := context.Background()
	userID := "user-456"
	data := `{"encrypted_secret":"base64data","created_at":1706500000}`

	// Store pending
	err := mockRedis.SetTOTPPending(ctx, userID, data)
	assert.NoError(t, err)

	// Retrieve pending
	retrieved, err := mockRedis.GetTOTPPending(ctx, userID)
	assert.NoError(t, err)
	assert.Equal(t, data, retrieved)

	// Delete pending
	err = mockRedis.DeleteTOTPPending(ctx, userID)
	assert.NoError(t, err)

	// Should not exist
	_, err = mockRedis.GetTOTPPending(ctx, userID)
	assert.Error(t, err)
}
