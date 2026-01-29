package totp

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrKeyNotFound = errors.New("key not found")
)

// MockEncryptor implements Encryptor interface for testing
type MockEncryptor struct {
	EncryptFunc func(plaintext []byte) (string, error)
	DecryptFunc func(ciphertext string) ([]byte, error)
}

func (m *MockEncryptor) Encrypt(plaintext []byte) (string, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(plaintext)
	}
	return "encrypted:" + string(plaintext), nil
}

func (m *MockEncryptor) Decrypt(ciphertext string) ([]byte, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ciphertext)
	}
	if len(ciphertext) > 10 && ciphertext[:10] == "encrypted:" {
		return []byte(ciphertext[10:]), nil
	}
	return nil, errors.New("invalid ciphertext")
}

// MockRedisClient implements RedisClient interface for testing
type MockRedisClient struct {
	MFATokens    map[string]string
	PendingTOTP  map[string]string
	UsedCodes    map[string]bool
	FailedCounts map[string]int64
	
	// Error injection
	GetMFATokenErr        error
	SetTOTPPendingErr     error
	GetTOTPPendingErr     error
	MarkTOTPCodeUsedErr   error
	IsAccountLockedErr    error
	IncrementTOTPFailedErr error
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		MFATokens:    make(map[string]string),
		PendingTOTP:  make(map[string]string),
		UsedCodes:    make(map[string]bool),
		FailedCounts: make(map[string]int64),
	}
}

func (m *MockRedisClient) GetMFAToken(ctx context.Context, token string) (string, error) {
	if m.GetMFATokenErr != nil {
		return "", m.GetMFATokenErr
	}
	if data, ok := m.MFATokens[token]; ok {
		return data, nil
	}
	return "", ErrKeyNotFound
}

func (m *MockRedisClient) SetMFAToken(ctx context.Context, token, data string) error {
	m.MFATokens[token] = data
	return nil
}

func (m *MockRedisClient) DeleteMFAToken(ctx context.Context, token string) error {
	delete(m.MFATokens, token)
	return nil
}

func (m *MockRedisClient) SetTOTPPending(ctx context.Context, userID, data string) error {
	if m.SetTOTPPendingErr != nil {
		return m.SetTOTPPendingErr
	}
	m.PendingTOTP[userID] = data
	return nil
}

func (m *MockRedisClient) GetTOTPPending(ctx context.Context, userID string) (string, error) {
	if m.GetTOTPPendingErr != nil {
		return "", m.GetTOTPPendingErr
	}
	if data, ok := m.PendingTOTP[userID]; ok {
		return data, nil
	}
	return "", ErrKeyNotFound
}

func (m *MockRedisClient) DeleteTOTPPending(ctx context.Context, userID string) error {
	delete(m.PendingTOTP, userID)
	return nil
}

func (m *MockRedisClient) MarkTOTPCodeUsed(ctx context.Context, userID, code string) (bool, error) {
	if m.MarkTOTPCodeUsedErr != nil {
		return false, m.MarkTOTPCodeUsedErr
	}
	key := userID + ":" + code
	if m.UsedCodes[key] {
		return false, nil // Already used (replay)
	}
	m.UsedCodes[key] = true
	return true, nil
}

func (m *MockRedisClient) IsAccountLocked(ctx context.Context, userID string) (bool, time.Duration, error) {
	if m.IsAccountLockedErr != nil {
		return false, 0, m.IsAccountLockedErr
	}
	if count := m.FailedCounts[userID]; count >= 5 {
		return true, 15 * time.Minute, nil
	}
	return false, 0, nil
}

func (m *MockRedisClient) GetTOTPFailedCount(ctx context.Context, userID string) (int64, error) {
	return m.FailedCounts[userID], nil
}

func (m *MockRedisClient) IncrementTOTPFailed(ctx context.Context, userID string) (int64, error) {
	if m.IncrementTOTPFailedErr != nil {
		return 0, m.IncrementTOTPFailedErr
	}
	m.FailedCounts[userID]++
	return m.FailedCounts[userID], nil
}

func (m *MockRedisClient) ResetTOTPFailed(ctx context.Context, userID string) error {
	m.FailedCounts[userID] = 0
	return nil
}

// MockUserRepository implements UserRepository interface for testing
type MockUserRepository struct {
	Users map[uuid.UUID]*domain.User
	
	// Error injection
	GetByIDErr    error
	EnableTOTPErr error
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		Users: make(map[uuid.UUID]*domain.User),
	}
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	if m.GetByIDErr != nil {
		return nil, m.GetByIDErr
	}
	if user, ok := m.Users[id]; ok {
		return user, nil
	}
	return nil, ErrNotFound
}

func (m *MockUserRepository) EnableTOTP(ctx context.Context, userID uuid.UUID, encryptedSecret []byte) error {
	if m.EnableTOTPErr != nil {
		return m.EnableTOTPErr
	}
	if user, ok := m.Users[userID]; ok {
		user.TOTPEnabled = true
		user.TOTPSecretEncrypted = encryptedSecret
	}
	return nil
}

func (m *MockUserRepository) DisableTOTP(ctx context.Context, userID uuid.UUID) error {
	if user, ok := m.Users[userID]; ok {
		user.TOTPEnabled = false
		user.TOTPSecretEncrypted = nil
	}
	return nil
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	return nil
}

// MockAuditRepository implements AuditRepository interface for testing
type MockAuditRepository struct {
	Events []repository.AuditEvent
}

func (m *MockAuditRepository) LogEvent(ctx context.Context, event repository.AuditEvent) error {
	m.Events = append(m.Events, event)
	return nil
}
