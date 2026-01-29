package recovery_test

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/repository"
)

// MockRecoveryRepository mocks RecoveryRepository interface
type MockRecoveryRepository struct {
	mock.Mock
}

func (m *MockRecoveryRepository) CreateCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	args := m.Called(ctx, userID, codeHashes)
	return args.Error(0)
}

func (m *MockRecoveryRepository) GetUnusedCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.RecoveryCode), args.Error(1)
}

func (m *MockRecoveryRepository) GetAllCodes(ctx context.Context, userID uuid.UUID) ([]*domain.RecoveryCode, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.RecoveryCode), args.Error(1)
}

func (m *MockRecoveryRepository) MarkCodeUsed(ctx context.Context, userID, codeID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, codeID)
	return args.Bool(0), args.Error(1)
}

func (m *MockRecoveryRepository) DeleteAllCodes(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRecoveryRepository) CountUnusedCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

// MockUserRepository mocks UserRepository interface
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// MockRedisClient mocks RedisClient interface
type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	args := m.Called(ctx, key)
	return args.String(0), args.Error(1)
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	args := m.Called(ctx, key, value, expiration)
	return args.Error(0)
}

func (m *MockRedisClient) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
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

// MockTOTPService mocks TOTPService interface
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	args := m.Called(ctx, userID, code)
	return args.Bool(0), args.Error(1)
}

// MockAuditRepository mocks AuditRepository interface
type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) LogEvent(ctx context.Context, event repository.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}
