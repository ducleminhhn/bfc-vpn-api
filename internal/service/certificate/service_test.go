package certificate

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/infrastructure/stepca"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCertRepository is a mock implementation of CertificateRepository
type mockCertRepository struct {
	createFunc       func(ctx context.Context, cert *domain.UserCertificate) error
	getByUserIDFunc  func(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error)
	getByIDFunc      func(ctx context.Context, certID, tenantID uuid.UUID) (*domain.UserCertificate, error)
	updateStatusFunc func(ctx context.Context, certID, tenantID uuid.UUID, status domain.CertificateStatus, reason string) error
	countActiveFunc  func(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

func (m *mockCertRepository) Create(ctx context.Context, cert *domain.UserCertificate) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, cert)
	}
	return nil
}

func (m *mockCertRepository) GetByUserID(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	if m.getByUserIDFunc != nil {
		return m.getByUserIDFunc(ctx, userID, tenantID)
	}
	return nil, nil
}

func (m *mockCertRepository) GetByID(ctx context.Context, certID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, certID, tenantID)
	}
	return nil, nil
}

func (m *mockCertRepository) UpdateStatus(ctx context.Context, certID, tenantID uuid.UUID, status domain.CertificateStatus, reason string) error {
	if m.updateStatusFunc != nil {
		return m.updateStatusFunc(ctx, certID, tenantID, status, reason)
	}
	return nil
}

func (m *mockCertRepository) CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	if m.countActiveFunc != nil {
		return m.countActiveFunc(ctx, tenantID)
	}
	return 0, nil
}

// mockAuditRepository is a mock implementation of CertificateAuditRepository
type mockAuditRepository struct {
	logFunc func(ctx context.Context, audit *domain.CertificateAudit) error
}

func (m *mockAuditRepository) Log(ctx context.Context, audit *domain.CertificateAudit) error {
	if m.logFunc != nil {
		return m.logFunc(ctx, audit)
	}
	return nil
}

// Helper to create a test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewServiceWithClient(t *testing.T) {
	mockClient := &stepca.MockClient{}
	mockCertRepo := &mockCertRepository{}
	mockAuditRepo := &mockAuditRepository{}
	encKey := make([]byte, 32)
	logger := testLogger()

	tests := []struct {
		name         string
		validityDays int
		expected     int
	}{
		{
			name:         "valid validity days",
			validityDays: 90,
			expected:     90,
		},
		{
			name:         "zero validity days defaults to 90",
			validityDays: 0,
			expected:     90,
		},
		{
			name:         "negative validity days defaults to 90",
			validityDays: -1,
			expected:     90,
		},
		{
			name:         "validity days > 365 defaults to 90",
			validityDays: 400,
			expected:     90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, tt.validityDays, logger)
			require.NotNil(t, svc)
			assert.Equal(t, tt.expected, svc.validityDays)
		})
	}
}

func TestService_GetUserCertificate(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	certID := uuid.New()

	tests := []struct {
		name     string
		setupFn  func(*mockCertRepository)
		wantCert bool
		wantErr  bool
	}{
		{
			name: "certificate found",
			setupFn: func(repo *mockCertRepository) {
				repo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return &domain.UserCertificate{
						ID:           certID,
						UserID:       uid,
						TenantID:     tid,
						SerialNumber: "123456",
						Status:       domain.CertStatusActive,
					}, nil
				}
			},
			wantCert: true,
			wantErr:  false,
		},
		{
			name: "certificate not found",
			setupFn: func(repo *mockCertRepository) {
				repo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return nil, nil
				}
			},
			wantCert: false,
			wantErr:  false,
		},
		{
			name: "repository error",
			setupFn: func(repo *mockCertRepository) {
				repo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return nil, errors.New("database error")
				}
			},
			wantCert: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCertRepo := &mockCertRepository{}
			tt.setupFn(mockCertRepo)

			mockClient := &stepca.MockClient{}
			mockAuditRepo := &mockAuditRepository{}
			encKey := make([]byte, 32)
			logger := testLogger()

			svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

			cert, err := svc.GetUserCertificate(context.Background(), userID, tenantID)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.wantCert {
				assert.NotNil(t, cert)
				assert.Equal(t, userID, cert.UserID)
			} else {
				assert.Nil(t, cert)
			}
		})
	}
}

func TestService_RevokeCertificate(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	certID := uuid.New()
	actorID := uuid.New()

	tests := []struct {
		name    string
		setupFn func(*mockCertRepository, *mockAuditRepository)
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful revocation",
			setupFn: func(certRepo *mockCertRepository, auditRepo *mockAuditRepository) {
				certRepo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return &domain.UserCertificate{
						ID:           certID,
						UserID:       uid,
						TenantID:     tid,
						SerialNumber: "123456",
						Status:       domain.CertStatusActive,
					}, nil
				}
				certRepo.updateStatusFunc = func(ctx context.Context, cid, tid uuid.UUID, status domain.CertificateStatus, reason string) error {
					return nil
				}
				auditRepo.logFunc = func(ctx context.Context, audit *domain.CertificateAudit) error {
					return nil
				}
			},
			wantErr: false,
		},
		{
			name: "certificate not found",
			setupFn: func(certRepo *mockCertRepository, auditRepo *mockAuditRepository) {
				certRepo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return nil, nil
				}
			},
			wantErr: true,
			errMsg:  "no active certificate found",
		},
		{
			name: "repository error on get",
			setupFn: func(certRepo *mockCertRepository, auditRepo *mockAuditRepository) {
				certRepo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return nil, errors.New("database error")
				}
			},
			wantErr: true,
			errMsg:  "get certificate",
		},
		{
			name: "repository error on update",
			setupFn: func(certRepo *mockCertRepository, auditRepo *mockAuditRepository) {
				certRepo.getByUserIDFunc = func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
					return &domain.UserCertificate{
						ID:           certID,
						UserID:       uid,
						TenantID:     tid,
						SerialNumber: "123456",
						Status:       domain.CertStatusActive,
					}, nil
				}
				certRepo.updateStatusFunc = func(ctx context.Context, cid, tid uuid.UUID, status domain.CertificateStatus, reason string) error {
					return errors.New("update failed")
				}
			},
			wantErr: true,
			errMsg:  "revoke certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCertRepo := &mockCertRepository{}
			mockAuditRepo := &mockAuditRepository{}
			tt.setupFn(mockCertRepo, mockAuditRepo)

			mockClient := &stepca.MockClient{}
			encKey := make([]byte, 32)
			logger := testLogger()

			svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

			err := svc.RevokeCertificate(context.Background(), userID, tenantID, "test reason", "127.0.0.1", &actorID)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestService_HealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		healthCheckErr error
		wantStatus     domain.StepCAHealthStatus
	}{
		{
			name:           "healthy",
			healthCheckErr: nil,
			wantStatus:     domain.StepCAHealthy,
		},
		{
			name:           "unhealthy",
			healthCheckErr: errors.New("connection refused"),
			wantStatus:     domain.StepCAUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &stepca.MockClient{
				HealthCheckFunc: func(ctx context.Context) error {
					return tt.healthCheckErr
				},
				CB: stepca.NewCircuitBreaker(stepca.CircuitBreakerConfig{
					FailureThreshold: 5,
					ResetTimeout:     30 * time.Second,
				}),
			}
			mockCertRepo := &mockCertRepository{}
			mockAuditRepo := &mockAuditRepository{}
			encKey := make([]byte, 32)
			logger := testLogger()

			svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

			health, err := svc.HealthCheck(context.Background())

			// HealthCheck always returns a result, even for errors
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, health.Status)
		})
	}
}

func TestService_GetCircuitBreakerState(t *testing.T) {
	t.Run("with circuit breaker", func(t *testing.T) {
		cb := stepca.NewCircuitBreaker(stepca.CircuitBreakerConfig{
			FailureThreshold: 5,
			ResetTimeout:     30 * time.Second,
		})
		mockClient := &stepca.MockClient{CB: cb}
		mockCertRepo := &mockCertRepository{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		state := svc.GetCircuitBreakerState()
		assert.Equal(t, "closed", state)
	})

	t.Run("without circuit breaker", func(t *testing.T) {
		mockClient := &stepca.MockClient{CB: nil}
		mockCertRepo := &mockCertRepository{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		state := svc.GetCircuitBreakerState()
		assert.Equal(t, "unknown", state)
	})
}

func TestService_GetCircuitBreakerResetTimeout(t *testing.T) {
	t.Run("with circuit breaker", func(t *testing.T) {
		cb := stepca.NewCircuitBreaker(stepca.CircuitBreakerConfig{
			FailureThreshold: 5,
			ResetTimeout:     30 * time.Second,
		})
		mockClient := &stepca.MockClient{CB: cb}
		mockCertRepo := &mockCertRepository{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		timeout := svc.GetCircuitBreakerResetTimeout()
		// Should be 0 when circuit breaker is closed
		assert.Equal(t, time.Duration(0), timeout)
	})

	t.Run("without circuit breaker", func(t *testing.T) {
		mockClient := &stepca.MockClient{CB: nil}
		mockCertRepo := &mockCertRepository{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		timeout := svc.GetCircuitBreakerResetTimeout()
		assert.Equal(t, time.Duration(0), timeout)
	})
}

func TestService_Close(t *testing.T) {
	closeCalled := false
	mockClient := &stepca.MockClient{
		CloseFunc: func() error {
			closeCalled = true
			return nil
		},
	}
	mockCertRepo := &mockCertRepository{}
	mockAuditRepo := &mockAuditRepository{}
	encKey := make([]byte, 32)
	logger := testLogger()

	svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

	err := svc.Close()
	assert.NoError(t, err)
	assert.True(t, closeCalled)
}

func TestService_UpdateActiveCertificateCount(t *testing.T) {
	tenantID := uuid.New()

	t.Run("success", func(t *testing.T) {
		mockCertRepo := &mockCertRepository{
			countActiveFunc: func(ctx context.Context, tid uuid.UUID) (int64, error) {
				return 42, nil
			},
		}
		mockClient := &stepca.MockClient{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		// Should not panic
		svc.UpdateActiveCertificateCount(context.Background(), tenantID)
	})

	t.Run("error", func(t *testing.T) {
		mockCertRepo := &mockCertRepository{
			countActiveFunc: func(ctx context.Context, tid uuid.UUID) (int64, error) {
				return 0, errors.New("count error")
			},
		}
		mockClient := &stepca.MockClient{}
		mockAuditRepo := &mockAuditRepository{}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		// Should not panic even with error
		svc.UpdateActiveCertificateCount(context.Background(), tenantID)
	})
}

func TestService_IssueForUser(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	actorID := uuid.New()

	t.Run("successful issuance - no existing cert", func(t *testing.T) {
		mockCertRepo := &mockCertRepository{
			getByUserIDFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return nil, nil
			},
			createFunc: func(ctx context.Context, cert *domain.UserCertificate) error {
				return nil
			},
		}
		mockAuditRepo := &mockAuditRepository{
			logFunc: func(ctx context.Context, audit *domain.CertificateAudit) error {
				return nil
			},
		}
		mockClient := &stepca.MockClient{
			IssueCertificateFunc: func(ctx context.Context, req *stepca.CertificateRequest) (*stepca.CertificateResponse, error) {
				return &stepca.CertificateResponse{
					CertificatePEM: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
					PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----"),
					SerialNumber:   "123456",
					IssuedAt:       time.Now(),
					ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
				}, nil
			},
		}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		cert, err := svc.IssueForUser(context.Background(), userID, tenantID, "test@example.com", "TestOrg", "127.0.0.1", &actorID, nil)

		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, userID, cert.UserID)
		assert.Equal(t, tenantID, cert.TenantID)
		assert.Equal(t, "123456", cert.SerialNumber)
	})

	t.Run("successful issuance - revokes existing cert", func(t *testing.T) {
		existingCertID := uuid.New()
		revokedCalled := false

		mockCertRepo := &mockCertRepository{
			getByUserIDFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return &domain.UserCertificate{
					ID:     existingCertID,
					Status: domain.CertStatusActive,
				}, nil
			},
			updateStatusFunc: func(ctx context.Context, cid, tid uuid.UUID, status domain.CertificateStatus, reason string) error {
				revokedCalled = true
				assert.Equal(t, existingCertID, cid)
				assert.Equal(t, domain.CertStatusRevoked, status)
				return nil
			},
			createFunc: func(ctx context.Context, cert *domain.UserCertificate) error {
				return nil
			},
		}
		mockAuditRepo := &mockAuditRepository{
			logFunc: func(ctx context.Context, audit *domain.CertificateAudit) error {
				return nil
			},
		}
		mockClient := &stepca.MockClient{
			IssueCertificateFunc: func(ctx context.Context, req *stepca.CertificateRequest) (*stepca.CertificateResponse, error) {
				return &stepca.CertificateResponse{
					CertificatePEM: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
					PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----"),
					SerialNumber:   "654321",
					IssuedAt:       time.Now(),
					ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
				}, nil
			},
		}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		cert, err := svc.IssueForUser(context.Background(), userID, tenantID, "test@example.com", "TestOrg", "127.0.0.1", &actorID, nil)

		require.NoError(t, err)
		assert.NotNil(t, cert)
		assert.True(t, revokedCalled, "existing certificate should be revoked")
	})

	t.Run("step-ca failure", func(t *testing.T) {
		mockCertRepo := &mockCertRepository{
			getByUserIDFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return nil, nil
			},
		}
		mockAuditRepo := &mockAuditRepository{}
		mockClient := &stepca.MockClient{
			IssueCertificateFunc: func(ctx context.Context, req *stepca.CertificateRequest) (*stepca.CertificateResponse, error) {
				return nil, errors.New("step-ca unavailable")
			},
		}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		cert, err := svc.IssueForUser(context.Background(), userID, tenantID, "test@example.com", "TestOrg", "127.0.0.1", &actorID, nil)

		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "issue certificate")
	})

	t.Run("repository create failure", func(t *testing.T) {
		mockCertRepo := &mockCertRepository{
			getByUserIDFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return nil, nil
			},
			createFunc: func(ctx context.Context, cert *domain.UserCertificate) error {
				return errors.New("database error")
			},
		}
		mockAuditRepo := &mockAuditRepository{}
		mockClient := &stepca.MockClient{
			IssueCertificateFunc: func(ctx context.Context, req *stepca.CertificateRequest) (*stepca.CertificateResponse, error) {
				return &stepca.CertificateResponse{
					CertificatePEM: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
					PrivateKeyPEM:  []byte("-----BEGIN EC PRIVATE KEY-----\nMOCK\n-----END EC PRIVATE KEY-----"),
					SerialNumber:   "123456",
					IssuedAt:       time.Now(),
					ExpiresAt:      time.Now().Add(90 * 24 * time.Hour),
				}, nil
			},
		}
		encKey := make([]byte, 32)
		logger := testLogger()

		svc := NewServiceWithClient(mockClient, mockCertRepo, mockAuditRepo, encKey, 90, logger)

		cert, err := svc.IssueForUser(context.Background(), userID, tenantID, "test@example.com", "TestOrg", "127.0.0.1", &actorID, nil)

		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "save certificate")
	})
}
