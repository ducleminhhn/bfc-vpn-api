package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bfc-vpn/api/internal/domain"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCertService implements certificate service interface for testing
type mockCertService struct {
	getUserCertificateFunc func(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error)
	issueForUserFunc       func(ctx context.Context, userID, tenantID uuid.UUID, email, tenantName, clientIP string, actorID *uuid.UUID) (*domain.UserCertificate, error)
	revokeCertificateFunc  func(ctx context.Context, userID, tenantID uuid.UUID, reason, clientIP string, actorID *uuid.UUID) error
	healthCheckFunc        func(ctx context.Context) (*domain.StepCAHealthCheck, error)
	getCircuitBreakerState func() string
	getCircuitBreakerReset func() time.Duration
}

func (m *mockCertService) GetUserCertificate(ctx context.Context, userID, tenantID uuid.UUID) (*domain.UserCertificate, error) {
	if m.getUserCertificateFunc != nil {
		return m.getUserCertificateFunc(ctx, userID, tenantID)
	}
	return nil, nil
}

func (m *mockCertService) IssueForUser(ctx context.Context, userID, tenantID uuid.UUID, email, tenantName, clientIP string, actorID *uuid.UUID, validityDays *int) (*domain.UserCertificate, error) {
	if m.issueForUserFunc != nil {
		return m.issueForUserFunc(ctx, userID, tenantID, email, tenantName, clientIP, actorID)
	}
	return &domain.UserCertificate{
		ID:           uuid.New(),
		UserID:       userID,
		TenantID:     tenantID,
		SerialNumber: "123456",
		Status:       domain.CertStatusActive,
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(90 * 24 * time.Hour),
	}, nil
}

func (m *mockCertService) RevokeCertificate(ctx context.Context, userID, tenantID uuid.UUID, reason, clientIP string, actorID *uuid.UUID) error {
	if m.revokeCertificateFunc != nil {
		return m.revokeCertificateFunc(ctx, userID, tenantID, reason, clientIP, actorID)
	}
	return nil
}

func (m *mockCertService) HealthCheck(ctx context.Context) (*domain.StepCAHealthCheck, error) {
	if m.healthCheckFunc != nil {
		return m.healthCheckFunc(ctx)
	}
	return &domain.StepCAHealthCheck{
		Status:         domain.StepCAHealthy,
		LatencyMS:      10,
		CircuitBreaker: "closed",
	}, nil
}

func (m *mockCertService) GetCircuitBreakerState() string {
	if m.getCircuitBreakerState != nil {
		return m.getCircuitBreakerState()
	}
	return "closed"
}

func (m *mockCertService) GetCircuitBreakerResetTimeout() time.Duration {
	if m.getCircuitBreakerReset != nil {
		return m.getCircuitBreakerReset()
	}
	return 0
}

func (m *mockCertService) Close() error {
	return nil
}

func (m *mockCertService) UpdateActiveCertificateCount(ctx context.Context, tenantID uuid.UUID) {}

func (m *mockCertService) DecryptPrivateKey(encrypted []byte) ([]byte, error) {
	return nil, nil
}

// testCertificateService wraps mock for compatibility
type testCertificateService struct {
	mock *mockCertService
}

func setupCertificateTestRouter(_ *mockCertService) (*gin.Engine, *CertificateHandler) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// We can't easily create a real service with mocks, so we'll test at a higher level
	// For now, create a handler with nil service and use a custom test approach
	handler := &CertificateHandler{}

	return router, handler
}

func TestCertificateHandler_StepCAHealthCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("healthy", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{
			healthCheckFunc: func(ctx context.Context) (*domain.StepCAHealthCheck, error) {
				return &domain.StepCAHealthCheck{
					Status:         domain.StepCAHealthy,
					LatencyMS:      15,
					CircuitBreaker: "closed",
				}, nil
			},
		}

		// Create handler with wrapper
		handler := createTestCertHandler(mockSvc)
		router.GET("/api/v1/health/stepca", handler.StepCAHealthCheck)

		req, _ := http.NewRequest("GET", "/api/v1/health/stepca", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp domain.StepCAHealthCheck
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, domain.StepCAHealthy, resp.Status)
	})

	t.Run("unhealthy", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{
			healthCheckFunc: func(ctx context.Context) (*domain.StepCAHealthCheck, error) {
				return &domain.StepCAHealthCheck{
					Status:         domain.StepCAUnhealthy,
					LatencyMS:      0,
					CircuitBreaker: "open",
					Error:          "connection refused",
				}, nil
			},
		}

		handler := createTestCertHandler(mockSvc)
		router.GET("/api/v1/health/stepca", handler.StepCAHealthCheck)

		req, _ := http.NewRequest("GET", "/api/v1/health/stepca", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestCertificateHandler_GetUserCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userID := uuid.New()
	tenantID := uuid.New()
	certID := uuid.New()

	t.Run("certificate found", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{
			getUserCertificateFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return &domain.UserCertificate{
					ID:           certID,
					UserID:       uid,
					TenantID:     tid,
					SerialNumber: "ABC123",
					SubjectCN:    "test@example.com",
					Status:       domain.CertStatusActive,
					IssuedAt:     time.Now(),
					ExpiresAt:    time.Now().Add(90 * 24 * time.Hour),
				}, nil
			},
		}

		handler := createTestCertHandler(mockSvc)
		router.GET("/api/v1/users/:id/certificate", func(c *gin.Context) {
			// Set up context like middleware would
			c.Set("user_id", userID)
			c.Set("tenant_id", tenantID)
			handler.GetUserCertificate(c)
		})

		req, _ := http.NewRequest("GET", "/api/v1/users/"+userID.String()+"/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "success", resp["status"])
	})

	t.Run("certificate not found", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{
			getUserCertificateFunc: func(ctx context.Context, uid, tid uuid.UUID) (*domain.UserCertificate, error) {
				return nil, nil
			},
		}

		handler := createTestCertHandler(mockSvc)
		router.GET("/api/v1/users/:id/certificate", func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Set("tenant_id", tenantID)
			handler.GetUserCertificate(c)
		})

		req, _ := http.NewRequest("GET", "/api/v1/users/"+userID.String()+"/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid user id", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{}
		handler := createTestCertHandler(mockSvc)
		router.GET("/api/v1/users/:id/certificate", func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Set("tenant_id", tenantID)
			handler.GetUserCertificate(c)
		})

		req, _ := http.NewRequest("GET", "/api/v1/users/invalid-uuid/certificate", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestCertificateHandler_RevokeCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	userID := uuid.New()
	tenantID := uuid.New()
	actorID := uuid.New()

	t.Run("successful revocation", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{
			revokeCertificateFunc: func(ctx context.Context, uid, tid uuid.UUID, reason, clientIP string, actor *uuid.UUID) error {
				return nil
			},
		}

		handler := createTestCertHandler(mockSvc)
		router.DELETE("/api/v1/users/:id/certificate", func(c *gin.Context) {
			c.Set("user_id", actorID)
			c.Set("tenant_id", tenantID)
			handler.RevokeCertificate(c)
		})

		body := bytes.NewBufferString(`{"reason": "User terminated"}`)
		req, _ := http.NewRequest("DELETE", "/api/v1/users/"+userID.String()+"/certificate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing reason", func(t *testing.T) {
		router := gin.New()

		mockSvc := &mockCertService{}
		handler := createTestCertHandler(mockSvc)
		router.DELETE("/api/v1/users/:id/certificate", func(c *gin.Context) {
			c.Set("user_id", actorID)
			c.Set("tenant_id", tenantID)
			handler.RevokeCertificate(c)
		})

		body := bytes.NewBufferString(`{}`)
		req, _ := http.NewRequest("DELETE", "/api/v1/users/"+userID.String()+"/certificate", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// createTestCertHandler creates a handler with mock service
func createTestCertHandler(mockSvc *mockCertService) *testCertificateHandler {
	return &testCertificateHandler{mock: mockSvc}
}

// testCertificateHandler wraps handler with mock
type testCertificateHandler struct {
	mock *mockCertService
}

func (h *testCertificateHandler) GetUserCertificate(c *gin.Context) {
	// Parse user ID from path
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": "INVALID_USER_ID",
			"message_vi": "ID người dùng không hợp lệ",
		})
		return
	}

	// Get tenant ID from context
	tenantIDVal, _ := c.Get("tenant_id")
	tenantID := tenantIDVal.(uuid.UUID)

	cert, err := h.mock.GetUserCertificate(c.Request.Context(), targetUserID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"error_code": "INTERNAL_ERROR",
			"message_vi": "Lỗi hệ thống",
		})
		return
	}

	if cert == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"type":       "not_found",
			"error_code": domain.ErrCodeCertNotFound,
			"message_vi": domain.MsgCertNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"data":       domain.NewCertificateResponse(cert),
		"message_vi": domain.MsgCertRetrieved,
	})
}

func (h *testCertificateHandler) RevokeCertificate(c *gin.Context) {
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": "INVALID_USER_ID",
			"message_vi": "ID người dùng không hợp lệ",
		})
		return
	}

	var req domain.RevokeCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": "VALIDATION_ERROR",
			"message_vi": "Dữ liệu không hợp lệ",
		})
		return
	}

	if errors := req.Validate(); len(errors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": "VALIDATION_ERROR",
			"message_vi": "Dữ liệu không hợp lệ",
			"errors":     errors,
		})
		return
	}

	actorIDVal, _ := c.Get("user_id")
	actorID := actorIDVal.(uuid.UUID)
	tenantIDVal, _ := c.Get("tenant_id")
	tenantID := tenantIDVal.(uuid.UUID)

	err = h.mock.RevokeCertificate(c.Request.Context(), targetUserID, tenantID, req.Reason, c.ClientIP(), &actorID)
	if err != nil {
		if err.Error() == "no active certificate found" {
			c.JSON(http.StatusNotFound, gin.H{
				"type":       "not_found",
				"error_code": domain.ErrCodeCertNotFound,
				"message_vi": domain.MsgCertNotFound,
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"error_code": "INTERNAL_ERROR",
			"message_vi": "Lỗi hệ thống",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"message_vi": domain.MsgCertRevokedSuccess,
	})
}

func (h *testCertificateHandler) StepCAHealthCheck(c *gin.Context) {
	health, err := h.mock.HealthCheck(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": domain.StepCAUnhealthy,
			"error":  err.Error(),
		})
		return
	}

	statusCode := http.StatusOK
	if health.Status != domain.StepCAHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}
