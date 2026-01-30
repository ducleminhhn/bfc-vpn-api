package handler

import (
	"net/http"

	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
	"github.com/bfc-vpn/api/internal/service/certificate"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CertificateHandler handles certificate API requests
type CertificateHandler struct {
	certService *certificate.Service
}

// NewCertificateHandler creates a new certificate handler
func NewCertificateHandler(certService *certificate.Service) *CertificateHandler {
	return &CertificateHandler{certService: certService}
}

// GetUserCertificate handles GET /api/v1/users/:id/certificate (AC-4)
func (h *CertificateHandler) GetUserCertificate(c *gin.Context) {
	// Parse user ID from path
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, apperror.ValidationError(
			"ID người dùng không hợp lệ",
			"Vui lòng cung cấp UUID hợp lệ",
		))
		return
	}

	// Get current user context
	currentUserID, tenantID, err := h.extractUserContext(c)
	if err != nil {
		response.Error(c, apperror.AuthenticationError(
			"Không thể xác định người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	// Authorization check: user can only access their own certificate unless admin
	isAdmin := h.isAdmin(c)
	if targetUserID != currentUserID && !isAdmin {
		response.Error(c, apperror.AuthorizationError(
			"Không có quyền truy cập",
			"Bạn chỉ có thể xem certificate của chính mình",
		))
		return
	}

	// Get certificate
	cert, err := h.certService.GetUserCertificate(c.Request.Context(), targetUserID, tenantID)
	if err != nil {
		response.Error(c, apperror.InternalError(
			"Không thể lấy thông tin certificate",
			"Vui lòng thử lại sau",
		).WithError(err))
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

// IssueCertificate handles POST /api/v1/users/:id/certificate (AC-1)
// Admin-only endpoint to issue/reissue certificate for a user
func (h *CertificateHandler) IssueCertificate(c *gin.Context) {
	// Parse target user ID from path
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, apperror.ValidationError(
			"ID người dùng không hợp lệ",
			"Vui lòng cung cấp UUID hợp lệ",
		))
		return
	}

	// Parse request body (optional validity_days)
	var req domain.IssueCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" {
		response.Error(c, apperror.ValidationError(
			"Dữ liệu không hợp lệ",
			"Vui lòng kiểm tra lại",
		))
		return
	}

	// Validate request
	if errors := req.Validate(); len(errors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": domain.ErrCodeCertValidityInvalid,
			"message_vi": domain.MsgCertValidityInvalid,
			"errors":     errors,
		})
		return
	}

	// Get actor context
	actorID, tenantID, err := h.extractUserContext(c)
	if err != nil {
		response.Error(c, apperror.AuthenticationError(
			"Không thể xác định người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	clientIP := c.ClientIP()

	// TODO: Get user email and tenant name from user service
	// For now, we need these from query params or request body
	email := c.Query("email")
	tenantName := c.Query("tenant_name")
	if email == "" {
		email = targetUserID.String() + "@placeholder.local"
	}
	if tenantName == "" {
		tenantName = "BFC-VPN"
	}

	// Check circuit breaker state
	cbState := h.certService.GetCircuitBreakerState()
	if cbState == "open" {
		resetTime := h.certService.GetCircuitBreakerResetTimeout()
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"type":                "service_unavailable",
			"error_code":          domain.ErrCodeCertCircuitOpen,
			"message_vi":          domain.MsgCertCircuitOpen,
			"retry_after_seconds": int(resetTime.Seconds()),
		})
		return
	}

	// Issue certificate - pass validity days if specified in request
	var validityDays *int
	if req.ValidityDays > 0 {
		validityDays = &req.ValidityDays
	}
	cert, err := h.certService.IssueForUser(
		c.Request.Context(),
		targetUserID,
		tenantID,
		email,
		tenantName,
		clientIP,
		&actorID,
		validityDays,
	)
	if err != nil {
		// Check if circuit breaker is now open
		newCBState := h.certService.GetCircuitBreakerState()
		if newCBState == "open" {
			resetTime := h.certService.GetCircuitBreakerResetTimeout()
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"type":                "service_unavailable",
				"error_code":          domain.ErrCodeCertCircuitOpen,
				"message_vi":          domain.MsgCertCircuitOpen,
				"retry_after_seconds": int(resetTime.Seconds()),
			})
			return
		}

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"type":       "service_unavailable",
			"error_code": domain.ErrCodeCertIssuanceFailed,
			"message_vi": domain.MsgCertIssuanceFailed,
			"error":      err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status": "success",
		"data": domain.CertificateIssuedResponse{
			UserID:        cert.UserID,
			CertificateID: cert.ID,
			SerialNumber:  cert.SerialNumber,
			IssuedAt:      cert.IssuedAt,
			ExpiresAt:     cert.ExpiresAt,
			Status:        string(cert.Status),
		},
		"message_vi": domain.MsgCertIssued,
	})
}

// RevokeCertificate handles DELETE /api/v1/users/:id/certificate (AC-4)
// Admin-only endpoint to revoke a user's certificate
func (h *CertificateHandler) RevokeCertificate(c *gin.Context) {
	// Parse target user ID from path
	targetUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.Error(c, apperror.ValidationError(
			"ID người dùng không hợp lệ",
			"Vui lòng cung cấp UUID hợp lệ",
		))
		return
	}

	// Parse request body
	var req domain.RevokeCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError(
			"Dữ liệu không hợp lệ",
			"Vui lòng cung cấp lý do thu hồi",
		))
		return
	}

	// Validate request
	if errors := req.Validate(); len(errors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"error_code": "VALIDATION_ERROR",
			"message_vi": "Dữ liệu không hợp lệ",
			"errors":     errors,
		})
		return
	}

	// Get actor context
	actorID, tenantID, err := h.extractUserContext(c)
	if err != nil {
		response.Error(c, apperror.AuthenticationError(
			"Không thể xác định người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	clientIP := c.ClientIP()

	// Revoke certificate
	err = h.certService.RevokeCertificate(
		c.Request.Context(),
		targetUserID,
		tenantID,
		req.Reason,
		clientIP,
		&actorID,
	)
	if err != nil {
		if err.Error() == "no active certificate found" {
			c.JSON(http.StatusNotFound, gin.H{
				"type":       "not_found",
				"error_code": domain.ErrCodeCertNotFound,
				"message_vi": domain.MsgCertNotFound,
			})
			return
		}

		response.Error(c, apperror.InternalError(
			"Không thể thu hồi certificate",
			"Vui lòng thử lại sau",
		).WithError(err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"message_vi": domain.MsgCertRevokedSuccess,
	})
}

// StepCAHealthCheck handles GET /api/v1/health/stepca (AC-5)
func (h *CertificateHandler) StepCAHealthCheck(c *gin.Context) {
	health, err := h.certService.HealthCheck(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":     domain.StepCAUnhealthy,
			"error":      err.Error(),
			"error_code": domain.ErrCodeCertIssuanceFailed,
			"message_vi": domain.MsgCertIssuanceFailed,
		})
		return
	}

	statusCode := http.StatusOK
	if health.Status != domain.StepCAHealthy {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// extractUserContext extracts user and tenant IDs from context
func (h *CertificateHandler) extractUserContext(c *gin.Context) (userID, tenantID uuid.UUID, err error) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, uuid.Nil, apperror.AuthenticationError("Missing user ID", "")
	}

	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return uuid.Nil, uuid.Nil, apperror.AuthenticationError("Missing tenant ID", "")
	}

	// Handle both string and uuid.UUID types
	switch v := userIDVal.(type) {
	case uuid.UUID:
		userID = v
	case string:
		userID, err = uuid.Parse(v)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}
	}

	switch v := tenantIDVal.(type) {
	case uuid.UUID:
		tenantID = v
	case string:
		tenantID, err = uuid.Parse(v)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}
	}

	return userID, tenantID, nil
}

// isAdmin checks if the current user has admin role
func (h *CertificateHandler) isAdmin(c *gin.Context) bool {
	roleVal, exists := c.Get("role")
	if !exists {
		return false
	}

	role, ok := roleVal.(string)
	if !ok {
		return false
	}

	return role == "admin" || role == "super_admin"
}
