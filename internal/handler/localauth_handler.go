package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
	"github.com/bfc-vpn/api/internal/service/localauth"
)

// LocalAuthHandler handles local authentication endpoints
type LocalAuthHandler struct {
	service *localauth.Service
}

// NewLocalAuthHandler creates a new local auth handler
func NewLocalAuthHandler(service *localauth.Service) *LocalAuthHandler {
	return &LocalAuthHandler{service: service}
}

// Login handles POST /api/v1/auth/local/login
// @Summary Local login with email/password
// @Description Authenticate user using local PostgreSQL database (Dual Auth backup)
// @Tags Local Auth
// @Accept json
// @Produce json
// @Param request body localauth.LoginRequest true "Login credentials"
// @Success 200 {object} localauth.LoginResponse
// @Failure 400 {object} apperror.AppError "Validation error"
// @Failure 401 {object} apperror.AppError "Authentication failed"
// @Failure 423 {object} apperror.AppError "Account locked"
// @Failure 429 {object} apperror.AppError "Too many requests"
// @Failure 503 {object} apperror.AppError "Service unavailable"
// @Router /api/v1/auth/local/login [post]
func (h *LocalAuthHandler) Login(c *gin.Context) {
	start := time.Now()

	var req localauth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		localauth.RecordDuration("login", "error", time.Since(start).Seconds())
		c.JSON(http.StatusBadRequest, apperror.ValidationError(
			"Email và mật khẩu là bắt buộc. Mật khẩu tối thiểu 12 ký tự.",
			"Vui lòng kiểm tra lại thông tin đăng nhập.",
		))
		return
	}

	resp, err := h.service.Login(c.Request.Context(), req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		localauth.RecordDuration("login", "error", time.Since(start).Seconds())
		handleLocalAuthError(c, err)
		return
	}

	localauth.RecordDuration("login", "success", time.Since(start).Seconds())
	c.JSON(http.StatusOK, resp)
}

// VerifyTOTP handles POST /api/v1/auth/local/totp/verify
// @Summary Verify TOTP code for local auth MFA
// @Description Validate TOTP code after successful password authentication
// @Tags Local Auth
// @Accept json
// @Produce json
// @Param request body localauth.VerifyTOTPRequest true "MFA token and TOTP code"
// @Success 200 {object} localauth.VerifyTOTPResponse
// @Failure 400 {object} apperror.AppError "Validation error"
// @Failure 401 {object} apperror.AppError "Invalid TOTP code or expired session"
// @Failure 503 {object} apperror.AppError "Service unavailable"
// @Router /api/v1/auth/local/totp/verify [post]
func (h *LocalAuthHandler) VerifyTOTP(c *gin.Context) {
	start := time.Now()

	var req localauth.VerifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		localauth.RecordDuration("totp_verify", "error", time.Since(start).Seconds())
		c.JSON(http.StatusBadRequest, apperror.ValidationError(
			"MFA token và mã TOTP 6 chữ số là bắt buộc.",
			"Vui lòng kiểm tra lại thông tin.",
		))
		return
	}

	resp, err := h.service.VerifyTOTP(c.Request.Context(), req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		localauth.RecordDuration("totp_verify", "error", time.Since(start).Seconds())
		handleLocalAuthError(c, err)
		return
	}

	localauth.RecordDuration("totp_verify", "success", time.Since(start).Seconds())
	c.JSON(http.StatusOK, resp)
}

// VerifyRecovery handles POST /api/v1/auth/local/recovery/verify
// @Summary Verify recovery code for local auth MFA
// @Description Validate recovery code after successful password authentication
// @Tags Local Auth
// @Accept json
// @Produce json
// @Param request body localauth.VerifyRecoveryRequest true "MFA token and recovery code"
// @Success 200 {object} localauth.VerifyRecoveryResponse
// @Failure 400 {object} apperror.AppError "Validation error"
// @Failure 401 {object} apperror.AppError "Invalid recovery code or expired session"
// @Failure 503 {object} apperror.AppError "Service unavailable"
// @Router /api/v1/auth/local/recovery/verify [post]
func (h *LocalAuthHandler) VerifyRecovery(c *gin.Context) {
	start := time.Now()

	var req localauth.VerifyRecoveryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		localauth.RecordDuration("recovery_verify", "error", time.Since(start).Seconds())
		c.JSON(http.StatusBadRequest, apperror.ValidationError(
			"MFA token và mã khôi phục là bắt buộc.",
			"Vui lòng kiểm tra lại thông tin.",
		))
		return
	}

	resp, err := h.service.VerifyRecovery(c.Request.Context(), req, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		localauth.RecordDuration("recovery_verify", "error", time.Since(start).Seconds())
		handleLocalAuthError(c, err)
		return
	}

	localauth.RecordDuration("recovery_verify", "success", time.Since(start).Seconds())
	c.JSON(http.StatusOK, resp)
}

// handleLocalAuthError handles errors from local auth service
func handleLocalAuthError(c *gin.Context, err error) {
	if appErr, ok := err.(*apperror.AppError); ok {
		// Add Retry-After header for 503 and 429
		if appErr.Status == http.StatusServiceUnavailable {
			c.Header("Retry-After", "60")
		}
		if appErr.Status == http.StatusTooManyRequests {
			c.Header("Retry-After", "3600") // 1 hour for IP block
		}
		response.Error(c, appErr)
		return
	}
	response.Error(c, apperror.InternalError("Đã xảy ra lỗi không xác định", "Vui lòng thử lại sau"))
}
