package handler

import (
	"net/http"

	"github.com/bfc-vpn/api/internal/service/dualauth"
	"github.com/gin-gonic/gin"
)

// DualAuthHandler handles dual auth endpoints
type DualAuthHandler struct {
	manager *dualauth.DualAuthManager
}

// NewDualAuthHandler creates a new dual auth handler
func NewDualAuthHandler(manager *dualauth.DualAuthManager) *DualAuthHandler {
	return &DualAuthHandler{manager: manager}
}

// LoginRequest represents login request
type DualAuthLoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=1"`
}

// Login handles unified login endpoint
func (h *DualAuthHandler) Login(c *gin.Context) {
	var req DualAuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"message_vi": "Dữ liệu không hợp lệ",
			"errors":     err.Error(),
		})
		return
	}

	result, err := h.manager.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		// Handle specific errors
		if err == dualauth.ErrAuthUnavailable {
			status, response := dualauth.CompleteOutageResponse()
			c.Header("Retry-After", "60")
			c.JSON(status, response)
			return
		}

		if err == dualauth.ErrPasswordOutOfSync {
			c.JSON(http.StatusUnauthorized, gin.H{
				"type":       "password_desync_error",
				"message_vi": "Mật khẩu đã được thay đổi. Vui lòng đợi Keycloak khôi phục.",
			})
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": "Đăng nhập không thành công",
		})
		return
	}

	if result != nil && !result.Success {
		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": result.ErrorVI,
			"error":      result.Error,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// VerifyTOTPRequest represents TOTP verification request
type VerifyTOTPRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	TOTPCode string `json:"totp_code" binding:"required,len=6"`
}

// VerifyTOTP handles TOTP verification
func (h *DualAuthHandler) VerifyTOTP(c *gin.Context) {
	var req VerifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"message_vi": "Dữ liệu không hợp lệ",
		})
		return
	}

	result, err := h.manager.VerifyTOTP(c.Request.Context(), req.MFAToken, req.TOTPCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": "Mã OTP không đúng",
		})
		return
	}

	if result != nil && !result.Success {
		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": result.ErrorVI,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// VerifyRecoveryRequest represents recovery code verification request
type VerifyRecoveryRequest struct {
	MFAToken     string `json:"mfa_token" binding:"required"`
	RecoveryCode string `json:"recovery_code" binding:"required"`
}

// VerifyRecovery handles recovery code verification
func (h *DualAuthHandler) VerifyRecovery(c *gin.Context) {
	var req VerifyRecoveryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"message_vi": "Dữ liệu không hợp lệ",
		})
		return
	}

	result, err := h.manager.VerifyRecovery(c.Request.Context(), req.MFAToken, req.RecoveryCode)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": "Mã khôi phục không đúng",
		})
		return
	}

	if result != nil && !result.Success {
		c.JSON(http.StatusUnauthorized, gin.H{
			"type":       "authentication_error",
			"message_vi": result.ErrorVI,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetAuthHealth returns current auth health status
func (h *DualAuthHandler) GetAuthHealth(c *gin.Context) {
	status := h.manager.GetStatus(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{
		"current_mode": status.CurrentMode,
	})
}

// GetDualStatus returns detailed dual auth status (admin only)
func (h *DualAuthHandler) GetDualStatus(c *gin.Context) {
	status := h.manager.GetStatus(c.Request.Context())
	c.JSON(http.StatusOK, status)
}

// ManualFailoverRequest represents manual failover request
type ManualFailoverRequest struct {
	Reason string `json:"reason" binding:"required"`
}

// ManualFailover triggers manual failover (admin only)
func (h *DualAuthHandler) ManualFailover(c *gin.Context) {
	var req ManualFailoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"message_vi": "Vui lòng cung cấp lý do",
		})
		return
	}

	adminID := c.GetString("user_id") // From auth middleware
	if adminID == "" {
		adminID = "unknown"
	}

	if err := h.manager.ManualFailover(c.Request.Context(), adminID, req.Reason); err != nil {
		if err == dualauth.ErrAlreadyInLocalMode {
			c.JSON(http.StatusConflict, gin.H{
				"type":       "conflict_error",
				"message_vi": "Hệ thống đang ở chế độ local",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"message_vi": "Không thể thực hiện failover",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message_vi": "Đã chuyển sang chế độ xác thực local",
	})
}

// ManualRecover triggers manual recovery (admin only)
func (h *DualAuthHandler) ManualRecover(c *gin.Context) {
	adminID := c.GetString("user_id")
	if adminID == "" {
		adminID = "unknown"
	}

	if err := h.manager.ManualRecovery(c.Request.Context(), adminID); err != nil {
		if err == dualauth.ErrAlreadyInKeycloakMode {
			c.JSON(http.StatusConflict, gin.H{
				"type":       "conflict_error",
				"message_vi": "Hệ thống đang ở chế độ Keycloak",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"message_vi": "Không thể khôi phục",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message_vi": "Đã khôi phục về chế độ Keycloak",
	})
}

// ResetFlapping resets flapping detection (admin only)
func (h *DualAuthHandler) ResetFlapping(c *gin.Context) {
	adminID := c.GetString("user_id")
	if adminID == "" {
		adminID = "unknown"
	}

	if err := h.manager.ResetFlapping(c.Request.Context(), adminID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"message_vi": "Không thể reset: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message_vi": "Đã reset trạng thái flapping",
	})
}

// SyncPasswordRequest represents password sync request (internal only)
type SyncPasswordRequest struct {
	UserID       string `json:"user_id" binding:"required"`
	PasswordHash string `json:"password_hash" binding:"required"`
}

// SyncPassword handles password sync (internal only)
func (h *DualAuthHandler) SyncPassword(c *gin.Context) {
	var req SyncPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"type":       "validation_error",
			"message_vi": "Dữ liệu không hợp lệ",
		})
		return
	}

	if err := h.manager.SyncPassword(c.Request.Context(), req.UserID, req.PasswordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"type":       "internal_error",
			"message_vi": "Không thể sync password",
			"error":      err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message_vi": "Password đã được sync",
	})
}

// GetSyncStatus returns current sync status (internal only)
func (h *DualAuthHandler) GetSyncStatus(c *gin.Context) {
	status := h.manager.GetSyncStatus(c.Request.Context())
	c.JSON(http.StatusOK, status)
}
