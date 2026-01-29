package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
	"github.com/bfc-vpn/api/internal/service/recovery"
)

// RecoveryHandler handles recovery code-related HTTP requests
type RecoveryHandler struct {
	service *recovery.Service
}

// NewRecoveryHandler creates a new recovery handler
func NewRecoveryHandler(service *recovery.Service) *RecoveryHandler {
	return &RecoveryHandler{service: service}
}

// Verify handles POST /api/v1/auth/recovery/verify
// Validates a recovery code and completes MFA authentication
func (h *RecoveryHandler) Verify(c *gin.Context) {
	var req recovery.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError(
			"Dữ liệu không hợp lệ",
			"Vui lòng cung cấp mfa_token và mã khôi phục",
		))
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Verify(c.Request.Context(), req, clientIP, userAgent)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	response.Success(c, resp)
}

// Regenerate handles POST /api/v1/auth/recovery/regenerate
// Regenerates all recovery codes (requires current TOTP)
func (h *RecoveryHandler) Regenerate(c *gin.Context) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		response.Error(c, apperror.AuthenticationError(
			"Không tìm thấy thông tin người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		response.Error(c, apperror.InternalError(
			"Lỗi xử lý ID",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	email, _ := c.Get("email")
	emailStr, _ := email.(string)

	var req recovery.RegenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError(
			"Dữ liệu không hợp lệ",
			"Vui lòng cung cấp mã TOTP hiện tại",
		))
		return
	}

	if len(req.TOTPCode) != 6 {
		response.Error(c, apperror.ValidationError(
			"Mã TOTP không hợp lệ",
			"Mã TOTP phải là 6 chữ số",
		))
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Regenerate(c.Request.Context(), userID, req, emailStr, clientIP, userAgent)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	response.Success(c, resp)
}

// GetStatus handles GET /api/v1/auth/recovery/status
// Returns the status of all recovery codes (used/unused)
func (h *RecoveryHandler) GetStatus(c *gin.Context) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		response.Error(c, apperror.AuthenticationError(
			"Không tìm thấy thông tin người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		response.Error(c, apperror.InternalError(
			"Lỗi xử lý ID",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	status, err := h.service.GetCodesStatus(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	response.Success(c, gin.H{
		"codes": status,
		"total": len(status),
		"used":  countUsed(status),
	})
}

// Download handles GET /api/v1/auth/recovery/download
// Returns recovery codes as plain text file (only during setup, from Redis temp storage)
// AC-3: Recovery Codes UI with Download option
func (h *RecoveryHandler) Download(c *gin.Context) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		response.Error(c, apperror.AuthenticationError(
			"Không tìm thấy thông tin người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		response.Error(c, apperror.InternalError(
			"Lỗi xử lý ID",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	codes, err := h.service.GetTemporaryCodes(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	var sb strings.Builder
	sb.WriteString("BFC-VPN Recovery Codes\n")
	sb.WriteString("=======================\n\n")
	sb.WriteString("LƯU Ý QUAN TRỌNG:\n")
	sb.WriteString("- Mỗi mã chỉ sử dụng được MỘT LẦN\n")
	sb.WriteString("- Lưu trữ an toàn, không chia sẻ với ai\n")
	sb.WriteString("- Sử dụng khi mất thiết bị xác thực\n\n")
	for i, code := range codes {
		sb.WriteString(fmt.Sprintf("%2d. %s\n", i+1, code))
	}
	sb.WriteString("\n---\n")
	sb.WriteString("Tạo lúc: " + time.Now().Format("2006-01-02 15:04:05"))

	c.Header("Content-Disposition", "attachment; filename=bfc-vpn-recovery-codes.txt")
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(sb.String()))
}

// Print handles GET /api/v1/auth/recovery/print
// Returns recovery codes as printable HTML (only during setup)
// AC-3: Recovery Codes UI with Print option
func (h *RecoveryHandler) Print(c *gin.Context) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		response.Error(c, apperror.AuthenticationError(
			"Không tìm thấy thông tin người dùng",
			"Vui lòng đăng nhập lại",
		))
		return
	}
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		response.Error(c, apperror.InternalError(
			"Lỗi xử lý ID",
			"Vui lòng đăng nhập lại",
		))
		return
	}

	codes, err := h.service.GetTemporaryCodes(c.Request.Context(), userID)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	var codesHTML strings.Builder
	for i, code := range codes {
		codesHTML.WriteString(fmt.Sprintf(`<div class="code">%2d. <strong>%s</strong></div>`, i+1, code))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>BFC-VPN Recovery Codes</title>
    <style>
        body { font-family: "IBM Plex Mono", "JetBrains Mono", monospace; max-width: 400px; margin: 50px auto; background: #0a0a0a; color: #ff9500; }
        h1 { color: #ff9500; font-size: 18px; border-bottom: 2px solid #ff9500; padding-bottom: 10px; }
        .warning { background: #1a0f05; padding: 15px; margin: 20px 0; border-left: 4px solid #ff9500; font-size: 14px; }
        .warning ul { margin: 10px 0 0 0; padding-left: 20px; }
        .codes { font-family: "JetBrains Mono", monospace; font-size: 16px; margin-top: 20px; }
        .code { padding: 8px 0; border-bottom: 1px dashed #995500; }
        .code strong { color: #ffb340; letter-spacing: 2px; }
        .footer { margin-top: 30px; font-size: 12px; color: #995500; border-top: 1px solid #333; padding-top: 15px; }
        @media print { 
            body { color: #000; background: #fff; } 
            h1 { color: #000; border-color: #000; }
            .warning { border-color: #000; background: #f0f0f0; color: #000; } 
            .code { border-color: #ccc; }
            .code strong { color: #000; }
            .footer { color: #666; border-color: #ccc; }
        }
    </style>
</head>
<body>
    <h1>🔐 BFC-VPN Recovery Codes</h1>
    <div class="warning">
        <strong>⚠️ LƯU Ý QUAN TRỌNG:</strong>
        <ul>
            <li>Mỗi mã chỉ sử dụng được <strong>MỘT LẦN</strong></li>
            <li>Lưu trữ an toàn, không chia sẻ với ai</li>
            <li>Sử dụng khi mất thiết bị xác thực</li>
        </ul>
    </div>
    <div class="codes">%s</div>
    <div class="footer">
        📅 Tạo lúc: %s<br>
        🏢 BFC-Metal-VPN Security System
    </div>
    <script>window.print();</script>
</body>
</html>`, codesHTML.String(), time.Now().Format("2006-01-02 15:04:05"))

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func countUsed(status []bool) int {
	count := 0
	for _, used := range status {
		if used {
			count++
		}
	}
	return count
}
