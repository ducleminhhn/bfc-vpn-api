package recovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	recoveryGen "github.com/bfc-vpn/api/internal/infrastructure/recovery"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/repository"
)

const (
	BcryptCost        = 10
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	FailedKeyPattern  = "recovery_failed:%s"
	// RecoveryCodesKeyPattern stores codes temporarily during setup (shown once)
	RecoveryCodesKeyPattern = "recovery_codes_temp:%s"
	RecoveryCodesTTL        = 10 * time.Minute
)

// Service handles recovery code operations
type Service struct {
	recoveryRepo RecoveryRepository
	userRepo     UserRepository
	auditRepo    AuditRepository
	totpService  TOTPService
	redisClient  RedisClient
}

// NewService creates a new recovery service
func NewService(
	recoveryRepo RecoveryRepository,
	userRepo UserRepository,
	auditRepo AuditRepository,
	totpService TOTPService,
	redisClient RedisClient,
) *Service {
	return &Service{
		recoveryRepo: recoveryRepo,
		userRepo:     userRepo,
		auditRepo:    auditRepo,
		totpService:  totpService,
		redisClient:  redisClient,
	}
}

// GenerateResponse contains generated recovery codes
type GenerateResponse struct {
	Codes []string `json:"codes"`
}

// VerifyRequest for recovery code verification
type VerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// VerifyResponse for successful verification
type VerifyResponse struct {
	Status         string `json:"status"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	ExpiresIn      int    `json:"expires_in"`
	UserID         string `json:"user_id"`
	CodesRemaining int    `json:"codes_remaining"`
}

// RegenerateRequest for regenerating recovery codes
type RegenerateRequest struct {
	TOTPCode string `json:"totp_code" binding:"required,len=6"`
}

// GenerateAndStore creates 10 recovery codes for a user
// Called when TOTP is first enabled
// Returns plain codes - these are shown ONCE
func (s *Service) GenerateAndStore(ctx context.Context, userID uuid.UUID, email, clientIP, userAgent string) (*GenerateResponse, error) {
	// Delete any existing codes
	if err := s.recoveryRepo.DeleteAllCodes(ctx, userID); err != nil {
		slog.Error("Failed to delete existing recovery codes", slog.Any("error", err))
	}

	// Generate new codes
	plainCodes, err := recoveryGen.GenerateCodes()
	if err != nil {
		return nil, apperror.InternalError("Lỗi tạo mã khôi phục", "Không thể tạo mã khôi phục. Vui lòng thử lại.")
	}

	// Hash codes with bcrypt
	hashedCodes := make([]string, len(plainCodes))
	for i, code := range plainCodes {
		// Normalize before hashing (remove hyphen)
		normalized := recoveryGen.NormalizeCode(code)
		hash, err := bcrypt.GenerateFromPassword([]byte(normalized), BcryptCost)
		if err != nil {
			return nil, apperror.InternalError("Lỗi mã hóa", "Không thể mã hóa mã khôi phục.")
		}
		hashedCodes[i] = string(hash)
	}

	// Store hashed codes in database
	if err := s.recoveryRepo.CreateCodes(ctx, userID, hashedCodes); err != nil {
		return nil, apperror.InternalError("Lỗi lưu trữ", "Không thể lưu mã khôi phục.")
	}

	// Store plain codes temporarily in Redis for download/print (shown once)
	codesJSON, _ := json.Marshal(plainCodes)
	tempKey := fmt.Sprintf(RecoveryCodesKeyPattern, userID.String())
	_ = s.redisClient.Set(ctx, tempKey, string(codesJSON), RecoveryCodesTTL)

	// Audit log
	s.logEvent(ctx, "recovery_codes_generated", userID.String(), email, clientIP, userAgent, true, "",
		map[string]interface{}{"code_count": len(plainCodes)})

	return &GenerateResponse{
		Codes: plainCodes,
	}, nil
}

// GetTemporaryCodes retrieves codes from Redis during setup flow (for download/print)
func (s *Service) GetTemporaryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	tempKey := fmt.Sprintf(RecoveryCodesKeyPattern, userID.String())
	codesJSON, err := s.redisClient.Get(ctx, tempKey)
	if err != nil {
		return nil, apperror.NotFoundError("mã khôi phục")
	}
	var codes []string
	if err := json.Unmarshal([]byte(codesJSON), &codes); err != nil {
		return nil, apperror.InternalError("Lỗi đọc mã", "Không thể đọc mã khôi phục từ bộ nhớ đệm.")
	}
	return codes, nil
}

// ClearTemporaryCodes removes codes from Redis after download/print
func (s *Service) ClearTemporaryCodes(ctx context.Context, userID uuid.UUID) {
	tempKey := fmt.Sprintf(RecoveryCodesKeyPattern, userID.String())
	_ = s.redisClient.Delete(ctx, tempKey)
}

// Verify validates a recovery code and completes MFA flow
func (s *Service) Verify(ctx context.Context, req VerifyRequest, clientIP, userAgent string) (*VerifyResponse, error) {
	// Validate MFA token
	mfaData, err := s.validateMFAToken(ctx, req.MFAToken, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	userID := mfaData["user_id"].(string)
	email := mfaData["email"].(string)
	userUUID := uuid.MustParse(userID)
	failedKey := fmt.Sprintf(FailedKeyPattern, userID)

	// Check brute force lockout
	if locked, err := s.isLockedOut(ctx, failedKey); err == nil && locked {
		ttl, _ := s.redisClient.TTL(ctx, failedKey)
		return nil, apperror.AuthenticationError(
			"Tài khoản tạm thời bị khóa",
			fmt.Sprintf("Quá nhiều lần thử sai. Vui lòng thử lại sau %d phút", int(ttl.Minutes())+1),
		)
	}

	// Validate format - recovery code format XXXX-XXXX (not TOTP 6 digits)
	if !recoveryGen.IsRecoveryCodeFormat(req.Code) {
		return nil, apperror.ValidationError(
			"Định dạng mã không hợp lệ",
			"Mã khôi phục có định dạng XXXX-XXXX. Nếu bạn muốn dùng mã TOTP 6 chữ số, vui lòng sử dụng endpoint /auth/totp/verify.",
		)
	}

	// Normalize input code
	normalizedInput := recoveryGen.NormalizeCode(req.Code)

	// Get unused codes from database
	codes, err := s.recoveryRepo.GetUnusedCodes(ctx, userUUID)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể truy xuất mã khôi phục.")
	}

	if len(codes) == 0 {
		return nil, apperror.AuthenticationError(
			"Không còn mã khôi phục",
			"Tất cả mã khôi phục đã được sử dụng. Vui lòng liên hệ admin để reset hoặc regenerate mã mới.",
		)
	}

	// Try to match against any unused code
	var matchedCode *struct {
		ID        uuid.UUID
		CodeIndex int
	}
	for _, code := range codes {
		if err := bcrypt.CompareHashAndPassword([]byte(code.CodeHash), []byte(normalizedInput)); err == nil {
			matchedCode = &struct {
				ID        uuid.UUID
				CodeIndex int
			}{ID: code.ID, CodeIndex: code.CodeIndex}
			break
		}
	}

	if matchedCode == nil {
		// Increment failure counter
		newCount := s.incrementFailedAttempts(ctx, failedKey)

		severity := "INFO"
		if newCount >= 3 {
			severity = "WARNING"
		}
		if newCount >= 5 {
			severity = "CRITICAL"
		}

		s.logEvent(ctx, "recovery_code_failed", userID, email, clientIP, userAgent, false, "invalid_code",
			map[string]interface{}{"attempt_count": newCount, "severity": severity})

		return nil, apperror.AuthenticationError(
			"Mã khôi phục không đúng",
			"Vui lòng kiểm tra lại mã khôi phục của bạn.",
		)
	}

	// Mark code as used (one-time use)
	marked, err := s.recoveryRepo.MarkCodeUsed(ctx, userUUID, matchedCode.ID)
	if err != nil || !marked {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể cập nhật trạng thái mã khôi phục.")
	}

	// Reset failure counter on success
	_ = s.redisClient.Delete(ctx, failedKey)

	// Get remaining codes count
	remaining, _ := s.recoveryRepo.CountUnusedCodes(ctx, userUUID)

	// Audit log
	s.logEvent(ctx, "recovery_code_verified", userID, email, clientIP, userAgent, true, "",
		map[string]interface{}{
			"code_index":      matchedCode.CodeIndex,
			"codes_remaining": remaining,
		})

	// Consume MFA token and return auth tokens
	_ = s.redisClient.Delete(ctx, "mfa_token:"+req.MFAToken)

	accessToken, _ := mfaData["access_token"].(string)
	refreshToken, _ := mfaData["refresh_token"].(string)

	return &VerifyResponse{
		Status:         "success",
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpiresIn:      900,
		UserID:         userID,
		CodesRemaining: int(remaining),
	}, nil
}

// Regenerate creates new recovery codes (requires TOTP verification)
func (s *Service) Regenerate(ctx context.Context, userID uuid.UUID, req RegenerateRequest, email, clientIP, userAgent string) (*GenerateResponse, error) {
	// SECURITY: Verify TOTP code before allowing regeneration
	if s.totpService == nil {
		return nil, apperror.InternalError("Lỗi cấu hình", "Dịch vụ TOTP không được cấu hình.")
	}

	valid, err := s.totpService.ValidateCode(ctx, userID, req.TOTPCode)
	if err != nil {
		return nil, apperror.InternalError("Lỗi xác thực", "Không thể xác thực mã TOTP.")
	}
	if !valid {
		s.logEvent(ctx, "recovery_regenerate_failed", userID.String(), email, clientIP, userAgent, false, "invalid_totp",
			map[string]interface{}{})
		return nil, apperror.AuthenticationError("Mã TOTP không đúng", "Vui lòng kiểm tra lại mã trong ứng dụng xác thực của bạn.")
	}

	// Audit log for regeneration
	s.logEvent(ctx, "recovery_codes_regenerated", userID.String(), email, clientIP, userAgent, true, "",
		map[string]interface{}{"reason": "user_request"})

	// Generate new codes (will delete old ones)
	return s.GenerateAndStore(ctx, userID, email, clientIP, userAgent)
}

// GetCodesStatus returns status of all codes (used/unused)
func (s *Service) GetCodesStatus(ctx context.Context, userID uuid.UUID) ([]bool, error) {
	codes, err := s.recoveryRepo.GetAllCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	status := make([]bool, len(codes))
	for i, code := range codes {
		status[i] = code.IsUsed()
	}
	return status, nil
}

// ValidateCode validates a recovery code without consuming it (for authentication flow)
func (s *Service) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	if !recoveryGen.IsRecoveryCodeFormat(code) {
		return false, nil
	}

	normalizedInput := recoveryGen.NormalizeCode(code)
	codes, err := s.recoveryRepo.GetUnusedCodes(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, c := range codes {
		if err := bcrypt.CompareHashAndPassword([]byte(c.CodeHash), []byte(normalizedInput)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// Helper functions

func (s *Service) validateMFAToken(ctx context.Context, token, clientIP, userAgent string) (map[string]interface{}, error) {
	data, err := s.redisClient.Get(ctx, "mfa_token:"+token)
	if err != nil {
		return nil, apperror.AuthenticationError("Phiên xác thực đã hết hạn", "Vui lòng đăng nhập lại")
	}
	var mfaData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &mfaData); err != nil {
		return nil, apperror.InternalError("Lỗi đọc dữ liệu phiên", "Dữ liệu phiên không hợp lệ")
	}

	// IP binding
	if storedIP, ok := mfaData["client_ip"].(string); ok && storedIP != clientIP {
		return nil, apperror.AuthenticationError("Phiên xác thực không hợp lệ", "Địa chỉ IP đã thay đổi. Vui lòng đăng nhập lại từ đầu")
	}
	// UA binding
	if storedUA, ok := mfaData["user_agent"].(string); ok && storedUA != userAgent {
		return nil, apperror.AuthenticationError("Phiên xác thực không hợp lệ", "Trình duyệt đã thay đổi. Vui lòng đăng nhập lại từ đầu")
	}
	return mfaData, nil
}

func (s *Service) isLockedOut(ctx context.Context, failedKey string) (bool, error) {
	failedCountStr, err := s.redisClient.Get(ctx, failedKey)
	if err != nil {
		return false, nil // No key means not locked
	}
	failedCount, _ := strconv.Atoi(failedCountStr)
	return failedCount >= MaxFailedAttempts, nil
}

func (s *Service) incrementFailedAttempts(ctx context.Context, failedKey string) int64 {
	newCount, _ := s.redisClient.Incr(ctx, failedKey)
	if newCount == 1 {
		_ = s.redisClient.Expire(ctx, failedKey, LockoutDuration)
	}
	return newCount
}

func (s *Service) logEvent(ctx context.Context, eventType, userID, email, clientIP, userAgent string, success bool, failureReason string, metadata map[string]interface{}) {
	if s.auditRepo != nil {
		event := repository.AuditEvent{
			EventType:   eventType,
			ActorID:     userID,
			ActorEmail:  email,
			ClientIP:    clientIP,
			UserAgent:   userAgent,
			Success:     success,
			Metadata:    metadata,
		}
		if failureReason != "" {
			event.FailureReason = failureReason
		}
		if err := s.auditRepo.LogEvent(ctx, event); err != nil {
			slog.Error("Failed to log audit event", slog.String("event_type", eventType), slog.Any("error", err))
		}
	}
}


// VerifyAndConsumeCode validates and consumes a recovery code (for local auth)
// Returns (valid, remaining_codes, error)
func (s *Service) VerifyAndConsumeCode(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	if !recoveryGen.IsRecoveryCodeFormat(code) {
		return false, 0, nil
	}

	normalizedInput := recoveryGen.NormalizeCode(code)
	codes, err := s.recoveryRepo.GetUnusedCodes(ctx, userID)
	if err != nil {
		return false, 0, err
	}

	if len(codes) == 0 {
		return false, 0, nil
	}

	// Try to match against any unused code
	var matchedCode *domain.RecoveryCode
	for _, c := range codes {
		if err := bcrypt.CompareHashAndPassword([]byte(c.CodeHash), []byte(normalizedInput)); err == nil {
			matchedCode = c
			break
		}
	}

	if matchedCode == nil {
		return false, len(codes), nil
	}

	// Mark code as used
	if _, err := s.recoveryRepo.MarkCodeUsed(ctx, userID, matchedCode.ID); err != nil {
		return false, len(codes), err
	}

	// Return success with remaining count (minus the one just used)
	remaining := len(codes) - 1
	return true, remaining, nil
}
