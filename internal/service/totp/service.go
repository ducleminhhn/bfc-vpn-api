package totp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/infrastructure/redis"
	totpGen "github.com/bfc-vpn/api/internal/infrastructure/totp"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/crypto"
	"github.com/bfc-vpn/api/internal/repository"
)

// Service handles TOTP operations
type Service struct {
	cfg         config.TOTPConfig
	encryptor   Encryptor
	userRepo    UserRepository
	auditRepo   AuditRepository
	redisClient RedisClient
    recoveryService RecoveryService // Optional, for generating recovery codes during TOTP setup
}

// NewService creates a new TOTP service with real implementations
func NewService(cfg config.TOTPConfig, userRepo repository.UserRepository, auditRepo repository.AuditRepository, redisClient *redis.Client) (*Service, error) {
	key, err := base64.StdEncoding.DecodeString(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TOTP encryption key: %w", err)
	}
	encryptor, err := crypto.NewAESEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encryptor: %w", err)
	}
	return &Service{
		cfg:         cfg,
		encryptor:   encryptor,
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		redisClient: redisClient,
	}, nil
}

// NewServiceWithDeps creates a new TOTP service with injected dependencies (for testing)
func NewServiceWithDeps(cfg config.TOTPConfig, encryptor Encryptor, userRepo UserRepository, auditRepo AuditRepository, redisClient RedisClient) *Service {
	return &Service{
		cfg:         cfg,
		encryptor:   encryptor,
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		redisClient: redisClient,
	}
}

// SetupRequest is the request for TOTP setup
type SetupRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
}

// SetupResponse is the response for TOTP setup
type SetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	QRCodeData string `json:"qrcode_data,omitempty"`
}

// VerifyRequest is the request for TOTP verification
type VerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

// VerifyResponse is the response for successful TOTP verification
type VerifyResponse struct {
	RecoveryCodes []string `json:"recovery_codes,omitempty"` // Only during TOTP setup
	Status       string `json:"status"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
}

// MFATokenData stores MFA session information in Redis
type MFATokenData struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	CreatedAt    int64  `json:"created_at"`
}

// Setup initiates TOTP setup for a user
func (s *Service) Setup(ctx context.Context, req SetupRequest, clientIP, userAgent string) (*SetupResponse, error) {
	// Validate MFA token with IP/UA binding (AC-8)
	mfaData, err := s.validateMFAToken(ctx, req.MFAToken, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	userID := mfaData.UserID
	email := mfaData.Email

	// Check if TOTP already enabled
	user, err := s.userRepo.GetByID(ctx, uuid.MustParse(userID))
	if err != nil {
		slog.Error("Failed to get user", slog.Any("error", err), slog.String("user_id", userID))
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể truy xuất thông tin người dùng")
	}
	if user.TOTPEnabled {
		return nil, apperror.ValidationError("TOTP đã được kích hoạt", "Tài khoản của bạn đã có xác thực hai yếu tố")
	}

	// Generate TOTP secret (AC-3)
	result, err := totpGen.Generate(s.cfg.Issuer, email)
	if err != nil {
		slog.Error("Failed to generate TOTP", slog.Any("error", err))
		return nil, apperror.InternalError("Lỗi tạo mã TOTP", "Vui lòng thử lại sau")
	}

	// Encrypt and store pending secret (AC-4)
	encryptedSecret, err := s.encryptor.Encrypt([]byte(result.Secret))
	if err != nil {
		slog.Error("Failed to encrypt secret", slog.Any("error", err))
		return nil, apperror.InternalError("Lỗi mã hóa", "Vui lòng thử lại sau")
	}

	pendingData := map[string]interface{}{
		"encrypted_secret": encryptedSecret,
		"created_at":       time.Now().Unix(),
	}
	pendingJSON, _ := json.Marshal(pendingData)
	if err := s.redisClient.SetTOTPPending(ctx, userID, string(pendingJSON)); err != nil {
		slog.Error("Failed to store pending TOTP", slog.Any("error", err))
		return nil, apperror.InternalError("Lỗi lưu trữ", "Vui lòng thử lại sau")
	}

	// Audit log
	s.logEvent(ctx, "totp_setup_initiated", userID, email, clientIP, userAgent, true, "", nil)

	return &SetupResponse{
		Secret:     result.Secret,
		OTPAuthURL: result.OTPAuthURL,
	}, nil
}

// Verify validates a TOTP code
func (s *Service) Verify(ctx context.Context, req VerifyRequest, clientIP, userAgent string) (*VerifyResponse, error) {
	// Validate MFA token with IP/UA binding (AC-8)
	mfaData, err := s.validateMFAToken(ctx, req.MFAToken, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	userID := mfaData.UserID
	email := mfaData.Email

	// SECURITY: Check brute force lockout (AC-9)
	locked, ttl, err := s.redisClient.IsAccountLocked(ctx, userID)
	if err != nil {
		slog.Error("Failed to check lockout", slog.Any("error", err))
	}
	if locked {
		minutes := int(ttl.Minutes()) + 1
		return nil, apperror.AuthenticationError(
			"Tài khoản tạm thời bị khóa",
			fmt.Sprintf("Quá nhiều lần thử sai. Vui lòng thử lại sau %d phút", minutes),
		)
	}

	// Get failed count for exponential backoff (AC-9)
	failedCount, _ := s.redisClient.GetTOTPFailedCount(ctx, userID)
	if failedCount > 0 {
		delay := CalculateBackoffDelay(failedCount)
		time.Sleep(delay)
	}

	// Get user and secret
	user, err := s.userRepo.GetByID(ctx, uuid.MustParse(userID))
	if err != nil {
		slog.Error("Failed to get user", slog.Any("error", err))
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể truy xuất thông tin người dùng")
	}

	var secret string
	var isSetup bool

	if user.TOTPEnabled {
		// Existing TOTP - decrypt from database
		decrypted, err := s.encryptor.Decrypt(string(user.TOTPSecretEncrypted))
		if err != nil {
			slog.Error("Failed to decrypt TOTP secret", slog.Any("error", err))
			return nil, apperror.InternalError("Lỗi giải mã", "Vui lòng liên hệ quản trị viên")
		}
		secret = string(decrypted)
	} else {
		// Setup flow - get from Redis pending
		pendingJSON, err := s.redisClient.GetTOTPPending(ctx, userID)
		if err != nil {
			return nil, apperror.ValidationError(
				"Phiên thiết lập đã hết hạn",
				"Vui lòng bắt đầu lại quá trình thiết lập TOTP",
			)
		}
		var pendingData map[string]interface{}
		if err := json.Unmarshal([]byte(pendingJSON), &pendingData); err != nil {
			return nil, apperror.InternalError("Lỗi dữ liệu", "Vui lòng thử lại")
		}
		encryptedSecret, ok := pendingData["encrypted_secret"].(string)
		if !ok {
			return nil, apperror.InternalError("Lỗi dữ liệu", "Vui lòng thử lại")
		}
		decrypted, err := s.encryptor.Decrypt(encryptedSecret)
		if err != nil {
			slog.Error("Failed to decrypt pending secret", slog.Any("error", err))
			return nil, apperror.InternalError("Lỗi giải mã", "Vui lòng thử lại")
		}
		secret = string(decrypted)
		isSetup = true
	}

	// Check replay attack (AC-6)
	isNew, err := s.redisClient.MarkTOTPCodeUsed(ctx, userID, req.Code)
	if err != nil {
		slog.Error("Failed to mark code used", slog.Any("error", err))
	}
	if !isNew {
		s.logEvent(ctx, "totp_verify_replay", userID, email, clientIP, userAgent, false, "replay_attack", nil)
		return nil, apperror.AuthenticationError(
			"Mã xác thực đã được sử dụng",
			"Vui lòng chờ mã mới được tạo (30 giây)",
		)
	}

	// Validate TOTP code (AC-5)
	if !totpGen.ValidateCode(secret, req.Code) {
		// Increment failure counter
		newCount, _ := s.redisClient.IncrementTOTPFailed(ctx, userID)

		// Determine severity for audit log (AC-10)
		severity := "INFO"
		if newCount >= 3 {
			severity = "WARNING"
		}
		if newCount >= 5 {
			severity = "CRITICAL"
		}

		s.logEvent(ctx, "totp_verify_failed", userID, email, clientIP, userAgent, false, "invalid_code",
			map[string]interface{}{"attempt_count": newCount, "severity": severity})

		return nil, apperror.AuthenticationError(
			"Mã xác thực không đúng",
			"Vui lòng kiểm tra lại mã trong ứng dụng xác thực của bạn",
		)
	}

	// SUCCESS - Enable TOTP if setup flow (AC-4)
	if isSetup {
		encryptedForDB, err := s.encryptor.Encrypt([]byte(secret))
		if err != nil {
			slog.Error("Failed to encrypt for DB", slog.Any("error", err))
			return nil, apperror.InternalError("Lỗi lưu trữ", "Vui lòng thử lại")
		}
		if err := s.userRepo.EnableTOTP(ctx, user.ID, []byte(encryptedForDB)); err != nil {
			slog.Error("Failed to enable TOTP", slog.Any("error", err))
			return nil, apperror.InternalError("Lỗi kích hoạt TOTP", "Vui lòng thử lại")
		}
		s.redisClient.DeleteTOTPPending(ctx, userID)
	}

	// Reset brute force counter and cleanup
	s.redisClient.ResetTOTPFailed(ctx, userID)
	s.redisClient.DeleteMFAToken(ctx, req.MFAToken)
	s.userRepo.UpdateLastLogin(ctx, user.ID)

	// Audit log
	eventType := "totp_verify_success"
	if isSetup {
		eventType = "totp_setup_completed"
	}
	s.logEvent(ctx, eventType, userID, email, clientIP, userAgent, true, "", nil)

	// Generate recovery codes if this is TOTP setup
	var recoveryCodes []string
	if isSetup && s.recoveryService != nil {
		resp, err := s.recoveryService.GenerateAndStore(ctx, user.ID, email, clientIP, userAgent)
		if err != nil {
			slog.Error("Failed to generate recovery codes", slog.Any("error", err))
			// Continue without recovery codes - TOTP is still enabled
		} else {
			recoveryCodes = resp.Codes
		}
	}

	return &VerifyResponse{
		RecoveryCodes: recoveryCodes,
		Status:        "success",
		AccessToken:   mfaData.AccessToken,
		RefreshToken:  mfaData.RefreshToken,
		ExpiresIn:     900, // 15 minutes
		UserID:        userID,
	}, nil
}

// validateMFAToken validates the MFA token and checks IP/UA binding
func (s *Service) validateMFAToken(ctx context.Context, token, clientIP, userAgent string) (*MFATokenData, error) {
	data, err := s.redisClient.GetMFAToken(ctx, token)
	if err != nil {
		return nil, apperror.AuthenticationError(
			"Phiên xác thực đã hết hạn",
			"Vui lòng đăng nhập lại",
		)
	}

	var mfaData MFATokenData
	if err := json.Unmarshal([]byte(data), &mfaData); err != nil {
		return nil, apperror.InternalError("Lỗi dữ liệu", "Vui lòng đăng nhập lại")
	}

	// IP binding (AC-8)
	if mfaData.ClientIP != "" && mfaData.ClientIP != clientIP {
		s.logEvent(ctx, "mfa_token_ip_mismatch", mfaData.UserID, mfaData.Email, clientIP, userAgent, false, "ip_mismatch",
			map[string]interface{}{"expected_ip": mfaData.ClientIP, "actual_ip": clientIP})
		return nil, apperror.AuthenticationError(
			"Phiên xác thực không hợp lệ",
			"Địa chỉ IP đã thay đổi. Vui lòng đăng nhập lại từ đầu",
		)
	}

	// UA binding (AC-8)
	if mfaData.UserAgent != "" && mfaData.UserAgent != userAgent {
		s.logEvent(ctx, "mfa_token_ua_mismatch", mfaData.UserID, mfaData.Email, clientIP, userAgent, false, "ua_mismatch", nil)
		return nil, apperror.AuthenticationError(
			"Phiên xác thực không hợp lệ",
			"Trình duyệt đã thay đổi. Vui lòng đăng nhập lại từ đầu",
		)
	}

	return &mfaData, nil
}

// logEvent logs audit events
func (s *Service) logEvent(ctx context.Context, eventType, userID, email, clientIP, userAgent string, success bool, failureReason string, metadata map[string]interface{}) {
	if s.auditRepo != nil {
		s.auditRepo.LogEvent(ctx, repository.AuditEvent{
			EventType:     eventType,
			ActorID:       userID,
			ActorEmail:    email,
			ClientIP:      clientIP,
			UserAgent:     userAgent,
			Success:       success,
			FailureReason: failureReason,
			Metadata:      metadata,
		})
	}
}

// GetFailedCount returns the current failed attempt count (for testing)
func (s *Service) GetFailedCount(ctx context.Context, userID string) (int64, error) {
	return s.redisClient.GetTOTPFailedCount(ctx, userID)
}

// CalculateBackoffDelay calculates exponential backoff delay based on failed count
func CalculateBackoffDelay(failedCount int64) time.Duration {
	delay := time.Duration(1<<(failedCount-1)) * time.Second
	if delay > 8*time.Second {
		delay = 8 * time.Second
	}
	return delay
}

// IsNumeric checks if a string is all digits
func IsNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// SetRecoveryService sets the recovery service for generating codes during TOTP setup
// This uses setter injection to avoid circular dependency between TOTP and Recovery services
func (s *Service) SetRecoveryService(rs RecoveryService) {
	s.recoveryService = rs
}


// ValidateCode validates a TOTP code for a user (simple interface for local auth)
func (s *Service) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if !user.TOTPEnabled || len(user.TOTPSecretEncrypted) == 0 {
		return false, nil
	}

	// Decrypt secret using service's encryptor
	secret, err := s.encryptor.Decrypt(string(user.TOTPSecretEncrypted))
	if err != nil {
		return false, err
	}

	// Validate using infrastructure totp package
	return totpGen.ValidateCode(string(secret), code), nil
}
