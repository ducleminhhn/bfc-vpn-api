package localauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/infrastructure/crypto"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
)

const (
	// Per-user rate limiting
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	RateLimitWindow   = 15 * time.Minute

	// Global IP rate limiting (AC-7)
	GlobalIPMaxAttempts    = 50
	GlobalIPWindow         = 15 * time.Minute
	GlobalIPBlockDuration  = 1 * time.Hour
	CrossUserThreshold     = 10
	CrossUserWindow        = 5 * time.Minute

	// Redis key patterns
	FailedKeyPattern       = "local_auth_failed:%s"
	LockoutKeyPattern      = "local_auth_lockout:%s"
	MFATokenKeyPattern     = "mfa_token:%s"
	GlobalIPFailedPattern  = "global_auth_failed:%s"
	GlobalIPBlockedPattern = "global_auth_blocked:%s"
	IPUserAttemptsPattern  = "ip_user_attempts:%s"

	// MFA token TTL
	MFATokenTTL = 5 * time.Minute
)

// Service handles local authentication
type Service struct {
	userRepo        UserRepository
	totpService     TOTPService
	recoveryService RecoveryService
	tokenService    TokenService
	auditLogger     AuditLogger
	redisClient     RedisClient
	argon2Params    *crypto.Argon2idParams
}

// NewService creates a new local auth service
func NewService(
	userRepo UserRepository,
	totpService TOTPService,
	recoveryService RecoveryService,
	tokenService TokenService,
	auditLogger AuditLogger,
	redisClient RedisClient,
) *Service {
	return &Service{
		userRepo:        userRepo,
		totpService:     totpService,
		recoveryService: recoveryService,
		tokenService:    tokenService,
		auditLogger:     auditLogger,
		redisClient:     redisClient,
		argon2Params:    crypto.DefaultParams(),
	}
}

// LoginRequest for local authentication
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=12"`
}

// LoginResponse for local authentication
type LoginResponse struct {
	Status       string `json:"status"`
	MFAToken     string `json:"mfa_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	UserID       string `json:"user_id"`
	RequiresMFA  bool   `json:"requires_mfa"`
	TOTPEnabled  bool   `json:"totp_enabled"`
}

// Login authenticates user with email/password using local PostgreSQL
func (s *Service) Login(ctx context.Context, req LoginRequest, clientIP, userAgent string) (*LoginResponse, error) {
	// AC-8: Check dependencies first (fail-secure)
	if err := s.checkDependencies(ctx); err != nil {
		return nil, err
	}

	// AC-7: Check global IP rate limiting
	if err := s.checkGlobalIPRateLimit(ctx, clientIP, ""); err != nil {
		return nil, err
	}

	// Get user by email
	user, err := s.userRepo.GetByEmailForLocalAuth(ctx, req.Email)
	if err != nil {
		s.logEvent(ctx, "local_auth_failed", "", req.Email, "", clientIP, userAgent, false, "user_not_found", nil)
		s.incrementGlobalIPCounter(ctx, clientIP, "")
		return nil, apperror.AuthenticationError(
			"Thông tin đăng nhập không đúng",
			"Email hoặc mật khẩu không chính xác. Vui lòng thử lại.",
		)
	}

	// Check if local auth is enabled for this user
	if !user.LocalAuthEnabled {
		s.logEvent(ctx, "local_auth_failed", user.ID.String(), user.Email, user.TenantID.String(), clientIP, userAgent, false, "local_auth_disabled", nil)
		return nil, apperror.AuthenticationError(
			"Xác thực cục bộ không khả dụng",
			"Tài khoản này chưa được kích hoạt xác thực cục bộ. Vui lòng sử dụng Keycloak.",
		)
	}

	// Check if password hash exists
	if user.PasswordHash == "" {
		s.logEvent(ctx, "local_auth_failed", user.ID.String(), user.Email, user.TenantID.String(), clientIP, userAgent, false, "no_password_hash", nil)
		return nil, apperror.AuthenticationError(
			"Xác thực cục bộ không khả dụng",
			"Tài khoản này chưa được thiết lập mật khẩu cục bộ.",
		)
	}

	userID := user.ID.String()
	tenantID := user.TenantID.String()
	failedKey := fmt.Sprintf(FailedKeyPattern, userID)
	lockoutKey := fmt.Sprintf(LockoutKeyPattern, userID)

	// Check if account is locked (Redis first, then DB)
	if locked, _ := s.redisClient.Get(ctx, lockoutKey); locked != "" {
		ttl, _ := s.redisClient.TTL(ctx, lockoutKey)
		s.logEvent(ctx, "local_auth_failed", userID, user.Email, tenantID, clientIP, userAgent, false, "account_locked",
			map[string]interface{}{"remaining_lockout_minutes": int(ttl.Minutes())})
		localAuthFailedTotal.WithLabelValues("account_locked").Inc()
		return nil, apperror.LockedError(
			"Tài khoản tạm thời bị khóa",
			fmt.Sprintf("Quá nhiều lần đăng nhập sai. Vui lòng thử lại sau %d phút.", int(ttl.Minutes())+1),
		)
	}

	// Check rate limiting (5 attempts/15 min) - AC-4
	failedCountStr, _ := s.redisClient.Get(ctx, failedKey)
	failedCount := 0
	if failedCountStr != "" {
		failedCount, _ = strconv.Atoi(failedCountStr)
	}
	if failedCount >= MaxFailedAttempts {
		// Trigger lockout - AC-5
		_ = s.redisClient.Set(ctx, lockoutKey, "1", LockoutDuration)
		_ = s.userRepo.LockUserAccount(ctx, user.ID, time.Now().Add(LockoutDuration))

		s.logEvent(ctx, "local_auth_lockout", userID, user.Email, tenantID, clientIP, userAgent, false, "max_attempts_exceeded",
			map[string]interface{}{"failed_attempts": failedCount, "lockout_duration_minutes": int(LockoutDuration.Minutes())})
		localAuthLockoutTotal.Inc()

		return nil, apperror.LockedError(
			"Tài khoản đã bị khóa",
			fmt.Sprintf("Đã vượt quá %d lần đăng nhập sai. Tài khoản bị khóa trong %d phút.", MaxFailedAttempts, int(LockoutDuration.Minutes())),
		)
	}

	// Verify password using Argon2id - AC-1
	valid, err := crypto.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		// Increment failure counter
		newCount, _ := s.redisClient.Incr(ctx, failedKey)
		if newCount == 1 {
			_ = s.redisClient.Expire(ctx, failedKey, RateLimitWindow)
		}
		_ = s.userRepo.IncrementFailedAttempts(ctx, user.ID)
		s.incrementGlobalIPCounter(ctx, clientIP, userID)

		severity := "INFO"
		if newCount >= 3 {
			severity = "WARNING"
		}
		if newCount >= 5 {
			severity = "CRITICAL"
		}

		s.logEvent(ctx, "local_auth_failed", userID, user.Email, tenantID, clientIP, userAgent, false, "invalid_password",
			map[string]interface{}{"attempt_count": newCount, "severity": severity, "remaining_attempts": MaxFailedAttempts - int(newCount)})
		localAuthFailedTotal.WithLabelValues("invalid_password").Inc()

		return nil, apperror.AuthenticationError(
			"Thông tin đăng nhập không đúng",
			fmt.Sprintf("Email hoặc mật khẩu không chính xác. Còn %d lần thử.", MaxFailedAttempts-int(newCount)),
		)
	}

	// Password valid - reset failure counter (AC-4: DELETE key, not just reset to 0)
	_ = s.redisClient.Delete(ctx, failedKey)
	_ = s.userRepo.ResetFailedAttempts(ctx, user.ID)

	// Check if user needs rehash (parameters upgraded)
	if crypto.NeedsRehash(user.PasswordHash, s.argon2Params) {
		newHash, err := crypto.HashPassword(req.Password, s.argon2Params)
		if err == nil {
			_ = s.userRepo.UpdatePasswordHash(ctx, user.ID, newHash)
			slog.Info("Password rehashed with upgraded parameters", slog.String("user_id", userID))
		}
	}

	// Check if MFA is required - AC-2
	if user.TOTPEnabled {
		return s.handleMFARequired(ctx, user, clientIP, userAgent)
	}

	// No MFA - generate tokens directly
	return s.generateLoginSuccess(ctx, user, clientIP, userAgent, false, "")
}

// VerifyTOTPRequest for TOTP verification
type VerifyTOTPRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

// VerifyTOTPResponse for TOTP verification
type VerifyTOTPResponse struct {
	Status       string `json:"status"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
}

// VerifyTOTP validates TOTP code for local auth MFA - AC-2
func (s *Service) VerifyTOTP(ctx context.Context, req VerifyTOTPRequest, clientIP, userAgent string) (*VerifyTOTPResponse, error) {
	// AC-8: Check dependencies
	if err := s.checkDependencies(ctx); err != nil {
		return nil, err
	}

	// Validate MFA token and get context
	mfaData, err := s.validateMFAToken(ctx, req.MFAToken, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	userID := mfaData["user_id"].(string)
	email := mfaData["email"].(string)
	tenantID := mfaData["tenant_id"].(string)
	userUUID := uuid.MustParse(userID)

	// Validate TOTP code using existing TOTP service
	valid, err := s.totpService.ValidateCode(ctx, userUUID, req.Code)
	if err != nil {
		localAuthFailedTotal.WithLabelValues("totp_service_error").Inc()
		return nil, apperror.InternalError("Lỗi xác thực", "Không thể xác thực mã TOTP.")
	}
	if !valid {
		s.logEvent(ctx, "local_auth_totp_failed", userID, email, tenantID, clientIP, userAgent, false, "invalid_totp", nil)
		localAuthFailedTotal.WithLabelValues("invalid_totp").Inc()
		return nil, apperror.AuthenticationError("Mã TOTP không đúng", "Vui lòng kiểm tra lại mã trong ứng dụng xác thực của bạn.")
	}

	// Consume MFA token
	_ = s.redisClient.Delete(ctx, fmt.Sprintf(MFATokenKeyPattern, req.MFAToken))

	accessToken := mfaData["access_token"].(string)
	refreshToken := mfaData["refresh_token"].(string)
	expiresIn := int(mfaData["expires_in"].(float64))

	s.logEvent(ctx, "local_auth_success", userID, email, tenantID, clientIP, userAgent, true, "",
		map[string]interface{}{"mfa_type": "totp"})
	localAuthSuccessTotal.WithLabelValues("totp").Inc()

	return &VerifyTOTPResponse{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		UserID:       userID,
	}, nil
}

// VerifyRecoveryRequest for recovery code verification
type VerifyRecoveryRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// VerifyRecoveryResponse for recovery code verification
type VerifyRecoveryResponse struct {
	Status         string `json:"status"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	ExpiresIn      int    `json:"expires_in"`
	UserID         string `json:"user_id"`
	CodesRemaining int    `json:"codes_remaining"`
}

// VerifyRecovery validates recovery code for local auth MFA - AC-3
func (s *Service) VerifyRecovery(ctx context.Context, req VerifyRecoveryRequest, clientIP, userAgent string) (*VerifyRecoveryResponse, error) {
	// AC-8: Check dependencies
	if err := s.checkDependencies(ctx); err != nil {
		return nil, err
	}

	// Validate MFA token
	mfaData, err := s.validateMFAToken(ctx, req.MFAToken, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	userID := mfaData["user_id"].(string)
	email := mfaData["email"].(string)
	tenantID := mfaData["tenant_id"].(string)
	userUUID := uuid.MustParse(userID)

	// Use existing recovery service - AC-3
	valid, remaining, err := s.recoveryService.Verify(ctx, userUUID, req.Code)
	if err != nil {
		localAuthFailedTotal.WithLabelValues("recovery_service_error").Inc()
		return nil, apperror.InternalError("Lỗi xác thực", "Không thể xác thực mã khôi phục.")
	}
	if !valid {
		s.logEvent(ctx, "local_auth_recovery_failed", userID, email, tenantID, clientIP, userAgent, false, "invalid_recovery_code", nil)
		localAuthFailedTotal.WithLabelValues("invalid_recovery").Inc()
		return nil, apperror.AuthenticationError("Mã khôi phục không đúng", "Mã khôi phục không hợp lệ hoặc đã được sử dụng.")
	}

	// Consume MFA token
	_ = s.redisClient.Delete(ctx, fmt.Sprintf(MFATokenKeyPattern, req.MFAToken))

	accessToken := mfaData["access_token"].(string)
	refreshToken := mfaData["refresh_token"].(string)
	expiresIn := int(mfaData["expires_in"].(float64))

	s.logEvent(ctx, "local_auth_success", userID, email, tenantID, clientIP, userAgent, true, "",
		map[string]interface{}{"mfa_type": "recovery_code", "codes_remaining": remaining})
	localAuthSuccessTotal.WithLabelValues("recovery_code").Inc()

	return &VerifyRecoveryResponse{
		Status:         "success",
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpiresIn:      expiresIn,
		UserID:         userID,
		CodesRemaining: remaining,
	}, nil
}

// SetPassword sets/updates local password for a user (for sync from Keycloak)
func (s *Service) SetPassword(ctx context.Context, userID uuid.UUID, password string) error {
	hash, err := crypto.HashPassword(password, s.argon2Params)
	if err != nil {
		return apperror.InternalError("Lỗi mã hóa", "Không thể mã hóa mật khẩu.")
	}
	return s.userRepo.UpdatePasswordHash(ctx, userID, hash)
}

// handleMFARequired handles the MFA required flow
func (s *Service) handleMFARequired(ctx context.Context, user *UserForLocalAuth, clientIP, userAgent string) (*LoginResponse, error) {
	userID := user.ID.String()
	email := user.Email
	tenantID := user.TenantID.String()

	// Generate MFA token
	mfaToken, err := s.tokenService.GenerateMFAToken(ctx, userID, email, clientIP, userAgent)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể tạo phiên xác thực MFA.")
	}

	// Generate tokens for later use after MFA
	accessToken, expiresIn, err := s.tokenService.GenerateAccessToken(ctx, userID, email, tenantID)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể tạo access token.")
	}
	refreshToken, err := s.tokenService.GenerateRefreshToken(ctx, userID)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể tạo refresh token.")
	}

	// Store MFA context in Redis
	mfaData := map[string]interface{}{
		"user_id":       userID,
		"email":         email,
		"tenant_id":     tenantID,
		"client_ip":     clientIP,
		"user_agent":    userAgent,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    expiresIn,
		"auth_method":   "local",
	}
	mfaJSON, _ := json.Marshal(mfaData)
	_ = s.redisClient.Set(ctx, fmt.Sprintf(MFATokenKeyPattern, mfaToken), string(mfaJSON), MFATokenTTL)

	s.logEvent(ctx, "local_auth_mfa_required", userID, email, tenantID, clientIP, userAgent, true, "",
		map[string]interface{}{"mfa_type": "totp"})

	return &LoginResponse{
		Status:      "mfa_required",
		MFAToken:    mfaToken,
		UserID:      userID,
		RequiresMFA: true,
		TOTPEnabled: true,
	}, nil
}

// generateLoginSuccess generates tokens for successful login
func (s *Service) generateLoginSuccess(ctx context.Context, user *UserForLocalAuth, clientIP, userAgent string, mfaUsed bool, mfaType string) (*LoginResponse, error) {
	userID := user.ID.String()
	email := user.Email
	tenantID := user.TenantID.String()

	accessToken, expiresIn, err := s.tokenService.GenerateAccessToken(ctx, userID, email, tenantID)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể tạo access token.")
	}
	refreshToken, err := s.tokenService.GenerateRefreshToken(ctx, userID)
	if err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể tạo refresh token.")
	}

	metadata := map[string]interface{}{"mfa_required": mfaUsed}
	if mfaType != "" {
		metadata["mfa_type"] = mfaType
	}
	s.logEvent(ctx, "local_auth_success", userID, email, tenantID, clientIP, userAgent, true, "", metadata)
	localAuthSuccessTotal.WithLabelValues("none").Inc()

	return &LoginResponse{
		Status:       "success",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		UserID:       userID,
		RequiresMFA:  false,
		TOTPEnabled:  user.TOTPEnabled,
	}, nil
}

// validateMFAToken validates MFA token with IP/UA binding
func (s *Service) validateMFAToken(ctx context.Context, token, clientIP, userAgent string) (map[string]interface{}, error) {
	data, err := s.redisClient.Get(ctx, fmt.Sprintf(MFATokenKeyPattern, token))
	if err != nil || data == "" {
		return nil, apperror.AuthenticationError("Phiên xác thực đã hết hạn", "Vui lòng đăng nhập lại.")
	}

	var mfaData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &mfaData); err != nil {
		return nil, apperror.InternalError("Lỗi hệ thống", "Không thể đọc dữ liệu phiên.")
	}

	// IP binding
	if storedIP, ok := mfaData["client_ip"].(string); ok && storedIP != clientIP {
		return nil, apperror.AuthenticationError("Phiên không hợp lệ", "Địa chỉ IP đã thay đổi. Vui lòng đăng nhập lại.")
	}
	// UA binding
	if storedUA, ok := mfaData["user_agent"].(string); ok && storedUA != userAgent {
		return nil, apperror.AuthenticationError("Phiên không hợp lệ", "Trình duyệt đã thay đổi. Vui lòng đăng nhập lại.")
	}

	return mfaData, nil
}

// checkDependencies verifies all required services are available (fail-secure) - AC-8
func (s *Service) checkDependencies(ctx context.Context) error {
	// Check Redis
	if err := s.redisClient.Ping(ctx); err != nil {
		slog.Error("Redis unavailable for local auth", slog.Any("error", err))
		s.logEvent(ctx, "local_auth_denied", "", "", "", "", "", false, "redis_unavailable",
			map[string]interface{}{"severity": "CRITICAL"})
		localAuthDependencyFailureTotal.WithLabelValues("redis").Inc()
		return apperror.ServiceUnavailableError(
			"Dịch vụ tạm thời không khả dụng",
			"Hệ thống xác thực cục bộ đang bảo trì. Vui lòng sử dụng Keycloak hoặc thử lại sau.",
		)
	}

	// Check Database (via user repo ping)
	if err := s.userRepo.Ping(ctx); err != nil {
		slog.Error("Database unavailable for local auth", slog.Any("error", err))
		s.logEvent(ctx, "local_auth_denied", "", "", "", "", "", false, "database_unavailable",
			map[string]interface{}{"severity": "CRITICAL"})
		localAuthDependencyFailureTotal.WithLabelValues("database").Inc()
		return apperror.ServiceUnavailableError(
			"Dịch vụ tạm thời không khả dụng",
			"Hệ thống xác thực cục bộ đang bảo trì. Vui lòng sử dụng Keycloak hoặc thử lại sau.",
		)
	}

	return nil
}

// checkGlobalIPRateLimit checks if IP is blocked or exceeds global rate limit - AC-7
func (s *Service) checkGlobalIPRateLimit(ctx context.Context, clientIP, userID string) error {
	// Check if IP is already blocked
	if blocked, _ := s.redisClient.Get(ctx, fmt.Sprintf(GlobalIPBlockedPattern, clientIP)); blocked != "" {
		localAuthFailedTotal.WithLabelValues("ip_blocked").Inc()
		return apperror.TooManyRequestsError(
			"Địa chỉ IP đã bị chặn tạm thời",
			"Quá nhiều yêu cầu đăng nhập từ địa chỉ IP này. Vui lòng thử lại sau 1 giờ.",
		)
	}

	// Check global IP attempt count
	globalKey := fmt.Sprintf(GlobalIPFailedPattern, clientIP)
	countStr, _ := s.redisClient.Get(ctx, globalKey)
	count := 0
	if countStr != "" {
		count, _ = strconv.Atoi(countStr)
	}
	if count >= GlobalIPMaxAttempts {
		// Block IP
		_ = s.redisClient.Set(ctx, fmt.Sprintf(GlobalIPBlockedPattern, clientIP), "1", GlobalIPBlockDuration)
		s.logEvent(ctx, "ip_blocked", "", "", "", clientIP, "", false, "global_rate_limit_exceeded",
			map[string]interface{}{"total_attempts": count})
		localAuthIPBlockedTotal.Inc()
		return apperror.TooManyRequestsError(
			"Địa chỉ IP đã bị chặn",
			"Vượt quá giới hạn đăng nhập. IP bị chặn trong 1 giờ.",
		)
	}

	return nil
}

// incrementGlobalIPCounter increments the global IP counter and checks credential stuffing - AC-7
func (s *Service) incrementGlobalIPCounter(ctx context.Context, clientIP, userID string) {
	// Increment global IP counter
	globalKey := fmt.Sprintf(GlobalIPFailedPattern, clientIP)
	newCount, _ := s.redisClient.Incr(ctx, globalKey)
	if newCount == 1 {
		_ = s.redisClient.Expire(ctx, globalKey, GlobalIPWindow)
	}

	// Track unique users per IP for credential stuffing detection
	if userID != "" {
		userSetKey := fmt.Sprintf(IPUserAttemptsPattern, clientIP)
		_ = s.redisClient.SAdd(ctx, userSetKey, userID)
		_ = s.redisClient.Expire(ctx, userSetKey, CrossUserWindow)

		userCount, _ := s.redisClient.SCard(ctx, userSetKey)
		if userCount >= CrossUserThreshold {
			// Credential stuffing detected - block IP
			_ = s.redisClient.Set(ctx, fmt.Sprintf(GlobalIPBlockedPattern, clientIP), "1", GlobalIPBlockDuration)
			s.logEvent(ctx, "credential_stuffing_detected", "", "", "", clientIP, "", false, "cross_user_threshold",
				map[string]interface{}{"unique_users": userCount, "severity": "CRITICAL"})
			credentialStuffingDetectedTotal.Inc()
		}
	}
}

// logEvent logs an audit event
func (s *Service) logEvent(ctx context.Context, eventType, userID, email, tenantID, clientIP, userAgent string, success bool, failureReason string, metadata map[string]interface{}) {
	if s.auditLogger == nil {
		return
	}
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	_ = s.auditLogger.LogEvent(ctx, AuditEvent{
		EventType:     eventType,
		ActorID:       userID,
		ActorEmail:    email,
		TenantID:      tenantID,
		ClientIP:      clientIP,
		UserAgent:     userAgent,
		Success:       success,
		FailureReason: failureReason,
		AuthMethod:    "local",
		Metadata:      metadata,
	})
}
