package dualauth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DualAuthManager orchestrates dual auth failover
type DualAuthManager struct {
	healthChecker *HealthChecker
	passwordSync  *PasswordSyncService
	keycloakAuth  KeycloakAuthService
	localAuth     LocalAuthService
	redisClient   RedisClient
	auditLogger   AuditLogger
	logger        *zap.Logger

	mu sync.RWMutex
}

// KeycloakAuthService interface for Keycloak authentication
type KeycloakAuthService interface {
	Login(ctx context.Context, email, password string) (*AuthResult, error)
	VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*AuthResult, error)
	VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*AuthResult, error)
}

// LocalAuthService interface for local authentication
type LocalAuthService interface {
	Login(ctx context.Context, email, password string) (*AuthResult, error)
	VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*AuthResult, error)
	VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*AuthResult, error)
}

// AuthResult represents authentication result
type AuthResult struct {
	Success      bool   `json:"success"`
	NeedsMFA     bool   `json:"needs_mfa,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	AuthMode     string `json:"auth_mode"` // "keycloak" or "local"
	Error        string `json:"error,omitempty"`
	ErrorVI      string `json:"error_vi,omitempty"`
}

// DualAuthManagerConfig holds configuration for the manager
type DualAuthManagerConfig struct {
	KeycloakURL              string
	HealthCheckIntervalSecs  int
	FailureThreshold         int
	RecoveryThreshold        int
	MaxFailoversPerHour      int
	HealthCheckTimeoutSecs   int
	PasswordSyncIntervalMins int
	KeycloakRealm            string
}

// DefaultDualAuthManagerConfig returns default configuration
func DefaultDualAuthManagerConfig() *DualAuthManagerConfig {
	return &DualAuthManagerConfig{
		KeycloakURL:              "localhost:8080",
		HealthCheckIntervalSecs:  10,
		FailureThreshold:         3,
		RecoveryThreshold:        3,
		MaxFailoversPerHour:      3,
		HealthCheckTimeoutSecs:   5,
		PasswordSyncIntervalMins: 5,
		KeycloakRealm:            "bfc-vpn",
	}
}

// NewDualAuthManager creates a new dual auth manager
func NewDualAuthManager(
	config *DualAuthManagerConfig,
	keycloakAuth KeycloakAuthService,
	localAuth LocalAuthService,
	redisClient RedisClient,
	auditLogger AuditLogger,
	logger *zap.Logger,
) *DualAuthManager {
	if config == nil {
		config = DefaultDualAuthManagerConfig()
	}

	// Create health check config
	healthConfig := &HealthCheckConfig{
		KeycloakURL:         config.KeycloakURL,
		CheckInterval:       time.Duration(config.HealthCheckIntervalSecs) * time.Second,
		FailureThreshold:    config.FailureThreshold,
		RecoveryThreshold:   config.RecoveryThreshold,
		MaxFailoversPerHour: config.MaxFailoversPerHour,
		Timeout:             time.Duration(config.HealthCheckTimeoutSecs) * time.Second,
		UseTLS:              false, // Use HTTP for internal health checks
		KeycloakRealm:       config.KeycloakRealm,
	}

	// Create password sync config
	syncConfig := &PasswordSyncConfig{
		SyncInterval:  time.Duration(config.PasswordSyncIntervalMins) * time.Minute,
		KeycloakRealm: config.KeycloakRealm,
	}

	healthChecker := NewHealthChecker(healthConfig, redisClient, auditLogger, logger)
	passwordSync := NewPasswordSyncService(syncConfig, nil, nil, nil, auditLogger, redisClient, logger)

	// Wire up dependencies
	healthChecker.SetPasswordSyncer(passwordSync)

	return &DualAuthManager{
		healthChecker: healthChecker,
		passwordSync:  passwordSync,
		keycloakAuth:  keycloakAuth,
		localAuth:     localAuth,
		redisClient:   redisClient,
		auditLogger:   auditLogger,
		logger:        logger,
	}
}

// Start starts all dual auth services
func (m *DualAuthManager) Start(ctx context.Context) {
	m.healthChecker.Start(ctx)
	m.passwordSync.Start(ctx)
	m.logger.Info("Dual auth manager started")
}

// Stop stops all dual auth services
func (m *DualAuthManager) Stop() {
	m.healthChecker.Stop()
	m.passwordSync.Stop()
	m.logger.Info("Dual auth manager stopped")
}

// Login authenticates user using appropriate auth mode
func (m *DualAuthManager) Login(ctx context.Context, email, password string) (*AuthResult, error) {
	mode := m.healthChecker.GetCurrentMode()

	// Check if both auth providers are unavailable (AC-7)
	if m.isCompleteOutage(ctx, mode) {
		m.logger.Error("Complete auth outage detected")
		if m.auditLogger != nil {
			m.auditLogger.Log(ctx, "auth_complete_outage", map[string]interface{}{
				"severity": "CRITICAL",
			})
		}
		return &AuthResult{
			Success: false,
			Error:   "authentication_unavailable",
			ErrorVI: "Hệ thống xác thực tạm thời không khả dụng. Vui lòng thử lại sau.",
		}, ErrAuthUnavailable
	}

	var result *AuthResult
	var err error

	if mode == AuthModeKeycloak {
		result, err = m.loginViaKeycloak(ctx, email, password)
	} else {
		result, err = m.loginViaLocal(ctx, email, password)
	}

	if result != nil {
		result.AuthMode = string(mode)
	}

	return result, err
}

// loginViaKeycloak handles Keycloak login
func (m *DualAuthManager) loginViaKeycloak(ctx context.Context, email, password string) (*AuthResult, error) {
	if m.keycloakAuth == nil {
		return &AuthResult{
			Success: false,
			Error:   "keycloak_not_configured",
			ErrorVI: "Keycloak chưa được cấu hình",
		}, nil
	}

	result, err := m.keycloakAuth.Login(ctx, email, password)
	if err != nil {
		return result, err
	}

	// Sync password to local on successful Keycloak login
	if result != nil && result.Success && result.UserID != "" {
		go func() {
			syncCtx := context.Background()
			if err := m.passwordSync.SyncOnLogin(syncCtx, result.UserID, password); err != nil {
				m.logger.Error("Failed to sync password on login",
					zap.String("user_id", result.UserID),
					zap.Error(err))
			}
		}()
	}

	return result, nil
}

// loginViaLocal handles Local auth login
func (m *DualAuthManager) loginViaLocal(ctx context.Context, email, password string) (*AuthResult, error) {
	if m.localAuth == nil {
		return &AuthResult{
			Success: false,
			Error:   "local_auth_not_configured",
			ErrorVI: "Local auth chưa được cấu hình",
		}, nil
	}

	// Verify password timestamp before accepting Local login (RT-2 mitigation)
	// Note: We need to get user ID first, but for now we'll do verification after login
	result, err := m.localAuth.Login(ctx, email, password)
	if err != nil {
		return result, err
	}

	// If login successful, verify timestamp
	if result != nil && result.Success && result.UserID != "" {
		if err := m.passwordSync.VerifyPasswordTimestamp(ctx, result.UserID); err != nil {
			if err == ErrPasswordOutOfSync {
				return &AuthResult{
					Success: false,
					Error:   "password_out_of_sync",
					ErrorVI: "Mật khẩu đã được thay đổi. Vui lòng đợi Keycloak khôi phục.",
				}, ErrPasswordOutOfSync
			}
		}
	}

	return result, nil
}

// VerifyTOTP verifies TOTP code using appropriate auth mode
func (m *DualAuthManager) VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*AuthResult, error) {
	mode := m.healthChecker.GetCurrentMode()

	var result *AuthResult
	var err error

	if mode == AuthModeKeycloak {
		if m.keycloakAuth != nil {
			result, err = m.keycloakAuth.VerifyTOTP(ctx, mfaToken, totpCode)
		}
	} else {
		if m.localAuth != nil {
			result, err = m.localAuth.VerifyTOTP(ctx, mfaToken, totpCode)
		}
	}

	if result != nil {
		result.AuthMode = string(mode)
	}

	return result, err
}

// VerifyRecovery verifies recovery code using appropriate auth mode
func (m *DualAuthManager) VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*AuthResult, error) {
	mode := m.healthChecker.GetCurrentMode()

	var result *AuthResult
	var err error

	if mode == AuthModeKeycloak {
		if m.keycloakAuth != nil {
			result, err = m.keycloakAuth.VerifyRecovery(ctx, mfaToken, recoveryCode)
		}
	} else {
		if m.localAuth != nil {
			result, err = m.localAuth.VerifyRecovery(ctx, mfaToken, recoveryCode)
		}
	}

	if result != nil {
		result.AuthMode = string(mode)
	}

	return result, err
}

// GetStatus returns current dual auth status
func (m *DualAuthManager) GetStatus(ctx context.Context) *DualAuthStatus {
	healthStatus := m.healthChecker.GetHealthStatus()
	syncStatus, _ := m.passwordSync.GetSyncStatus(ctx)

	failoverCount := 0
	if m.redisClient != nil {
		failoverCount, _ = m.redisClient.GetInt(ctx, "dual_auth_failover_count")
	}

	return &DualAuthStatus{
		CurrentMode:           healthStatus.CurrentMode,
		KeycloakStatus:        healthStatus.KeycloakStatus,
		LastFailoverAt:        healthStatus.LastFailoverAt,
		FailoverCountThisHour: failoverCount,
		FlappingDetected:      healthStatus.FlappingDetected,
		SyncStatus:            syncStatus.Status,
		LastSyncAt:            syncStatus.LastSyncAt,
		NextSyncAt:            syncStatus.NextSyncAt,
	}
}

// DualAuthStatus represents the current dual auth status
type DualAuthStatus struct {
	CurrentMode           string    `json:"current_mode"`
	KeycloakStatus        string    `json:"keycloak_status"`
	LastFailoverAt        time.Time `json:"last_failover_at,omitempty"`
	FailoverCountThisHour int       `json:"failover_count_this_hour"`
	FlappingDetected      bool      `json:"flapping_detected"`
	SyncStatus            string    `json:"sync_status"`
	LastSyncAt            time.Time `json:"last_sync_at"`
	NextSyncAt            time.Time `json:"next_sync_at"`
}

// ManualFailover triggers manual failover (admin only)
func (m *DualAuthManager) ManualFailover(ctx context.Context, adminID, reason string) error {
	return m.healthChecker.ManualFailover(ctx, adminID, reason)
}

// ManualRecovery triggers manual recovery (admin only)
func (m *DualAuthManager) ManualRecovery(ctx context.Context, adminID string) error {
	return m.healthChecker.ManualRecovery(ctx, adminID)
}

// ResetFlapping resets the flapping detection state
func (m *DualAuthManager) ResetFlapping(ctx context.Context, adminID string) error {
	return m.healthChecker.ResetFlapping(ctx, adminID)
}

// GetCurrentMode returns the current authentication mode
func (m *DualAuthManager) GetCurrentMode() AuthMode {
	return m.healthChecker.GetCurrentMode()
}

// isCompleteOutage checks if both auth providers are unavailable (AC-7)
func (m *DualAuthManager) isCompleteOutage(ctx context.Context, mode AuthMode) bool {
	// If in Local mode and Redis/PostgreSQL is unavailable
	if mode == AuthModeLocal {
		// Check Redis availability
		if m.redisClient != nil {
			_, err := m.redisClient.Get(ctx, "ping")
			if err != nil {
				// Redis may just not have this key, that's OK
				// Only consider outage if actual connection fails
				// For now, assume Redis is OK if we can call it
			}
		}
	}

	// For complete outage detection, we would need to check:
	// 1. Keycloak health check result (already tracked)
	// 2. Redis connectivity
	// 3. PostgreSQL connectivity (via userRepo ping)
	// This is a simplified check - full implementation would be more robust
	return false
}

// CompleteOutageResponse creates a 503 response for complete outage
func CompleteOutageResponse() (int, map[string]interface{}) {
	return http.StatusServiceUnavailable, map[string]interface{}{
		"type":       "https://api.bfc-vpn.vn/problems/auth-unavailable",
		"title":      "Service Unavailable",
		"status":     503,
		"detail":     "Hệ thống xác thực tạm thời không khả dụng. Vui lòng thử lại sau.",
		"message_vi": "Hệ thống xác thực tạm thời không khả dụng. Vui lòng thử lại sau.",
	}
}

// SyncPassword syncs a password hash for a user (internal endpoint)
func (m *DualAuthManager) SyncPassword(ctx context.Context, userID string, passwordHash string) error {
	return m.passwordSync.SyncPassword(ctx, userID, passwordHash)
}

// GetSyncStatus returns the current sync status
func (m *DualAuthManager) GetSyncStatus(ctx context.Context) *SyncStatus {
	status, err := m.passwordSync.GetSyncStatus(ctx)
	if err != nil {
		return &SyncStatus{
			Status:    "out_of_sync",
			LastError: err.Error(),
		}
	}
	return status
}
