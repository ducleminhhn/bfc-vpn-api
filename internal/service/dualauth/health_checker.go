package dualauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AuthMode represents the current authentication mode
type AuthMode string

const (
	AuthModeKeycloak AuthMode = "keycloak"
	AuthModeLocal    AuthMode = "local"
)

// HealthCheckConfig holds configuration for health checks
type HealthCheckConfig struct {
	KeycloakURL         string        // Keycloak base URL
	CheckInterval       time.Duration // Default: 10 seconds
	FailureThreshold    int           // Default: 3 consecutive failures
	RecoveryThreshold   int           // Default: 3 consecutive successes
	MaxFailoversPerHour int           // Default: 3
	Timeout             time.Duration // HTTP request timeout
	UseTLS              bool          // Default: true
	TLSSkipVerify       bool          // Default: false
	TLSCACertPath       string        // Optional CA cert path
	KeycloakRealm       string        // Default: "bfc-vpn"
}

// DefaultHealthCheckConfig returns default configuration
func DefaultHealthCheckConfig() *HealthCheckConfig {
	return &HealthCheckConfig{
		CheckInterval:       10 * time.Second,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              true, // Use HTTPS for production security (RT-4)
		TLSSkipVerify:       false,
		KeycloakRealm:       "bfc-vpn",
	}
}

// HealthChecker manages Keycloak health monitoring
type HealthChecker struct {
	config       *HealthCheckConfig
	httpClient   *http.Client
	logger       *zap.Logger
	redisClient  RedisClient
	auditLogger  AuditLogger
	passwordSync PasswordSyncer
	notifier     Notifier

	mu               sync.RWMutex
	currentMode      AuthMode
	consecutiveFails int
	consecutiveOKs   int
	lastFailoverAt   time.Time
	flappingDetected bool
	localModeCache   AuthMode

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker(
	config *HealthCheckConfig,
	redisClient RedisClient,
	auditLogger AuditLogger,
	logger *zap.Logger,
) *HealthChecker {
	if config == nil {
		config = DefaultHealthCheckConfig()
	}

	// Create HTTP client with optional TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		},
	}

	if config.TLSCACertPath != "" {
		caCert, err := os.ReadFile(config.TLSCACertPath)
		if err == nil {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			transport.TLSClientConfig.RootCAs = caCertPool
		}
	}

	return &HealthChecker{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
		logger:         logger,
		redisClient:    redisClient,
		auditLogger:    auditLogger,
		currentMode:    AuthModeKeycloak, // Start with Keycloak
		localModeCache: AuthModeKeycloak,
		stopCh:         make(chan struct{}),
	}
}

// SetPasswordSyncer sets the password syncer (to avoid circular dependency)
func (h *HealthChecker) SetPasswordSyncer(ps PasswordSyncer) {
	h.passwordSync = ps
}

// SetNotifier sets the notifier for alerts
func (h *HealthChecker) SetNotifier(n Notifier) {
	h.notifier = n
}

// Start begins the health check loop
func (h *HealthChecker) Start(ctx context.Context) {
	h.wg.Add(1)
	go h.run(ctx)
}

// Stop gracefully stops the health checker
func (h *HealthChecker) Stop() {
	close(h.stopCh)
	h.wg.Wait()
}

// GetCurrentMode returns the current authentication mode (thread-safe)
func (h *HealthChecker) GetCurrentMode() AuthMode {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.currentMode
}

// GetConsecutiveFails returns the current consecutive failure count
func (h *HealthChecker) GetConsecutiveFails() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.consecutiveFails
}

// GetConsecutiveOKs returns the current consecutive success count
func (h *HealthChecker) GetConsecutiveOKs() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.consecutiveOKs
}

// IsFlappingDetected returns whether flapping has been detected
func (h *HealthChecker) IsFlappingDetected() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.flappingDetected
}

// GetLastFailoverAt returns the timestamp of last failover
func (h *HealthChecker) GetLastFailoverAt() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastFailoverAt
}

// run is the main health check loop
func (h *HealthChecker) run(ctx context.Context) {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.CheckInterval)
	defer ticker.Stop()

	// Run initial health check
	h.performHealthCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.performHealthCheck(ctx)
		}
	}
}

// performHealthCheck checks Keycloak health and handles state transitions
func (h *HealthChecker) performHealthCheck(ctx context.Context) {
	startTime := time.Now()
	healthy := h.checkKeycloakHealth(ctx)
	latency := time.Since(startTime)

	h.logger.Debug("Health check completed",
		zap.Bool("healthy", healthy),
		zap.Duration("latency", latency))

	h.mu.Lock()
	defer h.mu.Unlock()

	if healthy {
		h.consecutiveFails = 0
		h.consecutiveOKs++

		// Check for recovery
		if h.currentMode == AuthModeLocal && h.consecutiveOKs >= h.config.RecoveryThreshold {
			h.triggerRecoveryLocked(ctx)
		}
	} else {
		h.consecutiveOKs = 0
		h.consecutiveFails++

		h.logger.Warn("Keycloak health check failed",
			zap.Int("consecutive_fails", h.consecutiveFails),
			zap.Int("threshold", h.config.FailureThreshold))

		// Check for failover
		if h.currentMode == AuthModeKeycloak && h.consecutiveFails >= h.config.FailureThreshold {
			h.triggerFailoverLocked(ctx)
		}
	}
}

// checkKeycloakHealth pings Keycloak OpenID Configuration endpoint
func (h *HealthChecker) checkKeycloakHealth(ctx context.Context) bool {
	scheme := "http"
	if h.config.UseTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/realms/%s/.well-known/openid-configuration",
		scheme,
		h.config.KeycloakURL,
		h.config.KeycloakRealm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		h.logger.Error("Failed to create health check request", zap.Error(err))
		return false
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		h.logger.Warn("Keycloak health check failed",
			zap.String("url", url),
			zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// triggerFailoverLocked switches to Local auth mode (must hold lock)
func (h *HealthChecker) triggerFailoverLocked(ctx context.Context) {
	// Check flapping prevention
	if h.flappingDetected {
		h.logger.Warn("Failover blocked due to flapping detection")
		return
	}

	failoverCount, err := h.getFailoverCount(ctx)
	if err != nil {
		h.logger.Error("Failed to get failover count", zap.Error(err))
	}

	if failoverCount >= h.config.MaxFailoversPerHour {
		h.flappingDetected = true
		h.logger.Error("Flapping detected - max failovers per hour exceeded",
			zap.Int("count", failoverCount),
			zap.Int("max", h.config.MaxFailoversPerHour))

		if h.auditLogger != nil {
			h.auditLogger.Log(ctx, "auth_flapping_detected", map[string]interface{}{
				"failover_count":    failoverCount,
				"severity":          "CRITICAL",
				"notification_sent": true,
			})
		}

		// Send immediate notification
		if h.notifier != nil {
			h.notifier.SendAlert(ctx, AlertConfig{
				Level:   "CRITICAL",
				Title:   "Dual Auth Flapping Detected",
				Message: fmt.Sprintf("Max failovers (%d) exceeded in 1 hour. Manual intervention required.", failoverCount),
				Channel: []string{"email", "slack", "webhook"},
			})
		}
		return
	}

	// Force sync before accepting Local logins (RT-1, RT-2 mitigation)
	if h.passwordSync != nil {
		h.logger.Info("Forcing password sync before Local auth activation")
		if err := h.passwordSync.SyncAllActiveUsers(ctx); err != nil {
			h.logger.Error("Failed to force sync, proceeding with caution", zap.Error(err))
			if h.auditLogger != nil {
				h.auditLogger.Log(ctx, "forced_sync_failed", map[string]interface{}{
					"error":    err.Error(),
					"severity": "WARNING",
				})
			}
		}
	}

	// Perform failover
	h.currentMode = AuthModeLocal
	h.localModeCache = AuthModeLocal
	h.lastFailoverAt = time.Now()
	h.consecutiveFails = 0

	// Increment failover count in Redis
	h.incrementFailoverCount(ctx)

	h.logger.Info("Failover triggered - switched to Local auth",
		zap.Time("timestamp", h.lastFailoverAt))

	if h.auditLogger != nil {
		h.auditLogger.Log(ctx, "auth_failover_triggered", map[string]interface{}{
			"from_mode":     "keycloak",
			"to_mode":       "local",
			"trigger":       "health_check_failure",
			"failure_count": h.config.FailureThreshold,
		})
	}
}

// triggerRecoveryLocked switches back to Keycloak auth mode (must hold lock)
func (h *HealthChecker) triggerRecoveryLocked(ctx context.Context) {
	duration := time.Since(h.lastFailoverAt)

	h.currentMode = AuthModeKeycloak
	h.localModeCache = AuthModeKeycloak
	h.consecutiveOKs = 0
	h.flappingDetected = false

	h.logger.Info("Recovery completed - switched back to Keycloak",
		zap.Duration("local_mode_duration", duration))

	if h.auditLogger != nil {
		h.auditLogger.Log(ctx, "auth_recovery_completed", map[string]interface{}{
			"from_mode":        "local",
			"to_mode":          "keycloak",
			"duration_seconds": duration.Seconds(),
		})
	}
}

// getFailoverCount gets current failover count from Redis
func (h *HealthChecker) getFailoverCount(ctx context.Context) (int, error) {
	if h.redisClient == nil {
		return 0, nil
	}
	count, err := h.redisClient.GetInt(ctx, "dual_auth_failover_count")
	if err != nil {
		// Treat error as 0 count (new key)
		return 0, nil
	}
	return count, nil
}

// incrementFailoverCount increments failover count in Redis with 1-hour TTL
func (h *HealthChecker) incrementFailoverCount(ctx context.Context) error {
	if h.redisClient == nil {
		return nil
	}
	return h.redisClient.Incr(ctx, "dual_auth_failover_count", time.Hour)
}

// ManualFailover triggers manual failover (for admin use)
func (h *HealthChecker) ManualFailover(ctx context.Context, adminID, reason string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currentMode == AuthModeLocal {
		return ErrAlreadyInLocalMode
	}

	// Force sync before accepting Local logins
	if h.passwordSync != nil {
		h.logger.Info("Forcing password sync for manual failover")
		if err := h.passwordSync.SyncAllActiveUsers(ctx); err != nil {
			h.logger.Error("Failed to force sync", zap.Error(err))
		}
	}

	h.currentMode = AuthModeLocal
	h.localModeCache = AuthModeLocal
	h.lastFailoverAt = time.Now()

	h.logger.Info("Manual failover triggered",
		zap.String("admin_id", adminID),
		zap.String("reason", reason))

	if h.auditLogger != nil {
		h.auditLogger.Log(ctx, "admin_manual_failover", map[string]interface{}{
			"admin_id": adminID,
			"reason":   reason,
		})
	}

	return nil
}

// ManualRecovery triggers manual recovery (for admin use)
func (h *HealthChecker) ManualRecovery(ctx context.Context, adminID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currentMode == AuthModeKeycloak {
		return ErrAlreadyInKeycloakMode
	}

	h.currentMode = AuthModeKeycloak
	h.localModeCache = AuthModeKeycloak
	h.flappingDetected = false

	h.logger.Info("Manual recovery triggered",
		zap.String("admin_id", adminID))

	if h.auditLogger != nil {
		h.auditLogger.Log(ctx, "admin_manual_recovery", map[string]interface{}{
			"admin_id": adminID,
		})
	}

	return nil
}

// ResetFlapping resets the flapping detection state (for admin use)
func (h *HealthChecker) ResetFlapping(ctx context.Context, adminID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.flappingDetected = false

	// Clear Redis counter
	if h.redisClient != nil {
		h.redisClient.Delete(ctx, "dual_auth_failover_count")
	}

	h.logger.Info("Flapping reset triggered",
		zap.String("admin_id", adminID))

	if h.auditLogger != nil {
		h.auditLogger.Log(ctx, "admin_flapping_reset", map[string]interface{}{
			"admin_id": adminID,
		})
	}

	return nil
}

// GetHealthStatus returns detailed health status
func (h *HealthChecker) GetHealthStatus() *HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	keycloakStatus := "healthy"
	if h.currentMode == AuthModeLocal {
		keycloakStatus = "unhealthy"
	}

	return &HealthStatus{
		CurrentMode:      string(h.currentMode),
		KeycloakStatus:   keycloakStatus,
		ConsecutiveFails: h.consecutiveFails,
		ConsecutiveOKs:   h.consecutiveOKs,
		LastFailoverAt:   h.lastFailoverAt,
		FlappingDetected: h.flappingDetected,
	}
}

// HealthStatus represents detailed health status
type HealthStatus struct {
	CurrentMode      string    `json:"current_mode"`
	KeycloakStatus   string    `json:"keycloak_status"`
	ConsecutiveFails int       `json:"consecutive_fails"`
	ConsecutiveOKs   int       `json:"consecutive_oks"`
	LastFailoverAt   time.Time `json:"last_failover_at,omitempty"`
	FlappingDetected bool      `json:"flapping_detected"`
}
