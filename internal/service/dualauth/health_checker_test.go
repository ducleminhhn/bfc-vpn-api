package dualauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockRedisClient is a mock implementation of RedisClient
type MockRedisClient struct {
	mu     sync.RWMutex
	data   map[string]interface{}
	incrs  map[string]int
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data:  make(map[string]interface{}),
		incrs: make(map[string]int),
	}
}

func (m *MockRedisClient) GetInt(ctx context.Context, key string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.incrs[key]; ok {
		return v, nil
	}
	return 0, nil
}

func (m *MockRedisClient) Incr(ctx context.Context, key string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incrs[key]++
	return nil
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.data[key]; ok {
		return v.(string), nil
	}
	return "", nil
}

func (m *MockRedisClient) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	delete(m.incrs, key)
	return nil
}

// MockAuditLogger is a mock implementation of AuditLogger
type MockAuditLogger struct {
	mu     sync.Mutex
	events []MockAuditEvent
}

type MockAuditEvent struct {
	Event string
	Data  map[string]interface{}
}

func NewMockAuditLogger() *MockAuditLogger {
	return &MockAuditLogger{
		events: make([]MockAuditEvent, 0),
	}
}

func (m *MockAuditLogger) Log(ctx context.Context, event string, data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, MockAuditEvent{Event: event, Data: data})
	return nil
}

func (m *MockAuditLogger) GetEvents() []MockAuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events
}

// MockPasswordSyncer is a mock implementation of PasswordSyncer
type MockPasswordSyncer struct {
	syncCalled bool
	mu         sync.Mutex
}

func NewMockPasswordSyncer() *MockPasswordSyncer {
	return &MockPasswordSyncer{}
}

func (m *MockPasswordSyncer) SyncPassword(ctx context.Context, userID string, passwordHash string) error {
	return nil
}

func (m *MockPasswordSyncer) SyncOnLogin(ctx context.Context, userID string, password string) error {
	return nil
}

func (m *MockPasswordSyncer) SyncAllActiveUsers(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncCalled = true
	return nil
}

func (m *MockPasswordSyncer) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	return &SyncStatus{Status: "synced"}, nil
}

func (m *MockPasswordSyncer) WasSyncCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncCalled
}

// MockNotifier is a mock implementation of Notifier
type MockNotifier struct {
	mu     sync.Mutex
	alerts []AlertConfig
}

func NewMockNotifier() *MockNotifier {
	return &MockNotifier{
		alerts: make([]AlertConfig, 0),
	}
}

func (m *MockNotifier) SendAlert(ctx context.Context, config AlertConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, config)
	return nil
}

func (m *MockNotifier) GetAlerts() []AlertConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.alerts
}

func TestHealthChecker_DetectsKeycloakDown(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:], // Remove "http://"
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	ctx := context.Background()

	// Perform health check
	checker.performHealthCheck(ctx)

	// Should increment consecutive fails
	assert.Equal(t, 1, checker.GetConsecutiveFails())
	assert.Equal(t, AuthModeKeycloak, checker.GetCurrentMode())
}

func TestHealthChecker_TriggersFailoverAfter3Failures(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	passwordSync := NewMockPasswordSyncer()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	checker.SetPasswordSyncer(passwordSync)
	ctx := context.Background()

	// Perform 3 health checks (should trigger failover)
	for i := 0; i < 3; i++ {
		checker.performHealthCheck(ctx)
	}

	// Should switch to Local mode
	assert.Equal(t, AuthModeLocal, checker.GetCurrentMode())
	
	// Should have logged audit event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "auth_failover_triggered", events[0].Event)
	
	// Should have called forced sync
	assert.True(t, passwordSync.WasSyncCalled())
}

func TestHealthChecker_TriggersRecoveryAfter3Successes(t *testing.T) {
	// Create a test server that returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"issuer": "test"}`))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	
	// Manually set to Local mode
	checker.mu.Lock()
	checker.currentMode = AuthModeLocal
	checker.lastFailoverAt = time.Now().Add(-time.Minute)
	checker.mu.Unlock()

	ctx := context.Background()

	// Perform 3 successful health checks (should trigger recovery)
	for i := 0; i < 3; i++ {
		checker.performHealthCheck(ctx)
	}

	// Should switch back to Keycloak mode
	assert.Equal(t, AuthModeKeycloak, checker.GetCurrentMode())
	
	// Should have logged audit event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "auth_recovery_completed", events[0].Event)
}

func TestHealthChecker_FlappingPrevention(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	notifier := NewMockNotifier()

	// Set failover count to max
	redis.incrs["dual_auth_failover_count"] = 3

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	checker.SetNotifier(notifier)
	ctx := context.Background()

	// Perform 3 health checks (would trigger failover normally)
	for i := 0; i < 3; i++ {
		checker.performHealthCheck(ctx)
	}

	// Should detect flapping and stay in Keycloak mode
	assert.True(t, checker.IsFlappingDetected())
	assert.Equal(t, AuthModeKeycloak, checker.GetCurrentMode())
	
	// Should have logged flapping event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "auth_flapping_detected", events[0].Event)
	
	// Should have sent notification
	alerts := notifier.GetAlerts()
	require.Len(t, alerts, 1)
	assert.Equal(t, "CRITICAL", alerts[0].Level)
}

func TestHealthChecker_RWMutexProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       50 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	ctx := context.Background()

	// Start multiple goroutines accessing the checker concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Read operations
			_ = checker.GetCurrentMode()
			_ = checker.GetConsecutiveFails()
			_ = checker.GetConsecutiveOKs()
			_ = checker.IsFlappingDetected()
			_ = checker.GetLastFailoverAt()
			_ = checker.GetHealthStatus()
		}()
	}

	// Also perform health checks concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checker.performHealthCheck(ctx)
		}()
	}

	wg.Wait()
	// If we reach here without deadlock or panic, the test passes
}

func TestHealthChecker_ManualFailover(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()
	passwordSync := NewMockPasswordSyncer()

	config := DefaultHealthCheckConfig()
	config.KeycloakURL = "localhost:8080"

	checker := NewHealthChecker(config, redis, audit, logger)
	checker.SetPasswordSyncer(passwordSync)
	ctx := context.Background()

	// Manual failover
	err := checker.ManualFailover(ctx, "admin-123", "Testing manual failover")
	require.NoError(t, err)

	assert.Equal(t, AuthModeLocal, checker.GetCurrentMode())
	
	// Should have called forced sync
	assert.True(t, passwordSync.WasSyncCalled())
	
	// Should have logged audit event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "admin_manual_failover", events[0].Event)

	// Second manual failover should fail
	err = checker.ManualFailover(ctx, "admin-123", "Another test")
	assert.Equal(t, ErrAlreadyInLocalMode, err)
}

func TestHealthChecker_ManualRecovery(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := DefaultHealthCheckConfig()
	config.KeycloakURL = "localhost:8080"

	checker := NewHealthChecker(config, redis, audit, logger)
	
	// Set to Local mode first
	checker.mu.Lock()
	checker.currentMode = AuthModeLocal
	checker.flappingDetected = true
	checker.mu.Unlock()

	ctx := context.Background()

	// Manual recovery
	err := checker.ManualRecovery(ctx, "admin-123")
	require.NoError(t, err)

	assert.Equal(t, AuthModeKeycloak, checker.GetCurrentMode())
	assert.False(t, checker.IsFlappingDetected())
	
	// Should have logged audit event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "admin_manual_recovery", events[0].Event)

	// Second manual recovery should fail
	err = checker.ManualRecovery(ctx, "admin-123")
	assert.Equal(t, ErrAlreadyInKeycloakMode, err)
}

func TestHealthChecker_ResetFlapping(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := DefaultHealthCheckConfig()
	config.KeycloakURL = "localhost:8080"

	checker := NewHealthChecker(config, redis, audit, logger)
	
	// Set flapping detected
	checker.mu.Lock()
	checker.flappingDetected = true
	checker.mu.Unlock()
	redis.incrs["dual_auth_failover_count"] = 5

	ctx := context.Background()

	// Reset flapping
	err := checker.ResetFlapping(ctx, "admin-123")
	require.NoError(t, err)

	assert.False(t, checker.IsFlappingDetected())
	
	// Redis counter should be deleted
	count, _ := redis.GetInt(ctx, "dual_auth_failover_count")
	assert.Equal(t, 0, count)
	
	// Should have logged audit event
	events := audit.GetEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "admin_flapping_reset", events[0].Event)
}

func TestHealthChecker_GetHealthStatus(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := DefaultHealthCheckConfig()
	config.KeycloakURL = "localhost:8080"

	checker := NewHealthChecker(config, redis, audit, logger)

	status := checker.GetHealthStatus()
	
	assert.Equal(t, "keycloak", status.CurrentMode)
	assert.Equal(t, "healthy", status.KeycloakStatus)
	assert.Equal(t, 0, status.ConsecutiveFails)
	assert.Equal(t, 0, status.ConsecutiveOKs)
	assert.False(t, status.FlappingDetected)
}

func TestHealthChecker_FailoverTiming(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	ctx := context.Background()

	startTime := time.Now()
	
	// Perform 3 health checks (should trigger failover)
	for i := 0; i < 3; i++ {
		checker.performHealthCheck(ctx)
	}

	failoverTime := time.Since(startTime)
	
	// Failover should complete in less than 30 seconds (AC-1 requirement)
	assert.Less(t, failoverTime, 30*time.Second)
	assert.Equal(t, AuthModeLocal, checker.GetCurrentMode())
}

func TestHealthChecker_StartAndStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"issuer": "test"}`))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       50 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the health checker
	checker.Start(ctx)

	// Wait for a few health checks
	time.Sleep(150 * time.Millisecond)

	// Stop the health checker
	checker.Stop()

	// Should have performed at least one health check
	assert.True(t, checker.GetConsecutiveOKs() > 0)
}

func TestHealthChecker_WithNilConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	// Pass nil config - should use defaults
	checker := NewHealthChecker(nil, redis, audit, logger)
	
	assert.NotNil(t, checker)
	assert.Equal(t, AuthModeKeycloak, checker.GetCurrentMode())
}

func TestHealthChecker_WithTLSConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         "localhost:8080",
		CheckInterval:       10 * time.Second,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              true,
		TLSSkipVerify:       true,
		TLSCACertPath:       "/nonexistent/path",
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	assert.NotNil(t, checker)
}

func TestHealthChecker_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	redis := NewMockRedisClient()
	audit := NewMockAuditLogger()

	config := &HealthCheckConfig{
		KeycloakURL:         server.URL[7:],
		CheckInterval:       100 * time.Millisecond,
		FailureThreshold:    3,
		RecoveryThreshold:   3,
		MaxFailoversPerHour: 3,
		Timeout:             5 * time.Second,
		UseTLS:              false,
		KeycloakRealm:       "bfc-vpn",
	}

	checker := NewHealthChecker(config, redis, audit, logger)
	ctx, cancel := context.WithCancel(context.Background())

	// Start the health checker
	checker.Start(ctx)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for goroutine to finish
	time.Sleep(50 * time.Millisecond)
}
