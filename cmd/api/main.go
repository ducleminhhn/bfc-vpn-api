package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/handler"
	"github.com/bfc-vpn/api/internal/infrastructure/keycloak"
	infraRedis "github.com/bfc-vpn/api/internal/infrastructure/redis"
	"github.com/bfc-vpn/api/internal/repository"
	"github.com/bfc-vpn/api/internal/service/auth"
	"github.com/bfc-vpn/api/internal/service/dualauth"
	"github.com/bfc-vpn/api/internal/service/localauth"
	"github.com/bfc-vpn/api/internal/service/recovery"
	"github.com/bfc-vpn/api/internal/service/totp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	slog.Info("Starting BFC-VPN API...")

	cfg, err := config.Load()
	if err != nil {
		slog.Error("Config load failed", slog.Any("error", err))
		os.Exit(1)
	}

	ctx := context.Background()

	db, err := repository.NewDB(ctx, cfg.Database)
	if err != nil {
		slog.Error("Database connection failed", slog.Any("error", err))
		os.Exit(1)
	}

	redisClient, err := infraRedis.NewClient(infraRedis.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err != nil {
		slog.Error("Redis connection failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("Redis connected")

	keycloakClient, err := keycloak.NewClient(ctx, cfg.Keycloak)
	if err != nil {
		slog.Error("Keycloak connection failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("Keycloak connected", slog.String("issuer", cfg.Keycloak.IssuerURL))

	userRepo := repository.NewUserRepository(db.Pool)
	auditRepo := repository.NewAuditRepository(db.Pool)
	recoveryRepo := repository.NewRecoveryRepository(db.Pool)
	localAuthRepo := repository.NewLocalAuthRepository(db.Pool)

	authService := auth.NewService(keycloakClient, userRepo, auditRepo, redisClient)

	totpService, err := totp.NewService(cfg.TOTP, userRepo, auditRepo, redisClient)
	if err != nil {
		slog.Error("TOTP service init failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("TOTP service initialized")

	recoveryService := recovery.NewService(recoveryRepo, userRepo, auditRepo, nil, redisClient)
	slog.Info("Recovery service initialized")

	totpService.SetRecoveryService(&recoveryServiceAdapter{recoveryService})

	localAuthService := localauth.NewService(
		&localAuthUserRepoAdapter{localAuthRepo},
		&localAuthTOTPAdapter{totpService},
		&localAuthRecoveryAdapter{recoveryService},
		&localAuthTokenAdapter{},
		&localAuthAuditAdapter{auditRepo},
		&localAuthRedisAdapter{redisClient},
	)
	slog.Info("Local Auth service initialized")

	// Story 2.7: Dual Auth Failover
	var dualAuthHandler *handler.DualAuthHandler = nil

	if cfg.DualAuth.Enabled {
		zapLogger, _ := zap.NewProduction()

		dualAuthConfig := &dualauth.DualAuthManagerConfig{
			KeycloakURL:              cfg.Keycloak.IssuerURL,
			HealthCheckIntervalSecs:  cfg.DualAuth.HealthCheckIntervalSecs,
			FailureThreshold:         cfg.DualAuth.FailureThreshold,
			RecoveryThreshold:        cfg.DualAuth.RecoveryThreshold,
			MaxFailoversPerHour:      cfg.DualAuth.MaxFailoversPerHour,
			HealthCheckTimeoutSecs:   cfg.DualAuth.HealthCheckTimeoutSecs,
			PasswordSyncIntervalMins: cfg.DualAuth.PasswordSyncIntervalMins,
			KeycloakRealm:            "bfc-vpn",
		}

		dualAuthManager := dualauth.NewDualAuthManager(
			dualAuthConfig,
			&dualAuthKeycloakAdapter{keycloakClient, authService},
			&dualAuthLocalAdapter{localAuthService},
			&dualAuthRedisAdapter{redisClient},
			&dualAuthAuditAdapter{auditRepo},
			zapLogger,
		)

		dualAuthManager.Start(ctx)
		defer dualAuthManager.Stop()

		slog.Info("Dual Auth service started",
			slog.Bool("enabled", true),
			slog.Int("health_interval_sec", cfg.DualAuth.HealthCheckIntervalSecs))

		dualAuthHandler = handler.NewDualAuthHandler(dualAuthManager)
		dualauth.InitMetrics()
	}

	healthHandler := handler.NewHealthHandler(db, redisClient)
	authHandler := handler.NewAuthHandler(authService)
	totpHandler := handler.NewTOTPHandler(totpService)
	recoveryHandler := handler.NewRecoveryHandler(recoveryService)
	localAuthHandler := handler.NewLocalAuthHandler(localAuthService)

	router := handler.NewRouter(cfg, healthHandler, authHandler, totpHandler, recoveryHandler, localAuthHandler, dualAuthHandler)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		slog.Info("Server starting", slog.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	slog.Info("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	srv.Shutdown(shutdownCtx)
	redisClient.Close()
	db.Close()
	slog.Info("Server stopped")
}

// Existing Adapters

type recoveryServiceAdapter struct{ service *recovery.Service }

func (a *recoveryServiceAdapter) GenerateAndStore(ctx context.Context, userID uuid.UUID, email, clientIP, userAgent string) (*totp.GenerateRecoveryResponse, error) {
	resp, err := a.service.GenerateAndStore(ctx, userID, email, clientIP, userAgent)
	if err != nil {
		return nil, err
	}
	return &totp.GenerateRecoveryResponse{Codes: resp.Codes}, nil
}

type localAuthUserRepoAdapter struct{ repo repository.LocalAuthRepository }

func (a *localAuthUserRepoAdapter) GetByEmailForLocalAuth(ctx context.Context, email string) (*localauth.UserForLocalAuth, error) {
	user, err := a.repo.GetByEmailForLocalAuth(ctx, email)
	if err != nil {
		return nil, err
	}
	return &localauth.UserForLocalAuth{
		ID: user.ID, TenantID: user.TenantID, Email: user.Email, PasswordHash: user.PasswordHash,
		TOTPEnabled: user.TOTPEnabled, TOTPSecretEncrypted: user.TOTPSecretEncrypted,
		Status: user.Status, LocalAuthEnabled: user.LocalAuthEnabled,
		LockedAt: user.LockedAt, LockedUntil: user.LockedUntil,
		FailedAttempts: user.FailedAttempts, LastFailedAt: user.LastFailedAt,
	}, nil
}

func (a *localAuthUserRepoAdapter) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	return a.repo.IncrementLocalFailedAttempts(ctx, userID)
}
func (a *localAuthUserRepoAdapter) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	return a.repo.ResetLocalFailedAttempts(ctx, userID)
}
func (a *localAuthUserRepoAdapter) LockUserAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	return a.repo.LockUserAccount(ctx, userID, lockedUntil)
}
func (a *localAuthUserRepoAdapter) UnlockUserAccount(ctx context.Context, userID uuid.UUID) error {
	return a.repo.UnlockUserAccount(ctx, userID)
}
func (a *localAuthUserRepoAdapter) IsUserLocked(ctx context.Context, userID uuid.UUID) (bool, error) {
	return a.repo.IsUserLockedForLocalAuth(ctx, userID)
}
func (a *localAuthUserRepoAdapter) UpdatePasswordHash(ctx context.Context, userID uuid.UUID, hash string) error {
	return a.repo.UpdateUserPasswordHash(ctx, userID, hash)
}
func (a *localAuthUserRepoAdapter) Ping(ctx context.Context) error { return a.repo.Ping(ctx) }

type localAuthTOTPAdapter struct{ service *totp.Service }

func (a *localAuthTOTPAdapter) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	return a.service.ValidateCode(ctx, userID, code)
}

type localAuthRecoveryAdapter struct{ service *recovery.Service }

func (a *localAuthRecoveryAdapter) Verify(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	return a.service.VerifyAndConsumeCode(ctx, userID, code)
}

type localAuthTokenAdapter struct{}

func (a *localAuthTokenAdapter) GenerateAccessToken(ctx context.Context, userID, email, tenantID string) (string, int, error) {
	return "local_access_token_" + userID, 900, nil
}
func (a *localAuthTokenAdapter) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	return "local_refresh_token_" + userID, nil
}
func (a *localAuthTokenAdapter) GenerateMFAToken(ctx context.Context, userID, email, clientIP, userAgent string) (string, error) {
	return uuid.New().String(), nil
}

type localAuthAuditAdapter struct{ repo repository.AuditRepository }

func (a *localAuthAuditAdapter) LogEvent(ctx context.Context, event localauth.AuditEvent) error {
	return a.repo.LogEvent(ctx, repository.AuditEvent{
		EventType: event.EventType, ActorID: event.ActorID, ActorEmail: event.ActorEmail,
		ClientIP: event.ClientIP, UserAgent: event.UserAgent, Success: event.Success,
		FailureReason: event.FailureReason, Metadata: event.Metadata,
	})
}

type localAuthRedisAdapter struct{ client *infraRedis.Client }

func (a *localAuthRedisAdapter) Get(ctx context.Context, key string) (string, error)                         { return a.client.Get(ctx, key) }
func (a *localAuthRedisAdapter) Set(ctx context.Context, key string, value interface{}, exp time.Duration) error { return a.client.Set(ctx, key, value, exp) }
func (a *localAuthRedisAdapter) Incr(ctx context.Context, key string) (int64, error)                         { return a.client.Incr(ctx, key) }
func (a *localAuthRedisAdapter) Expire(ctx context.Context, key string, exp time.Duration) error             { return a.client.Expire(ctx, key, exp) }
func (a *localAuthRedisAdapter) TTL(ctx context.Context, key string) (time.Duration, error)                  { return a.client.TTL(ctx, key) }
func (a *localAuthRedisAdapter) Delete(ctx context.Context, key string) error                                { return a.client.Delete(ctx, key) }
func (a *localAuthRedisAdapter) SAdd(ctx context.Context, key string, member interface{}) error              { return a.client.SAdd(ctx, key, member) }
func (a *localAuthRedisAdapter) SCard(ctx context.Context, key string) (int64, error)                        { return a.client.SCard(ctx, key) }
func (a *localAuthRedisAdapter) Ping(ctx context.Context) error                                              { return a.client.Ping(ctx) }

// Story 2.7: Dual Auth Adapters

type dualAuthRedisAdapter struct{ client *infraRedis.Client }

func (a *dualAuthRedisAdapter) GetInt(ctx context.Context, key string) (int, error) {
	val, err := a.client.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	var result int
	fmt.Sscanf(val, "%d", &result)
	return result, nil
}
func (a *dualAuthRedisAdapter) Incr(ctx context.Context, key string, ttl time.Duration) error {
	if _, err := a.client.Incr(ctx, key); err != nil {
		return err
	}
	return a.client.Expire(ctx, key, ttl)
}
func (a *dualAuthRedisAdapter) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error { return a.client.Set(ctx, key, value, ttl) }
func (a *dualAuthRedisAdapter) Get(ctx context.Context, key string) (string, error)                             { return a.client.Get(ctx, key) }
func (a *dualAuthRedisAdapter) Delete(ctx context.Context, key string) error                                    { return a.client.Delete(ctx, key) }

type dualAuthAuditAdapter struct{ repo repository.AuditRepository }

func (a *dualAuthAuditAdapter) Log(ctx context.Context, event string, data map[string]interface{}) error {
	return a.repo.LogEvent(ctx, repository.AuditEvent{EventType: event, Metadata: data, Success: true})
}

type dualAuthKeycloakAdapter struct {
	client  *keycloak.Client
	service *auth.Service
}

func (a *dualAuthKeycloakAdapter) Login(ctx context.Context, email, password string) (*dualauth.AuthResult, error) {
	req := auth.LoginRequest{Email: email, Password: password}
	result, err := a.service.Login(ctx, req, "", "")
	if err != nil {
		return nil, err
	}
	needsMFA := result.Status == "mfa_required"
	return &dualauth.AuthResult{
		Success:      true,
		NeedsMFA:     needsMFA,
		MFAToken:     result.MFAToken,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		UserID:       result.UserID,
		AuthMode:     "keycloak",
	}, nil
}
func (a *dualAuthKeycloakAdapter) VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*dualauth.AuthResult, error) {
	return nil, fmt.Errorf("not implemented - use TOTP service")
}
func (a *dualAuthKeycloakAdapter) VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*dualauth.AuthResult, error) {
	return nil, fmt.Errorf("not implemented - use recovery service")
}

type dualAuthLocalAdapter struct{ service *localauth.Service }

func (a *dualAuthLocalAdapter) Login(ctx context.Context, email, password string) (*dualauth.AuthResult, error) {
	req := localauth.LoginRequest{Email: email, Password: password}
	result, err := a.service.Login(ctx, req, "", "")
	if err != nil {
		return nil, err
	}
	success := result.Status == "success" || result.Status == "mfa_required"
	return &dualauth.AuthResult{
		Success:      success,
		NeedsMFA:     result.RequiresMFA,
		MFAToken:     result.MFAToken,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		UserID:       result.UserID,
		AuthMode:     "local",
	}, nil
}
func (a *dualAuthLocalAdapter) VerifyTOTP(ctx context.Context, mfaToken, totpCode string) (*dualauth.AuthResult, error) {
	req := localauth.VerifyTOTPRequest{MFAToken: mfaToken, Code: totpCode}
	result, err := a.service.VerifyTOTP(ctx, req, "", "")
	if err != nil {
		return nil, err
	}
	success := result.Status == "success"
	return &dualauth.AuthResult{
		Success:      success,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		UserID:       result.UserID,
		AuthMode:     "local",
	}, nil
}
func (a *dualAuthLocalAdapter) VerifyRecovery(ctx context.Context, mfaToken, recoveryCode string) (*dualauth.AuthResult, error) {
	req := localauth.VerifyRecoveryRequest{MFAToken: mfaToken, Code: recoveryCode}
	result, err := a.service.VerifyRecovery(ctx, req, "", "")
	if err != nil {
		return nil, err
	}
	success := result.Status == "success"
	return &dualauth.AuthResult{
		Success:      success,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		UserID:       result.UserID,
		AuthMode:     "local",
	}, nil
}
