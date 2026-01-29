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

	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/handler"
	"github.com/bfc-vpn/api/internal/infrastructure/keycloak"
	infraRedis "github.com/bfc-vpn/api/internal/infrastructure/redis"
	"github.com/bfc-vpn/api/internal/repository"
	"github.com/bfc-vpn/api/internal/service/auth"
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

	// Database connection
	db, err := repository.NewDB(ctx, cfg.Database)
	if err != nil {
		slog.Error("Database connection failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Redis connection using infrastructure client
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

	// Keycloak client
	keycloakClient, err := keycloak.NewClient(ctx, cfg.Keycloak)
	if err != nil {
		slog.Error("Keycloak connection failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("Keycloak connected", slog.String("issuer", cfg.Keycloak.IssuerURL))

	// Repositories
	userRepo := repository.NewUserRepository(db.Pool)
	auditRepo := repository.NewAuditRepository(db.Pool)
	recoveryRepo := repository.NewRecoveryRepository(db.Pool)
	localAuthRepo := repository.NewLocalAuthRepository(db.Pool) // Story 2.6

	// Services
	authService := auth.NewService(keycloakClient, userRepo, auditRepo, redisClient)

	totpService, err := totp.NewService(cfg.TOTP, userRepo, auditRepo, redisClient)
	if err != nil {
		slog.Error("TOTP service init failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("TOTP service initialized", slog.String("issuer", cfg.TOTP.Issuer))

	// Recovery service (Story 2.5)
	recoveryService := recovery.NewService(
		recoveryRepo,
		userRepo,
		auditRepo,
		nil,
		redisClient,
	)
	slog.Info("Recovery service initialized")

	// Wire up recovery service to TOTP service
	totpService.SetRecoveryService(&recoveryServiceAdapter{recoveryService})

	// Local Auth Service (Story 2.6)
	localAuthService := localauth.NewService(
		&localAuthUserRepoAdapter{localAuthRepo},
		&localAuthTOTPAdapter{totpService},
		&localAuthRecoveryAdapter{recoveryService},
		&localAuthTokenAdapter{},
		&localAuthAuditAdapter{auditRepo},
		&localAuthRedisAdapter{redisClient},
	)
	slog.Info("Local Auth service initialized")

	// Handlers
	healthHandler := handler.NewHealthHandler(db, redisClient)
	authHandler := handler.NewAuthHandler(authService)
	totpHandler := handler.NewTOTPHandler(totpService)
	recoveryHandler := handler.NewRecoveryHandler(recoveryService)
	localAuthHandler := handler.NewLocalAuthHandler(localAuthService)

	// Router
	router := handler.NewRouter(cfg, healthHandler, authHandler, totpHandler, recoveryHandler, localAuthHandler)

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

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Shutdown signal received", slog.String("signal", sig.String()))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP shutdown error", slog.Any("error", err))
	}
	if err := redisClient.Close(); err != nil {
		slog.Error("Redis close error", slog.Any("error", err))
	}
	db.Close()

	slog.Info("Server exited gracefully")
}

// ============================================================================
// ADAPTERS
// ============================================================================

// recoveryServiceAdapter for TOTP service
type recoveryServiceAdapter struct {
	service *recovery.Service
}

func (a *recoveryServiceAdapter) GenerateAndStore(ctx context.Context, userID uuid.UUID, email, clientIP, userAgent string) (*totp.GenerateRecoveryResponse, error) {
	resp, err := a.service.GenerateAndStore(ctx, userID, email, clientIP, userAgent)
	if err != nil {
		return nil, err
	}
	return &totp.GenerateRecoveryResponse{Codes: resp.Codes}, nil
}

// localAuthUserRepoAdapter adapts LocalAuthRepository to localauth.UserRepository
type localAuthUserRepoAdapter struct {
	repo repository.LocalAuthRepository
}

func (a *localAuthUserRepoAdapter) GetByEmailForLocalAuth(ctx context.Context, email string) (*localauth.UserForLocalAuth, error) {
	user, err := a.repo.GetByEmailForLocalAuth(ctx, email)
	if err != nil {
		return nil, err
	}
	return &localauth.UserForLocalAuth{
		ID:                  user.ID,
		TenantID:            user.TenantID,
		Email:               user.Email,
		PasswordHash:        user.PasswordHash,
		TOTPEnabled:         user.TOTPEnabled,
		TOTPSecretEncrypted: user.TOTPSecretEncrypted,
		Status:              user.Status,
		LocalAuthEnabled:    user.LocalAuthEnabled,
		LockedAt:            user.LockedAt,
		LockedUntil:         user.LockedUntil,
		FailedAttempts:      user.FailedAttempts,
		LastFailedAt:        user.LastFailedAt,
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

func (a *localAuthUserRepoAdapter) Ping(ctx context.Context) error {
	return a.repo.Ping(ctx)
}

// localAuthTOTPAdapter
type localAuthTOTPAdapter struct {
	service *totp.Service
}

func (a *localAuthTOTPAdapter) ValidateCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	return a.service.ValidateCode(ctx, userID, code)
}

// localAuthRecoveryAdapter
type localAuthRecoveryAdapter struct {
	service *recovery.Service
}

func (a *localAuthRecoveryAdapter) Verify(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	return a.service.VerifyAndConsumeCode(ctx, userID, code)
}

// localAuthTokenAdapter - simple token generation
type localAuthTokenAdapter struct{}

func (a *localAuthTokenAdapter) GenerateAccessToken(ctx context.Context, userID, email, tenantID string) (string, int, error) {
	// TODO: Implement proper JWT generation in Story 2.8
	return "local_access_token_" + userID, 900, nil
}

func (a *localAuthTokenAdapter) GenerateRefreshToken(ctx context.Context, userID string) (string, error) {
	return "local_refresh_token_" + userID, nil
}

func (a *localAuthTokenAdapter) GenerateMFAToken(ctx context.Context, userID, email, clientIP, userAgent string) (string, error) {
	return uuid.New().String(), nil
}

// localAuthAuditAdapter
type localAuthAuditAdapter struct {
	repo repository.AuditRepository
}

func (a *localAuthAuditAdapter) LogEvent(ctx context.Context, event localauth.AuditEvent) error {
	return a.repo.LogEvent(ctx, repository.AuditEvent{
		EventType:     event.EventType,
		ActorID:       event.ActorID,
		ActorEmail:    event.ActorEmail,
		ClientIP:      event.ClientIP,
		UserAgent:     event.UserAgent,
		Success:       event.Success,
		FailureReason: event.FailureReason,
		Metadata:      event.Metadata,
	})
}

// localAuthRedisAdapter
type localAuthRedisAdapter struct {
	client *infraRedis.Client
}

func (a *localAuthRedisAdapter) Get(ctx context.Context, key string) (string, error) {
	return a.client.Get(ctx, key)
}

func (a *localAuthRedisAdapter) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return a.client.Set(ctx, key, value, expiration)
}

func (a *localAuthRedisAdapter) Incr(ctx context.Context, key string) (int64, error) {
	return a.client.Incr(ctx, key)
}

func (a *localAuthRedisAdapter) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return a.client.Expire(ctx, key, expiration)
}

func (a *localAuthRedisAdapter) TTL(ctx context.Context, key string) (time.Duration, error) {
	return a.client.TTL(ctx, key)
}

func (a *localAuthRedisAdapter) Delete(ctx context.Context, key string) error {
	return a.client.Delete(ctx, key)
}

func (a *localAuthRedisAdapter) SAdd(ctx context.Context, key string, member interface{}) error {
	return a.client.SAdd(ctx, key, member)
}

func (a *localAuthRedisAdapter) SCard(ctx context.Context, key string) (int64, error) {
	return a.client.SCard(ctx, key)
}

func (a *localAuthRedisAdapter) Ping(ctx context.Context) error {
	return a.client.Ping(ctx)
}
