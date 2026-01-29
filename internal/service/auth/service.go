package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/bfc-vpn/api/internal/domain"
	"github.com/bfc-vpn/api/internal/infrastructure/keycloak"
	"github.com/bfc-vpn/api/internal/infrastructure/redis"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/repository"
)

// Default tenant ID for users created via Keycloak
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

type Service struct {
	keycloak    *keycloak.Client
	userRepo    repository.UserRepository
	auditRepo   repository.AuditRepository
	redisClient *redis.Client
}

func NewService(kc *keycloak.Client, userRepo repository.UserRepository, auditRepo repository.AuditRepository, redisClient *redis.Client) *Service {
	return &Service{
		keycloak:    kc,
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		redisClient: redisClient,
	}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=12"`
}

type LoginResponse struct {
	Status       string `json:"status"` // "success" or "mfa_required"
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"` // Temporary token for MFA flow
	UserID       string `json:"user_id,omitempty"`
}

// MFATokenData stores MFA session information in Redis (AC-8)
type MFATokenData struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	ClientIP     string `json:"client_ip"`     // SECURITY: IP binding
	UserAgent    string `json:"user_agent"`    // SECURITY: UA binding
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *Service) Login(ctx context.Context, req LoginRequest, clientIP, userAgent string) (*LoginResponse, error) {
	// Step 1: Exchange credentials with Keycloak
	tokenResp, err := s.keycloak.ExchangePassword(ctx, req.Email, req.Password)
	if err != nil {
		slog.Warn("Keycloak authentication failed",
			slog.String("email", req.Email),
			slog.String("client_ip", clientIP),
			slog.Any("error", err),
		)
		// Log failed attempt
		if s.auditRepo != nil {
			_ = s.auditRepo.LogLoginAttempt(ctx, DefaultTenantID, nil, req.Email, clientIP, userAgent, false, "invalid_credentials")
		}
		return nil, apperror.AuthenticationError(
			"Email hoặc mật khẩu không đúng",
			"Vui lòng kiểm tra lại thông tin đăng nhập",
		)
	}

	slog.Info("Keycloak token exchange successful", slog.String("email", req.Email))

	// Step 2: Verify ID token and extract claims
	claims, err := s.keycloak.VerifyIDToken(ctx, tokenResp.IDToken)
	if err != nil {
		slog.Error("ID token verification failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return nil, apperror.InternalError(
			"Lỗi xác thực token",
			"Vui lòng thử lại sau",
		)
	}

	// Step 3: Sync user to local PostgreSQL
	var user *domain.User
	if s.userRepo != nil {
		user, err = s.syncUserFromKeycloak(ctx, claims)
		if err != nil {
			slog.Error("User sync failed",
				slog.String("email", req.Email),
				slog.Any("error", err),
			)
			// Don't fail login, just log warning
			slog.Warn("Proceeding without user sync")
		}
	}

	// Step 4: Check if MFA is required (Story 2.4 Integration)
	if user != nil && user.TOTPEnabled {
		// Generate temporary MFA token
		mfaToken := uuid.New().String()

		// Store MFA token data in Redis with IP/UA binding (AC-8)
		mfaData := MFATokenData{
			UserID:       user.ID.String(),
			Email:        user.Email,
			ClientIP:     clientIP,     // SECURITY: IP binding
			UserAgent:    userAgent,    // SECURITY: UA binding
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			CreatedAt:    time.Now().Unix(),
		}
		mfaJSON, _ := json.Marshal(mfaData)

		if s.redisClient != nil {
			if err := s.redisClient.SetMFAToken(ctx, mfaToken, string(mfaJSON)); err != nil {
				slog.Error("Failed to store MFA token", slog.Any("error", err))
				return nil, apperror.InternalError("Lỗi hệ thống", "Vui lòng thử lại sau")
			}
		}

		if s.auditRepo != nil {
			_ = s.auditRepo.LogLoginAttempt(ctx, user.TenantID, &user.ID, req.Email, clientIP, userAgent, true, "mfa_required")
		}

		slog.Info("MFA required for login",
			slog.String("email", req.Email),
			slog.String("user_id", user.ID.String()),
		)

		return &LoginResponse{
			Status:   "mfa_required",
			MFAToken: mfaToken,
			UserID:   user.ID.String(),
		}, nil
	}

	// Step 5: Login successful
	if s.auditRepo != nil && user != nil {
		_ = s.auditRepo.LogLoginAttempt(ctx, user.TenantID, &user.ID, req.Email, clientIP, userAgent, true, "success")
	}

	// Update last login
	if user != nil && s.userRepo != nil {
		_ = s.userRepo.UpdateLastLogin(ctx, user.ID)
	}

	slog.Info("Login successful",
		slog.String("email", req.Email),
		slog.String("client_ip", clientIP),
	)

	userID := claims.Subject
	if user != nil {
		userID = user.ID.String()
	}

	return &LoginResponse{
		Status:       "success",
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresIn:    tokenResp.ExpiresIn,
		UserID:       userID,
	}, nil
}

func (s *Service) syncUserFromKeycloak(ctx context.Context, claims *keycloak.UserClaims) (*domain.User, error) {
	// Try to find existing user by keycloak_id
	user, err := s.userRepo.GetByKeycloakID(ctx, claims.Subject)
	if err == nil {
		// User exists, return
		return user, nil
	}

	// Try by email
	user, err = s.userRepo.GetByEmail(ctx, claims.Email)
	if err == nil {
		// Update keycloak_id
		if err := s.userRepo.UpdateKeycloakID(ctx, user.ID, claims.Subject); err != nil {
			return nil, err
		}
		user.KeycloakID = claims.Subject
		return user, nil
	}

	// Create new user (first login)
	newUser := &domain.User{
		ID:         uuid.New(),
		TenantID:   DefaultTenantID,
		Email:      claims.Email,
		FullName:   claims.Name,
		KeycloakID: claims.Subject,
		Status:     domain.UserStatusActive,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	slog.Info("New user created from Keycloak",
		slog.String("email", claims.Email),
		slog.String("keycloak_id", claims.Subject),
	)

	return newUser, nil
}
