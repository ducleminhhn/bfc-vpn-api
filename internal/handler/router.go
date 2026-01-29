package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/bfc-vpn/api/internal/config"
	"github.com/bfc-vpn/api/internal/middleware"
)

func NewRouter(
	cfg *config.Config,
	healthHandler *HealthHandler,
	authHandler *AuthHandler,
	totpHandler *TOTPHandler,
	recoveryHandler *RecoveryHandler,
	localAuthHandler *LocalAuthHandler, // Story 2.6
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// Global middleware (order matters!)
	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())
	r.Use(middleware.SecurityHeaders(cfg.Server.HTTPS))
	r.Use(middleware.Metrics())
	r.Use(middleware.CORS(cfg.CORS))

	// Health endpoints (no auth required)
	r.GET("/health", healthHandler.Shallow)
	r.GET("/health/ready", healthHandler.Ready)

	// Prometheus metrics endpoint (restrict to internal IPs in production)
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Login page (public)
	r.GET("/login", authHandler.LoginPage)

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/refresh", NotImplemented) // Story 2.8

			// TOTP endpoints (Story 2.4)
			totp := auth.Group("/totp")
			{
				totp.POST("/setup", totpHandler.Setup)
				totp.POST("/verify", totpHandler.Verify)
				totp.GET("/setup-page", totpHandler.SetupPage)
				totp.GET("/verify-page", totpHandler.VerifyPage)
			}

			// Recovery endpoints (Story 2.5)
			if recoveryHandler != nil {
				recovery := auth.Group("/recovery")
				{
					// Public - use recovery code for MFA instead of TOTP
					recovery.POST("/verify", recoveryHandler.Verify)
					// AC-3: Download and Print endpoints (available during setup flow)
					recovery.GET("/download", recoveryHandler.Download)
					recovery.GET("/print", recoveryHandler.Print)
				}
			}

			// Local authentication endpoints (Story 2.6 - Dual Auth Backup)
			if localAuthHandler != nil {
				localAuth := auth.Group("/local")
				{
					localAuth.POST("/login", localAuthHandler.Login)
					localAuth.POST("/totp/verify", localAuthHandler.VerifyTOTP)
					localAuth.POST("/recovery/verify", localAuthHandler.VerifyRecovery)
				}
			}
		}

		// Protected routes (require authentication) - Story 2.5 regenerate
		if recoveryHandler != nil {
			protected := v1.Group("/user")
			// TODO: Add auth middleware when implemented
			// protected.Use(middleware.Auth())
			{
				protected.POST("/recovery/regenerate", recoveryHandler.Regenerate)
				protected.GET("/recovery/status", recoveryHandler.GetStatus)
			}
		}
	}

	return r
}
