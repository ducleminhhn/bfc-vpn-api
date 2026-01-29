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
	localAuthHandler *LocalAuthHandler,
	dualAuthHandler *DualAuthHandler, // Story 2.7 - Dual Auth Failover
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
			// Dual Auth unified endpoints (Story 2.7)
			if dualAuthHandler != nil {
				auth.POST("/login", dualAuthHandler.Login)           // Unified login with failover
				auth.POST("/totp/verify", dualAuthHandler.VerifyTOTP)
				auth.POST("/recovery/verify", dualAuthHandler.VerifyRecovery)
				auth.GET("/health", dualAuthHandler.GetAuthHealth)   // Current auth mode status
			} else {
				// Fallback to original auth handler if dual auth not configured
				auth.POST("/login", authHandler.Login)
			}
			
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/refresh", NotImplemented) // Story 2.8

			// TOTP setup endpoints (Story 2.4)
			totp := auth.Group("/totp")
			{
				totp.POST("/setup", totpHandler.Setup)
				totp.GET("/setup-page", totpHandler.SetupPage)
				totp.GET("/verify-page", totpHandler.VerifyPage)
			}

			// Recovery endpoints (Story 2.5)
			if recoveryHandler != nil {
				recovery := auth.Group("/recovery")
				{
					recovery.GET("/download", recoveryHandler.Download)
					recovery.GET("/print", recoveryHandler.Print)
				}
			}

			// Local authentication endpoints (Story 2.6 - Direct local access)
			if localAuthHandler != nil {
				localAuth := auth.Group("/local")
				{
					localAuth.POST("/login", localAuthHandler.Login)
					localAuth.POST("/totp/verify", localAuthHandler.VerifyTOTP)
					localAuth.POST("/recovery/verify", localAuthHandler.VerifyRecovery)
				}
			}
		}

		// Admin routes (Story 2.7 - Dual Auth Admin)
		if dualAuthHandler != nil {
			admin := v1.Group("/admin/auth")
			// TODO: Add admin auth middleware when implemented
			// admin.Use(middleware.Auth(), middleware.RequireRole("admin", "super_admin"))
			{
				admin.GET("/dual-status", dualAuthHandler.GetDualStatus)
				admin.POST("/failover", dualAuthHandler.ManualFailover)
				admin.POST("/recover", dualAuthHandler.ManualRecover)
				admin.POST("/reset-flapping", dualAuthHandler.ResetFlapping)
			}
		}

		// Internal routes (Story 2.7 - Password Sync)
		if dualAuthHandler != nil {
			internal := v1.Group("/internal")
			internal.Use(middleware.InternalOnly(cfg.Security.InternalServiceSecret))
			{
				internal.POST("/sync/password", dualAuthHandler.SyncPassword)
				internal.GET("/sync/status", dualAuthHandler.GetSyncStatus)
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
