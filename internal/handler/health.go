package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/infrastructure/redis"
	"github.com/bfc-vpn/api/internal/repository"
)

type HealthHandler struct {
	db    *repository.DB
	redis *redis.Client
}

func NewHealthHandler(db *repository.DB, redis *redis.Client) *HealthHandler {
	return &HealthHandler{db: db, redis: redis}
}

func (h *HealthHandler) Shallow(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]gin.H)
	allHealthy := true

	// Database check
	start := time.Now()
	if err := h.db.HealthCheck(ctx); err != nil {
		checks["database"] = gin.H{"status": "unhealthy", "error": err.Error()}
		allHealthy = false
	} else {
		checks["database"] = gin.H{"status": "ok", "latency_ms": time.Since(start).Milliseconds()}
	}

	// Redis check
	start = time.Now()
	if err := h.redis.Ping(ctx); err != nil {
		checks["redis"] = gin.H{"status": "unhealthy", "error": err.Error()}
		allHealthy = false
	} else {
		checks["redis"] = gin.H{"status": "ok", "latency_ms": time.Since(start).Milliseconds()}
	}

	status := http.StatusOK
	statusStr := "ok"
	if !allHealthy {
		status = http.StatusServiceUnavailable
		statusStr = "unhealthy"
	}

	c.JSON(status, gin.H{"status": statusStr, "checks": checks})
}
