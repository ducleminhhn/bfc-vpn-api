package middleware

import (
	"log/slog"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
)

func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("Panic recovered",
					slog.Any("error", err),
					slog.String("stack", string(debug.Stack())),
				)
				appErr := apperror.InternalError("Lỗi hệ thống", "Vui lòng thử lại sau")
				// Add request ID if available
				if requestID := c.GetString(RequestIDKey); requestID != "" {
					appErr = appErr.WithRequestID(requestID)
				}
				c.JSON(appErr.Status, appErr)
				c.Abort()
			}
		}()
		c.Next()
	}
}
