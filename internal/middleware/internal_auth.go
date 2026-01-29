package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// InternalOnly middleware protects internal endpoints with service-to-service JWT
// This is RT-5 mitigation: Sync Endpoint Abuse prevention
func InternalOnly(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check X-Service-Token header
		token := c.GetHeader("X-Service-Token")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"type":       "authentication_error",
				"message":    "Missing service token",
				"message_vi": "Thiếu service token",
			})
			return
		}

		// Remove "Bearer " prefix if present
		token = strings.TrimPrefix(token, "Bearer ")

		// Verify JWT
		claims := jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
			// Ensure signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(secret), nil
		})

		if err != nil || !parsedToken.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"type":       "authentication_error",
				"message":    "Invalid service token",
				"message_vi": "Service token không hợp lệ",
			})
			return
		}

		// Verify token has service role
		if role, ok := claims["role"].(string); !ok || role != "internal_service" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"type":       "authorization_error",
				"message":    "Token does not have service role",
				"message_vi": "Token không có quyền service",
			})
			return
		}

		// Set service info in context
		if serviceName, ok := claims["service"].(string); ok {
			c.Set("service_name", serviceName)
		}

		c.Next()
	}
}

// GenerateServiceToken creates a JWT token for internal service-to-service calls
func GenerateServiceToken(secret string, serviceName string) (string, error) {
	claims := jwt.MapClaims{
		"role":    "internal_service",
		"service": serviceName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
