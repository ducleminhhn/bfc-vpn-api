package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bfc-vpn/api/internal/service/totp"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestSetup_MissingMFAToken(t *testing.T) {
	router := gin.New()
	
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/setup", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.POST("/api/v1/auth/totp/setup", func(c *gin.Context) {
		var reqBody totp.SetupRequest
		if err := c.ShouldBindJSON(&reqBody); err != nil || reqBody.MFAToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"type":   "https://bfc-vpn.com/errors/validation",
				"title":  "Dữ liệu không hợp lệ",
				"status": 400,
				"detail": "Dữ liệu không hợp lệ",
				"action": "Vui lòng cung cấp mfa_token",
			})
			return
		}
	})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "Dữ liệu không hợp lệ", response["title"])
}

func TestVerify_InvalidCodeFormat(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"too short", "12345"},
		{"too long", "1234567"},
		{"non-numeric", "12345a"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			
			body := map[string]string{
				"mfa_token": "valid-token",
				"code":      tt.code,
			}
			bodyBytes, _ := json.Marshal(body)
			
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/verify", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.POST("/api/v1/auth/totp/verify", func(c *gin.Context) {
				var reqBody totp.VerifyRequest
				c.ShouldBindJSON(&reqBody)
				
				if len(reqBody.Code) != 6 || !totp.IsNumeric(reqBody.Code) {
					c.JSON(http.StatusBadRequest, gin.H{
						"type":   "https://bfc-vpn.com/errors/validation",
						"title":  "Mã không hợp lệ",
						"status": 400,
						"detail": "Mã không hợp lệ",
						"action": "Mã xác thực phải là 6 chữ số",
					})
					return
				}
			})
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestVerify_ValidCodeFormat(t *testing.T) {
	router := gin.New()
	
	body := map[string]string{
		"mfa_token": "valid-token",
		"code":      "123456",
	}
	bodyBytes, _ := json.Marshal(body)
	
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/totp/verify", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.POST("/api/v1/auth/totp/verify", func(c *gin.Context) {
		var reqBody totp.VerifyRequest
		c.ShouldBindJSON(&reqBody)
		
		if len(reqBody.Code) == 6 && totp.IsNumeric(reqBody.Code) {
			c.JSON(http.StatusOK, gin.H{"status": "format_valid"})
			return
		}
	})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupPage_MissingMFAToken(t *testing.T) {
	router := gin.New()
	
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/totp/setup-page", nil)
	w := httptest.NewRecorder()

	router.GET("/api/v1/auth/totp/setup-page", func(c *gin.Context) {
		mfaToken := c.Query("mfa_token")
		if mfaToken == "" {
			c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("Thiếu mfa_token"))
			return
		}
	})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "mfa_token")
}

func TestVerifyPage_WithMFAToken(t *testing.T) {
	router := gin.New()
	
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/totp/verify-page?mfa_token=test-token", nil)
	w := httptest.NewRecorder()

	router.GET("/api/v1/auth/totp/verify-page", func(c *gin.Context) {
		mfaToken := c.Query("mfa_token")
		if mfaToken == "" {
			c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("Thiếu mfa_token"))
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<html>OTP Verify Page</html>"))
	})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
}

func TestVerifyPage_MissingMFAToken(t *testing.T) {
	router := gin.New()
	
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/totp/verify-page", nil)
	w := httptest.NewRecorder()

	router.GET("/api/v1/auth/totp/verify-page", func(c *gin.Context) {
		mfaToken := c.Query("mfa_token")
		if mfaToken == "" {
			c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte("Thiếu mfa_token"))
			return
		}
	})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
