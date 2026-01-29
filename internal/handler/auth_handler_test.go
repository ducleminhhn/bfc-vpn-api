package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/bfc-vpn/api/internal/handler"
	"github.com/bfc-vpn/api/internal/service/auth"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestAuthHandler_Login_ValidationError_EmptyBody(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("{}"))
	c.Request.Header.Set("Content-Type", "application/json")

	h := handler.NewAuthHandler(nil)
	h.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Dữ liệu không hợp lệ", response["title"])
}

func TestAuthHandler_Login_ValidationError_ShortPassword(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	body := `{"email":"test@bfc.vn","password":"short"}`
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h := handler.NewAuthHandler(nil)
	h.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_ValidationError_InvalidEmail(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	body := `{"email":"not-an-email","password":"BaDinh@@1972@@"}`
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")

	h := handler.NewAuthHandler(nil)
	h.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_LoginPage(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/login", nil)

	h := handler.NewAuthHandler(nil)
	h.LoginPage(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, w.Body.String(), "BFC METAL VPN")
	assert.Contains(t, w.Body.String(), "Đăng nhập")
	assert.Contains(t, w.Body.String(), "Mật khẩu")
	assert.Contains(t, w.Body.String(), "Email")
}

func TestAuthHandler_LoginPage_RetroTerminalTheme(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/login", nil)

	h := handler.NewAuthHandler(nil)
	h.LoginPage(c)

	body := w.Body.String()
	// Check Retro Terminal Theme colors
	assert.Contains(t, body, "#0d0800")  // background
	assert.Contains(t, body, "#ff9500")  // primary color
	assert.Contains(t, body, "IBM Plex Mono")  // font
}

func TestAuthHandler_LoginPage_VietnameseLabels(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/login", nil)

	h := handler.NewAuthHandler(nil)
	h.LoginPage(c)

	body := w.Body.String()
	assert.Contains(t, body, "Email")
	assert.Contains(t, body, "Mật khẩu")
	assert.Contains(t, body, "ĐĂNG NHẬP")
	assert.Contains(t, body, "Đăng nhập thành công")
}

func TestAuthHandler_Logout(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)

	h := handler.NewAuthHandler(nil)
	h.Logout(c)

	// Logout returns 204 No Content
	assert.True(t, w.Code == http.StatusNoContent || w.Code == http.StatusOK, "Expected 204 or 200, got %d", w.Code)
}

func TestAuthHandler_NotImplemented(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)

	handler.NotImplemented(c)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Chức năng chưa triển khai", response["title"])
}

func TestLoginRequest_Valid(t *testing.T) {
	req := auth.LoginRequest{
		Email:    "test@bfc.vn",
		Password: "BaDinh@@1972@@",
	}
	assert.Equal(t, "test@bfc.vn", req.Email)
	assert.Equal(t, "BaDinh@@1972@@", req.Password)
}

func TestNewAuthHandler(t *testing.T) {
	h := handler.NewAuthHandler(nil)
	assert.NotNil(t, h)
}
