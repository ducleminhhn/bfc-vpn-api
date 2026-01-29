package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
	"github.com/bfc-vpn/api/internal/service/auth"
)

type AuthHandler struct {
	authService *auth.Service
}

func NewAuthHandler(authService *auth.Service) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError(
			"Email hoặc mật khẩu không hợp lệ",
			"Vui lòng kiểm tra lại thông tin đăng nhập",
		).WithErrors(map[string]string{
			"email":    "Email không đúng định dạng",
			"password": "Mật khẩu tối thiểu 12 ký tự",
		}))
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	resp, err := h.authService.Login(c.Request.Context(), req, clientIP, userAgent)
	if err != nil {
		if appErr, ok := err.(*apperror.AppError); ok {
			response.Error(c, appErr)
			return
		}
		response.Error(c, apperror.InternalError(
			"Lỗi đăng nhập không xác định",
			"Vui lòng thử lại sau",
		).WithError(err))
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// TODO: Implement in Story 2.8 (Session Management)
	response.NoContent(c)
}

// LoginPage serves the HTML login form (Retro Terminal Theme)
func (h *AuthHandler) LoginPage(c *gin.Context) {
	html := `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BFC VPN - Đăng nhập</title>
    <style>
        body {
            background: #0d0800;
            color: #ff9500;
            font-family: 'IBM Plex Mono', 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-box {
            background: #1a0f05;
            border: 1px solid #ff9500;
            padding: 40px;
            max-width: 400px;
            box-shadow: 0 0 20px rgba(255, 149, 0, 0.3);
        }
        h1 { color: #ffd060; font-size: 24px; margin-bottom: 30px; text-align: center; }
        .subtitle { color: #995500; font-size: 12px; text-align: center; margin-top: -20px; margin-bottom: 30px; }
        label { display: block; margin-bottom: 5px; color: #ffd060; font-size: 14px; }
        input {
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            background: #0d0800;
            border: 1px solid #995500;
            color: #ff9500;
            font-family: inherit;
            box-sizing: border-box;
        }
        input:focus { border-color: #ffd060; outline: none; box-shadow: 0 0 5px rgba(255, 149, 0, 0.5); }
        input::placeholder { color: #664400; }
        button {
            width: 100%;
            padding: 14px;
            margin-top: 10px;
            background: #ff9500;
            color: #0d0800;
            border: none;
            cursor: pointer;
            font-family: inherit;
            font-weight: bold;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        button:hover { background: #ffd060; }
        button:disabled { background: #664400; cursor: not-allowed; }
        .error { color: #ff6666; font-size: 14px; margin-top: 15px; text-align: center; min-height: 20px; }
        .success { color: #66ff66; }
        .loading { color: #ffd060; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>▶ BFC METAL VPN</h1>
        <p class="subtitle">Secure Access Terminal v2.0</p>
        <form id="loginForm">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" placeholder="your@email.com" required>

            <label for="password">Mật khẩu</label>
            <input type="password" id="password" name="password" placeholder="••••••••••••" minlength="12" required>

            <button type="submit" id="submitBtn">ĐĂNG NHẬP</button>
            <div class="error" id="error"></div>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').onsubmit = async (e) => {
            e.preventDefault();
            const form = e.target;
            const error = document.getElementById('error');
            const submitBtn = document.getElementById('submitBtn');

            submitBtn.disabled = true;
            submitBtn.textContent = 'ĐANG XÁC THỰC...';
            error.className = 'error loading';
            error.textContent = 'Đang kết nối...';

            try {
                const resp = await fetch('/api/v1/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: form.email.value,
                        password: form.password.value
                    })
                });
                const data = await resp.json();
                if (resp.ok) {
                    if (data.status === 'mfa_required') {
                        error.className = 'error loading';
                        error.textContent = 'Yêu cầu xác thực MFA (Story 2.4)';
                    } else {
                        error.className = 'error success';
                        error.textContent = '✓ Đăng nhập thành công!';
                        console.log('Access token:', data.access_token);
                    }
                } else {
                    error.className = 'error';
                    error.textContent = data.detail || data.title || 'Đăng nhập thất bại';
                }
            } catch (err) {
                error.className = 'error';
                error.textContent = 'Lỗi kết nối server';
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = 'ĐĂNG NHẬP';
            }
        };
    </script>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// NotImplemented returns 501 for unimplemented endpoints
func NotImplemented(c *gin.Context) {
	response.Error(c, apperror.NotImplementedError())
}
