package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
	"github.com/bfc-vpn/api/internal/service/totp"
)

// TOTPHandler handles TOTP-related HTTP requests
type TOTPHandler struct {
	service *totp.Service
}

// NewTOTPHandler creates a new TOTP handler
func NewTOTPHandler(service *totp.Service) *TOTPHandler {
	return &TOTPHandler{service: service}
}

// Setup handles POST /api/v1/auth/totp/setup
func (h *TOTPHandler) Setup(c *gin.Context) {
	var req totp.SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError("Dữ liệu không hợp lệ", "Vui lòng cung cấp mfa_token"))
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Setup(c.Request.Context(), req, clientIP, userAgent)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	response.Success(c, resp)
}

// Verify handles POST /api/v1/auth/totp/verify
func (h *TOTPHandler) Verify(c *gin.Context) {
	var req totp.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, apperror.ValidationError("Dữ liệu không hợp lệ", "Vui lòng cung cấp mfa_token và mã 6 chữ số"))
		return
	}

	// Validate code format
	if len(req.Code) != 6 || !totp.IsNumeric(req.Code) {
		response.Error(c, apperror.ValidationError("Mã không hợp lệ", "Mã xác thực phải là 6 chữ số"))
		return
	}

	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Verify(c.Request.Context(), req, clientIP, userAgent)
	if err != nil {
		response.ErrorFromErr(c, err)
		return
	}

	response.Success(c, resp)
}

// SetupPage handles GET /api/v1/auth/totp/setup-page
func (h *TOTPHandler) SetupPage(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte(errorHTML("Thiếu mfa_token")))
		return
	}

	// Generate setup data
	req := totp.SetupRequest{MFAToken: mfaToken}
	clientIP := c.ClientIP()
	userAgent := c.Request.UserAgent()

	resp, err := h.service.Setup(c.Request.Context(), req, clientIP, userAgent)
	if err != nil {
		c.Data(http.StatusUnauthorized, "text/html; charset=utf-8", []byte(errorHTML("Phiên xác thực không hợp lệ. Vui lòng đăng nhập lại.")))
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(setupPageHTML(mfaToken, resp.Secret, resp.OTPAuthURL)))
}

// VerifyPage handles GET /api/v1/auth/totp/verify-page
func (h *TOTPHandler) VerifyPage(c *gin.Context) {
	mfaToken := c.Query("mfa_token")
	if mfaToken == "" {
		c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte(errorHTML("Thiếu mfa_token")))
		return
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(verifyPageHTML(mfaToken)))
}

func errorHTML(msg string) string {
	return `<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><title>Lỗi</title>
<style>body{font-family:monospace;background:#0d0800;color:#ff6666;display:flex;align-items:center;justify-content:center;min-height:100vh}
.error{background:#1a0f05;border:2px solid #ff6666;padding:32px;border-radius:8px;text-align:center}</style></head>
<body><div class="error"><h1>⚠️ Lỗi</h1><p>` + msg + `</p></div></body></html>`
}

func setupPageHTML(mfaToken, secret, otpauthURL string) string {
	return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Thiết lập TOTP - BFC VPN</title>
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:'IBM Plex Mono',monospace;background:#0d0800;color:#ff9500;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
        .container{background:#1a0f05;border:2px solid #ff9500;border-radius:8px;padding:32px;max-width:400px;width:100%}
        h1{color:#ffd060;font-size:20px;margin-bottom:24px;text-align:center}
        .qr-container{background:white;padding:16px;border-radius:8px;margin:24px auto;width:fit-content}
        .secret-code{background:#120a02;border:1px solid #995500;border-radius:4px;padding:12px;margin:16px 0;font-size:14px;word-break:break-all;text-align:center}
        .instructions{font-size:14px;line-height:1.6;margin:16px 0}
        .instructions ol{padding-left:20px}
        .instructions li{margin:8px 0}
        input[type="text"]{width:100%;padding:12px;background:#120a02;border:1px solid #995500;border-radius:4px;color:#ffd060;font-size:24px;text-align:center;letter-spacing:8px;font-family:'JetBrains Mono',monospace}
        input[type="text"]:focus{outline:none;border-color:#ffd060}
        button{width:100%;padding:12px;margin-top:16px;background:#ff9500;border:none;border-radius:4px;color:#0d0800;font-weight:bold;font-size:16px;cursor:pointer}
        button:hover{background:#ffd060}
        button:disabled{background:#995500;cursor:not-allowed}
        .error{color:#ff6666;text-align:center;margin-top:16px;display:none}
        .loading{display:none;text-align:center;margin-top:16px}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>🔐 Thiết lập xác thực hai yếu tố</h1>
        <div class="instructions">
            <ol>
                <li>Tải ứng dụng xác thực (Google Authenticator, Authy)</li>
                <li>Quét mã QR hoặc nhập mã thủ công</li>
                <li>Nhập mã 6 chữ số để xác nhận</li>
            </ol>
        </div>
        <div class="qr-container"><canvas id="qrcode"></canvas></div>
        <div class="secret-code"><strong>Mã thủ công:</strong><br>` + secret + `</div>
        <form id="verifyForm">
            <input type="hidden" name="mfa_token" value="` + mfaToken + `">
            <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{6}" placeholder="______" autocomplete="one-time-code" required>
            <button type="submit" id="submitBtn">Xác nhận</button>
        </form>
        <div class="error" id="errorMsg"></div>
        <div class="loading" id="loading">Đang xác thực...</div>
    </div>
    <script>
        QRCode.toCanvas(document.getElementById('qrcode'), '` + otpauthURL + `', {width:200,margin:0});
        const codeInput=document.getElementById('code'),form=document.getElementById('verifyForm'),submitBtn=document.getElementById('submitBtn'),errorMsg=document.getElementById('errorMsg'),loading=document.getElementById('loading');
        codeInput.addEventListener('input',function(){this.value=this.value.replace(/[^0-9]/g,'');if(this.value.length===6)form.dispatchEvent(new Event('submit'))});
        form.addEventListener('submit',async function(e){e.preventDefault();const code=codeInput.value;if(code.length!==6)return;submitBtn.disabled=true;loading.style.display='block';errorMsg.style.display='none';
        try{const response=await fetch('/api/v1/auth/totp/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mfa_token:'` + mfaToken + `',code:code})});
        const data=await response.json();if(response.ok){localStorage.setItem('access_token',data.access_token);localStorage.setItem('refresh_token',data.refresh_token);window.location.href='/dashboard'}
        else{errorMsg.textContent=data.detail||'Mã không đúng';errorMsg.style.display='block';codeInput.value='';codeInput.focus()}}
        catch(err){errorMsg.textContent='Lỗi kết nối';errorMsg.style.display='block'}finally{submitBtn.disabled=false;loading.style.display='none'}});
        codeInput.focus();
    </script>
</body>
</html>`
}

func verifyPageHTML(mfaToken string) string {
	return `<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xác thực OTP - BFC VPN</title>
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:'IBM Plex Mono',monospace;background:#0d0800;color:#ff9500;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
        .container{background:#1a0f05;border:2px solid #ff9500;border-radius:8px;padding:32px;max-width:400px;width:100%;text-align:center}
        h1{color:#ffd060;font-size:20px;margin-bottom:8px}
        .subtitle{color:#995500;font-size:14px;margin-bottom:24px}
        .otp-input{display:flex;gap:8px;justify-content:center;margin:24px 0}
        .otp-input input{width:48px;height:56px;background:#120a02;border:2px solid #995500;border-radius:8px;color:#ffd060;font-size:24px;text-align:center;font-family:'JetBrains Mono',monospace}
        .otp-input input:focus{outline:none;border-color:#ffd060}
        .error{color:#ff6666;margin-top:16px;display:none}
        .loading{display:none;margin-top:16px}
        .spinner{width:24px;height:24px;border:3px solid #995500;border-top-color:#ffd060;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto}
        @keyframes spin{to{transform:rotate(360deg)}}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Nhập mã xác thực</h1>
        <p class="subtitle">Mở ứng dụng xác thực và nhập mã 6 chữ số</p>
        <div class="otp-input" id="otpInputs">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric" autocomplete="one-time-code">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric">
            <input type="text" maxlength="1" pattern="[0-9]" inputmode="numeric">
        </div>
        <div class="error" id="errorMsg"></div>
        <div class="loading" id="loading"><div class="spinner"></div><p style="margin-top:8px">Đang xác thực...</p></div>
    </div>
    <script>
        const inputs=document.querySelectorAll('.otp-input input'),errorMsg=document.getElementById('errorMsg'),loading=document.getElementById('loading');
        inputs.forEach((input,index)=>{
            input.addEventListener('input',function(){this.value=this.value.replace(/[^0-9]/g,'');if(this.value&&index<inputs.length-1)inputs[index+1].focus();checkComplete()});
            input.addEventListener('keydown',function(e){if(e.key==='Backspace'&&!this.value&&index>0)inputs[index-1].focus()});
            input.addEventListener('paste',function(e){e.preventDefault();const paste=(e.clipboardData||window.clipboardData).getData('text');const digits=paste.replace(/[^0-9]/g,'').split('').slice(0,6);digits.forEach((digit,i)=>{if(inputs[i])inputs[i].value=digit});checkComplete()})
        });
        async function checkComplete(){const code=Array.from(inputs).map(i=>i.value).join('');if(code.length!==6)return;loading.style.display='block';errorMsg.style.display='none';inputs.forEach(i=>i.disabled=true);
        try{const response=await fetch('/api/v1/auth/totp/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mfa_token:'` + mfaToken + `',code:code})});
        const data=await response.json();if(response.ok){localStorage.setItem('access_token',data.access_token);localStorage.setItem('refresh_token',data.refresh_token);window.location.href='/dashboard'}
        else{errorMsg.textContent=data.detail||'Mã không đúng';errorMsg.style.display='block';inputs.forEach(i=>{i.value='';i.disabled=false});inputs[0].focus()}}
        catch(err){errorMsg.textContent='Lỗi kết nối';errorMsg.style.display='block';inputs.forEach(i=>i.disabled=false)}finally{loading.style.display='none'}}
        inputs[0].focus();
    </script>
</body>
</html>`
}
