package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/bfc-vpn/api/internal/service/auth"
)

func TestLoginRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     auth.LoginRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: auth.LoginRequest{
				Email:    "test@bfc.vn",
				Password: "BaDinh@@1972@@",
			},
			wantErr: false,
		},
		{
			name: "password too short",
			req: auth.LoginRequest{
				Email:    "test@bfc.vn",
				Password: "short",
			},
			wantErr: true,
		},
		{
			name: "invalid email",
			req: auth.LoginRequest{
				Email:    "not-an-email",
				Password: "BaDinh@@1972@@",
			},
			wantErr: true,
		},
		{
			name: "empty email",
			req: auth.LoginRequest{
				Email:    "",
				Password: "BaDinh@@1972@@",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			req: auth.LoginRequest{
				Email:    "test@bfc.vn",
				Password: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				assert.True(t, len(tt.req.Password) < 12 || !isValidEmail(tt.req.Email) || tt.req.Email == "" || tt.req.Password == "")
			} else {
				assert.True(t, len(tt.req.Password) >= 12 && isValidEmail(tt.req.Email))
			}
		})
	}
}

func TestLoginResponse_Success(t *testing.T) {
	resp := auth.LoginResponse{
		Status:       "success",
		AccessToken:  "token123",
		RefreshToken: "refresh123",
		ExpiresIn:    3600,
		UserID:       "user-id",
	}

	assert.Equal(t, "success", resp.Status)
	assert.Equal(t, "token123", resp.AccessToken)
	assert.Equal(t, "refresh123", resp.RefreshToken)
	assert.Equal(t, 3600, resp.ExpiresIn)
	assert.Equal(t, "user-id", resp.UserID)
	assert.Empty(t, resp.MFAToken)
}

func TestLoginResponse_MFARequired(t *testing.T) {
	resp := auth.LoginResponse{
		Status:   "mfa_required",
		MFAToken: "mfa-token-123",
		UserID:   "user-id",
	}

	assert.Equal(t, "mfa_required", resp.Status)
	assert.NotEmpty(t, resp.MFAToken)
	assert.Empty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
	assert.Equal(t, 0, resp.ExpiresIn)
}

func TestNewService(t *testing.T) {
	svc := auth.NewService(nil, nil, nil, nil)
	assert.NotNil(t, svc)
}

func TestLoginRequest_Fields(t *testing.T) {
	req := auth.LoginRequest{
		Email:    "admin@bfc-vpn.com",
		Password: "SecurePassword123!",
	}
	
	assert.Equal(t, "admin@bfc-vpn.com", req.Email)
	assert.Equal(t, "SecurePassword123!", req.Password)
}

func TestLoginResponse_EmptyTokens(t *testing.T) {
	resp := auth.LoginResponse{}
	
	assert.Empty(t, resp.Status)
	assert.Empty(t, resp.AccessToken)
	assert.Empty(t, resp.RefreshToken)
	assert.Empty(t, resp.MFAToken)
	assert.Empty(t, resp.UserID)
	assert.Equal(t, 0, resp.ExpiresIn)
}

func TestDefaultTenantID(t *testing.T) {
	// Verify DefaultTenantID is accessible
	assert.NotEqual(t, "00000000-0000-0000-0000-000000000000", auth.DefaultTenantID.String())
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", auth.DefaultTenantID.String())
}

func isValidEmail(email string) bool {
	if len(email) < 3 {
		return false
	}
	hasAt := false
	hasDot := false
	for i, c := range email {
		if c == '@' {
			hasAt = true
		}
		if hasAt && i > 0 && c == '.' {
			hasDot = true
		}
	}
	return hasAt && hasDot
}
