package apperror_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
)

func TestValidationError(t *testing.T) {
	err := apperror.ValidationError("Email không hợp lệ", "Nhập đúng định dạng email")

	assert.Equal(t, http.StatusBadRequest, err.Status)
	assert.Equal(t, "Dữ liệu không hợp lệ", err.Title)
	assert.Contains(t, err.Detail, "Email")
	assert.Contains(t, err.Type, "validation")
}

func TestAuthenticationError(t *testing.T) {
	err := apperror.AuthenticationError("Sai mật khẩu", "Kiểm tra lại mật khẩu")

	assert.Equal(t, http.StatusUnauthorized, err.Status)
	assert.Equal(t, "Xác thực thất bại", err.Title)
}

func TestErrorWithRequestID(t *testing.T) {
	err := apperror.AuthenticationError("Sai mật khẩu", "Kiểm tra lại mật khẩu").
		WithRequestID("req-123")

	assert.Equal(t, "req-123", err.RequestID)
}

func TestErrorWithErrors(t *testing.T) {
	fieldErrors := map[string]string{
		"email":    "Không hợp lệ",
		"password": "Quá ngắn",
	}
	err := apperror.ValidationError("Nhiều lỗi", "Sửa các trường").
		WithErrors(fieldErrors)

	assert.Equal(t, 2, len(err.Errors))
}

func TestUnwrap(t *testing.T) {
	inner := errors.New("database connection failed")
	err := apperror.InternalError("Lỗi kết nối", "Thử lại sau").WithError(inner)

	assert.ErrorIs(t, err, inner)
}

func TestNotFoundError(t *testing.T) {
	err := apperror.NotFoundError("người dùng")

	assert.Equal(t, http.StatusNotFound, err.Status)
	assert.Contains(t, err.Detail, "người dùng")
}

func TestRateLimitError(t *testing.T) {
	err := apperror.RateLimitError()

	assert.Equal(t, http.StatusTooManyRequests, err.Status)
	assert.Equal(t, "Quá nhiều yêu cầu", err.Title)
}

func TestNotImplementedError(t *testing.T) {
	err := apperror.NotImplementedError()

	assert.Equal(t, http.StatusNotImplemented, err.Status)
	assert.Equal(t, "Chức năng chưa triển khai", err.Title)
}

func TestErrorString(t *testing.T) {
	inner := errors.New("db error")
	err := apperror.InternalError("Lỗi", "Thử lại").WithError(inner)

	assert.Contains(t, err.Error(), "db error")
}
