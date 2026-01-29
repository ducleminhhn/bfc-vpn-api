package apperror

import (
	"fmt"
	"net/http"
)

// ErrorType identifies the category of error
type ErrorType string

const (
	TypeValidation     ErrorType = "validation_error"
	TypeAuthentication ErrorType = "authentication_error"
	TypeAuthorization  ErrorType = "authorization_error"
	TypeNotFound       ErrorType = "not_found"
	TypeConflict       ErrorType = "conflict"
	TypeRateLimit      ErrorType = "rate_limit_exceeded"
	TypeInternal       ErrorType = "internal_error"
)

// AppError represents RFC 7807 Problem Details
type AppError struct {
	Type      string            `json:"type"`
	Title     string            `json:"title"`
	Status    int               `json:"status"`
	Detail    string            `json:"detail"`
	Instance  string            `json:"instance,omitempty"`
	Action    string            `json:"action,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	err       error             // internal error for logging
}

func (e *AppError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %v", e.Title, e.err)
	}
	return e.Title
}

func (e *AppError) Unwrap() error {
	return e.err
}

func (e *AppError) WithError(err error) *AppError {
	e.err = err
	return e
}

func (e *AppError) WithRequestID(id string) *AppError {
	e.RequestID = id
	return e
}

func (e *AppError) WithErrors(errs map[string]string) *AppError {
	e.Errors = errs
	return e
}

// Factory functions with Vietnamese messages

func ValidationError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/validation",
		Title:  "Dữ liệu không hợp lệ",
		Status: http.StatusBadRequest,
		Detail: detail,
		Action: action,
	}
}

func AuthenticationError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/authentication",
		Title:  "Xác thực thất bại",
		Status: http.StatusUnauthorized,
		Detail: detail,
		Action: action,
	}
}

func AuthorizationError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/authorization",
		Title:  "Không có quyền truy cập",
		Status: http.StatusForbidden,
		Detail: detail,
		Action: action,
	}
}

func NotFoundError(resource string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/not-found",
		Title:  "Không tìm thấy",
		Status: http.StatusNotFound,
		Detail: fmt.Sprintf("Không tìm thấy %s", resource),
		Action: "Vui lòng kiểm tra lại thông tin",
	}
}

func ConflictError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/conflict",
		Title:  "Xung đột dữ liệu",
		Status: http.StatusConflict,
		Detail: detail,
		Action: action,
	}
}

func RateLimitError() *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/rate-limit",
		Title:  "Quá nhiều yêu cầu",
		Status: http.StatusTooManyRequests,
		Detail: "Bạn đã gửi quá nhiều yêu cầu trong thời gian ngắn",
		Action: "Vui lòng đợi một lát rồi thử lại",
	}
}

func InternalError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/internal",
		Title:  "Lỗi hệ thống",
		Status: http.StatusInternalServerError,
		Detail: detail,
		Action: action,
	}
}

func NotImplementedError() *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/not-implemented",
		Title:  "Chức năng chưa triển khai",
		Status: http.StatusNotImplemented,
		Detail: "Endpoint này sẽ được triển khai trong các story tiếp theo",
		Action: "Vui lòng quay lại sau",
	}
}

func ServiceUnavailableError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/service-unavailable",
		Title:  "Dịch vụ không khả dụng",
		Status: http.StatusServiceUnavailable,
		Detail: detail,
		Action: action,
	}
}

func (e *AppError) WithInstance(instance string) *AppError {
	e.Instance = instance
	return e
}

// ============================================================================
// LOCAL AUTH ERROR TYPES (Story 2.6)
// ============================================================================

// LockedError creates a 423 Locked error (AC-5: Account lockout)
func LockedError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/locked",
		Title:  "Tài khoản bị khóa",
		Status: http.StatusLocked, // 423
		Detail: detail,
		Action: action,
	}
}

// TooManyRequestsError creates a 429 Too Many Requests error (AC-7: Global IP rate limiting)
func TooManyRequestsError(detail, action string) *AppError {
	return &AppError{
		Type:   "https://bfc-vpn.com/errors/too-many-requests",
		Title:  "Quá nhiều yêu cầu",
		Status: http.StatusTooManyRequests, // 429
		Detail: detail,
		Action: action,
	}
}
