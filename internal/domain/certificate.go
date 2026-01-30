package domain

import (
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// CERTIFICATE ERROR CODES (Story 3.2)
// ============================================================================

const (
	ErrCodeCertNotFound        = "CERT_NOT_FOUND"
	ErrCodeCertIssuanceFailed  = "CERT_ISSUANCE_FAILED"
	ErrCodeCertCircuitOpen     = "CERT_CIRCUIT_OPEN"
	ErrCodeCertAlreadyExists   = "CERT_ALREADY_EXISTS"
	ErrCodeCertRevoked         = "CERT_REVOKED"
	ErrCodeCertExpired         = "CERT_EXPIRED"
	ErrCodeCertValidityInvalid = "CERT_VALIDITY_INVALID"
	ErrCodeCertDecryptFailed   = "CERT_DECRYPT_FAILED"
	ErrCodeCertUserNotFound    = "CERT_USER_NOT_FOUND"
)

// ============================================================================
// CERTIFICATE VIETNAMESE MESSAGES (Story 3.2)
// ============================================================================

const (
	MsgCertNotFound        = "Người dùng chưa có certificate"
	MsgCertIssuanceFailed  = "Không thể cấp certificate. Vui lòng thử lại sau."
	MsgCertCircuitOpen     = "Dịch vụ cấp certificate tạm thời không khả dụng, đang thử lại"
	MsgCertAlreadyExists   = "Người dùng đã có certificate active"
	MsgCertRevoked         = "Certificate đã bị thu hồi"
	MsgCertExpired         = "Certificate đã hết hạn"
	MsgCertIssued          = "Certificate đã được cấp thành công"
	MsgCertValidityInvalid = "Thời hạn certificate không hợp lệ (1-365 ngày)"
	MsgCertRetrieved       = "Thông tin certificate của người dùng"
	MsgCertRevokedSuccess  = "Certificate đã được thu hồi thành công"
	MsgCertDecryptFailed   = "Không thể giải mã private key"
	MsgCertUserNotFound    = "Không tìm thấy người dùng"
)

// ============================================================================
// CERTIFICATE RATE LIMITS (Story 3.2)
// ============================================================================

const (
	CertGetRateLimit    = 60 // requests per minute
	CertIssueRateLimit  = 10 // requests per hour
	CertRevokeRateLimit = 10 // requests per hour
)

// ============================================================================
// CERTIFICATE STATUS (AC-4)
// ============================================================================

// CertificateStatus represents the current state of a user certificate
type CertificateStatus string

const (
	CertStatusActive  CertificateStatus = "active"
	CertStatusRevoked CertificateStatus = "revoked"
	CertStatusExpired CertificateStatus = "expired"
	CertStatusPending CertificateStatus = "pending"
)

// IsValid checks if the status is a valid certificate status
func (s CertificateStatus) IsValid() bool {
	switch s {
	case CertStatusActive, CertStatusRevoked, CertStatusExpired, CertStatusPending:
		return true
	}
	return false
}

// String returns the string representation of the status
func (s CertificateStatus) String() string {
	return string(s)
}

// ============================================================================
// USER CERTIFICATE (AC-1, AC-4)
// ============================================================================

// UserCertificate represents a user's VPN certificate
type UserCertificate struct {
	ID                  uuid.UUID         `json:"id" db:"id"`
	UserID              uuid.UUID         `json:"user_id" db:"user_id"`
	TenantID            uuid.UUID         `json:"tenant_id" db:"tenant_id"`
	SerialNumber        string            `json:"serial_number" db:"serial_number"`
	SubjectCN           string            `json:"subject_cn" db:"subject_cn"`
	SubjectO            string            `json:"subject_o,omitempty" db:"subject_o"`
	CertificatePEM      string            `json:"-" db:"certificate_pem"`
	PrivateKeyEncrypted []byte            `json:"-" db:"private_key_encrypted"`
	Status              CertificateStatus `json:"status" db:"status"`
	IssuedAt            time.Time         `json:"issued_at" db:"issued_at"`
	ExpiresAt           time.Time         `json:"expires_at" db:"expires_at"`
	RevokedAt           *time.Time        `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokeReason        string            `json:"revoke_reason,omitempty" db:"revoke_reason"`
	CreatedAt           time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at" db:"updated_at"`
}

// DaysUntilExpiry calculates remaining validity days
func (c *UserCertificate) DaysUntilExpiry() int {
	hours := time.Until(c.ExpiresAt).Hours()
	if hours < 0 {
		return 0
	}
	return int(hours / 24)
}

// IsExpired checks if certificate is expired
func (c *UserCertificate) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsActive checks if certificate is active and not expired
func (c *UserCertificate) IsActive() bool {
	return c.Status == CertStatusActive && !c.IsExpired()
}

// IsRevoked checks if certificate is revoked
func (c *UserCertificate) IsRevoked() bool {
	return c.Status == CertStatusRevoked
}

// ============================================================================
// CERTIFICATE AUDIT (Per SP-5: Audit Everything)
// ============================================================================

// CertificateAuditAction represents types of certificate audit actions
type CertificateAuditAction string

const (
	CertAuditIssued     CertificateAuditAction = "issued"
	CertAuditRevoked    CertificateAuditAction = "revoked"
	CertAuditRenewed    CertificateAuditAction = "renewed"
	CertAuditDownloaded CertificateAuditAction = "downloaded"
)

// CertificateAudit represents an audit log entry for certificate operations
type CertificateAudit struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	CertificateID *uuid.UUID             `json:"certificate_id,omitempty" db:"certificate_id"`
	UserID        uuid.UUID              `json:"user_id" db:"user_id"`
	TenantID      uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Action        CertificateAuditAction `json:"action" db:"action"`
	ActorID       *uuid.UUID             `json:"actor_id,omitempty" db:"actor_id"`
	Details       map[string]interface{} `json:"details,omitempty" db:"details"`
	ClientIP      string                 `json:"client_ip" db:"client_ip"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
}

// ============================================================================
// CERTIFICATE REQUEST/RESPONSE DTOs
// ============================================================================

// IssueCertificateRequest represents a request to issue a certificate
type IssueCertificateRequest struct {
	ValidityDays int `json:"validity_days,omitempty" binding:"omitempty,min=1,max=365"`
}

// Validate validates the issue certificate request
func (r *IssueCertificateRequest) Validate() map[string]string {
	errors := make(map[string]string)
	if r.ValidityDays != 0 && (r.ValidityDays < 1 || r.ValidityDays > 365) {
		errors["validity_days"] = "Thời hạn certificate phải từ 1 đến 365 ngày"
	}
	return errors
}

// RevokeCertificateRequest represents a request to revoke a certificate
type RevokeCertificateRequest struct {
	Reason string `json:"reason" binding:"required,max=255"`
}

// Validate validates the revoke certificate request
func (r *RevokeCertificateRequest) Validate() map[string]string {
	errors := make(map[string]string)
	if r.Reason == "" {
		errors["reason"] = "Lý do thu hồi là bắt buộc"
	}
	if len(r.Reason) > 255 {
		errors["reason"] = "Lý do thu hồi tối đa 255 ký tự"
	}
	return errors
}

// CertificateResponse represents the API response for certificate info
type CertificateResponse struct {
	CertificateID   uuid.UUID         `json:"certificate_id"`
	SerialNumber    string            `json:"serial_number"`
	SubjectCN       string            `json:"subject_cn"`
	IssuedAt        time.Time         `json:"issued_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Status          CertificateStatus `json:"status"`
	DaysUntilExpiry int               `json:"days_until_expiry"`
}

// NewCertificateResponse creates a response from UserCertificate
func NewCertificateResponse(cert *UserCertificate) *CertificateResponse {
	return &CertificateResponse{
		CertificateID:   cert.ID,
		SerialNumber:    cert.SerialNumber,
		SubjectCN:       cert.SubjectCN,
		IssuedAt:        cert.IssuedAt,
		ExpiresAt:       cert.ExpiresAt,
		Status:          cert.Status,
		DaysUntilExpiry: cert.DaysUntilExpiry(),
	}
}

// CertificateIssuedResponse represents the response after issuing a certificate
type CertificateIssuedResponse struct {
	UserID        uuid.UUID `json:"user_id"`
	CertificateID uuid.UUID `json:"certificate_id"`
	SerialNumber  string    `json:"serial_number"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Status        string    `json:"status"`
}

// ============================================================================
// STEP-CA HEALTH CHECK (AC-5)
// ============================================================================

// StepCAHealthStatus represents the health status of step-ca
type StepCAHealthStatus string

const (
	StepCAHealthy   StepCAHealthStatus = "healthy"
	StepCAUnhealthy StepCAHealthStatus = "unhealthy"
)

// StepCAHealthCheck represents step-ca health check results
type StepCAHealthCheck struct {
	Status           StepCAHealthStatus `json:"status"`
	LatencyMS        int64              `json:"latency_ms"`
	CircuitBreaker   string             `json:"circuit_breaker"`
	Error            string             `json:"error,omitempty"`
	ErrorCode        string             `json:"error_code,omitempty"`
	MessageVI        string             `json:"message_vi,omitempty"`
	RetryAfterSecs   int                `json:"retry_after_seconds,omitempty"`
}
