package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCertificateStatus_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		status   CertificateStatus
		expected bool
	}{
		{"active is valid", CertStatusActive, true},
		{"revoked is valid", CertStatusRevoked, true},
		{"expired is valid", CertStatusExpired, true},
		{"pending is valid", CertStatusPending, true},
		{"unknown is invalid", CertificateStatus("unknown"), false},
		{"empty is invalid", CertificateStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsValid())
		})
	}
}

func TestCertificateStatus_String(t *testing.T) {
	assert.Equal(t, "active", CertStatusActive.String())
	assert.Equal(t, "revoked", CertStatusRevoked.String())
	assert.Equal(t, "expired", CertStatusExpired.String())
	assert.Equal(t, "pending", CertStatusPending.String())
}

func TestUserCertificate_DaysUntilExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		minDays   int
		maxDays   int
	}{
		{
			name:      "expires in 90 days",
			expiresAt: time.Now().Add(90 * 24 * time.Hour),
			minDays:   89,
			maxDays:   90,
		},
		{
			name:      "expires in 1 day",
			expiresAt: time.Now().Add(24 * time.Hour),
			minDays:   0,
			maxDays:   1,
		},
		{
			name:      "expires in 1 hour",
			expiresAt: time.Now().Add(1 * time.Hour),
			minDays:   0,
			maxDays:   0,
		},
		{
			name:      "already expired",
			expiresAt: time.Now().Add(-24 * time.Hour),
			minDays:   0,
			maxDays:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &UserCertificate{ExpiresAt: tt.expiresAt}
			days := cert.DaysUntilExpiry()
			assert.GreaterOrEqual(t, days, tt.minDays)
			assert.LessOrEqual(t, days, tt.maxDays)
		})
	}
}

func TestUserCertificate_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "expired 1 hour ago",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
		{
			name:      "expired 1 day ago",
			expiresAt: time.Now().Add(-24 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &UserCertificate{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, cert.IsExpired())
		})
	}
}

func TestUserCertificate_IsActive(t *testing.T) {
	tests := []struct {
		name      string
		status    CertificateStatus
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "active and not expired",
			status:    CertStatusActive,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  true,
		},
		{
			name:      "active but expired",
			status:    CertStatusActive,
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  false,
		},
		{
			name:      "revoked",
			status:    CertStatusRevoked,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
		{
			name:      "pending",
			status:    CertStatusPending,
			expiresAt: time.Now().Add(24 * time.Hour),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &UserCertificate{
				Status:    tt.status,
				ExpiresAt: tt.expiresAt,
			}
			assert.Equal(t, tt.expected, cert.IsActive())
		})
	}
}

func TestUserCertificate_IsRevoked(t *testing.T) {
	tests := []struct {
		name     string
		status   CertificateStatus
		expected bool
	}{
		{"revoked status", CertStatusRevoked, true},
		{"active status", CertStatusActive, false},
		{"expired status", CertStatusExpired, false},
		{"pending status", CertStatusPending, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &UserCertificate{Status: tt.status}
			assert.Equal(t, tt.expected, cert.IsRevoked())
		})
	}
}

func TestIssueCertificateRequest_Validate(t *testing.T) {
	tests := []struct {
		name         string
		validityDays int
		expectError  bool
		errorField   string
	}{
		{"zero uses default", 0, false, ""},
		{"1 day valid", 1, false, ""},
		{"90 days valid", 90, false, ""},
		{"365 days valid", 365, false, ""},
		{"negative invalid", -1, true, "validity_days"},
		{"over 365 invalid", 400, true, "validity_days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &IssueCertificateRequest{ValidityDays: tt.validityDays}
			errors := req.Validate()
			if tt.expectError {
				assert.Contains(t, errors, tt.errorField)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestRevokeCertificateRequest_Validate(t *testing.T) {
	tests := []struct {
		name        string
		reason      string
		expectError bool
	}{
		{"valid reason", "User left company", false},
		{"empty reason", "", true},
		{"max length reason", string(make([]byte, 255)), false},
		{"over max length", string(make([]byte, 256)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RevokeCertificateRequest{Reason: tt.reason}
			errors := req.Validate()
			if tt.expectError {
				assert.Contains(t, errors, "reason")
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestNewCertificateResponse(t *testing.T) {
	certID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(90 * 24 * time.Hour)

	cert := &UserCertificate{
		ID:           certID,
		UserID:       userID,
		TenantID:     tenantID,
		SerialNumber: "123456789",
		SubjectCN:    "test@example.com",
		Status:       CertStatusActive,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
	}

	resp := NewCertificateResponse(cert)

	assert.Equal(t, certID, resp.CertificateID)
	assert.Equal(t, "123456789", resp.SerialNumber)
	assert.Equal(t, "test@example.com", resp.SubjectCN)
	assert.Equal(t, CertStatusActive, resp.Status)
	assert.Equal(t, now, resp.IssuedAt)
	assert.Equal(t, expiresAt, resp.ExpiresAt)
	assert.True(t, resp.DaysUntilExpiry >= 89 && resp.DaysUntilExpiry <= 90)
}
