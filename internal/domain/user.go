package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
	UserStatusPending  UserStatus = "pending"
)

type User struct {
	ID                  uuid.UUID  `json:"id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	Email               string     `json:"email"`
	PasswordHash        string     `json:"-"` // Never expose
	TOTPSecretEncrypted []byte     `json:"-"` // Never expose
	TOTPEnabled         bool       `json:"totp_enabled"`
	Status              UserStatus `json:"status"`
	FullName            string     `json:"full_name"`
	KeycloakID          string     `json:"keycloak_id,omitempty"`
	FailedLoginAttempts int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// IsLocked checks if the user account is currently locked
func (u *User) IsLocked() bool {
	if u.Status == UserStatusLocked {
		return true
	}
	if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return true
	}
	return false
}

// CanLogin checks if the user can attempt login
func (u *User) CanLogin() bool {
	return u.Status == UserStatusActive && !u.IsLocked()
}
