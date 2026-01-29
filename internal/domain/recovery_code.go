package domain

import (
	"time"

	"github.com/google/uuid"
)

// RecoveryCode represents a one-time backup code for MFA
type RecoveryCode struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	CodeHash  string     `json:"-"` // Never expose hash
	CodeIndex int        `json:"code_index"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// IsUsed checks if the recovery code has been used
func (rc *RecoveryCode) IsUsed() bool {
	return rc.UsedAt != nil
}
