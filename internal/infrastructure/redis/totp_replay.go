package redis

import (
	"context"
	"fmt"
	"time"
)

const (
	// TOTPReplayTTL is the window to reject replay attacks (30 seconds = 1 TOTP period)
	TOTPReplayTTL = 30 * time.Second

	// MFATokenTTL is the expiry for MFA session tokens
	MFATokenTTL = 5 * time.Minute

	// TOTPPendingTTL is how long a pending TOTP setup is valid
	TOTPPendingTTL = 10 * time.Minute

	// TOTPLockoutTTL is the lockout period after too many failed attempts
	TOTPLockoutTTL = 15 * time.Minute

	// TOTPMaxAttempts is the maximum failed attempts before lockout
	TOTPMaxAttempts = 5
)

// Key patterns
const (
	totpReplayKeyPattern   = "totp_used:%s:%s"   // userID:code
	mfaTokenKeyPattern     = "mfa_token:%s"      // token
	totpPendingKeyPattern  = "totp_pending:%s"   // userID
	totpFailedKeyPattern   = "totp_failed:%s"    // userID
)

// TOTPReplayKey generates the key for tracking used TOTP codes
func TOTPReplayKey(userID, code string) string {
	return fmt.Sprintf(totpReplayKeyPattern, userID, code)
}

// MFATokenKey generates the key for storing MFA session tokens
func MFATokenKey(token string) string {
	return fmt.Sprintf(mfaTokenKeyPattern, token)
}

// TOTPPendingKey generates the key for pending TOTP setup data
func TOTPPendingKey(userID string) string {
	return fmt.Sprintf(totpPendingKeyPattern, userID)
}

// TOTPFailedKey generates the key for failed TOTP attempt counter
func TOTPFailedKey(userID string) string {
	return fmt.Sprintf(totpFailedKeyPattern, userID)
}

// MarkTOTPCodeUsed marks a TOTP code as used for replay protection
// Returns true if this is a new code (not a replay), false if already used
func (c *Client) MarkTOTPCodeUsed(ctx context.Context, userID, code string) (bool, error) {
	return c.SetNX(ctx, TOTPReplayKey(userID, code), "used", TOTPReplayTTL)
}

// SetMFAToken stores MFA token data with the associated session info
func (c *Client) SetMFAToken(ctx context.Context, token, data string) error {
	return c.Set(ctx, MFATokenKey(token), data, MFATokenTTL)
}

// GetMFAToken retrieves MFA token data
func (c *Client) GetMFAToken(ctx context.Context, token string) (string, error) {
	return c.Get(ctx, MFATokenKey(token))
}

// DeleteMFAToken removes an MFA token after successful verification
func (c *Client) DeleteMFAToken(ctx context.Context, token string) error {
	return c.Delete(ctx, MFATokenKey(token))
}

// SetTOTPPending stores pending TOTP setup data
func (c *Client) SetTOTPPending(ctx context.Context, userID, data string) error {
	return c.Set(ctx, TOTPPendingKey(userID), data, TOTPPendingTTL)
}

// GetTOTPPending retrieves pending TOTP setup data
func (c *Client) GetTOTPPending(ctx context.Context, userID string) (string, error) {
	return c.Get(ctx, TOTPPendingKey(userID))
}

// DeleteTOTPPending removes pending TOTP setup data
func (c *Client) DeleteTOTPPending(ctx context.Context, userID string) error {
	return c.Delete(ctx, TOTPPendingKey(userID))
}

// IncrementTOTPFailed increments the failed TOTP attempt counter
// Returns the new count and any error
func (c *Client) IncrementTOTPFailed(ctx context.Context, userID string) (int64, error) {
	key := TOTPFailedKey(userID)
	count, err := c.Incr(ctx, key)
	if err != nil {
		return 0, err
	}
	// Set expiry on first increment
	if count == 1 {
		c.Expire(ctx, key, TOTPLockoutTTL)
	}
	return count, nil
}

// GetTOTPFailedCount gets the current failed attempt count
func (c *Client) GetTOTPFailedCount(ctx context.Context, userID string) (int64, error) {
	val, err := c.Get(ctx, TOTPFailedKey(userID))
	if err != nil {
		return 0, nil // Key not found means 0 failures
	}
	var count int64
	fmt.Sscanf(val, "%d", &count)
	return count, nil
}

// GetTOTPLockoutTTL returns remaining lockout time
func (c *Client) GetTOTPLockoutTTL(ctx context.Context, userID string) (time.Duration, error) {
	return c.TTL(ctx, TOTPFailedKey(userID))
}

// ResetTOTPFailed clears the failed attempt counter on successful verification
func (c *Client) ResetTOTPFailed(ctx context.Context, userID string) error {
	return c.Delete(ctx, TOTPFailedKey(userID))
}

// IsAccountLocked checks if account is locked due to too many failed attempts
func (c *Client) IsAccountLocked(ctx context.Context, userID string) (bool, time.Duration, error) {
	count, err := c.GetTOTPFailedCount(ctx, userID)
	if err != nil {
		return false, 0, err
	}
	if count >= TOTPMaxAttempts {
		ttl, err := c.GetTOTPLockoutTTL(ctx, userID)
		if err != nil {
			return false, 0, err
		}
		return true, ttl, nil
	}
	return false, 0, nil
}
