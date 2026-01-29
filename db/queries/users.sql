-- name: GetUserByEmail :one
-- Lấy user theo email (dùng cho login)
SELECT id, tenant_id, email, password_hash, totp_secret_encrypted, totp_enabled,
       status, full_name, keycloak_id, failed_login_attempts, locked_until,
       password_changed_at, last_login_at, created_at, updated_at
FROM users
WHERE email = $1 AND status = 'active' AND deleted_at IS NULL
LIMIT 1;

-- name: GetUserByID :one
-- Lấy user theo ID
SELECT id, tenant_id, email, password_hash, totp_secret_encrypted, totp_enabled,
       status, full_name, keycloak_id, failed_login_attempts, locked_until,
       password_changed_at, last_login_at, created_at, updated_at
FROM users
WHERE id = $1 AND deleted_at IS NULL
LIMIT 1;

-- name: GetUserByKeycloakID :one
-- Lấy user theo Keycloak ID
SELECT id, tenant_id, email, password_hash, totp_secret_encrypted, totp_enabled,
       status, full_name, keycloak_id, failed_login_attempts, locked_until,
       password_changed_at, last_login_at, created_at, updated_at
FROM users
WHERE keycloak_id = $1 AND status = 'active' AND deleted_at IS NULL
LIMIT 1;

-- name: CreateUser :one
-- Tạo user mới (sync từ Keycloak)
INSERT INTO users (
    id, tenant_id, email, full_name, keycloak_id, status, auth_provider, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, 'keycloak', NOW(), NOW()
)
ON CONFLICT (tenant_id, email) WHERE deleted_at IS NULL DO UPDATE SET
    keycloak_id = EXCLUDED.keycloak_id,
    auth_provider = 'keycloak',
    updated_at = NOW()
RETURNING *;

-- name: UpdateUserKeycloakID :exec
-- Cập nhật Keycloak ID cho user
UPDATE users
SET keycloak_id = $2, auth_provider = 'keycloak', updated_at = NOW()
WHERE id = $1;

-- name: UpdateLastLogin :exec
-- Cập nhật thời gian đăng nhập cuối
UPDATE users
SET last_login_at = NOW(), failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
WHERE id = $1;

-- name: IncrementFailedLogin :one
-- Tăng số lần đăng nhập thất bại
UPDATE users
SET failed_login_attempts = failed_login_attempts + 1,
    locked_until = CASE
        WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
        ELSE locked_until
    END,
    updated_at = NOW()
WHERE id = $1
RETURNING failed_login_attempts, locked_until;

-- name: IsUserLocked :one
-- Kiểm tra user có bị khóa không
SELECT EXISTS(
    SELECT 1 FROM users
    WHERE id = $1 AND locked_until IS NOT NULL AND locked_until > NOW()
) AS is_locked;

-- name: CountActiveUsersByTenant :one
-- Đếm số users active của tenant
SELECT COUNT(*) AS count FROM users
WHERE tenant_id = $1 AND status = 'active' AND deleted_at IS NULL;

-- name: EnableTOTP :exec
-- Kích hoạt TOTP cho user
UPDATE users 
SET totp_secret_encrypted = $2, totp_enabled = true, updated_at = NOW() 
WHERE id = $1;

-- name: DisableTOTP :exec
-- Vô hiệu hóa TOTP cho user
UPDATE users 
SET totp_secret_encrypted = NULL, totp_enabled = false, updated_at = NOW() 
WHERE id = $1;

-- name: GetTOTPSecret :one
-- Lấy TOTP secret của user
SELECT totp_secret_encrypted, totp_enabled
FROM users
WHERE id = $1 AND deleted_at IS NULL;

-- ============================================================================
-- LOCAL AUTH QUERIES (Story 2.6)
-- ============================================================================

-- name: GetUserByEmailForLocalAuth :one
-- Lấy user theo email cho local auth (bao gồm local auth specific fields)
SELECT id, tenant_id, email, password_hash, totp_enabled, totp_secret_encrypted,
       status, local_auth_enabled, locked_at, locked_until, failed_attempts, last_failed_at
FROM users
WHERE email = $1 AND status != 'deleted' AND deleted_at IS NULL
LIMIT 1;

-- name: UpdateUserPasswordHash :exec
-- Cập nhật password hash và enable local auth
UPDATE users
SET password_hash = $2, local_auth_enabled = TRUE, updated_at = NOW()
WHERE id = $1;

-- name: IncrementLocalFailedAttempts :exec
-- Tăng số lần đăng nhập local thất bại
UPDATE users
SET failed_attempts = failed_attempts + 1,
    last_failed_at = NOW(),
    updated_at = NOW()
WHERE id = $1;

-- name: ResetLocalFailedAttempts :exec
-- Reset số lần đăng nhập thất bại sau login thành công
UPDATE users
SET failed_attempts = 0,
    last_failed_at = NULL,
    locked_at = NULL,
    locked_until = NULL,
    updated_at = NOW()
WHERE id = $1;

-- name: LockUserAccount :exec
-- Khóa tài khoản sau khi vượt quá số lần thử
UPDATE users
SET locked_at = NOW(),
    locked_until = $2,
    status = 'locked',
    updated_at = NOW()
WHERE id = $1;

-- name: UnlockUserAccount :exec
-- Mở khóa tài khoản
UPDATE users
SET locked_at = NULL,
    locked_until = NULL,
    failed_attempts = 0,
    status = 'active',
    updated_at = NOW()
WHERE id = $1;

-- name: IsUserLockedForLocalAuth :one
-- Kiểm tra user có bị khóa cho local auth không
SELECT locked_until IS NOT NULL AND locked_until > NOW() AS is_locked
FROM users
WHERE id = $1;

-- name: GetUserLocalAuthStatus :one
-- Lấy trạng thái local auth của user
SELECT id, email, local_auth_enabled, password_hash IS NOT NULL AS has_password_hash,
       locked_at, locked_until, failed_attempts
FROM users
WHERE id = $1 AND deleted_at IS NULL;
