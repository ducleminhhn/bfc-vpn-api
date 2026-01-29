-- name: LogLoginAttempt :exec
-- Ghi log đăng nhập
INSERT INTO audit_logs (
    id, tenant_id, action, actor_id, actor_type, target_type, target_id,
    details, ip_address, user_agent, created_at
) VALUES (
    gen_random_uuid(),
    $1,
    'login_attempt',
    $2,
    'user',
    'session',
    $2,
    $3,
    $4,
    $5,
    NOW()
);

-- name: GetLoginAttemptsByActorID :many
-- Lấy lịch sử đăng nhập theo actor_id
SELECT id, tenant_id, action, actor_id, actor_type, target_type, target_id,
       details, ip_address, user_agent, created_at
FROM audit_logs
WHERE actor_id = $1 AND action = 'login_attempt'
ORDER BY created_at DESC
LIMIT $2;

-- name: CountFailedLoginAttemptsByActorID :one
-- Đếm số lần đăng nhập thất bại trong khoảng thời gian
SELECT COUNT(*) as count
FROM audit_logs
WHERE actor_id = $1
  AND action = 'login_attempt'
  AND (details->>'success')::boolean = false
  AND created_at > $2;

-- name: LogTOTPEvent :exec
-- Ghi log sự kiện TOTP (setup, verify, failure)
INSERT INTO audit_logs (
    id, tenant_id, action, actor_id, actor_type, target_type, target_id,
    details, ip_address, user_agent, created_at
) VALUES (
    gen_random_uuid(),
    COALESCE($1, '00000000-0000-0000-0000-000000000001'::uuid),
    $2,
    $3,
    'user',
    'totp',
    $3,
    $4,
    $5,
    $6,
    NOW()
);

-- name: GetTOTPEventsByActorID :many
-- Lấy lịch sử TOTP theo actor_id
SELECT id, tenant_id, action, actor_id, actor_type, target_type, target_id,
       details, ip_address, user_agent, created_at
FROM audit_logs
WHERE actor_id = $1 AND action LIKE 'totp_%'
ORDER BY created_at DESC
LIMIT $2;

-- name: CountFailedTOTPAttemptsByActorID :one
-- Đếm số lần verify TOTP thất bại trong khoảng thời gian
SELECT COUNT(*) as count
FROM audit_logs
WHERE actor_id = $1
  AND action = 'totp_verify_failed'
  AND created_at > $2;
