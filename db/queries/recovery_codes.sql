-- name: CreateRecoveryCode :exec
INSERT INTO recovery_codes (user_id, code_hash, code_index, created_at)
VALUES ($1, $2, $3, NOW());

-- name: GetUnusedRecoveryCodesByUserID :many
SELECT id, user_id, code_hash, code_index, used_at, created_at
FROM recovery_codes
WHERE user_id = $1 AND used_at IS NULL
ORDER BY code_index;

-- name: GetAllRecoveryCodesByUserID :many
SELECT id, user_id, code_hash, code_index, used_at, created_at
FROM recovery_codes
WHERE user_id = $1
ORDER BY code_index;

-- name: MarkRecoveryCodeUsed :execrows
UPDATE recovery_codes
SET used_at = NOW()
WHERE user_id = $1 AND id = $2 AND used_at IS NULL;

-- name: DeleteRecoveryCodesByUserID :exec
DELETE FROM recovery_codes WHERE user_id = $1;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM recovery_codes
WHERE user_id = $1 AND used_at IS NULL;
