-- 000003_add_local_auth_columns.up.sql
-- Story 2.6: Local PostgreSQL Auth (Dual Auth Backup)
-- Add columns required for local authentication fallback system

-- Add password_hash column if not exists (for Argon2id hash storage)
-- Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- Add local_auth_enabled flag
ALTER TABLE users ADD COLUMN IF NOT EXISTS local_auth_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Add account lockout columns
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_failed_at TIMESTAMPTZ;

-- Index for quick lockout status check
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

-- Add comments for documentation
COMMENT ON COLUMN users.password_hash IS 'Argon2id hash for local auth fallback';
COMMENT ON COLUMN users.local_auth_enabled IS 'Flag to enable local PostgreSQL auth';
COMMENT ON COLUMN users.locked_at IS 'Timestamp when account was locked';
COMMENT ON COLUMN users.locked_until IS 'Timestamp until when account is locked';
COMMENT ON COLUMN users.failed_attempts IS 'Counter for failed login attempts';
COMMENT ON COLUMN users.last_failed_at IS 'Timestamp of last failed attempt';
