-- 000003_add_local_auth_columns.down.sql
-- Story 2.6: Rollback local auth columns

ALTER TABLE users DROP COLUMN IF EXISTS password_hash;
ALTER TABLE users DROP COLUMN IF EXISTS local_auth_enabled;
ALTER TABLE users DROP COLUMN IF EXISTS locked_at;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_attempts;
ALTER TABLE users DROP COLUMN IF EXISTS last_failed_at;
DROP INDEX IF EXISTS idx_users_locked_until;
