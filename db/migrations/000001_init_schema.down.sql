-- Down migration for init_schema
-- WARNING: This will drop all tables and data

DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_actor_id;
DROP INDEX IF EXISTS idx_users_keycloak_id;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS users;
