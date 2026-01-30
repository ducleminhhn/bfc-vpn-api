-- Story 3.2: User Certificate Auto-Issue - Rollback

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_update_user_certificates_updated_at ON user_certificates;
DROP FUNCTION IF EXISTS update_user_certificates_updated_at();

-- Drop RLS policies
DROP POLICY IF EXISTS tenant_isolation ON certificate_audit;
DROP POLICY IF EXISTS tenant_isolation ON user_certificates;

-- Drop indexes
DROP INDEX IF EXISTS idx_certificate_audit_action;
DROP INDEX IF EXISTS idx_certificate_audit_created_at;
DROP INDEX IF EXISTS idx_certificate_audit_tenant_id;
DROP INDEX IF EXISTS idx_certificate_audit_user_id;
DROP INDEX IF EXISTS idx_certificate_audit_certificate_id;
DROP INDEX IF EXISTS idx_user_certificates_user_active;
DROP INDEX IF EXISTS idx_user_certificates_expires_at;
DROP INDEX IF EXISTS idx_user_certificates_status;
DROP INDEX IF EXISTS idx_user_certificates_tenant_id;
DROP INDEX IF EXISTS idx_user_certificates_user_id;

-- Drop tables
DROP TABLE IF EXISTS certificate_audit;
DROP TABLE IF EXISTS user_certificates;

-- Drop enum type
DROP TYPE IF EXISTS certificate_status;
