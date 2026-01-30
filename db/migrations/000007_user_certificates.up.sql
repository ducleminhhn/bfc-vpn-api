-- Story 3.2: User Certificate Auto-Issue
-- Per project-context.md SP-5: Audit Everything

-- Create certificate status enum
CREATE TYPE certificate_status AS ENUM ('active', 'revoked', 'expired', 'pending');

-- Create user_certificates table
CREATE TABLE IF NOT EXISTS user_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    serial_number VARCHAR(100) UNIQUE NOT NULL,
    subject_cn VARCHAR(255) NOT NULL,
    subject_o VARCHAR(255),
    certificate_pem TEXT NOT NULL,
    -- Private key encrypted with AES-256-GCM
    -- Format: nonce(12 bytes) || ciphertext || tag(16 bytes)
    private_key_encrypted BYTEA NOT NULL,
    status certificate_status NOT NULL DEFAULT 'active',
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoke_reason VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for user_certificates
CREATE INDEX idx_user_certificates_user_id ON user_certificates(user_id);
CREATE INDEX idx_user_certificates_tenant_id ON user_certificates(tenant_id);
CREATE INDEX idx_user_certificates_status ON user_certificates(status);
CREATE INDEX idx_user_certificates_expires_at ON user_certificates(expires_at);
-- Ensure only one active certificate per user
CREATE UNIQUE INDEX idx_user_certificates_user_active ON user_certificates(user_id)
    WHERE status = 'active';

-- RLS Policy for tenant isolation
ALTER TABLE user_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_certificates
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Certificate audit log table
CREATE TABLE IF NOT EXISTS certificate_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id UUID REFERENCES user_certificates(id) ON DELETE SET NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    action VARCHAR(50) NOT NULL, -- 'issued', 'revoked', 'renewed', 'downloaded'
    actor_id UUID REFERENCES users(id), -- Who performed the action
    details JSONB,
    client_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for certificate_audit
CREATE INDEX idx_certificate_audit_certificate_id ON certificate_audit(certificate_id);
CREATE INDEX idx_certificate_audit_user_id ON certificate_audit(user_id);
CREATE INDEX idx_certificate_audit_tenant_id ON certificate_audit(tenant_id);
CREATE INDEX idx_certificate_audit_created_at ON certificate_audit(created_at);
CREATE INDEX idx_certificate_audit_action ON certificate_audit(action);

-- RLS Policy for certificate_audit tenant isolation
ALTER TABLE certificate_audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON certificate_audit
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_user_certificates_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_user_certificates_updated_at
    BEFORE UPDATE ON user_certificates
    FOR EACH ROW
    EXECUTE FUNCTION update_user_certificates_updated_at();

-- Grant permissions to app_user
GRANT SELECT, INSERT, UPDATE ON user_certificates TO app_user;
GRANT SELECT, INSERT ON certificate_audit TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;
