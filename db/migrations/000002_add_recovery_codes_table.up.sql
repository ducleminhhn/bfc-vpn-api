-- 000002_add_recovery_codes_table.up.sql
-- Story 2.5: Recovery Codes System

CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(60) NOT NULL,  -- bcrypt hash (60 chars)
    code_index SMALLINT NOT NULL,    -- 0-9 for display order
    used_at TIMESTAMPTZ,             -- NULL if not used
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, code_index)
);

-- Indexes for fast lookup
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);
CREATE INDEX idx_recovery_codes_user_unused ON recovery_codes(user_id) WHERE used_at IS NULL;

-- Comments for documentation
COMMENT ON TABLE recovery_codes IS 'One-time recovery codes for MFA backup (Story 2.5)';
COMMENT ON COLUMN recovery_codes.code_hash IS 'bcrypt hash of recovery code (cost 10)';
COMMENT ON COLUMN recovery_codes.code_index IS 'Position 0-9 for user display';
COMMENT ON COLUMN recovery_codes.used_at IS 'Timestamp when code was used, NULL if unused';
