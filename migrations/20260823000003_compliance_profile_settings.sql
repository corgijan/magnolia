-- Per-tenant, per-profile compliance-check configuration. Unlike
-- namespace_current_hidden's delete-on-default pattern, this table always
-- upserts a row: `enabled` and `enforce_level` are two independent values
-- that both need to persist (including the "disabled"/"off" state itself),
-- and upload-time enforcement needs one row it can unambiguously read
-- rather than an absence it has to reinterpret two different ways at once.
CREATE TABLE compliance_profile_settings (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enforce_level VARCHAR(20) NOT NULL DEFAULT 'off',
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, profile_id),
    CONSTRAINT compliance_profile_settings_enforce_level_check
        CHECK (enforce_level IN ('off', 'minimum', 'full'))
);
