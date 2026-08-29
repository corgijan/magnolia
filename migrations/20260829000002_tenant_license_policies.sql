-- Per-tenant license-compliance policy -- modeled directly on
-- compliance_profile_settings: always exactly one row per tenant (upserted,
-- never deleted-on-default), enforce_level carries the "off" state itself
-- rather than a separate enabled flag, since there's nothing else for a
-- license policy to be "enabled" independent of how strictly it's applied.
CREATE TABLE tenant_license_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- SPDX identifiers (or opaque free-text strings) this tenant rejects --
    -- matched case-insensitively against each individual identifier
    -- resolved out of a component's (possibly compound) license expression,
    -- not against the whole expression string. See
    -- magnolia_core::license::evaluate_license_policy.
    denied_licenses TEXT[] NOT NULL DEFAULT '{}',
    -- Whether a component with no usable license information at all
    -- (see sbom_components.license_expr) counts as a violation.
    flag_unknown BOOLEAN NOT NULL DEFAULT FALSE,
    enforce_level VARCHAR(20) NOT NULL DEFAULT 'off',
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tenant_license_policies_enforce_level_check
        CHECK (enforce_level IN ('off', 'warn', 'block'))
);
