-- Explicit namespace registry: a namespace can be created here ahead of any
-- SBOM ever being uploaded to it. By itself this table doesn't restrict
-- anything -- uploading to an unregistered namespace still works exactly as
-- before, same as every other namespace-scoped table in this schema
-- (namespace_current_hidden, compliance settings, ...), none of which ever
-- required upfront registration. Only `require_namespace_registration`
-- below turns this into an actual gate.
CREATE TABLE registered_namespaces (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    namespace VARCHAR(255) NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, namespace)
);

-- Per-tenant opt-in requiring upload_sbom's target namespace to already
-- exist in registered_namespaces -- off by default, same "explicit opt-in"
-- philosophy as require_semver_version.
ALTER TABLE tenants ADD COLUMN require_namespace_registration BOOLEAN NOT NULL DEFAULT FALSE;
