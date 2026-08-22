CREATE INDEX idx_manifests_tenant_namespace_current
    ON manifests (tenant_id, namespace, created_at DESC)
    WHERE revoked = FALSE;
