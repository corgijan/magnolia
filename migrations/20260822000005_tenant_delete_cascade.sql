-- Allows deleting a tenant to cascade to everything scoped to it (keys,
-- leaves, manifests, signed tree heads, audit log) instead of being blocked
-- by the FK constraints. The application layer still gates *who* can
-- delete a tenant and refuses to ever delete the platform tenant — this
-- migration only makes the DB-level delete itself possible/atomic.

ALTER TABLE api_keys
    DROP CONSTRAINT fk_api_keys_tenant,
    ADD CONSTRAINT fk_api_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE audit_logs
    DROP CONSTRAINT fk_audit_logs_tenant,
    ADD CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE manifests
    DROP CONSTRAINT fk_manifests_tenant,
    ADD CONSTRAINT fk_manifests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE merkle_leaves
    DROP CONSTRAINT fk_merkle_leaves_tenant,
    ADD CONSTRAINT fk_merkle_leaves_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- signed_tree_heads' FK was declared inline (no explicit name), so its
-- constraint name is whatever Postgres auto-generated — look it up rather
-- than guessing it.
DO $$
DECLARE
    conname text;
BEGIN
    SELECT tc.constraint_name INTO conname
    FROM information_schema.table_constraints tc
    WHERE tc.table_name = 'signed_tree_heads'
      AND tc.constraint_type = 'FOREIGN KEY';

    EXECUTE format('ALTER TABLE signed_tree_heads DROP CONSTRAINT %I', conname);
    EXECUTE 'ALTER TABLE signed_tree_heads ADD CONSTRAINT signed_tree_heads_tenant_id_fkey '
         || 'FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE';
END $$;
