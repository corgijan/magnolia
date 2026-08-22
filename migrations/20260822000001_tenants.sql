-- Tenants: a tenant is a domain. Every api_key/merkle_leaf/manifest/audit_log
-- row's tenant_id now refers to this table, and each tenant gets its own
-- Merkle tree / signed-tree-head chain (full data isolation between tenants).
--
-- NOTE: this is a schema-breaking migration (signed_tree_heads is rebuilt
-- with a new primary key). Apply it to a fresh database — this project has
-- no production data or migration-rollback tooling yet (see IMPLEMENTATION_STATUS.md).

CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE api_keys
    ADD CONSTRAINT fk_api_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE audit_logs
    ADD CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE manifests
    ADD CONSTRAINT fk_manifests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

-- Per-tenant leaf position (0-based), distinct from the global `seq_id`,
-- since each tenant now has its own Merkle tree.
ALTER TABLE merkle_leaves
    ADD COLUMN tenant_leaf_index BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT fk_merkle_leaves_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE UNIQUE INDEX idx_merkle_leaves_tenant_leaf_index ON merkle_leaves(tenant_id, tenant_leaf_index);

-- signed_tree_heads was a single global chain; rebuild it per tenant.
DROP TABLE signed_tree_heads;

CREATE TABLE signed_tree_heads (
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    tree_size BIGINT NOT NULL,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    frontier BYTEA[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, tree_size)
);

CREATE INDEX idx_signed_tree_heads_tenant_created ON signed_tree_heads(tenant_id, created_at DESC);
