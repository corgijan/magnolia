-- Create manifests table (hash-chained per-tenant manifest records)
CREATE TABLE manifests (
    manifest_hash VARCHAR(64) PRIMARY KEY,
    leaf_seq_id BIGINT NOT NULL REFERENCES merkle_leaves(seq_id),
    tenant_id UUID NOT NULL,
    sbom_hash VARCHAR(64) NOT NULL,
    sbom_format VARCHAR(20) NOT NULL,
    sbom_s3_key VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    previous_manifest_hash VARCHAR(64),
    signature BYTEA NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_manifests_tenant_id ON manifests(tenant_id);
CREATE INDEX idx_manifests_leaf_seq_id ON manifests(leaf_seq_id);