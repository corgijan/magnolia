-- Create signed_tree_heads table
CREATE TABLE signed_tree_heads (
    tree_size BIGINT PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    frontier BYTEA[] NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_signed_tree_heads_created_at ON signed_tree_heads(created_at DESC);

-- Create merkle_leaves table (append-only log)
CREATE TABLE merkle_leaves (
    seq_id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    sbom_s3_key VARCHAR(255) NOT NULL,
    leaf_hash BYTEA NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending_lock',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_merkle_leaves_tenant_id ON merkle_leaves(tenant_id);
CREATE INDEX idx_merkle_leaves_status ON merkle_leaves(status);
CREATE INDEX idx_merkle_leaves_created_at ON merkle_leaves(created_at DESC);

-- Create merkle_nodes cache table
CREATE TABLE merkle_nodes (
    level INT NOT NULL,
    index BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    PRIMARY KEY (level, index)
);

-- Create audit_logs table (append-only)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    principal VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    result VARCHAR(50) NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Create api_keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    domain VARCHAR(255) NOT NULL,
    namespace_scope VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_domain ON api_keys(domain);
