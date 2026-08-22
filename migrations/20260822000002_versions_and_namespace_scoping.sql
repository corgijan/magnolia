-- SBOM/manifest version (user-supplied at upload time, e.g. product/release
-- version — distinct from the manifest schema itself). Existing rows default
-- to '1.0', matching the value the app previously hardcoded here.
ALTER TABLE manifests ADD COLUMN version VARCHAR(100) NOT NULL DEFAULT '1.0';

-- Namespace on merkle_leaves (denormalized from the leaf's manifest) so leaf
-- listings can be filtered to a key's own namespace_scope without a join,
-- and so the UI can display which namespace each leaf belongs to.
ALTER TABLE merkle_leaves ADD COLUMN namespace VARCHAR(255) NOT NULL DEFAULT '/';
CREATE INDEX idx_merkle_leaves_namespace ON merkle_leaves(tenant_id, namespace);
