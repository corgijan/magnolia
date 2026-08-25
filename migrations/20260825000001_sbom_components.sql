-- Inverted index: component -> every manifest that contains it. Populated
-- at upload time (see upload_sbom), not computed per-query, so a search
-- is an indexed lookup (O(log n + result count)) rather than a scan over
-- every SBOM's raw bytes.
CREATE TABLE sbom_components (
    id BIGSERIAL PRIMARY KEY,
    manifest_hash TEXT NOT NULL REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    -- Denormalized from manifests so every search query can filter by
    -- tenant directly on this table (RBAC/tenant isolation) without a
    -- join being load-bearing for correctness.
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    purl TEXT,
    cpe TEXT,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE
);

-- Prefix search on name, case-insensitive, scoped per tenant.
CREATE INDEX sbom_components_name_idx ON sbom_components (tenant_id, lower(name));
-- Exact purl lookup -- the precise identifier when available.
CREATE INDEX sbom_components_purl_idx ON sbom_components (tenant_id, purl) WHERE purl IS NOT NULL;
-- Used by the ON DELETE CASCADE path and any "components for manifest X" lookup.
CREATE INDEX sbom_components_manifest_idx ON sbom_components (manifest_hash);
