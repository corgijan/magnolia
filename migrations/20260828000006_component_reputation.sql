-- Per-component registry identity, derived from `purl` at index time via
-- `magnolia_core::purl_to_depsdev_package` (see SUPPLY_CHAIN_SIGNALS_PLAN.md).
-- Stored rather than recomputed on every read so the reputation background
-- job can join against it in plain SQL instead of re-parsing every purl in
-- Rust on each tick. NULL when the component has no purl, or its purl's
-- type isn't one deps.dev tracks.
ALTER TABLE sbom_components ADD COLUMN ecosystem TEXT;
ALTER TABLE sbom_components ADD COLUMN registry_name TEXT;
CREATE INDEX sbom_components_reputation_idx ON sbom_components (ecosystem, registry_name)
    WHERE ecosystem IS NOT NULL;

-- deps.dev OpenSSF Scorecard data, cached per (ecosystem, registry_name) --
-- deployment-global, not per-tenant: a package's score doesn't depend on
-- which tenant uploaded it. Populated by a periodic background job (mirrors
-- dtrack_sync.rs's shape), not synchronously at upload -- unlike OSV's
-- malicious-package check, deps.dev has no batched-query endpoint, so
-- checking every component of a large SBOM inline would mean many
-- sequential external calls in the request path.
CREATE TABLE component_reputation (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    scorecard_score REAL,          -- 0.0-10.0; NULL if deps.dev has no scorecard for it
    project_repo TEXT,             -- e.g. "github.com/lodash/lodash"
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetch_error TEXT,              -- last fetch failure, if any; cleared on success
    PRIMARY KEY (ecosystem, name)
);
