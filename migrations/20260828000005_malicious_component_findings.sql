-- Confirmed-malicious component matches (OSV's MAL- prefixed advisories,
-- sourced from ossf/malicious-packages), found via one batched
-- `POST /v1/querybatch` call against OSV's public API at upload time (see
-- SUPPLY_CHAIN_SIGNALS_PLAN.md) — not a mirrored table like
-- dtrack_findings, since there's nothing to periodically resync: the check
-- runs once per manifest and its result is stored here.
CREATE TABLE malicious_component_findings (
    id BIGSERIAL PRIMARY KEY,
    manifest_hash TEXT NOT NULL REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    component_name TEXT NOT NULL,
    component_version TEXT,
    purl TEXT,
    osv_id TEXT NOT NULL,          -- e.g. "MAL-2024-1234"
    summary TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (manifest_hash, component_name, component_version, osv_id)
);
CREATE INDEX malicious_component_findings_manifest_idx ON malicious_component_findings (manifest_hash);
