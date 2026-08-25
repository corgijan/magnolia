-- One dtrack project per manifest (not per namespace): Magnolia's manifests
-- are immutable while dtrack's usual model is one project with many BOM
-- versions, so mapping one-to-one avoids re-analyzing/conflating unrelated
-- uploads under a single dtrack project.
CREATE TABLE dtrack_projects (
    manifest_hash TEXT PRIMARY KEY REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    dtrack_project_uuid UUID NOT NULL,
    pushed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at TIMESTAMPTZ
);
CREATE INDEX dtrack_projects_uuid_idx ON dtrack_projects (dtrack_project_uuid);

-- Cached copy of dtrack's findings, refreshed by the background sync loop.
-- Magnolia's own read path (GET /api/v1/manifest/:hash) only ever reads
-- this table — never calls dtrack live — so normal browsing stays
-- available independent of dtrack's uptime.
CREATE TABLE dtrack_findings (
    manifest_hash TEXT NOT NULL REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    component_name TEXT NOT NULL,
    component_version TEXT,
    vulnerability_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    analysis_state TEXT,          -- dtrack's own generic analysis state, synced verbatim
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Magnolia's own VEX-style triage, independent of dtrack's
    -- analysis_state above — the two can legitimately disagree, since
    -- dtrack has no notion of Magnolia's product/manifest context. Lives on
    -- the same row as the finding it's about (not a separate table): there
    -- is exactly one current triage state per finding, and audit_logs
    -- already captures triage history via its own reason field.
    vex_status TEXT,              -- 'affected' | 'not_affected' | 'fixed' | 'under_investigation' | NULL (untriaged)
    vex_justification TEXT,       -- required by the API layer when vex_status = 'not_affected', not DB-enforced
    triaged_by TEXT,
    triaged_at TIMESTAMPTZ,
    PRIMARY KEY (manifest_hash, finding_key),
    CONSTRAINT dtrack_findings_vex_status_check
        CHECK (vex_status IS NULL OR vex_status IN ('affected', 'not_affected', 'fixed', 'under_investigation'))
);
