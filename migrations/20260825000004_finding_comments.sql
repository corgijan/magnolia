-- Free-text discussion thread on a cached dtrack finding — an append-only
-- log (multiple analysts discussing one finding over time), which is a
-- different shape than the single-current-state vex_status/vex_justification
-- triage columns on dtrack_findings, so it needs its own table rather than
-- reusing that one-row-per-finding record.
CREATE TABLE finding_comments (
    id UUID PRIMARY KEY,
    manifest_hash TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (manifest_hash, finding_key)
        REFERENCES dtrack_findings (manifest_hash, finding_key) ON DELETE CASCADE
);
CREATE INDEX finding_comments_finding_idx ON finding_comments (manifest_hash, finding_key, created_at);
