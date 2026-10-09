-- CVE reachability, second step: a per-namespace default revision, opt-in
-- background analysis, and a cached status so lists can show evidence state
-- without calling the analyser once per row.

-- 1. Namespace source metadata.
--
-- `revision` is a branch, tag, or exact commit. It is only used for a
-- manifest that has no `source_commit` of its own (uploaded by a CI that does
-- not send one), and it is never analysed as a moving ref: the analyser
-- resolves it to an exact commit once, at request time, and that commit is
-- what gets stored and scanned. A manifest's own `source_commit` always wins,
-- because it is the revision the SBOM actually describes.
--
-- `auto_analyze` opts a namespace into background analysis of its current
-- manifest's untriaged findings. Off by default: each analysis costs several
-- inference calls, which is minutes of local-model time.
ALTER TABLE namespace_repos ADD COLUMN revision VARCHAR(255);
ALTER TABLE namespace_repos ADD COLUMN auto_analyze BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. Provenance of the analysed revision, and a status cache.
--
-- `commit_source` says where `commit_sha` came from: 'manifest' (the SBOM's
-- own recorded commit) or 'namespace_revision' (resolved from
-- `requested_ref`). The UI states the difference, because a resolved branch
-- head may not be the code the SBOM was generated from.
--
-- `status`/`priority` mirror the analyser's answer the last time AISE asked.
-- The analyser stays the source of truth; this exists so the findings list
-- can show a badge per row, and so the background loop can count how much
-- work is already queued. NULL for rows created before this migration until
-- they are next polled.
ALTER TABLE finding_reachability
    ADD COLUMN commit_source VARCHAR(32) NOT NULL DEFAULT 'manifest';
ALTER TABLE finding_reachability ADD COLUMN requested_ref TEXT;
ALTER TABLE finding_reachability ADD COLUMN status VARCHAR(32);
ALTER TABLE finding_reachability ADD COLUMN priority VARCHAR(64);
ALTER TABLE finding_reachability ADD COLUMN status_checked_at TIMESTAMPTZ;

-- Serves the background loop's "what is still in flight" poll and count.
CREATE INDEX idx_finding_reachability_pending
    ON finding_reachability (created_at)
    WHERE status IS NULL OR status IN ('queued', 'running');
