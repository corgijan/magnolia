-- CVE reachability, third step: keep the report AISE showed an analyst.
--
-- Until now AISE stored only the analyser's `analysis_id` plus a cached
-- status, and re-fetched the full report from `reach` on every single render
-- of the panel. That made the evidence as durable as the analyser's own
-- SQLite volume: reset it, and the report a human triaged against is gone for
-- good, recoverable only by spending the inference again — and the audit row
-- records which analysis ran, not what it concluded.
--
-- For a service whose whole subject is durable, auditable supply-chain
-- evidence, that is the wrong side of the tradeoff. `reach` stays the source
-- of truth for a *live* analysis; this column is the archived copy of the
-- finished one.
--
-- Stored as JSONB, unparsed and unreshaped, for the same reason
-- `crates/reachability` carries the report as `serde_json::Value`: the report
-- schema belongs to the analyser and will grow. AISE archives it; it does not
-- model it.
ALTER TABLE finding_reachability ADD COLUMN report_json JSONB;
ALTER TABLE finding_reachability ADD COLUMN report_stored_at TIMESTAMPTZ;

COMMENT ON COLUMN finding_reachability.report_json IS
    'Verbatim copy of the analyser''s report, written once the analysis reaches a terminal state. NULL while in flight, for an analysis that failed before producing one, and for rows created before this migration. Never reshaped: the schema belongs to reach.';

-- Serves "did we already archive this one", the only write-side check.
CREATE INDEX idx_finding_reachability_unarchived
    ON finding_reachability (analysis_id)
    WHERE report_json IS NULL;
