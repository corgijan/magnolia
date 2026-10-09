-- Job table. One row per analysis request, from queued to a stored report.
--
-- SQLite rather than Postgres deliberately: `reach` holds no tenant data and
-- no credentials, only jobs and their reports, and a single file keeps the
-- service a drop-in container with nothing else to provision. AISE remains
-- the system of record; this is a cache of work it asked for.
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    status          TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),

    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT,

    -- Request. `advisory_text` is attacker-influenceable input; it is stored
    -- verbatim so a report can always be traced back to exactly what was
    -- analysed, and it is never interpolated into a prompt unfenced.
    advisory_text   TEXT NOT NULL,
    osv_id          TEXT,
    package_name    TEXT,
    ecosystem       TEXT,
    repo_url        TEXT,
    commit_sha      TEXT,
    subpath         TEXT,

    -- Result. Exactly one of these is set once the job leaves 'running'.
    report_json     TEXT,
    -- Denormalised out of report_json so the list endpoint does not have to
    -- parse every report to show a column.
    priority        TEXT,
    error           TEXT
);

-- The worker's claim query: oldest queued job first.
CREATE INDEX IF NOT EXISTS analyses_status_created_idx ON analyses (status, created_at);

-- Serves the "has this exact question already been answered?" lookup that
-- keeps a UI button from re-running an identical analysis.
CREATE INDEX IF NOT EXISTS analyses_dedup_idx ON analyses (osv_id, repo_url, commit_sha);
