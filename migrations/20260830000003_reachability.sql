-- CVE reachability evidence: the AISE side of the `reach/` analyser.
--
-- Three pieces: where a namespace's source lives, which revision a manifest
-- was built from, and which analysis answers a given finding.

-- 1. Namespace -> repository mapping.
--
-- Follows the tenant-settings pattern: per-tenant, set through the settings
-- API, never inferred. An analysis cannot run for a namespace with no
-- mapping, and the UI says so rather than guessing a repository from an SBOM
-- component's homepage URL (which is the *dependency's* repository, not the
-- consuming application's -- exactly the wrong tree to scan).
CREATE TABLE namespace_repos (
    tenant_id   UUID NOT NULL,
    namespace   VARCHAR(255) NOT NULL,
    -- https:// URL, or an absolute local path for the offline demo. The
    -- analyser validates this again on its own side; storing an unusable
    -- value here is a bad setting, not a security boundary.
    repo_url    TEXT NOT NULL,
    -- Monorepo sub-directory to scan. NULL = the whole repository.
    subpath     TEXT,
    created_by  VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, namespace)
);

-- 2. The revision a manifest's SBOM was generated from.
--
-- Nullable because every manifest uploaded before this migration has no such
-- record, and backfilling one would mean inventing it. Reachability analysis
-- refuses to run without it: analysing the branch head instead would produce
-- evidence about code that is not what the SBOM describes, and would silently
-- change meaning every time someone pushed.
ALTER TABLE manifests ADD COLUMN source_commit VARCHAR(64);

COMMENT ON COLUMN manifests.source_commit IS
    'Full git object id the SBOM was generated from, sent by the upload CLI. NULL for manifests uploaded before reachability analysis existed; reachability refuses to run without it rather than falling back to HEAD.';

-- 3. Finding -> analysis link.
--
-- One row per (finding, analysis). Multiple rows per finding are expected and
-- wanted: re-running against a newer commit is a new analysis, and the old
-- one stays as the record of what was true then.
CREATE TABLE finding_reachability (
    id            BIGSERIAL PRIMARY KEY,
    manifest_hash TEXT NOT NULL REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    finding_key   TEXT NOT NULL,
    -- The analyser's own id. Deliberately not a foreign key to anything:
    -- `reach` is a separate service with a separate database, and AISE holds
    -- only the handle.
    analysis_id   UUID NOT NULL,
    -- Copied at request time so the link stays interpretable even if the
    -- namespace mapping later changes.
    repo_url      TEXT NOT NULL,
    commit_sha    VARCHAR(64) NOT NULL,
    subpath       TEXT,
    requested_by  VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (analysis_id)
);

-- Serves "the most recent analysis for this finding", the only read path.
CREATE INDEX idx_finding_reachability_finding
    ON finding_reachability (manifest_hash, finding_key, created_at DESC);
