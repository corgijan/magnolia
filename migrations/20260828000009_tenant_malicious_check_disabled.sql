-- Per-tenant opt-out of the "malicious package" panel being shown on that
-- tenant's manifests -- mirrors `reputation_disabled` exactly. Findings are
-- still detected and stored at upload time (the OSV check itself is
-- deployment-wide, per-manifest, and cheap -- one batched call already made
-- regardless), this only controls whether the SBOM detail view surfaces the
-- "malicious package" panel for this tenant. Off by default, same
-- "explicit opt-out" philosophy as dtrack_sync_disabled/reputation_disabled.
ALTER TABLE tenants ADD COLUMN malicious_check_disabled BOOLEAN NOT NULL DEFAULT FALSE;
