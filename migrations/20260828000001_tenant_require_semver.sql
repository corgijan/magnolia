-- Per-tenant opt-in requiring every SBOM upload's `version` field to be a
-- SemVer 2.0.0-compliant string (see https://semver.org). Off by default so
-- existing tenants using ad-hoc version strings (build numbers, dates,
-- "latest", etc.) aren't broken by upgrading -- same "explicit opt-in"
-- philosophy as `dtrack_sync_disabled`.
ALTER TABLE tenants ADD COLUMN require_semver_version BOOLEAN NOT NULL DEFAULT FALSE;
