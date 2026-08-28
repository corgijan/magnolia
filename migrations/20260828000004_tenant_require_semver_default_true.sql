-- Flips `require_semver_version` (added opt-in/off by
-- 20260828000001_tenant_require_semver.sql) to on-by-default, per a
-- follow-up decision made after that migration had already run against a
-- live database. Corrected here as a new migration rather than by editing
-- 20260828000001 in place: editing an already-applied migration file
-- changes its checksum, which sqlx's migrator refuses to run past
-- (`VersionMismatch`) -- exactly the failure this fixes. Backfills
-- existing tenants too, since the feature had not yet shipped to any real
-- upload path when this changed.
ALTER TABLE tenants ALTER COLUMN require_semver_version SET DEFAULT TRUE;
UPDATE tenants SET require_semver_version = TRUE WHERE require_semver_version = FALSE;
