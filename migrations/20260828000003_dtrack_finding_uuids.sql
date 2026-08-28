-- dtrack's own component/vulnerability UUIDs for each cached finding --
-- needed to push Magnolia's VEX triage back to dtrack's `PUT
-- /api/v1/analysis` endpoint, which addresses a finding by
-- project+component+vulnerability UUID, not by Magnolia's own finding_key.
-- Nullable: rows cached before this migration won't have these until their
-- next sync refresh (replace_dtrack_findings upserts them in going forward);
-- a triage push simply skips a finding that doesn't have them yet.
ALTER TABLE dtrack_findings ADD COLUMN component_uuid TEXT;
ALTER TABLE dtrack_findings ADD COLUMN vulnerability_uuid TEXT;
