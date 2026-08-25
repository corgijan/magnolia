-- Per-tenant opt-out of the deployment-wide Dependency-Track sync (see
-- DTRACK_PLAN.md). The integration itself stays deployment-wide
-- (DTRACK_URL/DTRACK_API_KEY, not a per-tenant credential), but a tenant
-- can turn off having its own manifests pushed/refreshed even while the
-- deployment runs dtrack for everyone else. Already-cached findings are
-- not cleared when this flips on — same "mark, don't delete" philosophy as
-- revocation and namespace hiding elsewhere in this schema; it only stops
-- future syncing.
ALTER TABLE tenants ADD COLUMN dtrack_sync_disabled BOOLEAN NOT NULL DEFAULT FALSE;
