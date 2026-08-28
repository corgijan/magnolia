-- Per-tenant opt-out of package reputation scoring being shown for that
-- tenant's manifests -- mirrors `dtrack_sync_disabled` exactly. Unlike
-- dtrack_sync_disabled, this has no effect on the background job itself
-- (`component_reputation` is deployment-global and identity-keyed, not
-- per-manifest, so there's nothing "belonging to this tenant" to stop
-- pushing/refreshing) -- it only controls whether the SBOM detail view
-- surfaces the "Package reputation" panel for this tenant. Off by default,
-- same "explicit opt-out" philosophy as dtrack_sync_disabled.
ALTER TABLE tenants ADD COLUMN reputation_disabled BOOLEAN NOT NULL DEFAULT FALSE;
