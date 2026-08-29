-- Cached "latest known version" per package, deployment-global and keyed
-- by (ecosystem, name) -- deliberately NOT per-version, same shape and same
-- reasoning as component_reputation: a package's latest release doesn't
-- depend on which version a given manifest happens to pin, or which tenant
-- uploaded it. Populated by a periodic background job cloning
-- reputation_sync.rs's shape (see freshness_sync.rs), not synchronously at
-- upload time.
CREATE TABLE component_freshness (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    latest_version TEXT,           -- NULL if deps.dev has no version info for this package
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetch_error TEXT,              -- last fetch failure, if any; cleared on success
    PRIMARY KEY (ecosystem, name)
);

-- Per-tenant opt-out of the "Outdated components" signal being shown for
-- that tenant's manifests -- mirrors reputation_disabled exactly, including
-- having no effect on the background job itself (component_freshness is
-- deployment-global and identity-keyed, nothing "belongs" to one tenant to
-- stop pushing/refreshing). Off by default, same explicit-opt-out
-- philosophy as reputation_disabled.
ALTER TABLE tenants ADD COLUMN freshness_disabled BOOLEAN NOT NULL DEFAULT FALSE;
