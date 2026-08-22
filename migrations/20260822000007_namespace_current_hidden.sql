-- Per-namespace opt-out from the "Currently running" view. A namespace is
-- shown by default (no row here); inserting a row hides it. Opt-out rather
-- than opt-in so no backfill is needed and every existing/future namespace
-- stays visible unless explicitly turned off.
CREATE TABLE namespace_current_hidden (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    namespace VARCHAR(255) NOT NULL,
    hidden_by TEXT NOT NULL,
    hidden_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, namespace)
);
