-- Per-tenant webhook endpoints -- a tenant subscribes a URL to one or more
-- event types (manifest.uploaded, manifest.revoked, finding.new_critical,
-- malicious.match_found, dtrack.push_failed) and gets a POST for each one
-- instead of having to poll. `id` is generated in application code (Rust's
-- own Uuid::new_v4(), same convention as tenants/api_keys), not a DB
-- default. `secret` is the HMAC-SHA256 signing key used to produce the
-- `X-Aise-Signature` header on every delivery -- shown to the operator only
-- at creation time, same "shown once" convention as an API key's secret,
-- but must stay readable server-side (unlike a password) since it's needed
-- on every delivery attempt, so it's stored in plain text rather than
-- hashed.
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    event_types TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_tenant_idx ON webhook_endpoints (tenant_id);

-- Delivery outbox -- `emit_event` writes one row per subscribed endpoint
-- per event (not one fan-out row per tenant), and the delivery worker
-- (`webhooks::run_webhook_delivery_loop`, modeled on `dtrack_sync.rs`'s
-- `run_sync_loop` shape) works through `pending` rows past their
-- `next_attempt_at`, same "poll a due-work queue" pattern as
-- `dtrack_findings`'s refresh loop. `payload` is the exact JSON body sent
-- (minus the signature/timestamp headers, which are computed fresh on each
-- attempt since they're derived from the current secret/time, not stored).
CREATE TABLE webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('pending', 'delivered', 'failed'))
);
-- The delivery worker's own "what's due right now" query -- partial on
-- `pending` only, since `delivered`/`failed` rows are never polled again.
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';
-- `GET /webhooks/{id}/deliveries`'s own query -- newest first, per endpoint.
CREATE INDEX webhook_deliveries_endpoint_idx ON webhook_deliveries (endpoint_id, created_at DESC);
