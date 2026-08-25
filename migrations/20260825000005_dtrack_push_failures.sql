-- Records the most recent push_bom failure for a manifest that has never
-- successfully synced to dtrack. Without this, a permanent rejection
-- (dtrack will never accept this content, e.g. it fails dtrack's own BOM
-- schema validation) looks identical in the UI to "hasn't been picked up
-- yet" forever, with no way to tell the two apart. Cleared as soon as a
-- later push attempt succeeds.
CREATE TABLE dtrack_push_failures (
    manifest_hash TEXT PRIMARY KEY REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    error TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
