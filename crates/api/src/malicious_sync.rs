use std::sync::Arc;
use std::time::Duration;

use magnolia_db::{Database, NewSbomComponent};
use magnolia_osv::OsvClient;

/// How many manifests to (re)check per tick — each one costs up to
/// `1 + distinct MAL- hits` OSV calls (one batched `querybatch`, plus one
/// `get_vuln` per newly-seen malicious id), so this bounds outbound request
/// volume per tick the same way `reputation_sync::BATCH_SIZE` does.
const BATCH_SIZE: i64 = 20;

/// A manifest not rechecked in this long is treated as stale — the whole
/// point of rescanning is catching a package that gets flagged `MAL-`
/// *after* it was uploaded, which can happen any time, so this is a much
/// shorter TTL than `reputation_sync::STALE_AFTER_DAYS` (reputation scores
/// move slowly; malicious-package advisories can land at any moment).
pub const STALE_AFTER_DAYS: i64 = 1;

pub fn stale_before_cutoff() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::days(STALE_AFTER_DAYS)
}

/// Periodic background job re-running the OSV malicious-package check
/// against manifests already in the archive — the upload-time check in
/// `malicious_check.rs` only ever sees a component as of the moment it was
/// uploaded, so without this, a package later flagged `MAL-` would never
/// surface on a manifest uploaded before that happened. Same shape as
/// `reputation_sync.rs`: no per-manifest state to reconcile beyond
/// `manifests.malicious_checked_at`, just a deployment-global backlog
/// worked through one tick's worth at a time. Every per-item failure is
/// caught and logged, never propagated — a transient OSV outage must not
/// kill the loop.
pub async fn run_malicious_sync_loop(db: Arc<Database>, client: Arc<OsvClient>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        sync_pass(&db, &client).await;
    }
}

/// One batch's worth of the malicious-sync loop's work, run either by the
/// periodic loop above or on-demand from `force_malicious_sync` (the "force
/// sync" button/endpoint) — same relationship as `reputation_sync::sync_pass`
/// to its own loop/force-sync handler. Returns how many manifests were
/// successfully (re)checked — a manifest whose OSV call itself failed is not
/// counted, and is left stale so it's retried on the very next pass instead
/// of waiting out the full `STALE_AFTER_DAYS` window.
pub async fn sync_pass(db: &Database, client: &OsvClient) -> usize {
    let pending = match db.list_manifests_needing_malicious_check(stale_before_cutoff(), BATCH_SIZE).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "malicious sync: failed to list pending manifests");
            return 0;
        }
    };

    let mut processed = 0;
    for manifest_hash in pending {
        let rows = match db.list_sbom_components_for_manifest(&manifest_hash).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(manifest_hash = %manifest_hash, error = %e, "malicious sync: failed to load components; skipping");
                continue;
            }
        };
        // `ecosystem`/`registry_name` are reputation-only fields —
        // `check_and_store_malicious_components` never reads them, only
        // `name`/`version`/`purl`.
        let components: Vec<NewSbomComponent> = rows
            .into_iter()
            .map(|c| NewSbomComponent {
                name: c.name,
                version: c.version,
                purl: c.purl,
                cpe: c.cpe,
                is_primary: c.is_primary,
                ecosystem: None,
                registry_name: None,
            })
            .collect();

        let ok =
            crate::malicious_check::check_and_store_malicious_components(db, client, &manifest_hash, &components)
                .await;
        if !ok {
            continue;
        }
        if let Err(e) = db.touch_manifest_malicious_checked(&manifest_hash).await {
            tracing::warn!(manifest_hash = %manifest_hash, error = %e, "malicious sync: failed to record malicious_checked_at");
            continue;
        }
        processed += 1;
    }
    processed
}
