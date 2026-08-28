use std::sync::Arc;
use std::time::Duration;

use magnolia_db::Database;
use magnolia_depsdev::DepsDevClient;

/// How many (ecosystem, registry_name) pairs to process per tick — each one
/// costs up to two sequential deps.dev calls (`get_version` then
/// `get_project`), so this bounds outbound request volume per tick the same
/// way `dtrack_sync::push_phase`'s `LIMIT 50` bounds its own per-tick work.
const BATCH_SIZE: i64 = 20;

/// How many `sbom_components` rows to backfill `ecosystem`/`registry_name`
/// for per tick — pure local computation (parses a purl, no I/O), so this
/// can be much larger than `BATCH_SIZE` (which bounds outbound deps.dev
/// calls) without costing anything but CPU.
const BACKFILL_BATCH_SIZE: i64 = 1000;

/// A cached result older than this is treated as stale and re-checked —
/// reputation moves slowly (a Scorecard result doesn't change day to day),
/// so this is a much longer TTL than dtrack's vulnerability refresh cadence.
/// Shared between `sync_pass` (what counts as "needs checking") and
/// `reputation_status` (what counts as "already checked") so the two never
/// disagree about a component sitting right at the boundary.
pub const STALE_AFTER_DAYS: i64 = 30;

pub fn stale_before_cutoff() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::days(STALE_AFTER_DAYS)
}

/// Periodic background job filling in `component_reputation` for components
/// `sbom_components` has indexed but no (or a stale) cached deps.dev
/// Scorecard result for. Unlike `dtrack_sync`'s push/refresh loop, this has
/// no per-manifest state to reconcile — it just works through a
/// deployment-global backlog of package identities, one tick's worth at a
/// time. Every per-item failure is caught and logged, never propagated
/// (same idiom as `dtrack_sync.rs`): a transient deps.dev outage must not
/// kill the loop.
pub async fn run_reputation_sync_loop(db: Arc<Database>, client: Arc<DepsDevClient>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        sync_pass(&db, &client).await;
    }
}

/// One batch's worth of the reputation sync loop's work, run either by the
/// periodic loop above or on-demand from `force_reputation_sync` (the
/// "force sync" button/endpoint) — same relationship as
/// `dtrack_sync::sync_now` to `run_sync_loop`. Returns how many components
/// were successfully processed (found-with-a-score, found-with-no-scorecard,
/// and "no related project at all" all count as processed; a fetch failure
/// does not).
pub async fn sync_pass(db: &Database, client: &DepsDevClient) -> usize {
    // Runs first so a component backfilled this tick is already eligible
    // for the fetch phase below in the same pass, not just the next one.
    backfill_ecosystem_phase(db).await;

    let pending = match db.list_components_needing_reputation(stale_before_cutoff(), BATCH_SIZE).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "reputation sync: failed to list pending components");
            return 0;
        }
    };

    let mut processed = 0;
    for identity in pending {
        let version = match client.get_version(&identity.ecosystem, &identity.registry_name, &identity.sample_version).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    ecosystem = %identity.ecosystem, name = %identity.registry_name, error = %e,
                    "reputation sync: get_version failed"
                );
                if let Err(e2) = db
                    .upsert_component_reputation(&identity.ecosystem, &identity.registry_name, None, None, Some(&e.to_string()))
                    .await
                {
                    tracing::warn!(error = %e2, "reputation sync: failed to record fetch error");
                }
                continue;
            }
        };

        // No related project at all (deps.dev doesn't know this package's
        // source repo) -- store as "checked, nothing found," not an error:
        // there's genuinely no scorecard to have.
        let Some(project_id) = version.related_projects.first().map(|p| p.project_key.id.clone()) else {
            if let Err(e) = db.upsert_component_reputation(&identity.ecosystem, &identity.registry_name, None, None, None).await {
                tracing::warn!(error = %e, "reputation sync: failed to record empty result");
            }
            processed += 1;
            continue;
        };

        let project = match client.get_project(&project_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(project_id = %project_id, error = %e, "reputation sync: get_project failed");
                if let Err(e2) = db
                    .upsert_component_reputation(&identity.ecosystem, &identity.registry_name, None, Some(&project_id), Some(&e.to_string()))
                    .await
                {
                    tracing::warn!(error = %e2, "reputation sync: failed to record fetch error");
                }
                continue;
            }
        };

        let score = project.scorecard.as_ref().and_then(|s| s.overall_score);
        if let Err(e) = db
            .upsert_component_reputation(&identity.ecosystem, &identity.registry_name, score, Some(&project_id), None)
            .await
        {
            tracing::warn!(error = %e, "reputation sync: failed to store result");
            continue;
        }
        processed += 1;
    }
    processed
}

/// Fills in `ecosystem`/`registry_name` for any `sbom_components` row that
/// was never run through `purl_to_depsdev_package` — the main case is a row
/// inserted before those columns existed at all (their own migration has no
/// backfill `UPDATE`), which `index_manifest_components` only ever computes
/// for a *new* upload. Without this phase, such a row is permanently
/// invisible to `list_components_needing_reputation` (which requires
/// `ecosystem IS NOT NULL`) and would never get reputation-scored no matter
/// how many sync passes run. See `list_sbom_components_missing_ecosystem`'s
/// doc comment for how a row that's genuinely unmappable (stored as
/// `ecosystem = ""`) avoids being re-attempted here forever. Best-effort,
/// same swallow-and-log idiom as the rest of this loop.
async fn backfill_ecosystem_phase(db: &Database) -> usize {
    let rows = match db.list_sbom_components_missing_ecosystem(BACKFILL_BATCH_SIZE).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "reputation sync: failed to list components missing ecosystem");
            return 0;
        }
    };

    let mut backfilled = 0;
    for (id, purl) in rows {
        let (ecosystem, registry_name) = match magnolia_core::purl_to_depsdev_package(&purl) {
            Some((eco, name)) => (eco, Some(name)),
            None => ("", None), // attempted, no deps.dev mapping for this purl type
        };
        if let Err(e) = db.set_sbom_component_ecosystem(id, Some(ecosystem), registry_name.as_deref()).await {
            tracing::warn!(id, error = %e, "reputation sync: failed to backfill ecosystem");
            continue;
        }
        backfilled += 1;
    }
    if backfilled > 0 {
        tracing::info!(backfilled, "reputation sync: backfilled ecosystem/registry_name for pre-existing components");
    }
    backfilled
}
