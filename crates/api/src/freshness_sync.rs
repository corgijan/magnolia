use std::sync::Arc;
use std::time::Duration;

use magnolia_db::Database;
use magnolia_depsdev::{DepsDevClient, PackageVersionSummary};

/// How many (ecosystem, registry_name) pairs to process per tick — mirrors
/// `reputation_sync::BATCH_SIZE` exactly (same one-call-per-pair cost via
/// `get_package`, same reasoning for the bound).
const BATCH_SIZE: i64 = 20;

/// A cached result older than this is treated as stale and re-checked — a
/// package's latest release doesn't change day to day, same reasoning (and
/// same value) as `reputation_sync::STALE_AFTER_DAYS`. Shared between
/// `sync_pass` (what counts as "needs checking") and `freshness_status`
/// (what counts as "already checked") so the two never disagree.
pub const STALE_AFTER_DAYS: i64 = 30;

pub fn stale_before_cutoff() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::days(STALE_AFTER_DAYS)
}

/// Periodic background job filling in `component_freshness` for components
/// `sbom_components` has indexed but no (or a stale) cached deps.dev
/// latest-version result for — same shape as `reputation_sync.rs`,
/// including sharing its `ecosystem`/`registry_name` backfill: that phase
/// lives only in `reputation_sync::sync_pass` (both jobs read the same
/// `sbom_components` columns, so there's nothing to gain from running the
/// same backfill twice), which is why this loop is only ever spawned
/// alongside the reputation loop, gated on the same `depsdev` client. Every
/// per-item failure is caught and logged, never propagated. Bursts through
/// a large backlog at `burst_interval` spacing rather than waiting a full
/// `interval` between every batch — see `sync_loop::run_burst_loop`.
pub async fn run_freshness_sync_loop(
    db: Arc<Database>,
    client: Arc<DepsDevClient>,
    interval: Duration,
    burst_interval: Duration,
) {
    crate::sync_loop::run_burst_loop(interval, burst_interval, move || {
        let db = db.clone();
        let client = client.clone();
        async move { sync_pass(&db, &client).await }
    })
    .await;
}

/// One batch's worth of the freshness sync loop's work, run either by the
/// periodic loop above or on-demand from `force_freshness_sync` — same
/// relationship as `reputation_sync::sync_pass` to its own callers. Returns
/// how many components were successfully processed (found-a-version and
/// "deps.dev has no version info at all" both count; a fetch failure does
/// not).
pub async fn sync_pass(db: &Database, client: &DepsDevClient) -> usize {
    let pending = match db.list_components_needing_freshness(stale_before_cutoff(), BATCH_SIZE).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "freshness sync: failed to list pending components");
            return 0;
        }
    };

    let mut processed = 0;
    for identity in pending {
        let package = match client.get_package(&identity.ecosystem, &identity.registry_name).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    ecosystem = %identity.ecosystem, name = %identity.registry_name, error = %e,
                    "freshness sync: get_package failed"
                );
                if let Err(e2) = db
                    .upsert_component_freshness(&identity.ecosystem, &identity.registry_name, None, Some(&e.to_string()))
                    .await
                {
                    tracing::warn!(error = %e2, "freshness sync: failed to record fetch error");
                }
                continue;
            }
        };

        let latest = pick_latest_version(&package.versions);
        if let Err(e) =
            db.upsert_component_freshness(&identity.ecosystem, &identity.registry_name, latest.as_deref(), None).await
        {
            tracing::warn!(error = %e, "freshness sync: failed to store result");
            continue;
        }
        processed += 1;
    }
    processed
}

/// deps.dev's own "default" version if one is flagged (see
/// `DepsDevClient::get_package`'s doc comment for why that's preferred over
/// a raw numeric-highest pick), otherwise the highest parseable SemVer
/// among every known version. `None` when deps.dev has no version info at
/// all (unknown package) or nothing among `versions[]` parses as SemVer.
/// Pure/no I/O, unit-testable on its own.
fn pick_latest_version(versions: &[PackageVersionSummary]) -> Option<String> {
    if let Some(default) = versions.iter().find(|v| v.is_default) {
        return Some(default.version_key.version.clone());
    }
    versions
        .iter()
        .filter_map(|v| {
            let parsed = semver::Version::parse(v.version_key.version.trim_start_matches('v')).ok()?;
            Some((parsed, v.version_key.version.clone()))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, raw)| raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(v: &str, is_default: bool) -> PackageVersionSummary {
        PackageVersionSummary {
            version_key: magnolia_depsdev::PackageVersionKey { version: v.to_string() },
            is_default,
        }
    }

    #[test]
    fn prefers_the_flagged_default_version() {
        let versions = vec![version("2.0.0", false), version("1.5.0", true), version("1.9.0", false)];
        assert_eq!(pick_latest_version(&versions), Some("1.5.0".to_string()));
    }

    #[test]
    fn falls_back_to_highest_semver_when_no_default_flagged() {
        let versions = vec![version("1.0.0", false), version("1.9.0", false), version("1.5.0", false)];
        assert_eq!(pick_latest_version(&versions), Some("1.9.0".to_string()));
    }

    #[test]
    fn ignores_unparseable_versions_in_the_fallback() {
        let versions = vec![version("not-semver", false), version("1.2.3", false)];
        assert_eq!(pick_latest_version(&versions), Some("1.2.3".to_string()));
    }

    #[test]
    fn empty_versions_yields_none() {
        assert_eq!(pick_latest_version(&[]), None);
    }
}
