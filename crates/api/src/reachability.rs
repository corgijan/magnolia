//! CVE reachability evidence: the parts shared by the request handlers and
//! the background loop.
//!
//! AISE's job here is narrow: decide *which* repository and revision a
//! finding's manifest corresponds to, hand that to the `reach` analyser, and
//! keep a small cache of how the analysis is going. The analysis, the prompts
//! and the report schema all live in `reach/`.
//!
//! The framing rule from CLAUDE.md travels with the data: the analyser
//! produces evidence for a human, never a verdict. Nothing here — including
//! the background loop — turns a report into a triage decision. No
//! auto-close, no VEX status written from a report; the loop only makes sure
//! the evidence is already waiting when a human opens the finding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use magnolia_db::{
    Database, DbError, DtrackFindingRecord, FindingReachabilityRecord, ManifestRecord,
    NewFindingReachability,
};
use magnolia_reachability::{AnalysisRequest, AnalysisView, ReachClient, ReachError};
use uuid::Uuid;

/// Recorded as `requested_by` (and as the audit principal) for analyses the
/// background loop queued, so the UI can say "queued automatically" and the
/// audit log can tell them apart from a person pressing the button.
pub const AUTO_PRINCIPAL: &str = "system:reachability-auto";

pub const COMMIT_SOURCE_MANIFEST: &str = "manifest";
pub const COMMIT_SOURCE_NAMESPACE_REVISION: &str = "namespace_revision";
/// The namespace revision was analysed *instead of* the manifest's own
/// recorded commit, because the namespace's testing override is on.
pub const COMMIT_SOURCE_REVISION_OVERRIDE: &str = "revision_override";

/// How long an in-flight analysis counts against the background loop's
/// concurrency budget. Past this, a row stuck at `queued`/`running` (an
/// analyser whose database was reset, say) stops blocking new work.
const IN_FLIGHT_WINDOW_HOURS: i64 = 24;

/// After a candidate could not be queued for a reason that will not fix
/// itself on the next tick (the analyser rejected the request, the branch
/// does not exist), leave it alone for this long rather than retrying it
/// every pass.
const CANDIDATE_BACKOFF: Duration = Duration::from_secs(6 * 60 * 60);

/// Most in-flight rows re-polled per background pass.
const REFRESH_BATCH: i64 = 50;

/// Which revision an analysis should scan, and where that choice came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revision {
    /// The manifest's own `source_commit` — the revision the SBOM describes.
    Manifest(String),
    /// The namespace's configured default (branch, tag or commit). Sent to
    /// the analyser as a ref and resolved there, once, to an exact commit.
    Namespace(String),
    /// The namespace revision, chosen over a commit the manifest *did*
    /// record, because the namespace's `ignore_source_commit` testing
    /// override is on. Sent and resolved like [`Revision::Namespace`].
    Override(String),
}

impl Revision {
    pub fn commit_source(&self) -> &'static str {
        match self {
            Revision::Manifest(_) => COMMIT_SOURCE_MANIFEST,
            Revision::Namespace(_) => COMMIT_SOURCE_NAMESPACE_REVISION,
            Revision::Override(_) => COMMIT_SOURCE_REVISION_OVERRIDE,
        }
    }

    /// `(exact commit, ref to resolve)` — exactly one is `Some`.
    pub fn commit_and_ref(&self) -> (Option<String>, Option<String>) {
        match self {
            Revision::Manifest(c) => (Some(c.clone()), None),
            Revision::Namespace(r) | Revision::Override(r) => (None, Some(r.clone())),
        }
    }
}

/// A manifest's own recorded commit always wins: it is the code the SBOM was
/// generated from. The namespace revision is only a fallback for manifests
/// that carry none — unless `ignore_source_commit` (a per-namespace testing
/// override) is on and a revision is configured, in which case the revision
/// is used and marked as an override. Pure, so the precedence is
/// unit-tested.
pub fn choose_revision(
    source_commit: Option<&str>,
    namespace_revision: Option<&str>,
    ignore_source_commit: bool,
) -> Option<Revision> {
    let clean = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let commit = clean(source_commit);
    let revision = clean(namespace_revision);
    match (commit, revision) {
        (Some(_), Some(r)) if ignore_source_commit => Some(Revision::Override(r)),
        (Some(c), _) => Some(Revision::Manifest(c)),
        (None, Some(r)) => Some(Revision::Namespace(r)),
        (None, None) => None,
    }
}

/// Everything needed to queue one analysis.
#[derive(Debug, Clone)]
pub struct AnalysisPlan {
    pub finding: DtrackFindingRecord,
    pub advisory_text: String,
    pub repo_url: String,
    pub subpath: Option<String>,
    pub revision: Revision,
}

/// Resolves a finding to what an analysis would need, or to the reason an
/// analysis cannot run. `Ok(Err(reason))` is an expected outcome (nothing
/// mapped, no revision known, no advisory text yet), phrased for the person
/// looking at the disabled button. Performs no authorization: callers have
/// already established that the manifest belongs to the tenant in scope.
pub async fn plan_analysis(
    db: &Database,
    manifest: &ManifestRecord,
    finding: DtrackFindingRecord,
) -> Result<Result<AnalysisPlan, String>, DbError> {
    let Some(repo) = db.get_namespace_repo(manifest.tenant_id, &manifest.namespace).await? else {
        return Ok(Err(format!(
            "No source repository is mapped for namespace {}. Set one under Settings → Source repositories before running a reachability analysis.",
            manifest.namespace
        )));
    };

    // Refusing to guess is the whole reason this can be blocked. Without a
    // manifest commit or an explicitly configured namespace revision there
    // is no defensible choice of tree to scan.
    let Some(revision) = choose_revision(
        manifest.source_commit.as_deref(),
        repo.revision.as_deref(),
        repo.ignore_source_commit,
    ) else {
        return Ok(Err(format!(
            "This manifest was uploaded without a source commit, and namespace {} has no default revision. Set a revision (for example `main` or a release tag) under Settings → Source repositories, or re-upload with the current CLI, which sends `git rev-parse HEAD`.",
            manifest.namespace
        )));
    };

    // The advisory text the analyser reasons over. `description` is what
    // dtrack synced from the upstream advisory; without it there is nothing
    // to extract a ruleset from.
    let Some(advisory_text) = finding
        .description
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(str::to_string)
    else {
        return Ok(Err(format!(
            "No advisory text is cached for {} yet, so there is nothing to analyse. It usually arrives with the next Dependency-Track sync.",
            finding.vulnerability_id
        )));
    };

    Ok(Ok(AnalysisPlan {
        finding,
        advisory_text,
        repo_url: repo.repo_url,
        subpath: repo.subpath,
        revision,
    }))
}

#[derive(Debug)]
pub enum QueueError {
    /// The analyser could not be reached at all.
    Unavailable,
    /// The analyser refused the request with a human-readable reason (a
    /// branch that does not exist, an unusable URL). Retrying will not help.
    Rejected(String),
    /// Anything else the analyser or the response got wrong.
    Failed(String),
    Db(DbError),
}

/// Queues `plan` on the analyser and records the finding→analysis link,
/// pinned to the exact commit the analyser will scan.
pub async fn queue_analysis(
    db: &Database,
    client: &ReachClient,
    manifest_hash: &str,
    plan: &AnalysisPlan,
    requested_by: &str,
) -> Result<FindingReachabilityRecord, QueueError> {
    let (commit, git_ref) = plan.revision.commit_and_ref();
    let request = AnalysisRequest {
        advisory_text: plan.advisory_text.clone(),
        osv_id: Some(plan.finding.vulnerability_id.clone()),
        package_name: Some(plan.finding.component_name.clone()),
        ecosystem: None,
        repo_url: Some(plan.repo_url.clone()),
        commit: commit.clone(),
        git_ref: git_ref.clone(),
        subpath: plan.subpath.clone(),
    };

    let created = client.create_analysis(&request).await.map_err(|e| {
        tracing::warn!(error = %e, "reachability analysis could not be queued");
        match e {
            ReachError::Unavailable(_) => QueueError::Unavailable,
            // 4xx from the analyser is written for a human — pass it on.
            ReachError::Upstream { status, body } if (400..500).contains(&status) => {
                QueueError::Rejected(analyser_error_message(&body))
            }
            other => QueueError::Failed(other.to_string()),
        }
    })?;

    // The analyser is the one that resolved a ref, so it is the one that
    // must say what it resolved to. An analyser too old to return that
    // cannot be used with a namespace revision: recording the ref instead of
    // a commit would make the stored evidence unpinnable.
    let commit_sha = created.commit.clone().or(commit).ok_or_else(|| {
        QueueError::Failed(
            "the analyser did not report which commit it resolved the namespace revision to — upgrade reach".to_string(),
        )
    })?;

    db.record_finding_reachability(NewFindingReachability {
        manifest_hash,
        finding_key: &plan.finding.finding_key,
        analysis_id: created.id,
        repo_url: &plan.repo_url,
        commit_sha: &commit_sha,
        subpath: plan.subpath.as_deref(),
        requested_by,
        commit_source: plan.revision.commit_source(),
        requested_ref: git_ref.as_deref(),
    })
    .await
    .map_err(QueueError::Db)
}

/// The analyser's 4xx body is `{"error": "..."}`; fall back to the raw body.
fn analyser_error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| body.to_string())
}

/// The priority label out of a report, without mirroring the report schema
/// (which belongs to the analyser).
pub fn report_priority(view: &AnalysisView) -> Option<String> {
    view.report
        .as_ref()
        .and_then(|r| r.get("priority"))
        .and_then(|p| p.as_str())
        .map(str::to_string)
}

/// Writes the analyser's latest answer into the status cache, archiving the
/// report itself once there is one. Best effort: a failure only means a list
/// badge is stale for one more poll.
///
/// `report` is `None` while an analysis is still in flight and whenever the
/// analyser could not be reached; the query coalesces, so that never erases an
/// already-archived report.
pub async fn cache_status(
    db: &Database,
    analysis_id: Uuid,
    status: &str,
    priority: Option<&str>,
    report: Option<&serde_json::Value>,
) {
    if let Err(e) =
        db.update_finding_reachability_status(analysis_id, status, priority, report).await
    {
        tracing::warn!(%analysis_id, error = %e, "could not cache reachability status");
    }
}

/// The report to archive from a poll: only from a terminal state, so a
/// partially-filled report from a still-running analysis is never mistaken
/// for the final one.
pub fn archivable_report(view: &AnalysisView) -> Option<&serde_json::Value> {
    match view.status.as_str() {
        "completed" | "failed" => view.report.as_ref(),
        _ => None,
    }
}

/// Re-polls analyses the cache still believes are in flight. Stops at the
/// first "analyser unreachable" rather than timing out once per row.
pub async fn refresh_in_flight(db: &Database, client: &ReachClient) -> usize {
    let rows = match db.list_pending_finding_reachability(REFRESH_BATCH).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "reachability refresh: could not list in-flight analyses");
            return 0;
        }
    };
    let mut updated = 0;
    for row in rows {
        match client.get_analysis(row.analysis_id).await {
            Ok(view) => {
                cache_status(
                    db,
                    row.analysis_id,
                    &view.status,
                    report_priority(&view).as_deref(),
                    archivable_report(&view),
                )
                .await;
                updated += 1;
            }
            Err(ReachError::NotFound) => {
                // No report to archive, and the coalescing write leaves any
                // already-archived one alone — which is the whole point: the
                // analyser losing an analysis must not lose the evidence.
                cache_status(db, row.analysis_id, "missing", None, None).await;
                updated += 1;
            }
            Err(ReachError::Unavailable(e)) => {
                tracing::debug!(error = %e, "reachability refresh: analyser unreachable, stopping this pass");
                break;
            }
            Err(e) => tracing::warn!(analysis_id = %row.analysis_id, error = %e, "reachability refresh failed"),
        }
    }
    updated
}

/// Background loop: keeps cached statuses fresh, and queues analyses for the
/// current, untriaged findings of namespaces opted into `auto_analyze` —
/// never more than `max_in_flight` at once, because each analysis occupies
/// the analyser's single worker for minutes against a local model. Every
/// failure is logged and skipped, never propagated, same as every other
/// loop in this crate.
pub async fn run_reachability_auto_loop(
    db: Arc<Database>,
    client: Arc<ReachClient>,
    interval: Duration,
    burst_interval: Duration,
    max_in_flight: i64,
) {
    let backoff: Arc<Mutex<HashMap<(String, String), Instant>>> = Arc::default();
    crate::sync_loop::run_burst_loop(interval, burst_interval, move || {
        let db = db.clone();
        let client = client.clone();
        let backoff = backoff.clone();
        async move { auto_pass(&db, &client, max_in_flight, &backoff).await }
    })
    .await;
}

/// One pass of the background loop. Returns how many analyses it queued, so
/// the burst loop drains a backlog quickly and backs off once the analyser's
/// budget is full or nothing is left.
pub async fn auto_pass(
    db: &Database,
    client: &ReachClient,
    max_in_flight: i64,
    backoff: &Mutex<HashMap<(String, String), Instant>>,
) -> usize {
    refresh_in_flight(db, client).await;

    let since = chrono::Utc::now() - chrono::Duration::hours(IN_FLIGHT_WINDOW_HOURS);
    let in_flight = match db.count_in_flight_finding_reachability(since).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "reachability auto: could not count in-flight analyses");
            return 0;
        }
    };
    let capacity = max_in_flight - in_flight;
    if capacity <= 0 {
        return 0;
    }

    // Over-fetch: some candidates may be backing off or turn out blocked.
    let candidates = match db.list_reachability_candidates(capacity * 4).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "reachability auto: could not list candidates");
            return 0;
        }
    };

    let mut queued = 0;
    for candidate in candidates {
        if queued >= capacity as usize {
            break;
        }
        let key = (candidate.manifest_hash.clone(), candidate.finding_key.clone());
        if is_backing_off(backoff, &key) {
            continue;
        }

        let Some(manifest) = db.get_manifest(&candidate.manifest_hash).await.ok().flatten() else {
            continue;
        };
        let finding = match db
            .get_dtrack_finding(&candidate.manifest_hash, &candidate.finding_key)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "reachability auto: could not load finding");
                continue;
            }
        };
        let Some(finding) = finding else { continue };

        let plan = match plan_analysis(db, &manifest, finding).await {
            Ok(Ok(plan)) => plan,
            Ok(Err(reason)) => {
                tracing::debug!(manifest_hash = %candidate.manifest_hash, %reason, "reachability auto: blocked");
                start_backoff(backoff, key);
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "reachability auto: could not plan analysis");
                continue;
            }
        };

        match queue_analysis(db, client, &candidate.manifest_hash, &plan, AUTO_PRINCIPAL).await {
            Ok(link) => {
                queued += 1;
                let reason = format!(
                    "analysis_id={}; vuln={}; commit={}; commit_source={}{}",
                    link.analysis_id,
                    plan.finding.vulnerability_id,
                    link.commit_sha,
                    link.commit_source,
                    link.requested_ref.as_deref().map(|r| format!("; ref={r}")).unwrap_or_default(),
                );
                if let Err(e) = db
                    .insert_audit_log(
                        Uuid::new_v4(),
                        candidate.tenant_id,
                        AUTO_PRINCIPAL,
                        "reachability_requested",
                        &format!("{}:{}", candidate.manifest_hash, candidate.finding_key),
                        "success",
                        Some(&reason),
                    )
                    .await
                {
                    tracing::warn!(error = %e, "reachability auto: could not write audit log");
                }
            }
            // The analyser is down: stop now, back off the whole loop.
            Err(QueueError::Unavailable) => break,
            Err(QueueError::Rejected(reason)) | Err(QueueError::Failed(reason)) => {
                tracing::warn!(manifest_hash = %candidate.manifest_hash, finding_key = %candidate.finding_key, %reason, "reachability auto: not queued");
                start_backoff(backoff, key);
            }
            Err(QueueError::Db(e)) => {
                tracing::warn!(error = %e, "reachability auto: analysis queued but not recorded");
            }
        }
    }
    queued
}

fn is_backing_off(backoff: &Mutex<HashMap<(String, String), Instant>>, key: &(String, String)) -> bool {
    let mut map = backoff.lock().unwrap_or_else(|p| p.into_inner());
    map.retain(|_, until| *until > Instant::now());
    map.contains_key(key)
}

fn start_backoff(backoff: &Mutex<HashMap<(String, String), Instant>>, key: (String, String)) {
    backoff
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key, Instant::now() + CANDIDATE_BACKOFF);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_commit_always_wins_over_the_namespace_revision() {
        assert_eq!(
            choose_revision(Some("a".repeat(40).as_str()), Some("main"), false),
            Some(Revision::Manifest("a".repeat(40)))
        );
    }

    #[test]
    fn the_namespace_revision_is_the_fallback_for_manifests_without_a_commit() {
        assert_eq!(choose_revision(None, Some("main"), false), Some(Revision::Namespace("main".into())));
        // Blank values count as absent, not as a revision named "".
        assert_eq!(choose_revision(Some("  "), Some(" v1.2 "), false), Some(Revision::Namespace("v1.2".into())));
    }

    #[test]
    fn with_neither_there_is_no_revision_rather_than_a_guess() {
        assert_eq!(choose_revision(None, None, false), None);
        assert_eq!(choose_revision(Some(""), Some(""), false), None);
    }

    #[test]
    fn commit_source_names_where_the_revision_came_from() {
        assert_eq!(Revision::Manifest("x".into()).commit_source(), "manifest");
        assert_eq!(Revision::Namespace("x".into()).commit_source(), "namespace_revision");
        assert_eq!(Revision::Override("x".into()).commit_source(), "revision_override");
    }

    #[test]
    #[test]
    fn the_testing_override_swaps_a_recorded_commit_for_the_revision() {
        let commit = "a".repeat(40);
        assert_eq!(
            choose_revision(Some(&commit), Some("main"), true),
            Some(Revision::Override("main".into()))
        );
        // Sent as a ref, resolved by the analyser — never as the old commit.
        assert_eq!(
            Revision::Override("main".into()).commit_and_ref(),
            (None, Some("main".into()))
        );
    }

    #[test]
    fn the_override_without_a_revision_falls_back_to_the_recorded_commit() {
        // Nothing to override with: refusing to analyse would be worse than
        // the normal rule.
        let commit = "a".repeat(40);
        assert_eq!(choose_revision(Some(&commit), None, true), Some(Revision::Manifest(commit.clone())));
        // And with no recorded commit the override changes nothing.
        assert_eq!(choose_revision(None, Some("main"), true), Some(Revision::Namespace("main".into())));
    }

    fn analyser_rejections_surface_their_own_message() {
        assert_eq!(
            analyser_error_message(r#"{"error":"revision nope does not exist"}"#),
            "revision nope does not exist"
        );
        assert_eq!(analyser_error_message("plain text"), "plain text");
    }

    #[test]
    fn backoff_expires_and_is_per_finding() {
        let map = Mutex::new(HashMap::new());
        let a = ("m".to_string(), "f1".to_string());
        let b = ("m".to_string(), "f2".to_string());
        start_backoff(&map, a.clone());
        assert!(is_backing_off(&map, &a));
        assert!(!is_backing_off(&map, &b));
        map.lock().unwrap().insert(a.clone(), Instant::now() - Duration::from_secs(1));
        assert!(!is_backing_off(&map, &a));
    }

    fn view_with(status: &str, report: Option<serde_json::Value>) -> AnalysisView {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "status": status,
            "report": report,
        }))
        .unwrap()
    }

    #[test]
    fn only_a_terminal_analysis_report_is_archived() {
        // A `running` analysis can already carry a partially-filled report;
        // archiving that would freeze an incomplete answer as the permanent
        // record and — because the write coalesces — prevent the finished one
        // from ever replacing it.
        let done = view_with("completed", Some(serde_json::json!({ "priority": "direct_references" })));
        assert!(archivable_report(&done).is_some());

        let failed = view_with("failed", Some(serde_json::json!({ "priority": "inconclusive" })));
        assert!(archivable_report(&failed).is_some());

        for in_flight in ["queued", "running"] {
            let view = view_with(in_flight, Some(serde_json::json!({ "priority": "x" })));
            assert!(archivable_report(&view).is_none(), "archived while {in_flight}");
        }
    }

    #[test]
    fn a_terminal_analysis_with_no_report_archives_nothing() {
        // "Could not fetch the source" fails an analysis before any report
        // exists. There is nothing to store, and storing `null` would look
        // like an archived empty report.
        assert!(archivable_report(&view_with("failed", None)).is_none());
        assert!(archivable_report(&view_with("completed", None)).is_none());
    }

    #[test]
    fn an_unknown_future_status_is_not_treated_as_terminal() {
        // The analyser owns its status vocabulary. A status this build has
        // never heard of must not be assumed finished.
        assert!(archivable_report(&view_with("paused", Some(serde_json::json!({})))).is_none());
    }

    #[test]
    fn priority_is_read_from_the_report_without_mirroring_its_schema() {
        let view: AnalysisView = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "status": "completed",
            "report": { "priority": "direct_references", "anything_else": 1 }
        }))
        .unwrap();
        assert_eq!(report_priority(&view).as_deref(), Some("direct_references"));
    }
}
