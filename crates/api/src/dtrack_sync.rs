use std::sync::Arc;
use std::time::Duration;

use magnolia_db::{Database, NewDtrackFinding};
use magnolia_dtrack::{DtrackClient, DtrackError};
use magnolia_storage::ObjectStore;
use uuid::Uuid;

/// Periodic background sync between Magnolia's archive and dtrack — the
/// first background/periodic task in this codebase, so kept deliberately
/// defensive: every per-item failure is caught and logged, never
/// propagated, since one bad SBOM or a transient dtrack outage must not
/// kill the loop or affect Magnolia's own request handling (same
/// "secondary concern can't block/fail the primary flow" idiom already
/// used for `record_audit` in `upload_sbom`). Push/refresh against dtrack
/// otherwise only ever happen here or in the on-demand `sync_now` (the
/// "force sync" button) — `push_triage_to_dtrack` below is a deliberate,
/// narrow exception: it's called synchronously from `triage_finding`, since
/// a human triage action is rare (not a hot path) and the whole point is
/// dtrack reflecting it immediately rather than waiting for the next
/// periodic pass.
pub async fn run_sync_loop(
    db: Arc<Database>,
    storage: Arc<dyn ObjectStore>,
    client: Arc<DtrackClient>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        push_phase(&db, &storage, &client, None).await;
        refresh_phase(&db, &client, None).await;
    }
}

/// One-shot sync pass for a single tenant, run synchronously from the
/// `POST /api/v1/dtrack/sync` handler (the "force sync now" button) — same
/// push+refresh logic the periodic loop uses, just scoped to one tenant so
/// triggering it can only ever affect that tenant's own manifests, and
/// bounded the same way (one pass' worth of items, not "until done") so a
/// button click can't turn into an unbounded request. Returns
/// (manifests_pushed, projects_refreshed) for the response.
pub async fn sync_now(
    db: &Database,
    storage: &Arc<dyn ObjectStore>,
    client: &DtrackClient,
    tenant_id: Uuid,
) -> (usize, usize) {
    let pushed = push_phase(db, storage, client, Some(tenant_id)).await;
    let refreshed = refresh_phase(db, client, Some(tenant_id)).await;
    (pushed, refreshed)
}

/// Pushes every manifest that doesn't have a dtrack project yet, resolving
/// the resulting project UUID and recording it. Returns how many manifests
/// were successfully pushed and recorded.
async fn push_phase(
    db: &Database,
    storage: &Arc<dyn ObjectStore>,
    client: &DtrackClient,
    tenant_id: Option<Uuid>,
) -> usize {
    let manifests = match db.list_manifests_without_dtrack_project(tenant_id, 50).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "dtrack sync: failed to list manifests needing a project");
            return 0;
        }
    };

    let mut pushed = 0;
    for m in manifests {
        let bom_bytes = match storage.get(&m.sbom_s3_key).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: failed to read SBOM bytes; skipping");
                continue;
            }
        };

        let domain = match db.get_tenant(m.tenant_id).await {
            Ok(Some(t)) => t.domain,
            Ok(None) => {
                tracing::warn!(manifest_hash = %m.manifest_hash, "dtrack sync: manifest's tenant no longer exists; skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: failed to look up tenant domain; skipping");
                continue;
            }
        };

        // One dtrack project per manifest (see DTRACK_PLAN.md's "Project
        // naming" rule) — the hash suffix guarantees uniqueness across
        // tenants/re-uploads sharing a namespace+version, since dtrack has
        // no notion of Magnolia's tenant boundary.
        let project_name = format!("{domain}{}", m.namespace);
        let hash_suffix = &m.manifest_hash[..m.manifest_hash.len().min(12)];
        let project_version = format!("{}-{hash_suffix}", m.version);

        if let Err(e) = client.push_bom(&project_name, &project_version, &bom_bytes).await {
            tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: push_bom failed; will retry next pass");
            if let Err(e2) = db.record_dtrack_push_failure(&m.manifest_hash, &e.to_string()).await {
                tracing::warn!(manifest_hash = %m.manifest_hash, error = %e2, "dtrack sync: failed to record push failure");
            }
            continue;
        }
        if let Err(e) = db.clear_dtrack_push_failure(&m.manifest_hash).await {
            tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: failed to clear push failure");
        }

        match client.lookup_project(&project_name, &project_version).await {
            Ok(Some(uuid)) => {
                if let Err(e) = db.insert_dtrack_project(&m.manifest_hash, uuid).await {
                    tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: failed to record dtrack project");
                } else {
                    pushed += 1;
                }
            }
            Ok(None) => {
                tracing::info!(manifest_hash = %m.manifest_hash, "dtrack sync: project not found yet after push; will retry next pass");
            }
            Err(e) => {
                tracing::warn!(manifest_hash = %m.manifest_hash, error = %e, "dtrack sync: lookup_project failed; will retry next pass");
            }
        }
    }
    pushed
}

/// Refreshes cached findings for every known dtrack project, stalest-first.
/// Returns how many projects were successfully refreshed.
async fn refresh_phase(db: &Database, client: &DtrackClient, tenant_id: Option<Uuid>) -> usize {
    let projects = match db.list_dtrack_projects(tenant_id, 100).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "dtrack sync: failed to list dtrack projects");
            return 0;
        }
    };

    let mut refreshed = 0;
    for p in projects {
        let findings = match client.get_findings(p.dtrack_project_uuid).await {
            Ok(f) => f,
            Err(DtrackError::Status { status: 404, .. }) => {
                tracing::warn!(manifest_hash = %p.manifest_hash, "dtrack sync: project no longer exists in dtrack (404) — clearing stale record so it gets re-pushed fresh");
                if let Err(e) = db.delete_dtrack_project(&p.manifest_hash).await {
                    tracing::warn!(manifest_hash = %p.manifest_hash, error = %e, "dtrack sync: failed to clear stale project record");
                }
                continue;
            }
            Err(e) => {
                tracing::warn!(manifest_hash = %p.manifest_hash, error = %e, "dtrack sync: get_findings failed; will retry next pass");
                continue;
            }
        };

        let new_findings: Vec<NewDtrackFinding> = findings
            .into_iter()
            .map(|f| NewDtrackFinding {
                finding_key: f.finding_key,
                component_name: f.component_name,
                component_version: f.component_version,
                vulnerability_id: f.vulnerability_id,
                severity: f.severity,
                description: f.description,
                analysis_state: f.analysis_state,
                component_uuid: f.component_uuid,
                vulnerability_uuid: f.vulnerability_uuid,
            })
            .collect();

        if let Err(e) = db.replace_dtrack_findings(&p.manifest_hash, &new_findings).await {
            tracing::warn!(manifest_hash = %p.manifest_hash, error = %e, "dtrack sync: failed to store findings");
            continue;
        }
        if let Err(e) = db.touch_dtrack_project_synced(&p.manifest_hash).await {
            tracing::warn!(manifest_hash = %p.manifest_hash, error = %e, "dtrack sync: failed to update last_synced_at");
        }
        refreshed += 1;
    }
    refreshed
}

/// Pushes Magnolia's own VEX-style triage for one finding into dtrack's own
/// analysis record (`PUT /api/v1/analysis`), so dtrack's own view — and
/// anything else reading dtrack directly — reflects Magnolia's judgment
/// instead of staying permanently "not set". Called from `triage_finding`
/// on every save. Best-effort and fully swallowed: by the time this runs,
/// Magnolia's own `dtrack_findings` row has already been committed, so a
/// dtrack outage or a stale/missing project mapping must not fail the
/// caller's triage write — only ever logged.
pub async fn push_triage_to_dtrack(
    db: &Database,
    client: &DtrackClient,
    manifest_hash: &str,
    component_uuid: &str,
    vulnerability_uuid: &str,
    vex_status: &str,
    justification: Option<&str>,
    comment: Option<&str>,
) {
    let project = match db.get_dtrack_project(manifest_hash).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::info!(manifest_hash = %manifest_hash, "dtrack triage push: no dtrack project for this manifest yet; skipping");
            return;
        }
        Err(e) => {
            tracing::warn!(manifest_hash = %manifest_hash, error = %e, "dtrack triage push: failed to look up dtrack project");
            return;
        }
    };

    let (analysis_state, analysis_justification) = map_vex_to_dtrack_analysis(vex_status, justification);

    if let Err(e) = client
        .set_analysis(
            project.dtrack_project_uuid,
            component_uuid,
            vulnerability_uuid,
            analysis_state,
            analysis_justification,
            comment,
        )
        .await
    {
        tracing::warn!(manifest_hash = %manifest_hash, error = %e, "dtrack triage push: set_analysis failed");
    }
}

/// Maps Magnolia's VEX vocabulary onto dtrack's own `AnalysisState`/
/// `AnalysisJustification` enums, which follow CycloneDX's impact-analysis
/// vocabulary — NOT OpenVEX's (see `handlers::VEX_JUSTIFICATIONS`). There is
/// no official one-to-one mapping between the two specs, so this is a
/// best-effort approximation: a couple of OpenVEX justification codes
/// collapse onto the same dtrack code, since dtrack/CycloneDX draws that
/// particular line differently than OpenVEX does.
fn map_vex_to_dtrack_analysis(vex_status: &str, justification: Option<&str>) -> (&'static str, Option<&'static str>) {
    let analysis_state = match vex_status {
        "affected" => "EXPLOITABLE",
        "not_affected" => "NOT_AFFECTED",
        "fixed" => "RESOLVED",
        // "under_investigation", and any future/unrecognized status.
        _ => "IN_TRIAGE",
    };
    let analysis_justification = (vex_status == "not_affected")
        .then(|| justification)
        .flatten()
        .and_then(|j| match j {
            "component_not_present" => Some("CODE_NOT_PRESENT"),
            "vulnerable_code_not_present" => Some("CODE_NOT_PRESENT"),
            "vulnerable_code_not_in_execute_path" => Some("CODE_NOT_REACHABLE"),
            "vulnerable_code_cannot_be_controlled_by_adversary" => Some("REQUIRES_CONFIGURATION"),
            "inline_mitigations_already_exist" => Some("PROTECTED_BY_MITIGATING_CONTROL"),
            _ => None,
        });
    (analysis_state, analysis_justification)
}
