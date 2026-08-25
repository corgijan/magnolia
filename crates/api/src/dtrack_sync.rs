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
/// used for `record_audit` in `upload_sbom`). No synchronous dtrack call is
/// ever made from inside an HTTP handler — this loop is the only
/// always-running caller of `DtrackClient`; `sync_now` below is the other,
/// on-demand one, triggered by the "force sync" button.
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
