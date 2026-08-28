use std::str::FromStr;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use magnolia_audit::{AuditLogEntry, AuditResult};
use magnolia_auth::{generate_server_key, Action, Role};
use magnolia_core::{
    build_envelope, ed25519_public_key_base64, ed25519_public_key_pem, pae, profile_by_id,
    registered_profiles, ComplianceReport as CoreComplianceReport, ConsistencyProof,
    DocumentPredicate, DocumentStatement, InclusionProof, ManifestPredicate, ManifestStatement,
    MerkleTree, SbomFormat, SignedTreeHead, Statement, Subject, DOCUMENT_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE, MANIFEST_PREDICATE_TYPE,
};
use magnolia_db::{DtrackFindingRecord, SbomComponentRow};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::{require, AuthGrant};
use crate::errors::ApiError;
use crate::state::AppState;

pub const MAX_SBOM_BYTES: usize = 10 * 1024 * 1024;

// ---------- DTOs ----------

#[derive(serde::Serialize)]
pub struct TreeHeadJson {
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
    pub frontier: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub signature_verified: bool,
}

#[derive(serde::Serialize)]
pub struct UploadResponse {
    pub sbom_hash: String,
    pub manifest_hash: String,
    pub version: String,
    pub namespace: String,
    pub domain: String,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub leaf_seq_id: i64,
    pub signed_tree_head: TreeHeadJson,
}

#[derive(serde::Serialize)]
pub struct LeafJson {
    pub seq_id: i64,
    pub leaf_index: u64,
    pub tenant_id: Uuid,
    pub namespace: String,
    pub sbom_s3_key: String,
    pub leaf_hash: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub manifest_hash: Option<String>,
    pub revoked: bool,
    pub domain: String,
    pub version: Option<String>,
    pub document_type: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ManifestJson {
    pub manifest_hash: String,
    pub leaf_seq_id: i64,
    pub tenant_id: Uuid,
    pub domain: String,
    pub version: String,
    pub sbom_hash: String,
    pub sbom_format: String,
    pub sbom_s3_key: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    /// Legacy hex-encoded signature — only populated for manifests signed
    /// before the DSSE migration. `None` for anything with `dsse_envelope`.
    pub signature: Option<String>,
    /// The canonical signed artifact for manifests signed after the DSSE
    /// migration. `None` for legacy manifests, which cannot be
    /// retroactively upgraded (no way to produce a new valid signature for
    /// old content without the original signing context).
    pub dsse_envelope: Option<serde_json::Value>,
    pub document_type: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub sbom_hex: String,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    /// One report per compliance profile enabled for this tenant (empty
    /// when none are enabled, or when the enabled ones don't apply to this
    /// upload's format — e.g. a generic `document`).
    pub compliance: Vec<ComplianceReportJson>,
    pub vulnerability_findings: Vec<DtrackFindingJson>,
    /// Set once dtrack has actually refreshed this manifest's findings at
    /// least once — lets the frontend tell "not synced yet" apart from
    /// "synced, and genuinely has zero findings" instead of reading an
    /// empty `vulnerability_findings` as always meaning the former.
    pub dtrack_synced_at: Option<DateTime<Utc>>,
    /// Set when the most recent attempt to push this manifest to dtrack
    /// failed — e.g. dtrack rejected the BOM as schema-invalid, which will
    /// never succeed on retry without different content. `None` once a
    /// later push succeeds (see `push_phase`'s `clear_dtrack_push_failure`).
    pub dtrack_push_error: Option<String>,
    /// Components matched against OSV's `MAL-`-prefixed malicious-package
    /// advisories, checked once at upload time (see
    /// `malicious_check::check_and_store_malicious_components`) — empty for
    /// almost every manifest. Informational only, same tier as
    /// `vulnerability_findings`: never blocks an upload.
    pub malicious_components: Vec<MaliciousComponentJson>,
    /// Cached deps.dev/OpenSSF Scorecard results for this manifest's
    /// components — populated in the background (see `reputation_sync.rs`),
    /// so a freshly-uploaded manifest's components simply won't appear here
    /// yet, same "not checked yet, not an error" convention as
    /// `dtrack_synced_at: null`.
    pub component_reputation: Vec<ComponentReputationJson>,
}

#[derive(serde::Serialize)]
pub struct MaliciousComponentJson {
    pub component_name: String,
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub osv_id: String,
    pub summary: Option<String>,
    pub detected_at: DateTime<Utc>,
}

impl From<magnolia_db::MaliciousFindingRecord> for MaliciousComponentJson {
    fn from(r: magnolia_db::MaliciousFindingRecord) -> Self {
        Self {
            component_name: r.component_name,
            component_version: r.component_version,
            purl: r.purl,
            osv_id: r.osv_id,
            summary: r.summary,
            detected_at: r.detected_at,
        }
    }
}

/// One component's cached deps.dev/OpenSSF Scorecard result. Only present
/// for components with a usable purl whose (ecosystem, registry_name) the
/// reputation background job has actually reached — see
/// `reputation_sync.rs`. `scorecard_score`/`project_repo` are `None` either
/// because the check hasn't run yet (`fetch_error` also `None`) or because
/// it ran and found genuinely nothing (also `fetch_error: None` — deps.dev
/// simply has no scorecard for this package) or failed (`fetch_error: Some`).
#[derive(serde::Serialize)]
pub struct ComponentReputationJson {
    pub component_name: String,
    pub component_version: Option<String>,
    pub scorecard_score: Option<f32>,
    /// Red/yellow/green classification of `scorecard_score` (see
    /// `reputation_bucket.rs` for the thresholds) — `None` whenever
    /// `scorecard_score` is `None`, computed here rather than left to the
    /// frontend so there is exactly one place the red/yellow/green cutoffs
    /// are defined.
    pub bucket: Option<crate::reputation_bucket::ReputationBucket>,
    pub project_repo: Option<String>,
    /// `None` means the reputation background job hasn't reached this
    /// component yet — the frontend renders this as a "pending" status, not
    /// an error or a zero score.
    pub checked_at: Option<DateTime<Utc>>,
    pub fetch_error: Option<String>,
}

impl From<magnolia_db::ComponentReputationRecord> for ComponentReputationJson {
    fn from(r: magnolia_db::ComponentReputationRecord) -> Self {
        Self {
            component_name: r.component_name,
            component_version: r.component_version,
            bucket: r.scorecard_score.map(crate::reputation_bucket::bucket_for_score),
            scorecard_score: r.scorecard_score,
            project_repo: r.project_repo,
            checked_at: r.checked_at,
            fetch_error: r.fetch_error,
        }
    }
}

#[derive(serde::Serialize)]
pub struct ComplianceProfileJson {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(serde::Serialize)]
pub struct ComplianceSettingJson {
    pub profile_id: String,
    pub profile_name: String,
    pub description: String,
    pub enabled: bool,
    pub enforce_level: String,
}

#[derive(serde::Deserialize)]
pub struct SetComplianceSettingRequest {
    pub profile_id: String,
    pub enabled: bool,
    pub enforce_level: String,
}

#[derive(serde::Serialize, Clone)]
pub struct ComplianceReportJson {
    pub profile_id: String,
    pub profile_name: String,
    pub applicable: bool,
    pub meets_minimum: bool,
    pub minimum_issues: Vec<String>,
    pub fully_compliant: bool,
    pub missing_fields: Vec<String>,
}

impl From<CoreComplianceReport> for ComplianceReportJson {
    fn from(r: CoreComplianceReport) -> Self {
        Self {
            profile_id: r.profile_id,
            profile_name: r.profile_name,
            applicable: r.applicable,
            meets_minimum: r.meets_minimum,
            minimum_issues: r.minimum_issues,
            fully_compliant: r.fully_compliant,
            missing_fields: r.missing_fields,
        }
    }
}

#[derive(serde::Serialize)]
pub struct DtrackFindingJson {
    pub finding_key: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    /// dtrack's own generic analysis state, synced verbatim — independent
    /// of `vex_status` below (see `dtrack_findings`' migration comment for
    /// why the two can legitimately disagree).
    pub analysis_state: Option<String>,
    pub vex_status: Option<String>,
    pub vex_justification: Option<String>,
    pub vex_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
}

impl From<DtrackFindingRecord> for DtrackFindingJson {
    fn from(r: DtrackFindingRecord) -> Self {
        Self {
            finding_key: r.finding_key,
            component_name: r.component_name,
            component_version: r.component_version,
            vulnerability_id: r.vulnerability_id,
            severity: r.severity,
            description: r.description,
            analysis_state: r.analysis_state,
            vex_status: r.vex_status,
            vex_justification: r.vex_justification,
            vex_comment: r.vex_comment,
            triaged_by: r.triaged_by,
            triaged_at: r.triaged_at,
        }
    }
}

#[derive(serde::Serialize)]
pub struct FindingWithContextJson {
    pub manifest_hash: String,
    pub finding_key: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    pub analysis_state: Option<String>,
    pub vex_status: Option<String>,
    pub vex_justification: Option<String>,
    pub vex_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<DateTime<Utc>>,
    pub domain: String,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
    pub comment_count: i64,
}

#[derive(serde::Deserialize)]
pub struct ListFindingsQuery {
    pub severity: Option<String>,
    /// Narrows to one manifest's findings — set when arriving from that
    /// manifest's own detail view (see `SbomDetailPanel`'s findings
    /// summary), otherwise every finding in scope is returned.
    pub manifest_hash: Option<String>,
    /// Exact-or-prefix match against the owning manifest's namespace, same
    /// semantics as `search_sbom_components`'s namespace filter.
    pub namespace: Option<String>,
    /// Exact match against the owning manifest's version.
    pub release_version: Option<String>,
    /// One of the four VEX statuses, or "untriaged" for findings with no
    /// vex_status set yet.
    pub vex_status: Option<String>,
    /// When true, only findings on each namespace's currently-running
    /// (latest non-revoked) manifest are returned — narrows triage to
    /// what's actually deployed, same "current" definition used by
    /// `GET /api/v1/manifests/current`.
    #[serde(default)]
    pub current_only: bool,
    /// When true, only the single newest non-revoked manifest per
    /// namespace is returned — an unconditional guarantee, independent of
    /// the admin-curated "currently running" namespace visibility that
    /// `current_only` also respects.
    #[serde(default)]
    pub hide_stale: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub tenant_id: Option<Uuid>,
}

/// Every cached finding across the tenant's archive (within the caller's
/// namespace scope), for the standalone Findings tab — `Action::Read`, same
/// as browsing the archive itself. DB read only, same as `manifest()`'s own
/// findings — never a live dtrack call in the request path.
pub async fn list_findings(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<ListFindingsQuery>,
) -> Result<Json<Vec<FindingWithContextJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let domain = if cross_tenant {
        state.db.get_tenant(tenant_id).await.map_err(db_err)?.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let limit = query.limit.clamp(1, 500);
    let offset = query.offset.max(0);
    let severity_filter = query.severity.as_deref().filter(|s| !s.is_empty());
    let namespace_filter = query.namespace.as_deref().filter(|s| !s.is_empty());
    let release_version_filter = query.release_version.as_deref().filter(|s| !s.is_empty());
    let vex_status_filter = query.vex_status.as_deref().filter(|s| !s.is_empty());
    if let Some(v) = vex_status_filter {
        if !["untriaged", "affected", "not_affected", "fixed", "under_investigation"].contains(&v) {
            return Err(ApiError::BadRequest("invalid vex_status filter".to_string()));
        }
    }

    let rows = state
        .db
        .list_findings_for_tenant(
            tenant_id,
            scope,
            severity_filter,
            query.manifest_hash.as_deref(),
            namespace_filter,
            release_version_filter,
            vex_status_filter,
            query.current_only,
            query.hide_stale,
            limit,
            offset,
        )
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| FindingWithContextJson {
                manifest_hash: r.manifest_hash,
                finding_key: r.finding_key,
                component_name: r.component_name,
                component_version: r.component_version,
                vulnerability_id: r.vulnerability_id,
                severity: r.severity,
                description: r.description,
                analysis_state: r.analysis_state,
                vex_status: r.vex_status,
                vex_justification: r.vex_justification,
                vex_comment: r.vex_comment,
                triaged_by: r.triaged_by,
                triaged_at: r.triaged_at,
                domain: domain.clone(),
                namespace: r.namespace,
                release_version: r.release_version,
                revoked: r.revoked,
                comment_count: r.comment_count,
            })
            .collect(),
    ))
}

#[derive(serde::Serialize)]
pub struct ComponentSearchResultJson {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub is_primary: bool,
    pub manifest_hash: String,
    pub domain: String,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
    pub document_type: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ReindexResponse {
    pub manifests_indexed: usize,
    pub components_indexed: usize,
}

#[derive(serde::Serialize)]
pub struct CurrentManifestJson {
    pub namespace: String,
    pub domain: String,
    pub version: String,
    pub manifest_hash: String,
    pub sbom_hash: String,
    pub sbom_format: String,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Deserialize)]
pub struct CreateKeyRequest {
    #[serde(default = "default_namespace_scope")]
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<String>,
    /// super_admin only: create this key for another tenant instead of
    /// your own.
    pub tenant_id: Option<Uuid>,
}

fn default_namespace_scope() -> String {
    "/".to_string()
}

#[derive(serde::Serialize)]
pub struct CreateKeyResponse {
    pub key: String,
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(serde::Deserialize)]
pub struct CreateTenantRequest {
    pub domain: String,
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct TenantJson {
    pub id: Uuid,
    pub domain: String,
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub is_platform: bool,
}

#[derive(serde::Serialize)]
pub struct CreateTenantResponse {
    pub tenant: TenantJson,
    /// The tenant's first key (domain_admin, unrestricted namespace scope),
    /// shown once so the caller can bootstrap the rest of the tenant.
    pub initial_key: CreateKeyResponse,
}

#[derive(serde::Serialize)]
pub struct KeyJson {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Serialize)]
pub struct AuditJson {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(serde::Deserialize)]
pub struct LeavesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct SearchComponentsQuery {
    pub name: Option<String>,
    pub version: Option<String>,
    pub namespace: Option<String>,
    pub purl: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub tenant_id: Option<Uuid>,
}

fn default_limit() -> i64 {
    50
}

fn default_audit_limit() -> i64 {
    100
}

// ---------- helpers ----------

/// Query param accepted by every tenant-scoped read/manage endpoint: lets a
/// super_admin act on a tenant other than its own ("see and manage all
/// other tenants"). Anyone else supplying it is rejected outright.
#[derive(serde::Deserialize)]
pub struct TenantOverrideQuery {
    pub tenant_id: Option<Uuid>,
}

/// Resolves which tenant a request should act on: the grant's own tenant by
/// default, or an explicit override — only ever honored for a super_admin
/// key belonging to the platform/bootstrap tenant (`is_platform_tenant`).
/// A super_admin key self-minted by some other tenant's domain_admin does
/// NOT get this reach, even though the role string is the same — otherwise
/// any tenant could grant itself platform-wide access to every other
/// tenant just by creating a key with role="super_admin" for itself.
/// The second element is `true` when acting on a tenant other than the
/// grant's own, in which case the grant's `namespace_scope` does not apply
/// (there's no meaningful "my namespace scope" in someone else's tenant —
/// a cross-tenant super_admin sees/manages that tenant in full).
fn effective_tenant(grant: &AuthGrant, requested: Option<Uuid>) -> Result<(Uuid, bool), ApiError> {
    match requested {
        Some(id) if grant.role == Role::SuperAdmin && grant.is_platform_tenant => {
            Ok((id, id != grant.tenant_id))
        }
        Some(_) => Err(ApiError::Forbidden(
            "only the platform super_admin can act on another tenant".to_string(),
        )),
        None => Ok((grant.tenant_id, false)),
    }
}

fn db_err(e: impl std::fmt::Display) -> ApiError {
    ApiError::InternalError(e.to_string())
}

/// `created_by`/principal is `apikey:<full key_id uuid>` — the key_id, not
/// the secret, but still a stable per-key identifier we don't want handed
/// out in full to anyone with read access to a namespace. Only the last 5
/// characters ever leave the server; the rest is truncated here, not just
/// hidden client-side, so the full value never reaches the browser at all.
pub(crate) fn mask_principal(principal: &str) -> String {
    let tail_len = 5.min(principal.len());
    format!("…{}", &principal[principal.len() - tail_len..])
}

fn normalize_namespace(raw: &str) -> Result<String, ApiError> {
    let mut ns = raw.trim().to_lowercase();
    if ns.contains("..") {
        return Err(ApiError::BadRequest(
            "namespace must not contain '..'".to_string(),
        ));
    }
    if !ns.starts_with('/') {
        ns.insert(0, '/');
    }
    while ns.len() > 1 && ns.ends_with('/') {
        ns.pop();
    }
    let cleaned: Vec<&str> = ns.split("//").collect();
    ns = cleaned.join("/");
    if ns.is_empty() {
        ns = "/".to_string();
    }
    Ok(ns)
}

fn normalize_domain(raw: &str) -> Result<String, ApiError> {
    let domain = raw.trim().to_lowercase();
    if domain.is_empty() {
        return Err(ApiError::BadRequest("domain must not be empty".to_string()));
    }
    Ok(domain)
}

/// Validates the uploaded bytes are a genuinely well-formed CycloneDX or
/// SPDX document (real JSON Schema validation against the official spec,
/// not just "valid JSON with the right marker field") — see
/// `magnolia_core::validate_sbom_schema`.
fn validate_sbom_content(data: &[u8], format: &str) -> Result<(), ApiError> {
    let sbom_format = match format {
        "cyclonedx" => SbomFormat::CycloneDx,
        "spdx" => SbomFormat::Spdx,
        other => {
            return Err(ApiError::BadRequest(format!(
                "unsupported format: {} (use cyclonedx or spdx)",
                other
            )))
        }
    };
    magnolia_core::validate_sbom_schema(data, sbom_format).map_err(|e| ApiError::BadRequest(e.to_string()))
}

/// Rejects an upload at the door when a compliance profile is enforced for
/// this tenant and the SBOM doesn't meet the configured bar. Runs after
/// schema validation (so `check()` can assume well-formed JSON) and after
/// the RBAC upload check (so an unauthorized caller learns nothing about
/// tenant policy), but before any side effect — storage write, Merkle
/// mutation, DB insert — so a rejection here leaves nothing to clean up.
async fn enforce_compliance(state: &AppState, tenant_id: Uuid, format: &str, sbom_bytes: &[u8]) -> Result<(), ApiError> {
    for profile in registered_profiles() {
        let Some(setting) = state.db.get_compliance_setting(tenant_id, profile.id()).await.map_err(db_err)? else {
            continue;
        };
        if !setting.enabled || setting.enforce_level == "off" {
            continue;
        }
        let report = profile.check(format, sbom_bytes);
        if !report.applicable {
            continue;
        }
        if !report.meets_minimum {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} minimum compliance: {}",
                profile.name(),
                report.minimum_issues.join("; ")
            )));
        }
        if setting.enforce_level == "full" && !report.fully_compliant {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} full compliance, missing: {}",
                profile.name(),
                report.missing_fields.join("; ")
            )));
        }
    }
    Ok(())
}

/// Extracts and indexes one manifest's components into the reverse-search
/// table — shared by the upload-time hook and the one-time reindex
/// endpoint, so there's exactly one implementation of "extract and index
/// one manifest." Returns how many components were indexed (0 for formats
/// with nothing to extract, e.g. an SBOM with no components at all).
async fn index_manifest_components(
    state: &AppState,
    tenant_id: Uuid,
    manifest_hash: &str,
    sbom_format: &str,
    sbom_bytes: &[u8],
) -> Result<usize, ApiError> {
    let extracted = magnolia_core::extract_components(sbom_format, sbom_bytes);
    if extracted.is_empty() {
        return Ok(0);
    }
    let components: Vec<magnolia_db::NewSbomComponent> = extracted
        .into_iter()
        .map(|c| {
            let (ecosystem, registry_name) = c
                .purl
                .as_deref()
                .and_then(magnolia_core::purl_to_depsdev_package)
                .map(|(eco, name)| (Some(eco.to_string()), Some(name)))
                .unwrap_or((None, None));
            magnolia_db::NewSbomComponent {
                name: c.name,
                version: c.version,
                purl: c.purl,
                cpe: c.cpe,
                is_primary: c.is_primary,
                ecosystem,
                registry_name,
            }
        })
        .collect();
    let count = components.len();
    state
        .db
        .insert_sbom_components(tenant_id, manifest_hash, &components)
        .await
        .map_err(db_err)?;

    // Best-effort, never fails the indexing step itself (see
    // `check_and_store_malicious_components`'s doc comment) — `None` when
    // `DISABLE_MALICIOUS_PACKAGE_CHECK` is set for this deployment.
    if let Some(osv) = &state.osv {
        crate::malicious_check::check_and_store_malicious_components(&state.db, osv, manifest_hash, &components)
            .await;
    }

    Ok(count)
}

async fn record_audit(
    state: &AppState,
    grant: &AuthGrant,
    action: &str,
    resource: &str,
    success: bool,
    reason: Option<String>,
) {
    let entry = if success {
        AuditLogEntry::success(
            grant.tenant_id,
            grant.principal(),
            action.to_string(),
            resource.to_string(),
            reason,
        )
    } else {
        AuditLogEntry::failure(
            grant.tenant_id,
            grant.principal(),
            action.to_string(),
            resource.to_string(),
            reason.unwrap_or_default(),
        )
    };
    let result_str = match entry.result {
        AuditResult::Success => "success",
        AuditResult::Failure => "failure",
    };
    state.audit.log(entry.clone());
    if let Err(e) = state
        .db
        .insert_audit_log(
            entry.id,
            entry.tenant_id,
            &entry.principal,
            &entry.action,
            &entry.resource,
            result_str,
            entry.reason.as_deref(),
        )
        .await
    {
        tracing::warn!(error = %e, "failed to persist audit log entry");
    }
}

fn sth_to_json(sth: &SignedTreeHead, verified: bool) -> TreeHeadJson {
    TreeHeadJson {
        tree_size: sth.tree_size,
        root_hash: hex::encode(&sth.root_hash),
        signature: hex::encode(&sth.signature),
        frontier: sth.frontier.iter().map(|h| hex::encode(h)).collect(),
        created_at: sth.created_at,
        signature_verified: verified,
    }
}

// ---------- handlers ----------

pub async fn health() -> StatusCode {
    StatusCode::OK
}

/// Served at `/install.sh` so `curl -fsSL <tenant_url>/install.sh | bash -s
/// -- --tenant-domain=...` works -- see scripts/magnolia-upload.sh's own
/// header comment for the script's usage. `include_str!` embeds the file at
/// compile time (not read from disk per-request), so this is always
/// byte-for-byte the same script checked into the repo -- no separate copy
/// to keep in sync, and no runtime dependency on `scripts/` existing next
/// to the deployed binary.
const MAGNOLIA_UPLOAD_SCRIPT: &str = include_str!("../../../scripts/magnolia-upload.sh");

pub async fn install_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        MAGNOLIA_UPLOAD_SCRIPT,
    )
}

#[derive(serde::Serialize)]
pub struct WhoAmIJson {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: String,
    /// Whether this key's tenant is the platform tenant — only then can it
    /// pass `?tenant_id=` to act on another tenant. The UI uses this to
    /// decide whether to offer that at all (the backend enforces it
    /// independently either way).
    pub is_platform_tenant: bool,
}

/// Confirms the caller's key is authenticated (not revoked/expired,
/// verified against its hash) without requiring any specific RBAC action —
/// every valid key can see its own identity. Used by the frontend to gate
/// access to the rest of the UI.
pub async fn whoami(grant: AuthGrant) -> Json<WhoAmIJson> {
    Json(WhoAmIJson {
        key_id: grant.key_id,
        tenant_id: grant.tenant_id,
        domain: grant.domain,
        namespace_scope: grant.namespace_scope,
        role: grant.role.to_string(),
        is_platform_tenant: grant.is_platform_tenant,
    })
}

#[derive(serde::Serialize)]
pub struct ConfigJson {
    pub storage_backend: String,
    pub signer_backend: String,
    pub dev_mode: bool,
    pub dtrack_enabled: bool,
    /// Present only when `dtrack_enabled` — lets the UI say "check back in
    /// about N minutes" instead of a made-up number.
    pub dtrack_sync_interval_secs: Option<u64>,
    pub reputation_enabled: bool,
}

/// Server-operational info, not tenant data — safe for any authenticated
/// key to see (no RBAC action required, same as `whoami`). Deliberately
/// excludes anything sensitive like file paths or connection strings;
/// exists so the UI can warn when running against a non-durable dev setup
/// (e.g. in-memory storage) rather than a silent trap.
pub async fn config(State(state): State<AppState>, _grant: AuthGrant) -> Json<ConfigJson> {
    Json(ConfigJson {
        storage_backend: state.storage_backend.to_string(),
        signer_backend: "local_file".to_string(),
        dev_mode: state.dev_mode,
        dtrack_enabled: state.dtrack.is_some(),
        dtrack_sync_interval_secs: state.dtrack.is_some().then_some(state.dtrack_sync_interval_secs),
        reputation_enabled: state.depsdev.is_some(),
    })
}

#[derive(serde::Serialize)]
pub struct DtrackSyncSettingJson {
    pub disabled: bool,
}

/// This tenant's opt-out of the deployment-wide dtrack sync — distinct from
/// `ConfigJson.dtrack_enabled`, which is deployment-wide and read-only here.
/// `Action::Read`, same as viewing any other tenant-wide setting (e.g.
/// hidden namespaces).
pub async fn dtrack_sync_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<DtrackSyncSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(DtrackSyncSettingJson { disabled: tenant.dtrack_sync_disabled }))
}

#[derive(serde::Deserialize)]
pub struct SetDtrackSyncSettingRequest {
    pub disabled: bool,
}

/// Toggles this tenant's opt-out of the deployment-wide dtrack sync — the
/// sync loop's push/refresh phases skip a tenant with this set, but nothing
/// already cached in `dtrack_findings` is touched (see the
/// `dtrack_sync_disabled` migration comment). `Action::ManageSettings`,
/// same tenant-wide-setting gate as `set_namespace_hidden`/compliance
/// enforcement — a plain `auditor` may view this but not change it.
pub async fn set_dtrack_sync_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetDtrackSyncSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_dtrack_sync_disabled(tenant_id, body.disabled).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "dtrack_sync_setting",
        &tenant_id.to_string(),
        true,
        Some(format!("disabled={}", body.disabled)),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct ReputationTenantSettingJson {
    pub disabled: bool,
}

/// This tenant's opt-out of the "Package reputation" panel appearing on its
/// own SBOM detail views — distinct from `ConfigJson.reputation_enabled`,
/// which is deployment-wide and read-only here. `Action::Read`, same as
/// `dtrack_sync_setting`.
pub async fn reputation_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ReputationTenantSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(ReputationTenantSettingJson { disabled: tenant.reputation_disabled }))
}

#[derive(serde::Deserialize)]
pub struct SetReputationTenantSettingRequest {
    pub disabled: bool,
}

/// Toggles this tenant's opt-out of the reputation panel — unlike
/// `set_dtrack_sync_setting`, this has no effect on the background job
/// itself (see the `reputation_disabled` migration comment), it only
/// controls display. `Action::ManageSettings`, same gate as
/// `set_dtrack_sync_setting`.
pub async fn set_reputation_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetReputationTenantSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_reputation_disabled(tenant_id, body.disabled).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "reputation_tenant_setting",
        &tenant_id.to_string(),
        true,
        Some(format!("disabled={}", body.disabled)),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct SemverSettingJson {
    pub required: bool,
}

/// This tenant's requirement that `upload_sbom`'s `version` field be
/// SemVer 2.0.0-compliant -- on by default. Same read/write split as `dtrack_sync_setting`:
/// any valid key can view it, only `Action::ManageSettings` can change it.
pub async fn semver_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<SemverSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(SemverSettingJson { required: tenant.require_semver_version }))
}

#[derive(serde::Deserialize)]
pub struct SetSemverSettingRequest {
    pub required: bool,
}

/// Toggles this tenant's SemVer enforcement for future uploads —
/// `Action::ManageSettings`, same tenant-wide-setting gate as
/// `set_dtrack_sync_setting`. Does not retroactively touch manifests already
/// uploaded with a non-SemVer version.
pub async fn set_semver_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetSemverSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_require_semver_version(tenant_id, body.required).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "semver_setting",
        &tenant_id.to_string(),
        true,
        Some(format!("required={}", body.required)),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct NamespaceRegistrationSettingJson {
    pub required: bool,
}

/// This tenant's requirement that `upload_sbom`'s target namespace already
/// exist in `registered_namespaces`. Same read/write split as
/// `semver_setting`.
pub async fn namespace_registration_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<NamespaceRegistrationSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(NamespaceRegistrationSettingJson { required: tenant.require_namespace_registration }))
}

#[derive(serde::Deserialize)]
pub struct SetNamespaceRegistrationSettingRequest {
    pub required: bool,
}

/// Toggles this tenant's namespace-registration enforcement for future
/// uploads — `Action::ManageSettings`, same gate as `set_semver_setting`.
/// Does not retroactively touch manifests already uploaded to an
/// unregistered namespace.
pub async fn set_namespace_registration_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetNamespaceRegistrationSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_require_namespace_registration(tenant_id, body.required).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "namespace_registration_setting",
        &tenant_id.to_string(),
        true,
        Some(format!("required={}", body.required)),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct RegisteredNamespaceJson {
    pub namespace: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl From<magnolia_db::RegisteredNamespaceRecord> for RegisteredNamespaceJson {
    fn from(r: magnolia_db::RegisteredNamespaceRecord) -> Self {
        Self { namespace: r.namespace, created_by: r.created_by, created_at: r.created_at }
    }
}

/// Every namespace explicitly registered for this tenant, within namespace
/// scope — `Action::Read`, same as `list_hidden_namespaces`.
pub async fn list_registered_namespaces(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<RegisteredNamespaceJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let rows = state.db.list_registered_namespaces(tenant_id, scope).await.map_err(db_err)?;
    Ok(Json(rows.into_iter().map(RegisteredNamespaceJson::from).collect()))
}

#[derive(serde::Deserialize)]
pub struct CreateNamespaceRequest {
    pub namespace: String,
}

/// Registers a namespace so it can be required to exist before an upload
/// (see `require_namespace_registration`). `Action::ManageSettings` — an
/// admin-only action, unlike browsing the archive itself, matching
/// `set_namespace_hidden`'s gate. Idempotent: registering an
/// already-registered namespace succeeds without error (still 204, no way
/// to distinguish "created" from "already existed" in the response — there's
/// nothing actionable a caller would do differently either way).
pub async fn create_namespace(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<CreateNamespaceRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let namespace = normalize_namespace(&body.namespace)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden("namespace out of scope".to_string()));
    }

    state.db.create_namespace(tenant_id, &namespace, &grant.principal()).await.map_err(db_err)?;

    let _ = record_audit(&state, &grant, "namespace_create", &namespace, true, None).await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct SigningKeyJson {
    pub algorithm: String,
    pub keyid: String,
    pub public_key_base64: String,
    pub public_key_pem: String,
}

/// Exposes the signing public key so DSSE-signed manifests can be verified
/// by third-party tooling (`cosign verify-blob-attestation`, `openssl
/// pkeyutl -verify -rawin`, etc.) without trusting Magnolia's own
/// verification code. Same auth tier as `config`/`whoami`: any valid key,
/// no RBAC action — server-operational material, not tenant data.
pub async fn signing_key(
    State(state): State<AppState>,
    _grant: AuthGrant,
) -> Result<Json<SigningKeyJson>, ApiError> {
    let raw = state
        .signer
        .public_key()
        .await
        .map_err(|e| ApiError::InternalError(format!("public key lookup failed: {}", e)))?;
    Ok(Json(SigningKeyJson {
        algorithm: "ed25519".to_string(),
        keyid: hex::encode(Sha256::digest(&raw)),
        public_key_base64: ed25519_public_key_base64(&raw),
        public_key_pem: ed25519_public_key_pem(&raw).map_err(|e| ApiError::InternalError(e.to_string()))?,
    }))
}

/// Turns a raw `multer`/axum multipart error into a descriptive `ApiError`,
/// preserving the underlying reason (e.g. "stream size exceeded" when a
/// field trips `DefaultBodyLimit`) instead of a generic message, and mapping
/// to 413 rather than 400 when that's what actually happened -- so clients
/// get "payload too large" instead of a misleading "invalid sbom_file
/// field" that looks like a malformed-request bug.
fn multipart_err(context: &str, e: axum::extract::multipart::MultipartError) -> ApiError {
    let detail = format!("{context}: {}", e.body_text());
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge(detail)
    } else {
        ApiError::BadRequest(detail)
    }
}

pub async fn upload_sbom(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, ApiError> {
    let field = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err("invalid multipart body", e))?
        .ok_or_else(|| ApiError::BadRequest("missing sbom_file field".to_string()))?;
    let _file_name = field.file_name().map(|s| s.to_string());
    let sbom_bytes = field
        .bytes()
        .await
        .map_err(|e| multipart_err("invalid sbom_file field", e))?
        .to_vec();

    let mut format = "cyclonedx".to_string();
    let mut namespace = "/".to_string();
    let mut version = String::new();
    let mut document_type = String::new();
    while let Some(next) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err("invalid multipart body", e))?
    {
        match next.name() {
            Some("format") => format = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid format field", e))?
                .to_lowercase(),
            Some("namespace") => namespace = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid namespace field", e))?
                .to_string(),
            Some("version") => version = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid version field", e))?
                .trim()
                .to_string(),
            Some("document_type") => document_type = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid document_type field", e))?
                .trim()
                .to_string(),
            _ => {}
        }
    }

    let namespace = normalize_namespace(&namespace)?;
    if version.is_empty() {
        return Err(ApiError::BadRequest("version is required".to_string()));
    }

    if sbom_bytes.is_empty() {
        return Err(ApiError::BadRequest("sbom_file is empty".to_string()));
    }
    if sbom_bytes.len() > MAX_SBOM_BYTES {
        return Err(ApiError::BadRequest(
            "sbom_file exceeds 10 MiB limit".to_string(),
        ));
    }
    if !matches!(format.as_str(), "cyclonedx" | "spdx" | "document") {
        return Err(ApiError::BadRequest(format!(
            "unsupported format: {} (use cyclonedx, spdx, or document)",
            format
        )));
    }
    if format == "document" && document_type.is_empty() {
        return Err(ApiError::BadRequest(
            "document_type is required when format=document".to_string(),
        ));
    }
    if format != "document" {
        validate_sbom_content(&sbom_bytes, &format)?;
    }

    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    // Cross-tenant uploads are only reachable at all if `effective_tenant`
    // already proved this is the platform super_admin — that implies full
    // access to the target tenant, so the grant's own namespace_scope
    // (which describes ITS tenant, not the target's) doesn't apply. Normal
    // same-tenant uploads still go through the regular RBAC/scope check.
    if !cross_tenant {
        if let Err(e) = require(&grant, Action::Upload, &namespace) {
            let _ = record_audit(
                &state,
                &grant,
                "upload",
                &format!("{}:{}", grant.domain, namespace),
                false,
                Some(e.to_string()),
            )
            .await;
            return Err(e);
        }
    }

    if format != "document" {
        enforce_compliance(&state, tenant_id, &format, &sbom_bytes).await?;
    }

    let tenant_record = state
        .db
        .get_tenant(tenant_id)
        .await
        .map_err(db_err)?
        .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?;

    if tenant_record.require_semver_version && semver::Version::parse(&version).is_err() {
        return Err(ApiError::BadRequest(format!(
            "version must be SemVer 2.0.0 compliant (e.g. 1.2.3, 1.2.3-rc.1): {}",
            version
        )));
    }

    if tenant_record.require_namespace_registration
        && !state.db.namespace_is_registered(tenant_id, &namespace).await.map_err(db_err)?
    {
        return Err(ApiError::BadRequest(format!(
            "namespace '{namespace}' has not been registered for this tenant; create it first (see Settings)"
        )));
    }

    let target_tenant = if cross_tenant { Some(tenant_record) } else { None };

    // The platform tenant exists to hold the bootstrap/admin key that
    // manages every other tenant — it's not a product tenant, and letting
    // real SBOM data accumulate there defeats the "keep it clean and
    // administrative only" separation the whole multi-tenancy model relies
    // on. Blocked unconditionally, even for the platform super_admin.
    let is_platform_target = if cross_tenant {
        target_tenant.as_ref().map(|t| t.is_platform).unwrap_or(false)
    } else {
        grant.is_platform_tenant
    };
    if is_platform_target {
        return Err(ApiError::BadRequest(
            "uploads are not allowed to the platform tenant".to_string(),
        ));
    }

    let domain = if cross_tenant {
        target_tenant.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let sbom_hash = hex::encode(Sha256::digest(&sbom_bytes));
    let s3_key = format!("tenants/{}/sboms/{}.sbom", tenant_id, sbom_hash);

    state
        .storage
        .put(&s3_key, &sbom_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage put failed: {}", e)))?;

    let (leaf_hash, tree_size, tenant_leaf_index, sth) = {
        let mut trees = state.trees.lock().await;
        let tree = trees.entry(tenant_id).or_insert_with(MerkleTree::new);
        let leaf_hash = tree.add_leaf(&sbom_bytes);
        let tree_size = tree.tree_size();
        let mut sth = SignedTreeHead::new(
            tree_size,
            tree.root_hash().to_vec(),
            tree.frontier_hashes(),
            Vec::new(),
        );
        let signature = state
            .signer
            .sign(&sth.signing_payload())
            .await
            .map_err(|e| ApiError::InternalError(format!("signing failed: {}", e)))?;
        sth.signature = signature;
        (leaf_hash, tree_size, (tree_size - 1) as i64, sth)
    };

    let leaf_seq_id = state
        .db
        .insert_merkle_leaf(
            tenant_id,
            tenant_leaf_index,
            &namespace,
            &s3_key,
            &leaf_hash,
            "locked",
        )
        .await
        .map_err(db_err)?;

    state
        .db
        .insert_signed_tree_head(
            tenant_id,
            tree_size as i64,
            &sth.root_hash,
            &sth.signature,
            &sth.frontier,
        )
        .await
        .map_err(db_err)?;

    let previous = state.db.latest_manifest(tenant_id).await.map_err(db_err)?;
    let previous_manifest_hash = previous.as_ref().map(|m| m.manifest_hash.clone());

    let manifest_created_at = Utc::now();

    // The in-toto Statement's subject digest is the SAME sbom_hash already
    // fed to tree.add_leaf() above — this is what makes DSSE verification
    // also a structural binding check between "this metadata" and "this
    // exact SBOM content", not just a signature over arbitrary bytes.
    //
    // Documents reuse the exact same Statement/PAE/sign/envelope pipeline
    // as SBOM manifests, just with a different predicate shape and type —
    // everything from here down operates only on `statement_bytes`.
    let document_type_opt = if format == "document" {
        Some(document_type.as_str())
    } else {
        None
    };
    let statement_bytes = if let Some(document_type) = document_type_opt {
        let statement: DocumentStatement = Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: format!("{}{}@{}", domain, namespace, version),
                digest: [("sha256".to_string(), sbom_hash.clone())].into_iter().collect(),
            }],
            predicate_type: DOCUMENT_PREDICATE_TYPE.to_string(),
            predicate: DocumentPredicate {
                document_type: document_type.to_string(),
                version: version.clone(),
                namespace: namespace.clone(),
                previous_manifest_hash: previous_manifest_hash.clone(),
                created_by: grant.principal(),
                created_at: manifest_created_at,
                tenant_id,
            },
        };
        serde_json::to_vec(&statement).map_err(|e| ApiError::InternalError(e.to_string()))?
    } else {
        let statement: ManifestStatement = Statement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: format!("{}{}@{}", domain, namespace, version),
                digest: [("sha256".to_string(), sbom_hash.clone())].into_iter().collect(),
            }],
            predicate_type: MANIFEST_PREDICATE_TYPE.to_string(),
            predicate: ManifestPredicate {
                version: version.clone(),
                namespace: namespace.clone(),
                previous_manifest_hash: previous_manifest_hash.clone(),
                sbom_format: format.clone(),
                created_by: grant.principal(),
                created_at: manifest_created_at,
                tenant_id,
            },
        };
        serde_json::to_vec(&statement).map_err(|e| ApiError::InternalError(e.to_string()))?
    };

    let pae_bytes = pae(DSSE_PAYLOAD_TYPE, &statement_bytes);
    let raw_signature = state
        .signer
        .sign(&pae_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("manifest signing failed: {}", e)))?;
    let public_key = state
        .signer
        .public_key()
        .await
        .map_err(|e| ApiError::InternalError(format!("public key lookup failed: {}", e)))?;
    let keyid = hex::encode(Sha256::digest(&public_key));

    let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, &raw_signature, &keyid);
    let envelope_json =
        serde_json::to_value(&envelope).map_err(|e| ApiError::InternalError(e.to_string()))?;
    let manifest_hash = hex::encode(Sha256::digest(
        serde_json::to_vec(&envelope_json).map_err(|e| ApiError::InternalError(e.to_string()))?,
    ));

    state
        .db
        .insert_manifest(
            &manifest_hash,
            leaf_seq_id,
            tenant_id,
            &version,
            &sbom_hash,
            &format,
            &s3_key,
            &namespace,
            previous_manifest_hash.as_deref(),
            &envelope_json,
            document_type_opt,
            &grant.principal(),
            manifest_created_at,
        )
        .await
        .map_err(db_err)?;

    if format != "document" {
        if let Err(e) = index_manifest_components(&state, tenant_id, &manifest_hash, &format, &sbom_bytes).await {
            tracing::warn!(manifest_hash = %manifest_hash, error = %e, "component indexing failed (upload still succeeded)");
        }

        // Nudges dtrack to pick this upload up right away instead of
        // waiting for the next periodic tick (up to
        // `dtrack_sync_interval_secs` away). Spawned, not awaited — dtrack
        // sync is a secondary concern that must never block or fail the
        // upload response, same idiom as the periodic loop itself (see
        // dtrack_sync.rs's module doc comment: no dtrack call is ever made
        // synchronously from inside a handler). `sync_now` re-checks
        // per-tenant sync-disabled and format eligibility on its own, so
        // nothing needs duplicating here beyond "is dtrack configured at
        // all".
        if let Some(client) = state.dtrack.clone() {
            let db = state.db.clone();
            let storage = state.storage.clone();
            tokio::spawn(async move {
                crate::dtrack_sync::sync_now(&db, &storage, &client, tenant_id).await;
            });
        }
    }

    let sth_json = sth_to_json(&sth, true);
    let _ = record_audit(
        &state,
        &grant,
        "upload",
        &manifest_hash,
        true,
        None,
    )
    .await;

    Ok(Json(UploadResponse {
        sbom_hash,
        manifest_hash,
        version,
        namespace,
        domain,
        tree_size,
        leaf_index: tree_size - 1,
        leaf_seq_id,
        signed_tree_head: sth_json,
    }))
}

pub async fn tree_head_latest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<TreeHeadJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_latest_signed_tree_head(tenant_id)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(tree_head_record_to_json(&state, record).await?))
}

pub async fn tree_head_at(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(tree_size): Path<i64>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<TreeHeadJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_signed_tree_head(tenant_id, tree_size)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(tree_head_record_to_json(&state, record).await?))
}

async fn tree_head_record_to_json(
    state: &AppState,
    record: magnolia_db::SignedTreeHeadRecord,
) -> Result<TreeHeadJson, ApiError> {
    let sth = SignedTreeHead {
        tree_size: record.tree_size as u64,
        root_hash: record.root_hash.clone(),
        signature: record.signature.clone(),
        frontier: record.frontier,
        created_at: record.created_at,
    };
    let verified = state
        .signer
        .verify(&sth.signing_payload(), &sth.signature)
        .await
        .unwrap_or(false);
    Ok(sth_to_json(&sth, verified))
}

pub async fn inclusion_proof(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(leaf_index): Path<u64>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<InclusionProof>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    let trees = state.trees.lock().await;
    let tree = trees.get(&tenant_id).ok_or(ApiError::NotFound)?;
    let proof = tree
        .generate_inclusion_proof(leaf_index)
        .map_err(|_| ApiError::NotFound)?;
    let _ = record_audit(
        &state,
        &grant,
        "proof_inclusion",
        &leaf_index.to_string(),
        true,
        None,
    )
    .await;
    Ok(Json(proof))
}

pub async fn consistency_proof(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((old_tree_size, new_tree_size)): Path<(u64, u64)>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ConsistencyProof>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    if old_tree_size > new_tree_size {
        return Err(ApiError::BadRequest(
            "old_tree_size must be <= new_tree_size".to_string(),
        ));
    }
    let trees = state.trees.lock().await;
    let tree = trees.get(&tenant_id).cloned().unwrap_or_default();
    if new_tree_size != tree.tree_size() {
        return Err(ApiError::BadRequest(format!(
            "new_tree_size must equal the current tree size ({})",
            tree.tree_size()
        )));
    }
    let proof = tree
        .generate_consistency_proof(old_tree_size)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let _ = record_audit(
        &state,
        &grant,
        "proof_consistency",
        &format!("{}->{}", old_tree_size, new_tree_size),
        true,
        None,
    )
    .await;
    Ok(Json(proof))
}

pub async fn leaves(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<LeavesQuery>,
) -> Result<Json<Vec<LeafJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    // Acting on another tenant sees it in full — "my namespace scope"
    // doesn't apply to someone else's tenant.
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let limit = query.limit.clamp(1, 500);
    let offset = query.offset.max(0);
    let rows = state
        .db
        .list_merkle_leaves(tenant_id, scope, limit, offset)
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| LeafJson {
                leaf_index: row.tenant_leaf_index.max(0) as u64,
                leaf_hash: hex::encode(&row.leaf_hash),
                seq_id: row.seq_id,
                tenant_id: row.tenant_id,
                namespace: row.namespace,
                sbom_s3_key: row.sbom_s3_key,
                status: row.status,
                created_at: row.created_at,
                manifest_hash: row.manifest_hash,
                revoked: row.revoked,
                domain: row.domain,
                version: row.version,
                document_type: row.document_type,
            })
            .collect(),
    ))
}

pub async fn manifest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ManifestJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_manifest(&manifest_hash)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    // Don't confirm existence of another tenant's (or another namespace's)
    // manifest: 404, not 403, either way. A cross-tenant super_admin sees
    // the target tenant in full — namespace scope doesn't apply there.
    if record.tenant_id != tenant_id
        || (!cross_tenant
            && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let sbom_bytes = state
        .storage
        .get(&record.sbom_s3_key)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage get failed: {}", e)))?;

    // Only computed for profiles this tenant has actually enabled — a
    // disabled profile's report would just be noise in the response.
    let compliance: Vec<ComplianceReportJson> = {
        let settings = state.db.list_compliance_settings(tenant_id).await.map_err(db_err)?;
        let enabled_ids: std::collections::HashSet<_> =
            settings.into_iter().filter(|s| s.enabled).map(|s| s.profile_id).collect();
        registered_profiles()
            .iter()
            .filter(|p| enabled_ids.contains(p.id()))
            .filter_map(|p| {
                let r = p.check(&record.sbom_format, &sbom_bytes);
                if r.applicable { Some(ComplianceReportJson::from(r)) } else { None }
            })
            .collect()
    };

    // DB read only — never a live dtrack call in the request path. Stays
    // available (returns whatever's cached, possibly empty) independent of
    // dtrack's uptime.
    let vulnerability_findings: Vec<DtrackFindingJson> = state
        .db
        .list_dtrack_findings(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(DtrackFindingJson::from)
        .collect();

    let dtrack_synced_at = state
        .db
        .get_dtrack_project(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .and_then(|p| p.last_synced_at);

    let dtrack_push_error = state
        .db
        .get_dtrack_push_failure(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .map(|f| f.error);

    let malicious_components: Vec<MaliciousComponentJson> = state
        .db
        .list_malicious_findings(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(MaliciousComponentJson::from)
        .collect();

    let component_reputation: Vec<ComponentReputationJson> = state
        .db
        .list_reputation_for_manifest(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(ComponentReputationJson::from)
        .collect();

    Ok(Json(ManifestJson {
        sbom_hex: hex::encode(&sbom_bytes),
        manifest_hash: record.manifest_hash,
        leaf_seq_id: record.leaf_seq_id,
        tenant_id: record.tenant_id,
        domain,
        version: record.version,
        sbom_hash: record.sbom_hash,
        sbom_format: record.sbom_format,
        sbom_s3_key: record.sbom_s3_key,
        namespace: record.namespace,
        previous_manifest_hash: record.previous_manifest_hash,
        signature: record.signature.as_ref().map(hex::encode),
        dsse_envelope: record.dsse_envelope.clone(),
        document_type: record.document_type.clone(),
        created_by: mask_principal(&record.created_by),
        created_at: record.created_at,
        revoked: record.revoked,
        revoked_at: record.revoked_at,
        revoked_by: record.revoked_by,
        compliance,
        vulnerability_findings,
        dtrack_synced_at,
        dtrack_push_error,
        malicious_components,
        component_reputation,
    }))
}

#[derive(serde::Serialize)]
pub struct VexVulnerabilityJson {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct VexProductJson {
    #[serde(rename = "@id")]
    pub id: String,
}

#[derive(serde::Serialize)]
pub struct VexStatementJson {
    pub vulnerability: VexVulnerabilityJson,
    pub timestamp: DateTime<Utc>,
    pub products: Vec<VexProductJson>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_notes: Option<String>,
}

#[derive(serde::Serialize)]
pub struct VexDocumentJson {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@id")]
    pub id: String,
    pub author: String,
    pub timestamp: DateTime<Utc>,
    pub version: u32,
    pub statements: Vec<VexStatementJson>,
}

/// Exports Magnolia's own VEX triage for one manifest as an OpenVEX document
/// (https://github.com/openvex/spec) — one statement per cached dtrack
/// finding. Same auth/tenant-ownership gate as `manifest()`: `Action::Read`,
/// 404 (not 403) for another tenant's/namespace's manifest.
///
/// Untriaged findings (`vex_status IS NULL`) are exported as
/// `under_investigation` — OpenVEX's own convention for "not yet reviewed" —
/// rather than omitted, so a consumer diffing this document against dtrack's
/// raw finding list sees every finding accounted for. `justification` is
/// only ever emitted for `not_affected`, matching OpenVEX's own constraint
/// (see `VEX_JUSTIFICATIONS`); `status_notes` carries the free-text
/// `vex_comment` regardless of status. There's no persisted document
/// revision history — this is regenerated fresh from `dtrack_findings` on
/// every request, so `version` is always `1`.
pub async fn manifest_vex(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<VexDocumentJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state.db.get_manifest(&manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let domain = if cross_tenant {
        state.db.get_tenant(tenant_id).await.map_err(db_err)?.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let findings = state.db.list_dtrack_findings(&record.manifest_hash).await.map_err(db_err)?;

    let statements = findings
        .into_iter()
        .map(|f| {
            let status = f.vex_status.unwrap_or_else(|| "under_investigation".to_string());
            let justification = if status == "not_affected" { f.vex_justification } else { None };
            let product_id = match f.component_version {
                Some(v) if !v.is_empty() => format!("{}@{}", f.component_name, v),
                _ => f.component_name,
            };
            VexStatementJson {
                vulnerability: VexVulnerabilityJson { name: f.vulnerability_id },
                timestamp: f.triaged_at.unwrap_or(f.synced_at),
                products: vec![VexProductJson { id: product_id }],
                status,
                justification,
                status_notes: f.vex_comment,
            }
        })
        .collect();

    Ok(Json(VexDocumentJson {
        context: "https://openvex.dev/ns/v0.2.0".to_string(),
        id: format!("urn:magnolia:vex:{}", record.manifest_hash),
        author: format!("Magnolia ({domain})"),
        timestamp: Utc::now(),
        version: 1,
        statements,
    }))
}

#[derive(serde::Deserialize)]
pub struct ManifestDiffQuery {
    pub tenant_id: Option<Uuid>,
    /// Manifest hash to diff against. Defaults to the immediately-previous
    /// manifest in the same namespace (by upload order) when omitted.
    pub against: Option<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct ComponentSummaryJson {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ComponentVersionChangeJson {
    pub name: String,
    pub purl: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ManifestDiffJson {
    pub from_manifest_hash: String,
    pub from_version: String,
    pub to_manifest_hash: String,
    pub to_version: String,
    pub added: Vec<ComponentSummaryJson>,
    pub removed: Vec<ComponentSummaryJson>,
    pub changed: Vec<ComponentVersionChangeJson>,
    pub unchanged_count: usize,
}

/// Component identity for matching across two manifests' component lists:
/// `purl` with its trailing `@version` segment stripped when present (a
/// purl's version is always separated by a literal `@`, with any real `@`
/// inside the name/namespace itself percent-encoded per the purl spec, so a
/// plain split is safe), else the lowercased component name. Two components
/// sharing an identity but a different `version` are a `changed` entry;
/// present on only one side is `added`/`removed`.
fn component_identity(name: &str, purl: Option<&str>) -> String {
    match purl {
        Some(p) if !p.is_empty() => p.split('@').next().unwrap_or(p).to_string(),
        _ => name.to_lowercase(),
    }
}

#[derive(serde::Deserialize)]
pub struct NamespaceManifestsQuery {
    pub namespace: String,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Serialize)]
pub struct ManifestVersionJson {
    pub manifest_hash: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

/// One namespace's full upload history (real SBOMs only, newest first) —
/// feeds the diff UI's "choose which version to diff against" dropdown.
/// `Action::Read`, namespace-scope-checked the same way every other
/// namespace-scoped listing here is (`list_hidden_namespaces`,
/// `list_registered_namespaces`).
pub async fn namespace_manifest_versions(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<NamespaceManifestsQuery>,
) -> Result<Json<Vec<ManifestVersionJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let namespace = normalize_namespace(&q.namespace)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden("namespace out of scope".to_string()));
    }

    let rows = state.db.list_manifest_versions_in_namespace(tenant_id, &namespace).await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|r| ManifestVersionJson {
                manifest_hash: r.manifest_hash,
                version: r.version,
                created_at: r.created_at,
                revoked: r.revoked,
            })
            .collect(),
    ))
}

/// Diffs one manifest's indexed component list against another's. Reuses
/// the `sbom_components` reverse-search index built at upload time (see
/// `insert_sbom_components`) rather than re-parsing either SBOM's raw
/// bytes. `Action::Read`, same tenant/namespace-ownership gate as
/// `manifest()` — checked independently for both manifests, since `against`
/// could in principle name one in a different namespace (allowed; same
/// scope rule as everywhere else, just an unusual comparison to ask for).
/// Neither manifest may be a `document_type` upload — those have no
/// components to compare.
pub async fn manifest_diff(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<ManifestDiffQuery>,
) -> Result<Json<ManifestDiffJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let to_record = state.db.get_manifest(&manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if to_record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&to_record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }
    if to_record.document_type.is_some() {
        return Err(ApiError::BadRequest(
            "cannot diff a document upload -- no SBOM components to compare".to_string(),
        ));
    }

    let from_record = match &q.against {
        Some(hash) => {
            let r = state.db.get_manifest(hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
            if r.tenant_id != tenant_id
                || (!cross_tenant && !magnolia_auth::namespace_in_scope(&r.namespace, &grant.namespace_scope))
            {
                return Err(ApiError::NotFound);
            }
            if r.document_type.is_some() {
                return Err(ApiError::BadRequest(
                    "cannot diff against a document upload -- no SBOM components to compare".to_string(),
                ));
            }
            r
        }
        None => state
            .db
            .get_previous_manifest_in_namespace(
                tenant_id,
                &to_record.namespace,
                to_record.created_at,
                to_record.leaf_seq_id,
            )
            .await
            .map_err(db_err)?
            .ok_or_else(|| {
                ApiError::BadRequest("no previous manifest in this namespace to diff against".to_string())
            })?,
    };

    let from_components = state.db.list_sbom_components_for_manifest(&from_record.manifest_hash).await.map_err(db_err)?;
    let to_components = state.db.list_sbom_components_for_manifest(&to_record.manifest_hash).await.map_err(db_err)?;

    let from_map: std::collections::HashMap<String, SbomComponentRow> = from_components
        .into_iter()
        .map(|c| (component_identity(&c.name, c.purl.as_deref()), c))
        .collect();
    let to_map: std::collections::HashMap<String, SbomComponentRow> = to_components
        .into_iter()
        .map(|c| (component_identity(&c.name, c.purl.as_deref()), c))
        .collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged_count = 0;
    for (id, to_c) in &to_map {
        match from_map.get(id) {
            None => added.push(ComponentSummaryJson {
                name: to_c.name.clone(),
                version: to_c.version.clone(),
                purl: to_c.purl.clone(),
            }),
            Some(from_c) if from_c.version != to_c.version => changed.push(ComponentVersionChangeJson {
                name: to_c.name.clone(),
                purl: to_c.purl.clone(),
                from_version: from_c.version.clone(),
                to_version: to_c.version.clone(),
            }),
            Some(_) => unchanged_count += 1,
        }
    }
    let mut removed: Vec<ComponentSummaryJson> = from_map
        .iter()
        .filter(|(id, _)| !to_map.contains_key(*id))
        .map(|(_, c)| ComponentSummaryJson { name: c.name.clone(), version: c.version.clone(), purl: c.purl.clone() })
        .collect();

    added.sort_by(|a, b| a.name.cmp(&b.name));
    removed.sort_by(|a, b| a.name.cmp(&b.name));
    changed.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Json(ManifestDiffJson {
        from_manifest_hash: from_record.manifest_hash,
        from_version: from_record.version,
        to_manifest_hash: to_record.manifest_hash,
        to_version: to_record.version,
        added,
        removed,
        changed,
        unchanged_count,
    }))
}

/// The most recent non-revoked manifest per namespace — "what's currently
/// deployed" for each deployable, not just the single latest upload
/// tenant-wide. Recency (`created_at`), not `version` magnitude, decides
/// "current" — a rollback to an older version number is still correctly
/// reported as current, since it's what was actually deployed last.
pub async fn current_manifests(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<CurrentManifestJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let rows = state
        .db
        .latest_manifests_by_namespace(tenant_id, scope)
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| CurrentManifestJson {
                namespace: r.namespace,
                domain: domain.clone(),
                version: r.version,
                manifest_hash: r.manifest_hash,
                sbom_hash: r.sbom_hash,
                sbom_format: r.sbom_format,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

#[derive(serde::Deserialize, Default)]
pub struct SnapshotRequest {
    pub namespace: Option<String>,
    pub version: Option<String>,
}

/// A signed, downloadable audit archive (tar) of every manifest/document
/// matching the requested scope — deliberately uncurated (see
/// `list_manifests_for_export`'s doc comment), unlike "currently running".
/// Defaults to everything within the caller's RBAC namespace scope; the
/// optional `namespace`/`version` fields narrow further. `POST`, not `GET`,
/// since every call mints a fresh signature/timestamp — not idempotent.
pub async fn snapshot(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(req): Json<SnapshotRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let namespace_filter = req.namespace.as_deref();
    let version_filter = req.version.as_deref();

    let tar_bytes = crate::snapshot::build_snapshot_tar(
        &state,
        tenant_id,
        &domain,
        &grant.principal(),
        scope,
        namespace_filter,
        version_filter,
    )
    .await?;

    let scope_desc = match (namespace_filter, version_filter) {
        (None, None) => "all".to_string(),
        (Some(ns), None) => format!("namespace={ns}"),
        (None, Some(v)) => format!("version={v}"),
        (Some(ns), Some(v)) => format!("namespace={ns} version={v}"),
    };
    let _ = record_audit(&state, &grant, "snapshot", &scope_desc, true, None).await;

    let filename = format!("magnolia-audit-{}-{}.tar", domain, Utc::now().timestamp());
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-tar".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        tar_bytes,
    ))
}

/// Namespaces currently opted out of the "current" view for this tenant
/// (scoped to the caller's `namespace_scope`, or the full tenant when
/// acting cross-tenant).
pub async fn list_hidden_namespaces(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<String>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let rows = state
        .db
        .list_hidden_namespaces(tenant_id, scope)
        .await
        .map_err(db_err)?;
    Ok(Json(rows))
}

#[derive(serde::Deserialize)]
pub struct SetNamespaceHiddenRequest {
    pub namespace: String,
    pub hidden: bool,
}

/// Toggles whether a namespace is excluded from the "current" view — a
/// display filter only (declutter test/staging namespaces from "what's
/// running in prod"), not a tracking pause: uploads, revocation, and the
/// Merkle log/proofs are entirely unaffected either way. Gated with
/// `Action::ManageSettings` — a tenant-wide setting, not a per-item
/// curatorial action, so (unlike manifest revocation) `auditor` may view
/// it but not change it.
pub async fn set_namespace_hidden(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetNamespaceHiddenRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let namespace = normalize_namespace(&body.namespace)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden("namespace out of scope".to_string()));
    }

    state
        .db
        .set_namespace_hidden(tenant_id, &namespace, body.hidden, &grant.principal())
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every registered compliance profile — informational, not tenant-scoped,
/// so plain `Action::Read` is enough.
pub async fn list_compliance_profiles(grant: AuthGrant) -> Result<Json<Vec<ComplianceProfileJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    Ok(Json(
        registered_profiles()
            .iter()
            .map(|p| ComplianceProfileJson {
                id: p.id().to_string(),
                name: p.name().to_string(),
                description: p.description().to_string(),
            })
            .collect(),
    ))
}

#[derive(serde::Serialize)]
pub struct ComplianceCheckResponse {
    pub reports: Vec<ComplianceReportJson>,
}

/// Standalone "does this SBOM meet requirements" check — the Tools tab's
/// compliance checker. Runs the exact same profile `check()` logic
/// `upload_sbom`/`manifest()` use, but on caller-supplied bytes that are
/// never stored, indexed, or added to the Merkle log: nothing here
/// persists, so it's safe to try an SBOM that doesn't belong in the
/// archive yet (a draft, a "does this even qualify" spot check) without
/// creating a real, permanent manifest. Every registered profile is
/// checked regardless of this tenant's own enable/enforce settings — the
/// point is exploring what a document would score, not tenant policy.
pub async fn check_compliance(
    grant: AuthGrant,
    mut multipart: Multipart,
) -> Result<Json<ComplianceCheckResponse>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;

    let field = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err("invalid multipart body", e))?
        .ok_or_else(|| ApiError::BadRequest("missing sbom_file field".to_string()))?;
    let sbom_bytes = field
        .bytes()
        .await
        .map_err(|e| multipart_err("invalid sbom_file field", e))?
        .to_vec();

    let mut format = "cyclonedx".to_string();
    while let Some(next) = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err("invalid multipart body", e))?
    {
        if next.name() == Some("format") {
            format = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid format field", e))?
                .to_lowercase();
        }
    }

    if sbom_bytes.is_empty() {
        return Err(ApiError::BadRequest("sbom_file is empty".to_string()));
    }
    if sbom_bytes.len() > MAX_SBOM_BYTES {
        return Err(ApiError::BadRequest("sbom_file exceeds 10 MiB limit".to_string()));
    }
    validate_sbom_content(&sbom_bytes, &format)?;

    let reports: Vec<ComplianceReportJson> = registered_profiles()
        .iter()
        .map(|p| p.check(&format, &sbom_bytes))
        .filter(|r| r.applicable)
        .map(ComplianceReportJson::from)
        .collect();

    Ok(Json(ComplianceCheckResponse { reports }))
}

/// This tenant's setting for every registered profile — always the full
/// list, even for profiles the tenant has never touched (those default to
/// disabled/off). Viewing is `Action::Read`; only `set_compliance_setting`
/// (below) requires `Action::ManageSettings`.
pub async fn compliance_settings(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<ComplianceSettingJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let rows = state.db.list_compliance_settings(tenant_id).await.map_err(db_err)?;
    let by_id: std::collections::HashMap<_, _> = rows.into_iter().map(|r| (r.profile_id.clone(), r)).collect();
    Ok(Json(
        registered_profiles()
            .iter()
            .map(|p| {
                let row = by_id.get(p.id());
                ComplianceSettingJson {
                    profile_id: p.id().to_string(),
                    profile_name: p.name().to_string(),
                    description: p.description().to_string(),
                    enabled: row.map(|r| r.enabled).unwrap_or(false),
                    enforce_level: row.map(|r| r.enforce_level.clone()).unwrap_or_else(|| "off".to_string()),
                }
            })
            .collect(),
    ))
}

/// Enables/disables a compliance profile for this tenant and sets its
/// enforcement level. `Action::ManageSettings` — deliberately excludes
/// `auditor`, since this can turn on upload-rejecting enforcement for the
/// whole tenant.
pub async fn set_compliance_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetComplianceSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    if profile_by_id(&body.profile_id).is_none() {
        return Err(ApiError::BadRequest(format!("unknown compliance profile_id: {}", body.profile_id)));
    }
    if !matches!(body.enforce_level.as_str(), "off" | "minimum" | "full") {
        return Err(ApiError::BadRequest("enforce_level must be one of: off, minimum, full".to_string()));
    }
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    state
        .db
        .set_compliance_setting(tenant_id, &body.profile_id, body.enabled, &body.enforce_level, &grant.principal())
        .await
        .map_err(db_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reverse component search — "which manifests contain component X (at
/// version Y)?" — an indexed lookup against `sbom_components`, not a scan
/// over every SBOM's raw bytes. `Action::Read`, same as anyone who can
/// already browse the archive. Requires at least one of `name`/`purl`.
pub async fn search_components(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<SearchComponentsQuery>,
) -> Result<Json<Vec<ComponentSearchResultJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    if query.name.as_deref().unwrap_or("").is_empty() && query.purl.as_deref().unwrap_or("").is_empty() {
        return Err(ApiError::BadRequest("provide at least one of name or purl".to_string()));
    }

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .map(|t| t.domain)
            .unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let limit = query.limit.clamp(1, 200);
    let offset = query.offset.max(0);
    let name_filter = query.name.as_deref().filter(|s| !s.is_empty());
    let version_filter = query.version.as_deref().filter(|s| !s.is_empty());
    let namespace_filter = query.namespace.as_deref().filter(|s| !s.is_empty());
    let purl_filter = query.purl.as_deref().filter(|s| !s.is_empty());

    let rows = state
        .db
        .search_sbom_components(
            tenant_id,
            scope,
            namespace_filter,
            name_filter,
            version_filter,
            purl_filter,
            limit,
            offset,
        )
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ComponentSearchResultJson {
                name: r.name,
                version: r.version,
                purl: r.purl,
                cpe: r.cpe,
                is_primary: r.is_primary,
                manifest_hash: r.manifest_hash,
                domain: domain.clone(),
                namespace: r.namespace,
                release_version: r.release_version,
                revoked: r.revoked,
                document_type: r.document_type,
            })
            .collect(),
    ))
}

/// One-time backfill for manifests uploaded before component search
/// shipped (extraction only happens at upload time going forward — this
/// endpoint is how existing archive content catches up). Administrative,
/// not routine, hence `Action::ManageSettings` rather than `Read`.
pub async fn reindex_components(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ReindexResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let pending = state
        .db
        .list_manifests_missing_from_component_index(tenant_id, scope)
        .await
        .map_err(db_err)?;

    let mut manifests_indexed = 0;
    let mut components_indexed = 0;
    for record in pending {
        let bytes = match state.storage.get(&record.sbom_s3_key).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(manifest_hash = %record.manifest_hash, error = %e, "reindex: storage read failed, skipping");
                continue;
            }
        };
        match index_manifest_components(&state, tenant_id, &record.manifest_hash, &record.sbom_format, &bytes).await {
            Ok(count) => {
                manifests_indexed += 1;
                components_indexed += count;
            }
            Err(e) => {
                tracing::warn!(manifest_hash = %record.manifest_hash, error = %e, "reindex: indexing failed, skipping");
            }
        }
    }

    let _ = record_audit(
        &state,
        &grant,
        "reindex_components",
        &format!("manifests_indexed={manifests_indexed} components_indexed={components_indexed}"),
        true,
        None,
    )
    .await;

    Ok(Json(ReindexResponse { manifests_indexed, components_indexed }))
}

#[derive(serde::Serialize)]
pub struct DtrackSyncResponse {
    pub manifests_pushed: usize,
    pub projects_refreshed: usize,
}

/// "Force sync now" — runs one push+refresh pass immediately instead of
/// waiting for the periodic background loop, scoped to the caller's own
/// tenant only (never another tenant's, even for a cross-tenant
/// super_admin override — `sync_now` always takes the *resolved* tenant,
/// same as every other tenant-scoped write here). `Action::ManageSettings`,
/// same gate as `reindex_components` — an on-demand bulk/external-API
/// action, not a routine read. 400 if dtrack isn't configured for this
/// deployment at all (nothing to sync against).
pub async fn force_dtrack_sync(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<DtrackSyncResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let client = state.dtrack.as_ref().ok_or_else(|| {
        ApiError::BadRequest("Dependency-Track is not enabled for this deployment".to_string())
    })?;

    let (manifests_pushed, projects_refreshed) =
        crate::dtrack_sync::sync_now(&state.db, &state.storage, client, tenant_id).await;

    let _ = record_audit(
        &state,
        &grant,
        "dtrack_force_sync",
        &format!("manifests_pushed={manifests_pushed} projects_refreshed={projects_refreshed}"),
        true,
        None,
    )
    .await;

    Ok(Json(DtrackSyncResponse { manifests_pushed, projects_refreshed }))
}

#[derive(serde::Serialize)]
pub struct ReputationSyncResponse {
    pub components_processed: usize,
}

/// Runs one on-demand batch of the reputation background job (see
/// `reputation_sync.rs`) instead of waiting for its next scheduled tick —
/// same relationship `force_dtrack_sync` has to the periodic dtrack loop.
/// Deployment-global, unlike `force_dtrack_sync`: reputation isn't
/// tenant-scoped (a package's Scorecard doesn't depend on who uploaded it),
/// so there's no `tenant_id` to resolve here, and one call processes the
/// deployment's whole pending backlog one batch at a time regardless of
/// which tenant's key triggered it. `Action::ManageSettings`, same gate as
/// `force_dtrack_sync`/`reindex_components`. 400 if reputation scoring
/// isn't enabled for this deployment at all (nothing to sync against).
pub async fn force_reputation_sync(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<ReputationSyncResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;

    let client = state.depsdev.as_ref().ok_or_else(|| {
        ApiError::BadRequest("package reputation scoring is disabled for this deployment".to_string())
    })?;

    let components_processed = crate::reputation_sync::sync_pass(&state.db, client).await;

    let _ = record_audit(
        &state,
        &grant,
        "reputation_force_sync",
        &format!("components_processed={components_processed}"),
        true,
        None,
    )
    .await;

    Ok(Json(ReputationSyncResponse { components_processed }))
}

#[derive(serde::Serialize)]
pub struct ReputationStatusJson {
    pub pending: i64,
    pub checked: i64,
    pub failed: i64,
}

/// Deployment-wide counts of the reputation background job's progress —
/// lets the Settings UI show "12 pending, 3 checked, 0 failed" instead of
/// the caller having to infer status from one manifest's (possibly empty)
/// `component_reputation` list. `Action::Read`, same as viewing any other
/// deployment-operational info (`config`, `whoami`) — this is a read, not a
/// mutation, unlike `force_reputation_sync`.
pub async fn reputation_status(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<ReputationStatusJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let status = state.db.reputation_status(crate::reputation_sync::stale_before_cutoff()).await.map_err(db_err)?;
    Ok(Json(ReputationStatusJson { pending: status.pending, checked: status.checked, failed: status.failed }))
}

#[derive(serde::Serialize)]
pub struct ReputationComponentSummaryJson {
    pub ecosystem: String,
    pub name: String,
    pub scorecard_score: f32,
    pub bucket: crate::reputation_bucket::ReputationBucket,
    pub project_repo: Option<String>,
    pub checked_at: DateTime<Utc>,
}

impl From<magnolia_db::ComponentReputationSummaryRow> for ReputationComponentSummaryJson {
    fn from(r: magnolia_db::ComponentReputationSummaryRow) -> Self {
        Self {
            bucket: crate::reputation_bucket::bucket_for_score(r.scorecard_score),
            ecosystem: r.ecosystem,
            name: r.name,
            scorecard_score: r.scorecard_score,
            project_repo: r.project_repo,
            checked_at: r.checked_at,
        }
    }
}

/// Every package with a cached Scorecard score, deployment-wide, ascending
/// by score — backs the Settings page's aggregation modal (a `manifest()`
/// call only ever shows one manifest's own components; this shows the whole
/// deployment's scored backlog at once). `Action::Read`: informational,
/// not tenant data (see `component_reputation`'s migration comment — a
/// package's score isn't scoped to who uploaded it).
pub async fn reputation_components(grant: AuthGrant, State(state): State<AppState>) -> Result<Json<Vec<ReputationComponentSummaryJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let rows = state.db.list_all_reputation().await.map_err(db_err)?;
    Ok(Json(rows.into_iter().map(ReputationComponentSummaryJson::from).collect()))
}

/// Marks a manifest revoked — a status flag, not a delete: the manifest
/// row, its signature, and the Merkle leaf/hash it's chained from are
/// untouched, so the append-only log and tamper-evidence are unaffected.
///
/// Normally requires `Action::Annotate` (super_admin, domain_admin,
/// auditor). If the server has `DEV_MODE=true` set, an `uploader`-role key
/// may also revoke — for local testing where the same pipeline that
/// uploaded a bad SBOM wants to retract it without a separate admin key.
/// Never relies on DEV_MODE for anything beyond that one relaxation.
pub async fn revoke_manifest(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<StatusCode, ApiError> {
    if let Err(e) = require(&grant, Action::Annotate, &grant.namespace_scope) {
        if state.dev_mode {
            require(&grant, Action::Upload, &grant.namespace_scope)?;
        } else {
            return Err(e);
        }
    }

    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state
        .db
        .get_manifest(&manifest_hash)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    if record.tenant_id != tenant_id
        || (!cross_tenant
            && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let updated = state
        .db
        .revoke_manifest(tenant_id, &manifest_hash, &grant.principal())
        .await
        .map_err(db_err)?;

    if !updated {
        return Err(ApiError::BadRequest("manifest already revoked".to_string()));
    }

    let _ = record_audit(&state, &grant, "manifest_revoke", &manifest_hash, true, None).await;

    Ok(StatusCode::NO_CONTENT)
}

/// The fixed OpenVEX justification vocabulary (https://github.com/openvex/spec) —
/// only meaningful (and only accepted) alongside `vex_status: "not_affected"`,
/// since a justification is specifically an explanation of *why* something
/// isn't affected. Kept as a closed set rather than free text so a VEX
/// consumer (see `manifest_vex`'s export) can machine-match it instead of
/// parsing prose.
const VEX_JUSTIFICATIONS: &[&str] = &[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

#[derive(serde::Deserialize)]
pub struct TriageFindingRequest {
    pub vex_status: String,
    pub justification: Option<String>,
    /// Always-optional free-text context a fixed `justification` code can't
    /// capture (e.g. "confirmed with vendor advisory, see JIRA-1234") —
    /// unlike `justification`, allowed alongside any `vex_status`. Maps to
    /// OpenVEX's own `status_notes` on export.
    pub comment: Option<String>,
}

/// Sets Magnolia's own VEX-style triage on one cached dtrack finding — this
/// is Magnolia's product-specific exploitability judgment, independent of
/// dtrack's own `analysis_state` (see the `dtrack_findings` migration
/// comment). Follows `revoke_manifest`'s exact pattern: `Action::Annotate`,
/// tenant/namespace isolation before touching the row, audit-logged via the
/// existing `record_audit` (justification/comment ride in its `reason`
/// field — no schema change needed there).
pub async fn triage_finding(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<TriageFindingRequest>,
) -> Result<Json<DtrackFindingJson>, ApiError> {
    require(&grant, Action::Annotate, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state.db.get_manifest(&manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    if !["affected", "not_affected", "fixed", "under_investigation"].contains(&body.vex_status.as_str()) {
        return Err(ApiError::BadRequest("invalid vex_status".to_string()));
    }
    if body.vex_status == "not_affected" {
        if !body.justification.as_deref().map(|j| VEX_JUSTIFICATIONS.contains(&j)).unwrap_or(false) {
            return Err(ApiError::BadRequest(format!(
                "justification is required when vex_status is not_affected and must be one of: {}",
                VEX_JUSTIFICATIONS.join(", ")
            )));
        }
    } else if body.justification.is_some() {
        return Err(ApiError::BadRequest(
            "justification is only valid when vex_status is not_affected".to_string(),
        ));
    }

    let updated = state
        .db
        .set_finding_triage(
            &manifest_hash,
            &finding_key,
            &body.vex_status,
            body.justification.as_deref(),
            body.comment.as_deref(),
            &grant.principal(),
        )
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    let reason = match (&body.justification, &body.comment) {
        (Some(j), Some(c)) => Some(format!("justification={j}; comment={c}")),
        (Some(j), None) => Some(format!("justification={j}")),
        (None, Some(c)) => Some(format!("comment={c}")),
        (None, None) => None,
    };
    let _ = record_audit(
        &state,
        &grant,
        "finding_triage",
        &format!("{manifest_hash}:{finding_key}"),
        true,
        reason,
    )
    .await;

    // Best-effort: push this triage into dtrack's own analysis record too
    // (see `dtrack_sync::push_triage_to_dtrack`), so dtrack's own view
    // reflects Magnolia's judgment instead of staying permanently "not
    // set". Skipped, not failed, when dtrack isn't configured, this tenant
    // has opted out of dtrack sync, or this finding has no cached
    // component/vulnerability UUID yet (pre-migration row, or dtrack
    // hasn't refreshed it since).
    if let Some(dtrack) = &state.dtrack {
        let sync_disabled = state
            .db
            .get_tenant(tenant_id)
            .await
            .map(|t| t.map(|t| t.dtrack_sync_disabled).unwrap_or(true))
            .unwrap_or(true);
        if !sync_disabled {
            match (&updated.component_uuid, &updated.vulnerability_uuid) {
                (Some(cuuid), Some(vuuid)) => {
                    crate::dtrack_sync::push_triage_to_dtrack(
                        &state.db,
                        dtrack,
                        &manifest_hash,
                        cuuid,
                        vuuid,
                        &body.vex_status,
                        body.justification.as_deref(),
                        body.comment.as_deref(),
                    )
                    .await;
                }
                _ => {
                    tracing::info!(
                        manifest_hash = %manifest_hash,
                        finding_key = %finding_key,
                        "dtrack triage push: finding has no cached component/vulnerability uuid yet; skipping"
                    );
                }
            }
        }
    }

    Ok(Json(updated.into()))
}

#[derive(serde::Serialize)]
pub struct FindingCommentJson {
    pub id: Uuid,
    pub author: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

impl From<magnolia_db::FindingCommentRecord> for FindingCommentJson {
    fn from(r: magnolia_db::FindingCommentRecord) -> Self {
        Self { id: r.id, author: r.author, body: r.body, created_at: r.created_at }
    }
}

#[derive(serde::Deserialize)]
pub struct AddFindingCommentRequest {
    pub body: String,
}

/// Fetches (and, for the tenant/namespace check, discards) the manifest
/// behind a finding — shared by the comment endpoints below, mirroring the
/// same isolation check `triage_finding` does before touching the finding.
async fn authorize_finding_access(
    state: &AppState,
    grant: &AuthGrant,
    manifest_hash: &str,
    tenant_id: Uuid,
    cross_tenant: bool,
) -> Result<(), ApiError> {
    let record = state.db.get_manifest(manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

/// Adds one comment to a finding's discussion thread — a lighter-weight
/// counterpart to `triage_finding`'s single VEX status: comments are a
/// free-text, multi-entry log for analysts to work through a finding
/// together, so they get their own append-only table (`finding_comments`)
/// instead of a mutable column. The author is always `grant.principal()`
/// (the calling API key), same as `triaged_by` — Magnolia's auth model has
/// no separate human-identity concept to attribute a comment to instead.
pub async fn add_finding_comment(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<AddFindingCommentRequest>,
) -> Result<Json<FindingCommentJson>, ApiError> {
    require(&grant, Action::Annotate, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    authorize_finding_access(&state, &grant, &manifest_hash, tenant_id, cross_tenant).await?;

    let text = body.body.trim();
    if text.is_empty() {
        return Err(ApiError::BadRequest("comment body must not be empty".to_string()));
    }

    let comment = state
        .db
        .add_finding_comment(&manifest_hash, &finding_key, &grant.principal(), text)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    let _ = record_audit(
        &state,
        &grant,
        "finding_comment",
        &format!("{manifest_hash}:{finding_key}"),
        true,
        Some(text.to_string()),
    )
    .await;

    Ok(Json(comment.into()))
}

pub async fn list_finding_comments(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<FindingCommentJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    authorize_finding_access(&state, &grant, &manifest_hash, tenant_id, cross_tenant).await?;

    let comments = state.db.list_finding_comments(&manifest_hash, &finding_key).await.map_err(db_err)?;
    Ok(Json(comments.into_iter().map(Into::into).collect()))
}

/// Mints a key for `tenant_id`/`domain`. Shared by `create_key` (caller
/// creates a key for their own tenant) and `create_tenant` (mints the new
/// tenant's first key).
async fn mint_key(
    state: &AppState,
    tenant_id: Uuid,
    domain: &str,
    role: Role,
    namespace_scope: &str,
    expires_at: Option<DateTime<Utc>>,
) -> Result<CreateKeyResponse, ApiError> {
    let (key_id, secret, full_key) = generate_server_key();
    let key_material = magnolia_auth::ApiKey {
        key: secret,
        created_at: Utc::now(),
    };
    let hashed = key_material
        .hash()
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    state
        .db
        .insert_api_key(
            key_id,
            tenant_id,
            domain,
            namespace_scope,
            &role.to_string(),
            &hashed.hash,
            expires_at,
        )
        .await
        .map_err(db_err)?;

    Ok(CreateKeyResponse {
        key: full_key,
        key_id,
        tenant_id,
        domain: domain.to_string(),
        namespace_scope: namespace_scope.to_string(),
        role: role.to_string(),
        expires_at,
    })
}

fn parse_expires_at(text: &Option<String>) -> Result<Option<DateTime<Utc>>, ApiError> {
    match text {
        Some(text) => Ok(Some(
            DateTime::parse_from_rfc3339(text)
                .map_err(|_| ApiError::BadRequest("expires_at must be RFC3339".to_string()))?
                .with_timezone(&Utc),
        )),
        None => Ok(None),
    }
}

pub async fn create_key(
    State(state): State<AppState>,
    grant: AuthGrant,
    Json(request): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, request.tenant_id)?;

    let role = Role::from_str(&request.role)
        .map_err(|_| ApiError::BadRequest(format!("unknown role: {}", request.role)))?;
    let namespace_scope = normalize_namespace(&request.namespace_scope)?;
    let expires_at = parse_expires_at(&request.expires_at)?;

    // A key is created for the caller's own tenant/domain by default; only
    // super_admin can target another tenant (and must supply its domain
    // explicitly, since a key row always carries one). Also fetched
    // (same-tenant or not) whenever the requested role is super_admin, to
    // check platform status below.
    let target_tenant = if cross_tenant || role == Role::SuperAdmin {
        Some(
            state
                .db
                .get_tenant(tenant_id)
                .await
                .map_err(db_err)?
                .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?,
        )
    } else {
        None
    };

    // super_admin is only meaningful on the platform tenant — it's the
    // role that bootstraps and administers every other tenant. Minting one
    // for a regular product tenant would let that tenant's own
    // domain_admin (who already holds ManageKeys) grant itself
    // unconditional access to every RBAC-gated action within its tenant
    // (`(Role::SuperAdmin, _) => Ok(())` in the RBAC matrix), plus
    // Action::ManageTenants — a privilege-escalation path with no
    // legitimate use, so it's rejected outright rather than left to the
    // caller's discretion.
    if role == Role::SuperAdmin && !target_tenant.as_ref().map(|t| t.is_platform).unwrap_or(false) {
        return Err(ApiError::BadRequest(
            "super_admin keys can only be created for the platform tenant".to_string(),
        ));
    }

    let domain = if cross_tenant {
        target_tenant.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let response = mint_key(&state, tenant_id, &domain, role, &namespace_scope, expires_at).await?;

    let _ = record_audit(
        &state,
        &grant,
        "key_create",
        &response.key_id.to_string(),
        true,
        None,
    )
    .await;

    Ok(Json(response))
}

pub async fn create_tenant(
    State(state): State<AppState>,
    grant: AuthGrant,
    Json(request): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, ApiError> {
    require(&grant, Action::ManageTenants, "")?;
    // The RBAC matrix's ManageTenants check only verifies `role ==
    // SuperAdmin`, not platform-tenant status (the base `Grant` type it
    // operates on doesn't carry that field at all) — this handler-level
    // check closes that gap directly, same pattern `upload_sbom` already
    // uses for its own extra `is_platform_target` check beyond `require`.
    if !grant.is_platform_tenant {
        return Err(ApiError::Forbidden(
            "only the platform super_admin can create tenants".to_string(),
        ));
    }

    let domain = normalize_domain(&request.domain)?;
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_string()));
    }

    let tenant_id = Uuid::new_v4();
    let created_at = Utc::now();
    state
        .db
        .insert_tenant(tenant_id, &domain, name, &grant.principal(), false)
        .await
        .map_err(|e| match e {
            magnolia_db::DbError::Conflict(_) => {
                ApiError::BadRequest(format!("domain '{}' is already in use", domain))
            }
            other => db_err(other),
        })?;

    let initial_key = mint_key(
        &state,
        tenant_id,
        &domain,
        Role::DomainAdmin,
        "/",
        None,
    )
    .await?;

    let _ = record_audit(
        &state,
        &grant,
        "tenant_create",
        &tenant_id.to_string(),
        true,
        None,
    )
    .await;

    Ok(Json(CreateTenantResponse {
        tenant: TenantJson {
            id: tenant_id,
            domain,
            name: name.to_string(),
            created_by: grant.principal(),
            created_at,
            is_platform: false,
        },
        initial_key,
    }))
}

pub async fn list_tenants(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<Vec<TenantJson>>, ApiError> {
    require(&grant, Action::ManageTenants, "")?;

    let rows = state.db.list_tenants().await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| TenantJson {
                id: row.id,
                domain: row.domain,
                name: row.name,
                created_by: row.created_by,
                created_at: row.created_at,
                is_platform: row.is_platform,
            })
            .collect(),
    ))
}

/// Outside `DEV_MODE`, "deleting" a tenant only hides it — everything it
/// owns (keys, leaves, manifests, signed tree heads, audit log) stays
/// fully intact and still reachable directly (e.g. via `?tenant_id=`
/// override); it just disappears from listings/selectors. A compliance
/// archive shouldn't let one admin action permanently erase years of SBOM
/// history with no retention floor. The hard, cascading delete is only
/// available when `DEV_MODE=true`, for local test cleanup.
///
/// Gated more strictly than `create_tenant`/`list_tenants`: those allow any
/// super_admin (`Action::ManageTenants`), but this is a cross-tenant action
/// on another tenant's entire history, so it requires the platform
/// super_admin specifically — the same bar as the `?tenant_id` override
/// elsewhere. The platform tenant itself can never be deleted or hidden
/// (it's the one tenant capable of managing all the others).
pub async fn delete_tenant(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(tenant_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if !(grant.role == Role::SuperAdmin && grant.is_platform_tenant) {
        return Err(ApiError::Forbidden(
            "only the platform super_admin can delete a tenant".to_string(),
        ));
    }

    let target = state
        .db
        .get_tenant(tenant_id)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;

    if target.is_platform {
        return Err(ApiError::BadRequest(
            "cannot delete the platform tenant".to_string(),
        ));
    }

    if state.dev_mode {
        state.db.delete_tenant(tenant_id).await.map_err(db_err)?;
        state.trees.lock().await.remove(&tenant_id);

        let _ = record_audit(
            &state,
            &grant,
            "tenant_delete",
            &format!("{} ({})", tenant_id, target.domain),
            true,
            None,
        )
        .await;
    } else {
        state.db.hide_tenant(tenant_id).await.map_err(db_err)?;

        let _ = record_audit(
            &state,
            &grant,
            "tenant_hide",
            &format!("{} ({})", tenant_id, target.domain),
            true,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_keys(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<KeyJson>>, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let domain = if cross_tenant {
        state
            .db
            .get_tenant(tenant_id)
            .await
            .map_err(db_err)?
            .ok_or_else(|| ApiError::BadRequest("unknown tenant_id".to_string()))?
            .domain
    } else {
        grant.domain.clone()
    };

    let rows = state.db.list_api_keys(&domain).await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| KeyJson {
                id: row.id,
                tenant_id: row.tenant_id,
                domain: row.domain,
                namespace_scope: row.namespace_scope,
                role: row.role,
                expires_at: row.expires_at,
                revoked: row.revoked,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

pub async fn revoke_key(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(key_id): Path<Uuid>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageKeys, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, q.tenant_id)?;

    // Scoped to the target tenant at the DB layer: a key can only ever be
    // revoked by (an admin of) its own tenant — or a super_admin acting on
    // that tenant explicitly.
    let found = state
        .db
        .revoke_api_key(tenant_id, key_id)
        .await
        .map_err(db_err)?;

    if !found {
        return Err(ApiError::NotFound);
    }

    let _ = record_audit(&state, &grant, "key_revoke", &key_id.to_string(), true, None).await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn audit_logs(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _) = effective_tenant(&grant, query.tenant_id)?;

    let rows = state
        .db
        .list_audit_logs(tenant_id, query.limit.clamp(1, 500))
        .await
        .map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AuditJson {
                id: row.id,
                tenant_id: row.tenant_id,
                principal: row.principal,
                action: row.action,
                resource: row.resource,
                result: row.result,
                reason: row.reason,
                created_at: row.created_at,
            })
            .collect(),
    ))
}