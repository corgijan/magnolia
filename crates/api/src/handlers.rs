use std::str::FromStr;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use magnolia_audit::{AuditLogEntry, AuditResult};
use magnolia_auth::{Action, Role};
use magnolia_core::{
    build_envelope, ed25519_public_key_base64, ed25519_public_key_pem, pae, profile_by_id,
    registered_profiles, ComplianceReport as CoreComplianceReport, ConsistencyProof,
    DocumentPredicate, DocumentStatement, InclusionProof, LicenseViolation as CoreLicenseViolation,
    ManifestPredicate, ManifestStatement, MerkleTree, SbomFormat, SignedTreeHead, Statement, Subject,
    DOCUMENT_PREDICATE_TYPE, DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE, MANIFEST_PREDICATE_TYPE,
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
    /// Present only when the upload declared a source repository (the
    /// Magnoliafile's `source_repo`): `"recorded"` when it is now the
    /// namespace's mapping, `"kept_existing"` when an admin-set mapping
    /// took precedence, `"not_recorded"` when saving it failed (the upload
    /// itself still succeeded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<&'static str>,
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
    /// This tenant's license-policy violations for this manifest's
    /// components — recomputed on read from the stored SBOM bytes and the
    /// tenant's current policy (same "always live, never a stale snapshot"
    /// convention as `compliance` above), so an edit to the policy is
    /// reflected immediately on every manifest, not just new uploads. Empty
    /// whenever the tenant's `enforce_level` is `off`.
    pub license_violations: Vec<LicenseViolationJson>,
    /// Cached deps.dev latest-version results for this manifest's
    /// components, classified against the installed version — populated in
    /// the background (see `freshness_sync.rs`), same "not checked yet, not
    /// an error" convention as `component_reputation`.
    pub component_freshness: Vec<ComponentFreshnessJson>,
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

/// One component's cached deps.dev latest-version result, classified
/// against the installed version. Only present for components with a
/// usable purl whose (ecosystem, registry_name) the freshness background
/// job has actually reached — see `freshness_sync.rs`.
#[derive(serde::Serialize)]
pub struct ComponentFreshnessJson {
    pub component_name: String,
    pub component_version: Option<String>,
    pub latest_version: Option<String>,
    /// `"current"` | `"behind"` | `"major_behind"` | `"unknown"` — `None`
    /// only when the freshness job hasn't reached this component yet
    /// (`checked_at` also `None`), distinct from `"unknown"` (checked, but
    /// one of the two version strings isn't parseable SemVer).
    pub status: Option<magnolia_core::FreshnessStatus>,
    pub checked_at: Option<DateTime<Utc>>,
    pub fetch_error: Option<String>,
}

/// Not a plain `From` impl since `status` is a derived field, not a stored
/// column — `None` only when the freshness job hasn't reached this
/// component yet; `Some(Unknown)` (as opposed to `None`) once it has been
/// checked but one of the two version strings isn't parseable SemVer, so
/// the frontend can tell "pending" apart from "checked, but can't compare."
fn component_freshness_json(r: magnolia_db::ComponentFreshnessRecord) -> ComponentFreshnessJson {
    let status = if r.checked_at.is_some() {
        match (r.component_version.as_deref(), r.latest_version.as_deref()) {
            (Some(cv), Some(lv)) => Some(magnolia_core::classify_freshness(cv, lv)),
            _ => Some(magnolia_core::FreshnessStatus::Unknown),
        }
    } else {
        None
    };
    ComponentFreshnessJson {
        component_name: r.component_name,
        component_version: r.component_version,
        latest_version: r.latest_version,
        status,
        checked_at: r.checked_at,
        fetch_error: r.fetch_error,
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

#[derive(serde::Serialize)]
pub struct LicensePolicyJson {
    pub denied_licenses: Vec<String>,
    /// "ignore" | "warn" | "flag" — see `magnolia_core::UnknownLicenseHandling`.
    pub unknown_license_handling: String,
    pub enforce_level: String,
}

#[derive(serde::Deserialize)]
pub struct SetLicensePolicyRequest {
    pub denied_licenses: Vec<String>,
    pub unknown_license_handling: String,
    pub enforce_level: String,
}

#[derive(serde::Serialize, Clone)]
pub struct LicenseViolationJson {
    pub component_name: String,
    pub component_version: Option<String>,
    pub license_expr: Option<String>,
    /// "denied" or "unknown" — see `magnolia_core::LicenseViolationReason`.
    pub reason: String,
    /// The specific denied identifier matched, e.g. "GPL-3.0-only" out of a
    /// compound "MIT AND GPL-3.0-only" expression — `None` for `unknown`.
    pub denied_license: Option<String>,
}

impl From<CoreLicenseViolation> for LicenseViolationJson {
    fn from(v: CoreLicenseViolation) -> Self {
        let (reason, denied_license) = match v.reason {
            magnolia_core::LicenseViolationReason::Denied { denied } => ("denied".to_string(), Some(denied)),
            magnolia_core::LicenseViolationReason::Unknown => ("unknown".to_string(), None),
        };
        Self {
            component_name: v.component_name,
            component_version: v.component_version,
            license_expr: v.license_expr,
            reason,
            denied_license,
        }
    }
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
    /// `"manual"` | `"vex_import"` | `null` (never triaged, or triaged
    /// before this field existed) — lets the UI show where the current
    /// triage came from, e.g. "imported from VEX".
    pub triage_source: Option<String>,
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
            triage_source: r.triage_source,
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
    pub triage_source: Option<String>,
    pub domain: String,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
    pub comment_count: i64,
    /// Cached state of the finding's latest reachability analysis
    /// (`queued`/`running`/`completed`/`failed`/`missing`), if any.
    pub reachability_status: Option<String>,
    /// The analysis' ordinal priority label once completed. Not a probability.
    pub reachability_priority: Option<String>,
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
    /// When true, only findings whose namespace has a source repository
    /// mapped — the ones a reachability analysis can run on.
    #[serde(default)]
    pub known_source: bool,
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
            query.known_source,
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
                triage_source: r.triage_source,
                domain: domain.clone(),
                namespace: r.namespace,
                release_version: r.release_version,
                revoked: r.revoked,
                comment_count: r.comment_count,
                reachability_status: r.reachability_status,
                reachability_priority: r.reachability_priority,
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
    pub license_expr: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ReindexResponse {
    pub manifests_indexed: usize,
    pub components_indexed: usize,
}

/// One manifest in a "blast radius" answer (`GET /components/affected`,
/// `GET /vulnerabilities/{id}/affected`) — deliberately thinner than
/// `ComponentSearchResultJson`: the caller already knows which component or
/// vulnerability it asked about, so only manifest identity/location is
/// echoed back.
#[derive(serde::Serialize)]
pub struct AffectedManifestJson {
    pub manifest_hash: String,
    pub domain: String,
    pub namespace: String,
    pub release_version: String,
    pub revoked: bool,
}

#[derive(serde::Deserialize)]
pub struct ComponentAffectedQuery {
    pub purl: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub current_only: bool,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Deserialize)]
pub struct VulnerabilityAffectedQuery {
    #[serde(default)]
    pub current_only: bool,
    pub tenant_id: Option<Uuid>,
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
    // Same "latest non-revoked upload per namespace, respecting namespace
    // visibility" definition as `ListFindingsQuery.current_only` — see
    // `search_sbom_components`'s doc comment.
    #[serde(default)]
    pub current_only: bool,
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

/// One registered compliance profile's report for a tenant, alongside the
/// `enforce_level` that report was checked under — the input
/// `enforce_compliance` needs to decide whether to reject, and `/verify`
/// needs to build its own check rows from, without either duplicating the
/// "which profiles are enabled, and applicable to this format" logic.
struct ComplianceEnforcementReport {
    enforce_level: String,
    report: CoreComplianceReport,
}

/// Every compliance profile this tenant has enabled that's applicable to
/// `format` — a pure read, no side effects, doesn't reject anything. Shared
/// by `enforce_compliance` (which rejects an upload based on it) and
/// `/verify` (which reports it directly as check rows).
async fn compliance_reports_for_tenant(
    state: &AppState,
    tenant_id: Uuid,
    format: &str,
    sbom_bytes: &[u8],
) -> Result<Vec<ComplianceEnforcementReport>, ApiError> {
    let mut out = Vec::new();
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
        out.push(ComplianceEnforcementReport { enforce_level: setting.enforce_level, report });
    }
    Ok(out)
}

/// Every registered compliance profile applicable to `format`, each paired
/// with this tenant's `enforce_level` for it — `"off"` when the tenant has
/// never enabled that profile at all, same convention
/// `license_violations_preview_for_tenant` uses for an unconfigured license
/// policy. Unlike `compliance_reports_for_tenant` (real enforcement, only
/// what's actually enabled), this always reports every applicable profile:
/// `/verify`'s preview wants to show what a document would score against
/// every profile, not just what this tenant currently enforces. Never
/// rejects anything.
async fn compliance_reports_preview_for_tenant(
    state: &AppState,
    tenant_id: Uuid,
    format: &str,
    sbom_bytes: &[u8],
) -> Result<Vec<ComplianceEnforcementReport>, ApiError> {
    let mut out = Vec::new();
    for profile in registered_profiles() {
        let report = profile.check(format, sbom_bytes);
        if !report.applicable {
            continue;
        }
        let enforce_level = match state.db.get_compliance_setting(tenant_id, profile.id()).await.map_err(db_err)? {
            Some(setting) if setting.enabled => setting.enforce_level,
            _ => "off".to_string(),
        };
        out.push(ComplianceEnforcementReport { enforce_level, report });
    }
    Ok(out)
}

/// Rejects an upload at the door when a compliance profile is enforced for
/// this tenant and the SBOM doesn't meet the configured bar. Runs after
/// schema validation (so `check()` can assume well-formed JSON) and after
/// the RBAC upload check (so an unauthorized caller learns nothing about
/// tenant policy), but before any side effect — storage write, Merkle
/// mutation, DB insert — so a rejection here leaves nothing to clean up.
async fn enforce_compliance(state: &AppState, tenant_id: Uuid, format: &str, sbom_bytes: &[u8]) -> Result<(), ApiError> {
    for r in compliance_reports_for_tenant(state, tenant_id, format, sbom_bytes).await? {
        if !r.report.meets_minimum {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} minimum compliance: {}",
                r.report.profile_name,
                r.report.minimum_issues.join("; ")
            )));
        }
        if r.enforce_level == "full" && !r.report.fully_compliant {
            return Err(ApiError::BadRequest(format!(
                "upload rejected: does not meet {} full compliance, missing: {}",
                r.report.profile_name,
                r.report.missing_fields.join("; ")
            )));
        }
    }
    Ok(())
}

/// This tenant's current license-policy violations for `sbom_bytes`, plus
/// the policy's `enforce_level` — shared by upload-time enforcement, live
/// manifest reads (`manifest()`), and `/verify`, so `extract_components` +
/// `evaluate_license_policy` are wired to a tenant's stored policy in
/// exactly one place. `enforce_level` is `"off"` (with an empty violations
/// list) when the tenant has never set a policy — same "always a full
/// answer" convention `get_tenant_license_policy`'s callers already use.
async fn license_violations_for_tenant(
    state: &AppState,
    tenant_id: Uuid,
    format: &str,
    sbom_bytes: &[u8],
) -> Result<(Vec<CoreLicenseViolation>, String, magnolia_core::UnknownLicenseHandling), ApiError> {
    let Some(policy) = state.db.get_tenant_license_policy(tenant_id).await.map_err(db_err)? else {
        return Ok((Vec::new(), "off".to_string(), magnolia_core::UnknownLicenseHandling::Ignore));
    };
    let unknown_handling = magnolia_core::UnknownLicenseHandling::parse(&policy.unknown_license_handling);
    if policy.enforce_level == "off" {
        return Ok((Vec::new(), policy.enforce_level, unknown_handling));
    }
    let components = magnolia_core::extract_components(format, sbom_bytes);
    let core_policy =
        magnolia_core::LicensePolicy { denied_licenses: policy.denied_licenses, unknown_license_handling: unknown_handling };
    let violations = magnolia_core::evaluate_license_policy(&components, &core_policy);
    Ok((violations, policy.enforce_level, unknown_handling))
}

/// Same evaluation as `license_violations_for_tenant`, but never gated on
/// `enforce_level == "off"` — used by `/verify`'s preview, which wants to
/// show what WOULD flag against this tenant's configured deny-list/
/// unknown-license handling even before enforcement is turned on. A tenant
/// that's never touched the license policy at all gets an empty deny-list
/// here (not an error), which naturally yields zero violations.
async fn license_violations_preview_for_tenant(
    state: &AppState,
    tenant_id: Uuid,
    format: &str,
    sbom_bytes: &[u8],
) -> Result<(Vec<CoreLicenseViolation>, String, magnolia_core::UnknownLicenseHandling), ApiError> {
    let policy = state.db.get_tenant_license_policy(tenant_id).await.map_err(db_err)?;
    let (denied_licenses, unknown_handling, enforce_level) = match policy {
        Some(p) => (p.denied_licenses, magnolia_core::UnknownLicenseHandling::parse(&p.unknown_license_handling), p.enforce_level),
        None => (Vec::new(), magnolia_core::UnknownLicenseHandling::Ignore, "off".to_string()),
    };
    let components = magnolia_core::extract_components(format, sbom_bytes);
    let core_policy = magnolia_core::LicensePolicy { denied_licenses, unknown_license_handling: unknown_handling };
    let violations = magnolia_core::evaluate_license_policy(&components, &core_policy);
    Ok((violations, enforce_level, unknown_handling))
}

fn license_violation_detail(v: &CoreLicenseViolation) -> String {
    match &v.reason {
        magnolia_core::LicenseViolationReason::Denied { denied } => format!("{} ({})", v.component_name, denied),
        magnolia_core::LicenseViolationReason::Unknown => format!("{} (no license information)", v.component_name),
    }
}

/// Rejects an upload at the door when this tenant's license policy is set to
/// `block` and the SBOM contains a denied (or, with `flag_unknown` set,
/// license-less) component. Runs alongside `enforce_compliance`, at the same
/// point in the pipeline and for the same reason: once
/// `index_manifest_components` runs below, the SBOM is already stored and
/// its Merkle leaf/manifest record already committed — nothing past that
/// point can be un-committed, so `block` enforcement can't be deferred to
/// that best-effort indexing step and instead re-extracts components here,
/// before any side effect.
async fn enforce_license_policy(
    state: &AppState,
    tenant_id: Uuid,
    format: &str,
    sbom_bytes: &[u8],
) -> Result<(), ApiError> {
    let (violations, enforce_level, unknown_handling) =
        license_violations_for_tenant(state, tenant_id, format, sbom_bytes).await?;
    if magnolia_core::license_policy_status(&violations, &enforce_level, unknown_handling) != "fail" {
        return Ok(());
    }
    let details: Vec<String> = violations.iter().map(license_violation_detail).collect();
    Err(ApiError::BadRequest(format!("upload rejected: license policy violation: {}", details.join("; "))))
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
            // `Some(String::new())`/sentinel for "has a purl, ran through
            // purl_to_depsdev_package, no deps.dev mapping for this purl
            // type" vs. `None` for "no purl at all" — the distinction lets
            // `reputation_sync`'s backfill phase tell a genuinely
            // never-attempted row (`ecosystem IS NULL`) apart from one that
            // was attempted and correctly found nothing, so it doesn't keep
            // re-attempting the latter forever. See that phase's doc
            // comment.
            let (ecosystem, registry_name) = match c.purl.as_deref().filter(|p| !p.is_empty()) {
                None => (None, None),
                Some(purl) => match magnolia_core::purl_to_depsdev_package(purl) {
                    Some((eco, name)) => (Some(eco.to_string()), Some(name)),
                    None => (Some(String::new()), None),
                },
            };
            magnolia_db::NewSbomComponent {
                name: c.name,
                version: c.version,
                purl: c.purl,
                cpe: c.cpe,
                is_primary: c.is_primary,
                ecosystem,
                registry_name,
                license_expr: c.license,
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
    // `DISABLE_MALICIOUS_PACKAGE_CHECK` is set for this deployment. Only
    // marks `malicious_checked_at` on a successful check, so a failed
    // upload-time check still gets picked up by `malicious_sync`'s next
    // pass instead of silently waiting out the full rescan interval.
    if let Some(osv) = &state.osv {
        let result =
            crate::malicious_check::check_and_store_malicious_components(&state.db, osv, manifest_hash, &components)
                .await;
        if let Ok(new_findings) = &result {
            if let Err(e) = state.db.touch_manifest_malicious_checked(manifest_hash).await {
                tracing::warn!(manifest_hash = %manifest_hash, error = %e, "failed to record malicious_checked_at");
            }
            if !new_findings.is_empty() {
                crate::webhooks::emit_event(
                    &state.db,
                    tenant_id,
                    crate::webhooks::EVENT_MALICIOUS_MATCH_FOUND,
                    serde_json::json!({
                        "manifest_hash": manifest_hash,
                        "matches": new_findings.iter().map(|f| serde_json::json!({
                            "component_name": f.component_name,
                            "component_version": f.component_version,
                            "osv_id": f.osv_id,
                        })).collect::<Vec<_>>(),
                    }),
                )
                .await;
            }
        }
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

/// Served at `/install.py` so `curl -fsSL <tenant_url>/install.py | python3
/// - -- --tenant-domain=...` works -- a stdlib-only Python port of the same
/// tool (same flags, same Magnoliafile format, same exit codes; see
/// scripts/magnolia-upload.py's own module docstring), for environments
/// that have python3 but not bash (or just prefer it) -- Python is the
/// primary, most-documented path in the README; `/install.sh` stays for
/// bash-only environments.
const MAGNOLIA_UPLOAD_SCRIPT_PY: &str = include_str!("../../../scripts/magnolia-upload.py");

pub async fn install_script_py() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/x-python; charset=utf-8")],
        MAGNOLIA_UPLOAD_SCRIPT_PY,
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
    /// Currently always equal to `reputation_enabled` — freshness checking
    /// shares deps.dev's presence gate (see `freshness_sync.rs`'s module
    /// doc comment) — but surfaced as its own field so the frontend doesn't
    /// have to know that's true today.
    pub freshness_enabled: bool,
    pub malicious_check_enabled: bool,
    /// Whether this deployment has a CVE-reachability analyser configured.
    /// The UI hides the "Analyze reachability" affordance entirely when
    /// false, rather than showing a button that can only fail.
    pub reachability_enabled: bool,
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
        freshness_enabled: state.depsdev.is_some(),
        malicious_check_enabled: state.osv.is_some(),
        reachability_enabled: state.reach.is_some(),
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
pub struct FreshnessTenantSettingJson {
    pub disabled: bool,
}

/// This tenant's opt-out of the "Outdated components" panel appearing on
/// its own SBOM detail views — same read/write split and reasoning as
/// `reputation_tenant_setting`.
pub async fn freshness_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<FreshnessTenantSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(FreshnessTenantSettingJson { disabled: tenant.freshness_disabled }))
}

#[derive(serde::Deserialize)]
pub struct SetFreshnessTenantSettingRequest {
    pub disabled: bool,
}

/// Toggles this tenant's opt-out of the freshness panel — has no effect on
/// the background job itself (see the `freshness_disabled` migration
/// comment), only on display. `Action::ManageSettings`, same gate as
/// `set_reputation_tenant_setting`.
pub async fn set_freshness_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetFreshnessTenantSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_freshness_disabled(tenant_id, body.disabled).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "freshness_tenant_setting",
        &tenant_id.to_string(),
        true,
        Some(format!("disabled={}", body.disabled)),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct MaliciousCheckTenantSettingJson {
    pub disabled: bool,
}

/// This tenant's opt-out of the "malicious package" panel appearing on its
/// own SBOM detail views — distinct from `ConfigJson.malicious_check_enabled`,
/// which is deployment-wide and read-only here. Same read/write split as
/// `reputation_tenant_setting`.
pub async fn malicious_check_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<MaliciousCheckTenantSettingJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let tenant = state.db.get_tenant(tenant_id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    Ok(Json(MaliciousCheckTenantSettingJson { disabled: tenant.malicious_check_disabled }))
}

#[derive(serde::Deserialize)]
pub struct SetMaliciousCheckTenantSettingRequest {
    pub disabled: bool,
}

/// Toggles this tenant's opt-out of the malicious-package panel — same
/// display-only shape as `set_reputation_tenant_setting`: detection at
/// upload time (`check_and_store_malicious_components`) is untouched
/// either way, this only controls whether `manifest()`'s
/// `malicious_components` gets shown on this tenant's SBOM detail views.
pub async fn set_malicious_check_tenant_setting(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetMaliciousCheckTenantSettingRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    state.db.set_tenant_malicious_check_disabled(tenant_id, body.disabled).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "malicious_check_tenant_setting",
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

#[derive(serde::Deserialize)]
pub struct DeleteNamespaceQuery {
    pub namespace: String,
    pub tenant_id: Option<Uuid>,
}

/// Un-registers a namespace — the only way back once a wrong one (a typo,
/// most commonly) was registered and `require_namespace_registration` is
/// on: it would otherwise sit there forever, blocking the *correct*
/// namespace with no indication why, since `create_namespace` has no
/// expiry and no uniqueness check against near-misses. Same gate as
/// `create_namespace`. Idempotent: deleting an unregistered namespace
/// succeeds without error, same "nothing actionable differs either way"
/// reasoning that function's own doc comment gives.
pub async fn delete_namespace(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<DeleteNamespaceQuery>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let namespace = normalize_namespace(&q.namespace)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden("namespace out of scope".to_string()));
    }

    state.db.delete_namespace(tenant_id, &namespace).await.map_err(db_err)?;

    let _ = record_audit(&state, &grant, "namespace_delete", &namespace, true, None).await;

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
    // Optional: the git revision the SBOM was generated from, sent by the
    // upload CLI. Recorded so CVE-reachability analysis has an exact tree to
    // scan; without it that feature refuses to run rather than analysing a
    // moving branch head.
    let mut source_commit = String::new();
    // Optional: where this namespace's source lives (Magnoliafile
    // `source_repo`/`source_subpath`/`source_revision`). Recorded as the
    // namespace's repository mapping unless an admin already set one.
    let mut source_repo = String::new();
    let mut source_subpath = String::new();
    let mut source_revision = String::new();
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
            Some("source_commit") => source_commit = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid source_commit field", e))?
                .trim()
                .to_ascii_lowercase(),
            Some("source_repo") => source_repo = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid source_repo field", e))?,
            Some("source_subpath") => source_subpath = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid source_subpath field", e))?,
            Some("source_revision") => source_revision = next
                .text()
                .await
                .map_err(|e| multipart_err("invalid source_revision field", e))?,
            _ => {}
        }
    }

    let namespace = normalize_namespace(&namespace)?;
    if version.is_empty() {
        return Err(ApiError::BadRequest("version is required".to_string()));
    }

    // Rejected rather than silently dropped: an upload that believes it
    // recorded a revision, and didn't, would leave the reachability button
    // mysteriously disabled with nothing to point at.
    let source_commit = if source_commit.is_empty() {
        None
    } else {
        let looks_like_object_id = (source_commit.len() == 40 || source_commit.len() == 64)
            && source_commit.chars().all(|c| c.is_ascii_hexdigit());
        if !looks_like_object_id {
            return Err(ApiError::BadRequest(
                "source_commit must be a full 40- or 64-character git object id (`git rev-parse HEAD`), not a branch or tag"
                    .to_string(),
            ));
        }
        Some(source_commit)
    };

    // Validated before anything is stored, same as source_commit: a bad
    // value in the Magnoliafile should fail the CI step that introduced it.
    let declared_repo = parse_declared_source_repo(&source_repo, &source_subpath, &source_revision)?;

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
        enforce_license_policy(&state, tenant_id, &format, &sbom_bytes).await?;
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
        // Names the tenant's actual registered namespaces rather than just
        // rejecting -- a bare "not registered" message gives no way to spot
        // a typo (e.g. registering "/tets" and then trying to upload to
        // "/test"), which otherwise looks exactly like a stuck/broken
        // upload from the caller's side.
        let registered = state.db.list_registered_namespaces(tenant_id, "/").await.map_err(db_err)?;
        let hint = if registered.is_empty() {
            "no namespaces are registered for this tenant yet".to_string()
        } else {
            let names: Vec<&str> = registered.iter().map(|r| r.namespace.as_str()).take(20).collect();
            format!("registered namespaces: {}", names.join(", "))
        };
        return Err(ApiError::BadRequest(format!(
            "namespace '{namespace}' has not been registered for this tenant ({hint}); create it first, or check for a typo (see Settings)"
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
            source_commit.as_deref(),
        )
        .await
        .map_err(db_err)?;

    // After the manifest is stored, and never fatal: the SBOM is in the log
    // either way, and the mapping is a convenience the response reports on.
    let source_repo_outcome = match &declared_repo {
        None => None,
        Some(d) => Some(
            match state
                .db
                .set_namespace_repo_from_upload(
                    tenant_id,
                    &namespace,
                    &d.repo_url,
                    d.subpath.as_deref(),
                    d.revision.as_deref(),
                    &format!("{MAGNOLIAFILE_PRINCIPAL_PREFIX}{}", grant.principal()),
                )
                .await
            {
                Ok(Some(_)) => {
                    let _ = record_audit(
                        &state,
                        &grant,
                        "namespace_repo_set",
                        &format!("{}:{}", grant.domain, namespace),
                        true,
                        Some(format!(
                            "from upload; repo_url={}; revision={}",
                            d.repo_url,
                            d.revision.as_deref().unwrap_or("-")
                        )),
                    )
                    .await;
                    "recorded"
                }
                Ok(None) => "kept_existing",
                Err(e) => {
                    tracing::warn!(%namespace, error = %e, "could not record the upload's source repository");
                    "not_recorded"
                }
            },
        ),
    };

    crate::webhooks::emit_event(
        &state.db,
        tenant_id,
        crate::webhooks::EVENT_MANIFEST_UPLOADED,
        serde_json::json!({
            "manifest_hash": manifest_hash,
            "namespace": namespace,
            "version": version,
            "document_type": document_type_opt,
        }),
    )
    .await;

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

        // Same nudge, same reasoning, for package-reputation/freshness:
        // without this, a freshly uploaded component's score/latest-version
        // sits unscored until the next periodic tick (up to
        // `REPUTATION_SYNC_INTERVAL_SECS`/`FRESHNESS_SYNC_INTERVAL_SECS`
        // away, default 1h) even though `index_manifest_components` above
        // just gave `sync_pass` real work to do. Both passes are
        // deployment-wide (not scoped to this tenant/manifest — same shape
        // as the "Force sync now" buttons in Settings), so this can run
        // unconditionally whenever depsdev is configured at all; spawned,
        // never awaited, so a slow/failing deps.dev call can't block or
        // fail the upload response.
        if let Some(client) = state.depsdev.clone() {
            let db = state.db.clone();
            let reputation_client = client.clone();
            tokio::spawn(async move {
                crate::reputation_sync::sync_pass(&db, &reputation_client).await;
            });
            let db = state.db.clone();
            tokio::spawn(async move {
                crate::freshness_sync::sync_pass(&db, &client).await;
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
        source_repo: source_repo_outcome,
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

    let component_freshness: Vec<ComponentFreshnessJson> = state
        .db
        .list_freshness_for_manifest(&record.manifest_hash)
        .await
        .map_err(db_err)?
        .into_iter()
        .map(component_freshness_json)
        .collect();

    // Live-recomputed, not read back from `sbom_components.license_expr` —
    // same reasoning as `compliance` above: a policy edit should be
    // reflected on every existing manifest immediately, not just ones
    // reindexed since. `document` uploads have no components to extract
    // (matches `enforce_license_policy`/`index_manifest_components`
    // skipping them at upload time). Uses the *preview* variant, not
    // `license_violations_for_tenant` — this is a live "what would this
    // score" display like `/verify`'s, not a record of what was actually
    // enforced, so it stays populated even when `enforce_level == "off"`
    // (a tenant trying out "warn" on unknown-license handling should see
    // it reflected here immediately, not just once they also flip
    // Enforcement on).
    let license_violations: Vec<LicenseViolationJson> = if record.document_type.is_none() {
        license_violations_preview_for_tenant(&state, tenant_id, &record.sbom_format, &sbom_bytes)
            .await?
            .0
            .into_iter()
            .map(LicenseViolationJson::from)
            .collect()
    } else {
        Vec::new()
    };

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
        license_violations,
        component_freshness,
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
pub struct VexImportQuery {
    /// When `false` (the default), a statement matching a finding that
    /// already carries a human ("manual", or unset/legacy) triage is
    /// skipped rather than overwritten — counted in `skipped_manual`. A
    /// finding whose current triage is itself a *previous* VEX import is
    /// always safely refreshed regardless of this flag.
    #[serde(default)]
    pub overwrite: bool,
    pub tenant_id: Option<Uuid>,
}

#[derive(serde::Serialize)]
pub struct VexImportUnmatchedJson {
    pub vuln_id: String,
    pub reason: String,
}

#[derive(serde::Serialize)]
pub struct VexImportResponse {
    /// Findings whose triage was actually written by this import.
    pub applied: usize,
    /// Findings a statement matched but that were left untouched because
    /// they already carry a human triage and `overwrite` wasn't set.
    pub skipped_manual: usize,
    /// Statements that matched zero findings in this manifest at all —
    /// wrong vulnerability id, a product purl not found in this manifest's
    /// components, or a status/justification Magnolia doesn't recognize.
    pub unmatched: Vec<VexImportUnmatchedJson>,
}

/// Imports a supplier-provided VEX document and applies its statements to
/// this manifest's cached dtrack findings. OpenVEX only in v1 — CSAF 2.0 is
/// a documented follow-up (see `magnolia_core::parse_openvex`'s doc
/// comment). Matching is purely by exact vulnerability id — **no CVE↔GHSA
/// alias resolution**, a documented v1 gap: a statement about
/// "CVE-2024-1234" will not match a cached finding dtrack only ever
/// reported as "GHSA-xxxx" for the same underlying vulnerability, even
/// though they're the same vulnerability. When a statement names specific
/// products, matching is further narrowed by purl against this manifest's
/// indexed `sbom_components` — a statement naming no products applies to
/// every finding for its vulnerability id in this manifest.
///
/// Same `Action::Annotate`/tenant-namespace isolation gate as
/// `triage_finding`, since this is fundamentally a bulk triage write. The
/// raw document is stored in object storage next to the SBOM (provenance:
/// every applied finding gets a comment citing its storage key) before any
/// triage is applied, so it's preserved even if every statement turns out
/// unmatched.
pub async fn import_manifest_vex(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(manifest_hash): Path<String>,
    Query(q): Query<VexImportQuery>,
    mut multipart: Multipart,
) -> Result<Json<VexImportResponse>, ApiError> {
    require(&grant, Action::Annotate, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let record = state.db.get_manifest(&manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }

    let field = multipart
        .next_field()
        .await
        .map_err(|e| multipart_err("invalid multipart body", e))?
        .ok_or_else(|| ApiError::BadRequest("missing vex_file field".to_string()))?;
    let vex_bytes = field.bytes().await.map_err(|e| multipart_err("invalid vex_file field", e))?.to_vec();
    if vex_bytes.is_empty() {
        return Err(ApiError::BadRequest("vex_file is empty".to_string()));
    }
    if vex_bytes.len() > MAX_SBOM_BYTES {
        return Err(ApiError::BadRequest("vex_file exceeds 10 MiB limit".to_string()));
    }

    let statements =
        magnolia_core::parse_openvex(&vex_bytes).map_err(|e| ApiError::BadRequest(format!("invalid VEX document: {e}")))?;

    // Provenance, written before any triage is applied — same `tenants/{id}/...`
    // key convention as the SBOM itself (`upload_sbom`'s `s3_key`), content-hash
    // suffixed so re-importing the identical document twice doesn't collide
    // with (or overwrite) the first import's stored copy.
    let doc_hash = hex::encode(Sha256::digest(&vex_bytes));
    let vex_s3_key = format!("tenants/{}/vex/{}-{}.json", tenant_id, manifest_hash, &doc_hash[..16]);
    state
        .storage
        .put(&vex_s3_key, &vex_bytes)
        .await
        .map_err(|e| ApiError::InternalError(format!("storage put failed: {}", e)))?;

    let findings = state.db.list_dtrack_findings(&manifest_hash).await.map_err(db_err)?;
    let components = state.db.list_sbom_components_for_manifest(&manifest_hash).await.map_err(db_err)?;

    // Resolved once up front, same "don't push to dtrack when sync is off
    // for this tenant" gate `triage_finding` applies per-call.
    let dtrack_ready = match &state.dtrack {
        Some(client) => {
            let sync_disabled = state
                .db
                .get_tenant(tenant_id)
                .await
                .map(|t| t.map(|t| t.dtrack_sync_disabled).unwrap_or(true))
                .unwrap_or(true);
            (!sync_disabled).then(|| client.clone())
        }
        None => None,
    };

    let mut applied = 0usize;
    let mut skipped_manual = 0usize;
    let mut unmatched = Vec::new();

    for stmt in statements {
        if !["affected", "not_affected", "fixed", "under_investigation"].contains(&stmt.status.as_str()) {
            unmatched.push(VexImportUnmatchedJson {
                vuln_id: stmt.vuln_id,
                reason: format!("unrecognized status '{}'", stmt.status),
            });
            continue;
        }
        if stmt.status == "not_affected"
            && !stmt.justification.as_deref().map(|j| VEX_JUSTIFICATIONS.contains(&j)).unwrap_or(false)
        {
            unmatched.push(VexImportUnmatchedJson {
                vuln_id: stmt.vuln_id,
                reason: "missing or unrecognized justification for a not_affected statement".to_string(),
            });
            continue;
        }

        // Product scoping: `None` means the statement named no products
        // (applies to every finding for this vuln_id); `Some` is the set of
        // (component_name, component_version) pairs this manifest's
        // indexed components resolve the statement's purls to.
        let scoped_components: Option<std::collections::HashSet<(String, Option<String>)>> = if stmt.purls.is_empty()
        {
            None
        } else {
            Some(
                components
                    .iter()
                    .filter(|c| c.purl.as_deref().map(|p| stmt.purls.iter().any(|sp| sp == p)).unwrap_or(false))
                    .map(|c| (c.name.clone(), c.version.clone()))
                    .collect(),
            )
        };

        let matched: Vec<&DtrackFindingRecord> = findings
            .iter()
            .filter(|f| f.vulnerability_id == stmt.vuln_id)
            .filter(|f| match &scoped_components {
                None => true,
                Some(set) => set.contains(&(f.component_name.clone(), f.component_version.clone())),
            })
            .collect();

        if matched.is_empty() {
            let reason = if stmt.purls.is_empty() {
                format!("no cached finding for {} in this manifest", stmt.vuln_id)
            } else {
                "no component in this manifest matches the statement's product purl(s)".to_string()
            };
            unmatched.push(VexImportUnmatchedJson { vuln_id: stmt.vuln_id, reason });
            continue;
        }

        for finding in matched {
            let has_existing_triage = finding.vex_status.is_some();
            let human_owned = has_existing_triage && finding.triage_source.as_deref() != Some("vex_import");
            if human_owned && !q.overwrite {
                skipped_manual += 1;
                continue;
            }

            let Ok(Some(updated)) = state
                .db
                .set_finding_triage(
                    &manifest_hash,
                    &finding.finding_key,
                    &stmt.status,
                    stmt.justification.as_deref(),
                    stmt.status_notes.as_deref(),
                    &grant.principal(),
                    "vex_import",
                )
                .await
            else {
                continue;
            };
            applied += 1;

            let _ = state
                .db
                .add_finding_comment(
                    &manifest_hash,
                    &finding.finding_key,
                    &grant.principal(),
                    &format!("Applied from imported VEX document ({vex_s3_key}): status={}", stmt.status),
                )
                .await;

            if let Some(client) = &dtrack_ready {
                if let (Some(cuuid), Some(vuuid)) = (&updated.component_uuid, &updated.vulnerability_uuid) {
                    crate::dtrack_sync::push_triage_to_dtrack(
                        &state.db,
                        client,
                        &manifest_hash,
                        cuuid,
                        vuuid,
                        &stmt.status,
                        stmt.justification.as_deref(),
                        stmt.status_notes.as_deref(),
                    )
                    .await;
                }
            }
        }
    }

    let _ = record_audit(
        &state,
        &grant,
        "vex_import",
        &manifest_hash,
        true,
        Some(format!("applied={applied}; skipped_manual={skipped_manual}; unmatched={}", unmatched.len())),
    )
    .await;

    Ok(Json(VexImportResponse { applied, skipped_manual, unmatched }))
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
pub struct VerifyCheckJson {
    pub id: String,
    /// "pass" | "fail" | "warn" | "not_evaluated".
    pub status: String,
    /// The enforce level this check ran under — echoes the tenant's own
    /// configuration (compliance profile's/license policy's enforce_level),
    /// "warn" for the fixed-informational malicious-package check, or "n/a"
    /// for the always-`not_evaluated` async signals.
    pub enforce_level: String,
    pub details: Vec<String>,
}

/// Per-profile compliance detail behind `VerifyResponse::compliance` —
/// `checks` only carries a flattened pass/fail/warn status, which collapses
/// "meets the minimum bar but isn't fully compliant" and "doesn't even meet
/// the minimum bar" into the same "warn"/"fail" label. This carries
/// `meets_minimum`/`fully_compliant` explicitly so the UI can show that
/// distinction directly instead of the caller reverse-engineering it from a
/// status string.
#[derive(serde::Serialize)]
pub struct VerifyComplianceJson {
    pub profile_id: String,
    pub profile_name: String,
    /// This tenant's enforce_level for this profile — "off" when the
    /// profile isn't enabled at all, same convention `checks` uses.
    pub enforce_level: String,
    pub meets_minimum: bool,
    pub minimum_issues: Vec<String>,
    pub fully_compliant: bool,
    pub missing_fields: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct VerifyResponse {
    /// "pass" | "fail" — "fail" iff at least one check's status is "fail".
    /// A "warn"-status check never flips this to "fail": CI decides its own
    /// strictness by reading `checks`, this field alone is "would the
    /// equivalent upload have been accepted."
    pub verdict: String,
    pub checks: Vec<VerifyCheckJson>,
    /// Same compliance-profile results as the `compliance:*` rows in
    /// `checks` above, kept there too for CI scripts that just walk
    /// `checks` generically — this is the richer, UI-friendly view of the
    /// exact same evaluation.
    pub compliance: Vec<VerifyComplianceJson>,
}

fn verify_check(id: &str, status: &str, enforce_level: &str, details: Vec<String>) -> VerifyCheckJson {
    VerifyCheckJson { id: id.to_string(), status: status.to_string(), enforce_level: enforce_level.to_string(), details }
}

/// `POST /verify` — the CI policy gate: runs the exact same schema,
/// compliance-profile, and license-policy checks `upload_sbom` enforces,
/// plus a synchronous malicious-package check, against caller-supplied
/// bytes that are never stored, indexed, or added to the Merkle log — no
/// `sbom_file` reaches `state.storage`, no leaf/manifest row is written, no
/// namespace or version is even required. A dry run for CI to gate a
/// pipeline step on before an actual `upload_sbom` call.
///
/// Package reputation and Dependency-Track findings are inherently
/// asynchronous — populated by background jobs on their own schedules, not
/// computable synchronously from SBOM bytes alone — and are reported
/// `not_evaluated` rather than making CI wait on external service latency
/// or giving a false "pass" for something that was never actually checked.
///
/// `Action::Upload` — strictly weaker than an actual upload (nothing is
/// written here), so this reuses that permission rather than inventing a
/// separate one.
pub async fn verify_sbom(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    mut multipart: Multipart,
) -> Result<Json<VerifyResponse>, ApiError> {
    require(&grant, Action::Upload, &grant.namespace_scope)?;

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
            format = next.text().await.map_err(|e| multipart_err("invalid format field", e))?.to_lowercase();
        }
    }

    if sbom_bytes.is_empty() {
        return Err(ApiError::BadRequest("sbom_file is empty".to_string()));
    }
    if sbom_bytes.len() > MAX_SBOM_BYTES {
        return Err(ApiError::BadRequest("sbom_file exceeds 10 MiB limit".to_string()));
    }
    if !matches!(format.as_str(), "cyclonedx" | "spdx") {
        return Err(ApiError::BadRequest(format!("unsupported format: {} (use cyclonedx or spdx)", format)));
    }

    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let mut checks = Vec::new();
    let mut compliance = Vec::new();

    // ---- schema: everything below assumes well-formed JSON matching the
    // format's spec (same precondition `ComplianceProfile::check` and
    // `extract_components` document), so a schema failure short-circuits
    // every other check rather than running them against malformed input.
    let schema_ok = match validate_sbom_content(&sbom_bytes, &format) {
        Ok(()) => {
            checks.push(verify_check("schema", "pass", "block", Vec::new()));
            true
        }
        Err(e) => {
            checks.push(verify_check("schema", "fail", "block", vec![e.to_string()]));
            false
        }
    };

    if schema_ok {
        // ---- compliance profiles — previews EVERY registered profile
        // applicable to this format (BSI TR-03183, NTIA, etc.), not just
        // the ones this tenant has enabled: this used to be the Tools tab's
        // separate "Check compliance" tool, folded in here so the policy
        // gate is the one place that answers "what would this SBOM score."
        // A profile this tenant hasn't enabled reports under `enforce_level
        // "off"` and can only ever "pass"/"warn" — it never flips the
        // verdict, since nothing here is actually being enforced for it.
        for r in compliance_reports_preview_for_tenant(&state, tenant_id, &format, &sbom_bytes).await? {
            let mut details = r.report.minimum_issues.clone();
            details.extend(r.report.missing_fields.clone());
            let compliant = r.report.meets_minimum && r.report.fully_compliant;
            let status = if r.enforce_level == "off" {
                if compliant { "pass" } else { "warn" }
            } else if !r.report.meets_minimum {
                "fail"
            } else if r.enforce_level == "full" && !r.report.fully_compliant {
                "fail"
            } else if !r.report.fully_compliant {
                "warn"
            } else {
                "pass"
            };
            checks.push(verify_check(&format!("compliance:{}", r.report.profile_id), status, &r.enforce_level, details));
            compliance.push(VerifyComplianceJson {
                profile_id: r.report.profile_id.clone(),
                profile_name: r.report.profile_name.clone(),
                enforce_level: r.enforce_level.clone(),
                meets_minimum: r.report.meets_minimum,
                minimum_issues: r.report.minimum_issues.clone(),
                fully_compliant: r.report.fully_compliant,
                missing_fields: r.report.missing_fields.clone(),
            });
        }

        // ---- license policy — always previewed against this tenant's
        // configured deny-list/unknown-license handling, even when
        // enforce_level is "off" or nothing has been configured yet (an
        // empty deny-list then, not an error). Also folded in from the
        // former Tools "Check compliance" tool — a tenant drafting a policy
        // wants to preview its effect before flipping enforcement on. Only
        // actually fails the verdict when `enforce_level == "block"` AND at
        // least one violation is severe enough to block (a denied license,
        // or an unknown-license one under "flag" handling — see
        // `license_policy_status`; "warn" handling never blocks).
        let (violations, license_enforce_level, unknown_handling) =
            license_violations_preview_for_tenant(&state, tenant_id, &format, &sbom_bytes).await?;
        let status = magnolia_core::license_policy_status(&violations, &license_enforce_level, unknown_handling);
        let details = violations.iter().map(license_violation_detail).collect();
        checks.push(verify_check("license-policy", status, &license_enforce_level, details));

        // ---- malicious packages + general vulnerabilities (synchronous OSV
        // querybatch — the same shared check `index_manifest_components`
        // uses at upload time, see `malicious_check::find_malicious_components`).
        // One querybatch call backs both checks below; neither fails the
        // verdict on its own (matches real uploads, which are never
        // rejected for this) — "warn" only.
        match &state.osv {
            Some(osv) => {
                let extracted = magnolia_core::extract_components(&format, &sbom_bytes);
                let components: Vec<magnolia_db::NewSbomComponent> = extracted
                    .into_iter()
                    .map(|c| magnolia_db::NewSbomComponent {
                        name: c.name,
                        version: c.version,
                        purl: c.purl,
                        cpe: c.cpe,
                        is_primary: c.is_primary,
                        ecosystem: None,
                        registry_name: None,
                        license_expr: None,
                    })
                    .collect();
                match crate::malicious_check::find_malicious_components(osv, &components).await {
                    Some(result) => {
                        let malicious_status = if result.malicious.is_empty() { "pass" } else { "warn" };
                        let malicious_details =
                            result.malicious.iter().map(|f| format!("{} ({})", f.component_name, f.osv_id)).collect();
                        checks.push(verify_check("malicious-packages", malicious_status, "warn", malicious_details));

                        let vuln_status = if result.vulnerabilities.is_empty() { "pass" } else { "warn" };
                        let vuln_details = result
                            .vulnerabilities
                            .iter()
                            .map(|v| format!("{} ({})", v.component_name, v.vuln_id))
                            .collect();
                        checks.push(verify_check("vulnerabilities", vuln_status, "warn", vuln_details));
                    }
                    None => {
                        checks.push(verify_check(
                            "malicious-packages",
                            "not_evaluated",
                            "warn",
                            vec!["OSV lookup failed".to_string()],
                        ));
                        checks.push(verify_check(
                            "vulnerabilities",
                            "not_evaluated",
                            "warn",
                            vec!["OSV lookup failed".to_string()],
                        ));
                    }
                }
            }
            None => {
                checks.push(verify_check(
                    "malicious-packages",
                    "not_evaluated",
                    "warn",
                    vec!["malicious-package checking is disabled for this deployment".to_string()],
                ));
                checks.push(verify_check(
                    "vulnerabilities",
                    "not_evaluated",
                    "warn",
                    vec!["OSV-backed vulnerability checking is disabled for this deployment".to_string()],
                ));
            }
        }

        // ---- outdated components (major-version-behind only, warn-only —
        // a read against the freshness background job's existing cache, no
        // live deps.dev call in the request path, so this doesn't add to
        // CI's external latency the way a fresh lookup would).
        match &state.depsdev {
            Some(_) => {
                let extracted = magnolia_core::extract_components(&format, &sbom_bytes);
                let mut major_behind = Vec::new();
                for c in &extracted {
                    let (Some(purl), Some(version)) = (c.purl.as_deref().filter(|p| !p.is_empty()), c.version.as_deref())
                    else {
                        continue;
                    };
                    let Some((ecosystem, name)) = magnolia_core::purl_to_depsdev_package(purl) else { continue };
                    if let Ok(Some(latest)) = state.db.get_component_freshness(ecosystem, &name).await {
                        if magnolia_core::classify_freshness(version, &latest) == magnolia_core::FreshnessStatus::MajorBehind
                        {
                            major_behind.push(format!("{} ({version} → {latest})", c.name));
                        }
                    }
                }
                let status = if major_behind.is_empty() { "pass" } else { "warn" };
                checks.push(verify_check("outdated-components", status, "warn", major_behind));
            }
            None => checks.push(verify_check(
                "outdated-components",
                "not_evaluated",
                "warn",
                vec!["freshness checking is disabled for this deployment".to_string()],
            )),
        }
    }

    // ---- package reputation (OpenSSF Scorecard, warn-only — a read
    // against the reputation background job's existing cache, no live
    // deps.dev call in the request path; same "cache read, not a live
    // call" shape as `outdated-components` above, and gated on the same
    // `state.depsdev` since `component_reputation` is populated by the
    // reputation-sync loop that requires it).
    match &state.depsdev {
        Some(_) => {
            let extracted = magnolia_core::extract_components(&format, &sbom_bytes);
            let mut low_reputation = Vec::new();
            for c in &extracted {
                let Some(purl) = c.purl.as_deref().filter(|p| !p.is_empty()) else { continue };
                let Some((ecosystem, name)) = magnolia_core::purl_to_depsdev_package(purl) else { continue };
                if let Ok(Some(score)) = state.db.get_component_reputation(ecosystem, &name).await {
                    if crate::reputation_bucket::bucket_for_score(score) == crate::reputation_bucket::ReputationBucket::Red {
                        low_reputation.push(format!("{} (score {score:.1})", c.name));
                    }
                }
            }
            let status = if low_reputation.is_empty() { "pass" } else { "warn" };
            checks.push(verify_check("package-reputation", status, "warn", low_reputation));
        }
        None => checks.push(verify_check(
            "package-reputation",
            "not_evaluated",
            "warn",
            vec!["reputation checking is disabled for this deployment".to_string()],
        )),
    }

    // ---- async-by-nature signals: never evaluated synchronously, see this
    // function's doc comment.
    checks.push(verify_check(
        "dependency-track",
        "not_evaluated",
        "n/a",
        vec!["Dependency-Track scanning runs asynchronously; not evaluated synchronously".to_string()],
    ));

    let verdict = if checks.iter().any(|c| c.status == "fail") { "fail" } else { "pass" };

    record_audit(
        &state,
        &grant,
        "verify",
        &format!("{}:{}", grant.domain, format),
        verdict == "pass",
        Some(format!("verdict={}", verdict)),
    )
    .await;

    Ok(Json(VerifyResponse { verdict: verdict.to_string(), checks, compliance }))
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

/// This tenant's license policy — defaults reported when the tenant has
/// never set one (`enforce_level: "off"`, empty deny-list), same "always a
/// full answer, never a 404" convention as `compliance_settings`.
/// `Action::Read`; only `set_license_policy` requires `ManageSettings`.
pub async fn license_policy(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<LicensePolicyJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let row = state.db.get_tenant_license_policy(tenant_id).await.map_err(db_err)?;
    Ok(Json(match row {
        Some(r) => LicensePolicyJson {
            denied_licenses: r.denied_licenses,
            unknown_license_handling: r.unknown_license_handling,
            enforce_level: r.enforce_level,
        },
        None => LicensePolicyJson {
            denied_licenses: Vec::new(),
            unknown_license_handling: "ignore".to_string(),
            enforce_level: "off".to_string(),
        },
    }))
}

/// Sets this tenant's license policy. `Action::ManageSettings` — same gate
/// as `set_compliance_setting`, since `block` can reject uploads tenant-wide.
pub async fn set_license_policy(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetLicensePolicyRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    if !matches!(body.enforce_level.as_str(), "off" | "warn" | "block") {
        return Err(ApiError::BadRequest("enforce_level must be one of: off, warn, block".to_string()));
    }
    if !matches!(body.unknown_license_handling.as_str(), "ignore" | "warn" | "flag") {
        return Err(ApiError::BadRequest(
            "unknown_license_handling must be one of: ignore, warn, flag".to_string(),
        ));
    }
    let denied_licenses: Vec<String> =
        body.denied_licenses.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let invalid: Vec<&str> = denied_licenses
        .iter()
        .map(String::as_str)
        .filter(|id| !magnolia_core::is_valid_spdx_license_id(id))
        .collect();
    if !invalid.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "not a recognized SPDX license identifier (case-sensitive): {}",
            invalid.join(", ")
        )));
    }
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    state
        .db
        .set_tenant_license_policy(
            tenant_id,
            &denied_licenses,
            &body.unknown_license_handling,
            &body.enforce_level,
            &grant.principal(),
        )
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
            query.current_only,
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
                license_expr: r.license_expr,
            })
            .collect(),
    ))
}

/// "Which namespaces/manifests contain component X" — the component side of
/// blast radius. Same `Action::Read` + namespace-scope honoring as
/// `search_components`; at least one of `purl`/`name` is required, same
/// convention as that endpoint.
pub async fn components_affected(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(query): Query<ComponentAffectedQuery>,
) -> Result<Json<Vec<AffectedManifestJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let purl = query.purl.as_deref().filter(|s| !s.is_empty());
    let name = query.name.as_deref().filter(|s| !s.is_empty());
    let version = query.version.as_deref().filter(|s| !s.is_empty());
    if purl.is_none() && name.is_none() {
        return Err(ApiError::BadRequest("provide at least one of purl or name".to_string()));
    }

    let domain = if cross_tenant {
        state.db.get_tenant(tenant_id).await.map_err(db_err)?.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let rows = state
        .db
        .list_manifests_containing_component(tenant_id, scope, purl, name, version, query.current_only)
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AffectedManifestJson {
                manifest_hash: r.manifest_hash,
                domain: domain.clone(),
                namespace: r.namespace,
                release_version: r.release_version,
                revoked: r.revoked,
            })
            .collect(),
    ))
}

/// "Which manifests are affected by CVE/advisory Y" — the vulnerability
/// side of blast radius. Matches both `dtrack_findings` (CVE/GHSA ids) and
/// `malicious_component_findings` (OSV `MAL-` ids) so one id, from either
/// signal source, resolves to every manifest it touches.
pub async fn vulnerability_affected(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(vuln_id): Path<String>,
    Query(query): Query<VulnerabilityAffectedQuery>,
) -> Result<Json<Vec<AffectedManifestJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, query.tenant_id)?;
    let scope = if cross_tenant { "/" } else { &grant.namespace_scope };

    let domain = if cross_tenant {
        state.db.get_tenant(tenant_id).await.map_err(db_err)?.map(|t| t.domain).unwrap_or_default()
    } else {
        grant.domain.clone()
    };

    let rows = state
        .db
        .list_manifests_affected_by_vulnerability(tenant_id, scope, &vuln_id, query.current_only)
        .await
        .map_err(db_err)?;

    Ok(Json(
        rows.into_iter()
            .map(|r| AffectedManifestJson {
                manifest_hash: r.manifest_hash,
                domain: domain.clone(),
                namespace: r.namespace,
                release_version: r.release_version,
                revoked: r.revoked,
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
pub struct ClearTenantCachesResponse {
    pub component_index_rows: u64,
    pub malicious_findings_rows: u64,
    pub dtrack_findings_rows: u64,
    pub dtrack_projects_rows: u64,
}

/// Deletes this tenant's derived/cached data — the component-search index
/// (`sbom_components`), cached malicious-package findings, and cached
/// Dependency-Track findings/projects — without touching manifests, the
/// Merkle log, or stored SBOM bytes. Every one of these is rebuilt from
/// source on its own schedule (a fresh upload or `reindex_components` for
/// the component index, the next OSV sync for malicious findings, the next
/// dtrack sync for dtrack data), so this is always recoverable, just not
/// instantly.
///
/// `Action::ManageTenantData` — **super_admin only**, deliberately stricter
/// than the `ManageSettings` gate `reindex_components` uses. Reindexing only
/// ever adds rows; this deletes them in bulk, and the dtrack half cascades
/// into `finding_comments`, destroying human-authored triage notes that no
/// background sync can rebuild. That is not something a `domain_admin`
/// should be able to do to a tenant by accident.
///
/// Two real side effects worth knowing before using this (also called out
/// in `clear_malicious_findings_for_tenant`/`clear_dtrack_cache_for_tenant`'s
/// own doc comments): clearing malicious findings can re-fire
/// `malicious.match_found` webhooks for previously-known hits on the next
/// OSV sync; clearing dtrack findings permanently loses any manual
/// triage/VEX comments recorded on them (`finding_comments` cascades).
pub async fn clear_tenant_caches(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ClearTenantCachesResponse>, ApiError> {
    require(&grant, Action::ManageTenantData, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let component_index_rows = state.db.clear_component_index(tenant_id).await.map_err(db_err)?;
    let malicious_findings_rows = state.db.clear_malicious_findings_for_tenant(tenant_id).await.map_err(db_err)?;
    let (dtrack_findings_rows, dtrack_projects_rows) =
        state.db.clear_dtrack_cache_for_tenant(tenant_id).await.map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "clear_tenant_caches",
        &format!(
            "components={component_index_rows} malicious={malicious_findings_rows} \
             dtrack_findings={dtrack_findings_rows} dtrack_projects={dtrack_projects_rows}"
        ),
        true,
        None,
    )
    .await;

    Ok(Json(ClearTenantCachesResponse {
        component_index_rows,
        malicious_findings_rows,
        dtrack_findings_rows,
        dtrack_projects_rows,
    }))
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
pub struct FreshnessSyncResponse {
    pub components_processed: usize,
}

/// Runs one on-demand batch of the freshness background job (see
/// `freshness_sync.rs`) — same deployment-global, `Action::ManageSettings`
/// shape as `force_reputation_sync`. 400 if reputation/freshness scoring
/// isn't enabled for this deployment (freshness shares `depsdev`'s presence
/// gate — there is no separate `DISABLE_FRESHNESS_CHECK` flag, see
/// `freshness_sync.rs`'s module doc comment).
pub async fn force_freshness_sync(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<FreshnessSyncResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;

    let client = state
        .depsdev
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("package freshness checking is disabled for this deployment".to_string()))?;

    let components_processed = crate::freshness_sync::sync_pass(&state.db, client).await;

    let _ = record_audit(
        &state,
        &grant,
        "freshness_force_sync",
        &format!("components_processed={components_processed}"),
        true,
        None,
    )
    .await;

    Ok(Json(FreshnessSyncResponse { components_processed }))
}

#[derive(serde::Serialize)]
pub struct FreshnessStatusJson {
    pub pending: i64,
    pub checked: i64,
    pub failed: i64,
}

/// Deployment-wide counts of the freshness background job's progress — same
/// shape/reasoning as `reputation_status`.
pub async fn freshness_status(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<FreshnessStatusJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let status = state.db.freshness_status(crate::freshness_sync::stale_before_cutoff()).await.map_err(db_err)?;
    Ok(Json(FreshnessStatusJson { pending: status.pending, checked: status.checked, failed: status.failed }))
}

#[derive(serde::Serialize)]
pub struct MaliciousSyncResponse {
    pub manifests_processed: usize,
}

/// Runs one on-demand batch of the malicious-package rescan background job
/// (see `malicious_sync.rs`) instead of waiting for its next scheduled tick
/// — same relationship `force_reputation_sync` has to `reputation_sync`'s
/// loop. Deployment-global, same reasoning as `force_reputation_sync`: which
/// manifests are due for a rescan doesn't depend on which tenant's key
/// triggered it. `Action::ManageSettings`, same gate as
/// `force_reputation_sync`. 400 if malicious-package checking isn't enabled
/// for this deployment at all (nothing to check against).
pub async fn force_malicious_sync(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<MaliciousSyncResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;

    let client = state.osv.as_ref().ok_or_else(|| {
        ApiError::BadRequest("malicious-package checking is disabled for this deployment".to_string())
    })?;

    let manifests_processed = crate::malicious_sync::sync_pass(&state.db, client).await;

    let _ = record_audit(
        &state,
        &grant,
        "malicious_force_sync",
        &format!("manifests_processed={manifests_processed}"),
        true,
        None,
    )
    .await;

    Ok(Json(MaliciousSyncResponse { manifests_processed }))
}

#[derive(serde::Serialize)]
pub struct MaliciousCheckStatusJson {
    pub pending: i64,
    pub checked: i64,
}

/// Deployment-wide counts of the malicious-sync background job's progress —
/// same shape as `reputation_status`, minus `failed` (see
/// `MaliciousCheckStatus`'s field docs for why). `Action::Read`, same as
/// `reputation_status` — a read, not a mutation, unlike `force_malicious_sync`.
pub async fn malicious_check_status(
    State(state): State<AppState>,
    grant: AuthGrant,
) -> Result<Json<MaliciousCheckStatusJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let status =
        state.db.malicious_check_status(crate::malicious_sync::stale_before_cutoff()).await.map_err(db_err)?;
    Ok(Json(MaliciousCheckStatusJson { pending: status.pending, checked: status.checked }))
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

/// Every scored package that appears in **this tenant's** SBOMs, ascending
/// by score — backs the Settings page's aggregation modal (a `manifest()`
/// call only ever shows one manifest's own components; this shows the
/// tenant's whole scored surface at once).
///
/// Previously this listed `component_reputation` deployment-wide under
/// plain `Action::Read`, on the reasoning that a Scorecard score is a
/// property of the package rather than of who uploaded it. That is true of
/// the *score*, but not of the *fact that a package is present*: the raw
/// list enumerated every dependency of every other tenant on the
/// deployment, which is exactly the kind of cross-tenant inference the rest
/// of the API is careful to prevent. It is now scoped through
/// `sbom_components` (`list_reputation_for_tenant`) and gated on
/// `ManageTenantData` — super_admin only, since even within one tenant this
/// is the whole dependency surface in a single view.
pub async fn reputation_components(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<ReputationComponentSummaryJson>>, ApiError> {
    require(&grant, Action::ManageTenantData, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let rows = state.db.list_reputation_for_tenant(tenant_id).await.map_err(db_err)?;
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

    crate::webhooks::emit_event(
        &state.db,
        tenant_id,
        crate::webhooks::EVENT_MANIFEST_REVOKED,
        serde_json::json!({
            "manifest_hash": manifest_hash,
            "namespace": record.namespace,
            "revoked_by": grant.principal(),
        }),
    )
    .await;

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
            "manual",
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

// ---------- Webhooks ----------

/// A tenant's webhook endpoint as returned by every read/list/create/update
/// call — `secret` is deliberately never included here (write-only, shown
/// once at creation in `CreateWebhookEndpointResponse`, same "shown once"
/// convention as an API key's secret).
#[derive(serde::Serialize)]
pub struct WebhookEndpointJson {
    pub id: Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl From<magnolia_db::WebhookEndpointRecord> for WebhookEndpointJson {
    fn from(r: magnolia_db::WebhookEndpointRecord) -> Self {
        Self {
            id: r.id,
            url: r.url,
            event_types: r.event_types,
            enabled: r.enabled,
            created_by: mask_principal(&r.created_by),
            created_at: r.created_at,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct CreateWebhookEndpointRequest {
    pub url: String,
    pub event_types: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct CreateWebhookEndpointResponse {
    pub id: Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    /// The HMAC-SHA256 signing secret — shown exactly once, here. Lost if
    /// not copied now; there is no "reveal secret" endpoint, same as an API
    /// key's secret.
    pub secret: String,
}

#[derive(serde::Deserialize)]
pub struct UpdateWebhookEndpointRequest {
    pub url: String,
    pub event_types: Vec<String>,
    pub enabled: bool,
}

fn validate_webhook_event_types(event_types: &[String]) -> Result<(), ApiError> {
    if event_types.is_empty() {
        return Err(ApiError::BadRequest("event_types must not be empty".to_string()));
    }
    for et in event_types {
        if !crate::webhooks::ALL_EVENT_TYPES.contains(&et.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown event_type '{et}' (valid: {})",
                crate::webhooks::ALL_EVENT_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

/// Every webhook endpoint registered for this tenant. `Action::Read` — same
/// gate as browsing any other tenant configuration; only creating/changing
/// one requires `ManageSettings`.
pub async fn list_webhooks(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<WebhookEndpointJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let rows = state.db.list_webhook_endpoints(tenant_id).await.map_err(db_err)?;
    Ok(Json(rows.into_iter().map(WebhookEndpointJson::from).collect()))
}

/// Registers a new webhook endpoint. `Action::ManageSettings` — this is
/// tenant-wide infrastructure (any subscribed event fires to this URL for
/// every uploader), same gate as compliance-profile enforcement.
pub async fn create_webhook(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<CreateWebhookEndpointRequest>,
) -> Result<Json<CreateWebhookEndpointResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let url = body.url.trim().to_string();
    if url.is_empty() {
        return Err(ApiError::BadRequest("url must not be empty".to_string()));
    }
    crate::webhooks::check_webhook_url(&url, state.dev_mode).map_err(ApiError::BadRequest)?;
    validate_webhook_event_types(&body.event_types)?;

    let id = Uuid::new_v4();
    // Same "two concatenated UUIDs" idiom `generate_server_key` uses for an
    // API key's secret — plenty of entropy for an HMAC key, no extra `rand`
    // dependency needed.
    let secret = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    state
        .db
        .insert_webhook_endpoint(id, tenant_id, &url, &secret, &body.event_types, &grant.principal())
        .await
        .map_err(db_err)?;

    let _ = record_audit(&state, &grant, "webhook_create", &id.to_string(), true, None).await;

    Ok(Json(CreateWebhookEndpointResponse { id, url, event_types: body.event_types, secret }))
}

/// Updates an existing endpoint's URL/subscriptions/enabled state.
/// `Action::ManageSettings`, tenant-scoped via the `WHERE` clause inside
/// `update_webhook_endpoint` — a 404 (not 403) either way an id doesn't
/// resolve within this tenant, same "don't confirm existence of another
/// tenant's resource" convention used elsewhere.
pub async fn update_webhook(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<UpdateWebhookEndpointRequest>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let url = body.url.trim().to_string();
    if url.is_empty() {
        return Err(ApiError::BadRequest("url must not be empty".to_string()));
    }
    crate::webhooks::check_webhook_url(&url, state.dev_mode).map_err(ApiError::BadRequest)?;
    validate_webhook_event_types(&body.event_types)?;

    let updated =
        state.db.update_webhook_endpoint(tenant_id, id, &url, &body.event_types, body.enabled).await.map_err(db_err)?;
    if !updated {
        return Err(ApiError::NotFound);
    }
    let _ = record_audit(&state, &grant, "webhook_update", &id.to_string(), true, None).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let deleted = state.db.delete_webhook_endpoint(tenant_id, id).await.map_err(db_err)?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    let _ = record_audit(&state, &grant, "webhook_delete", &id.to_string(), true, None).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Serialize)]
pub struct WebhookTestResponse {
    pub ok: bool,
    pub error: Option<String>,
}

/// Sends a one-off `webhook.test` event to this endpoint right now,
/// bypassing the outbox's polling delay — the "Send test event" button.
/// `Action::ManageSettings`, same gate as create/update: this makes an
/// outbound HTTP call to a URL an operator controls, which is the same
/// class of action as registering that URL in the first place.
pub async fn test_webhook(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<WebhookTestResponse>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let endpoint = state.db.get_webhook_endpoint(tenant_id, id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;

    let http = reqwest::Client::new();
    match crate::webhooks::send_test_event(&state.db, &http, &endpoint, state.dev_mode).await {
        Ok(()) => Ok(Json(WebhookTestResponse { ok: true, error: None })),
        Err(e) => Ok(Json(WebhookTestResponse { ok: false, error: Some(e) })),
    }
}

#[derive(serde::Serialize)]
pub struct WebhookDeliveryJson {
    pub id: i64,
    pub event_type: String,
    pub status: String,
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

impl From<magnolia_db::WebhookDeliveryRecord> for WebhookDeliveryJson {
    fn from(r: magnolia_db::WebhookDeliveryRecord) -> Self {
        Self {
            id: r.id,
            event_type: r.event_type,
            status: r.status,
            attempts: r.attempts,
            next_attempt_at: r.next_attempt_at,
            last_error: r.last_error,
            created_at: r.created_at,
            delivered_at: r.delivered_at,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct WebhookDeliveriesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    pub tenant_id: Option<Uuid>,
}

/// One endpoint's recent delivery history, newest first — what the
/// Settings page's "recent deliveries" table reads.
pub async fn webhook_deliveries(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path(id): Path<Uuid>,
    Query(q): Query<WebhookDeliveriesQuery>,
) -> Result<Json<Vec<WebhookDeliveryJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, _cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    state.db.get_webhook_endpoint(tenant_id, id).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    let limit = q.limit.clamp(1, 200);
    let rows = state.db.list_webhook_deliveries_for_endpoint(tenant_id, id, limit).await.map_err(db_err)?;
    Ok(Json(rows.into_iter().map(WebhookDeliveryJson::from).collect()))
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
    let generated =
        magnolia_auth::GeneratedKey::new().map_err(|e| ApiError::InternalError(e.to_string()))?;
    let key_id = generated.key_id;

    state
        .db
        .insert_api_key(
            key_id,
            tenant_id,
            domain,
            namespace_scope,
            &role.to_string(),
            &generated.key_hash,
            expires_at,
        )
        .await
        .map_err(db_err)?;

    Ok(CreateKeyResponse {
        key: generated.token,
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
// ============================================================================
// CVE reachability evidence
// ============================================================================
//
// AISE's side of the `reach/` analyser. Three responsibilities and no more:
// resolve which repository and revision a finding's manifest corresponds to,
// hand that to the analyser, and proxy the result back. The analysis itself,
// the prompts, and the report schema all live in `reach/`.
//
// The framing rule from CLAUDE.md travels with the data: the analyser
// produces evidence for a human, never a verdict, and nothing here turns a
// report into a triage decision. No auto-close, no VEX status written from a
// report — a human still triages, now with the call sites in front of them.

/// A namespace's source-repository mapping.
#[derive(serde::Serialize)]
pub struct NamespaceRepoJson {
    pub namespace: String,
    pub repo_url: String,
    pub subpath: Option<String>,
    /// Default branch/tag/commit, used only for manifests uploaded without
    /// a `source_commit` of their own.
    pub revision: Option<String>,
    pub auto_analyze: bool,
    /// Testing override: analyse `revision` even when a manifest recorded
    /// its own commit.
    pub ignore_source_commit: bool,
    pub created_by: String,
    pub updated_at: String,
}

impl From<magnolia_db::NamespaceRepoRecord> for NamespaceRepoJson {
    fn from(r: magnolia_db::NamespaceRepoRecord) -> Self {
        Self {
            namespace: r.namespace,
            repo_url: r.repo_url,
            subpath: r.subpath,
            revision: r.revision,
            auto_analyze: r.auto_analyze,
            ignore_source_commit: r.ignore_source_commit,
            created_by: r.created_by,
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

/// `GET /api/v1/settings/namespace-repos`
pub async fn list_namespace_repos(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<Vec<NamespaceRepoJson>>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let rows = state.db.list_namespace_repos(tenant_id).await.map_err(db_err)?;
    Ok(Json(
        rows.into_iter()
            // A namespace-scoped key must not learn the repository URLs of
            // namespaces it cannot otherwise see.
            .filter(|r| {
                cross_tenant
                    || magnolia_auth::namespace_in_scope(&r.namespace, &grant.namespace_scope)
            })
            .map(NamespaceRepoJson::from)
            .collect(),
    ))
}

#[derive(serde::Deserialize)]
pub struct SetNamespaceRepoRequest {
    pub namespace: String,
    /// `https://` URL, or an absolute path for the offline demo fetcher.
    pub repo_url: String,
    /// Monorepo sub-directory to scan; `null` or empty means the whole tree.
    #[serde(default)]
    pub subpath: Option<String>,
    /// Branch, tag or exact commit to analyse for manifests that carry no
    /// `source_commit`. `null` or empty means "none" — such manifests stay
    /// blocked rather than defaulting to some branch.
    #[serde(default)]
    pub revision: Option<String>,
    /// Queue analyses for this namespace's current untriaged findings in the
    /// background.
    #[serde(default)]
    pub auto_analyze: bool,
    /// Testing override: use `revision` even for manifests that recorded
    /// their own `source_commit`. Requires `revision`.
    #[serde(default)]
    pub ignore_source_commit: bool,
}

/// `POST /api/v1/settings/namespace-repos`
///
/// `ManageSettings`, not `Annotate`: this decides which repository an
/// analyser is pointed at on this tenant's behalf, which is tenant-wide
/// configuration rather than a per-finding annotation.
pub async fn set_namespace_repo(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<SetNamespaceRepoRequest>,
) -> Result<Json<NamespaceRepoJson>, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let namespace = normalize_namespace(&body.namespace)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden(
            "namespace is outside this key's scope".to_string(),
        ));
    }

    // Validated here as well as in the analyser: a caller should learn that
    // a URL is unusable when they save the setting, not later from a failed
    // analysis. The analyser still validates independently — this is a
    // usability check, not the security boundary.
    let repo_url = body.repo_url.trim().to_string();
    validate_repo_url_shape(&repo_url)?;

    let subpath = body.subpath.as_deref().map(str::trim).filter(|s| !s.is_empty());
    if let Some(sub) = subpath {
        validate_subpath_shape(sub)?;
    }

    let revision = body.revision.as_deref().map(str::trim).filter(|r| !r.is_empty());
    if let Some(r) = revision {
        validate_revision_shape(r)?;
    }
    // Rejected rather than silently ignored: with no revision, the switch
    // would look on in Settings and change nothing.
    if body.ignore_source_commit && revision.is_none() {
        return Err(ApiError::BadRequest(
            "ignoring the recorded commit needs a revision to analyse instead".to_string(),
        ));
    }

    let record = state
        .db
        .set_namespace_repo(
            tenant_id,
            &namespace,
            &repo_url,
            subpath,
            revision,
            body.auto_analyze,
            body.ignore_source_commit,
            &grant.principal(),
        )
        .await
        .map_err(db_err)?;

    let _ = record_audit(
        &state,
        &grant,
        "namespace_repo_set",
        &format!("{}:{}", grant.domain, namespace),
        true,
        Some(format!(
            "repo_url={repo_url}; revision={}; auto_analyze={}; ignore_source_commit={}",
            revision.unwrap_or("-"),
            body.auto_analyze,
            body.ignore_source_commit
        )),
    )
    .await;

    Ok(Json(record.into()))
}

/// `DELETE /api/v1/settings/namespace-repos?namespace=...`
pub async fn delete_namespace_repo(
    State(state): State<AppState>,
    grant: AuthGrant,
    Query(q): Query<NamespaceRepoDeleteQuery>,
) -> Result<StatusCode, ApiError> {
    require(&grant, Action::ManageSettings, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let namespace = normalize_namespace(&q.namespace)?;
    if !cross_tenant && !magnolia_auth::namespace_in_scope(&namespace, &grant.namespace_scope) {
        return Err(ApiError::Forbidden(
            "namespace is outside this key's scope".to_string(),
        ));
    }

    let removed = state.db.delete_namespace_repo(tenant_id, &namespace).await.map_err(db_err)?;
    if !removed {
        return Err(ApiError::NotFound);
    }
    let _ = record_audit(
        &state,
        &grant,
        "namespace_repo_deleted",
        &format!("{}:{}", grant.domain, namespace),
        true,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize)]
pub struct NamespaceRepoDeleteQuery {
    pub namespace: String,
    #[serde(default)]
    pub tenant_id: Option<uuid::Uuid>,
}

/// Mirrors the analyser's own scheme allowlist so a bad value is rejected at
/// the point it is typed. Kept intentionally simple: `reach` re-validates
/// (including the argv-injection and credential checks), so this exists to
/// produce a good error message, not to be relied on.
fn validate_repo_url_shape(url: &str) -> Result<(), ApiError> {
    if url.is_empty() {
        return Err(ApiError::BadRequest("repo_url is required".to_string()));
    }
    if url.starts_with('-') || url.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest("repo_url is not a valid URL".to_string()));
    }
    if let Some(rest) = url.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or("");
        if authority.is_empty() {
            return Err(ApiError::BadRequest("repo_url is missing a host".to_string()));
        }
        if authority.contains('@') {
            return Err(ApiError::BadRequest(
                "repo_url must not contain credentials — configure REACH_GIT_TOKEN on the analyser instead"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    if url.starts_with('/') && !url.split('/').any(|c| c == "..") {
        // The offline demo / eval fixture path.
        return Ok(());
    }
    Err(ApiError::BadRequest(
        "repo_url must be an https:// URL (or an absolute local path for an offline demo)".to_string(),
    ))
}

fn validate_subpath_shape(sub: &str) -> Result<(), ApiError> {
    if sub.starts_with('/') || sub.split('/').any(|c| c == ".." || c == ".git") {
        return Err(ApiError::BadRequest(
            "subpath must be a relative path inside the repository, with no '..'".to_string(),
        ));
    }
    Ok(())
}

/// `created_by` prefix marking a namespace-repo mapping that came from an
/// upload's Magnoliafile rather than from Settings. Only mappings with this
/// prefix are ever replaced by a later upload; one an admin saved in
/// Settings always wins.
pub const MAGNOLIAFILE_PRINCIPAL_PREFIX: &str = "magnoliafile:";

/// A source repository declared on an upload.
#[derive(Debug, PartialEq, Eq)]
pub struct DeclaredSourceRepo {
    pub repo_url: String,
    pub subpath: Option<String>,
    pub revision: Option<String>,
}

/// `Ok(None)` when the upload declared no repository — the normal case, and
/// never an error. Stricter than the Settings form in one way: `https://`
/// only. The absolute-local-path form exists for the offline demo, and is an
/// admin's call; an upload key pointing the analyser at a path inside its
/// own container would be a different matter.
fn parse_declared_source_repo(
    repo: &str,
    subpath: &str,
    revision: &str,
) -> Result<Option<DeclaredSourceRepo>, ApiError> {
    let repo = repo.trim();
    let subpath = subpath.trim().trim_end_matches('/');
    let revision = revision.trim();
    if repo.is_empty() {
        if !subpath.is_empty() || !revision.is_empty() {
            return Err(ApiError::BadRequest(
                "source_subpath/source_revision were given without source_repo".to_string(),
            ));
        }
        return Ok(None);
    }
    if !repo.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "source_repo must be an https:// URL".to_string(),
        ));
    }
    validate_repo_url_shape(repo)?;
    if !subpath.is_empty() {
        validate_subpath_shape(subpath)?;
    }
    if !revision.is_empty() {
        validate_revision_shape(revision)?;
    }
    Ok(Some(DeclaredSourceRepo {
        repo_url: repo.to_string(),
        subpath: (!subpath.is_empty()).then(|| subpath.to_string()),
        revision: (!revision.is_empty()).then(|| revision.to_string()),
    }))
}

/// Mirrors the analyser's ref-name rules (`reach/src/fetcher/resolve.rs`) so
/// a typo is reported when the setting is saved. The analyser re-validates,
/// and is the one that finds out whether the branch actually exists.
fn validate_revision_shape(r: &str) -> Result<(), ApiError> {
    let bad = || {
        Err(ApiError::BadRequest(
            "revision must be a branch name, tag or commit id (letters, digits and . _ / + - only, no '..')"
                .to_string(),
        ))
    };
    if r.len() > 200
        || r.starts_with('-')
        || r.starts_with('/')
        || r.ends_with('/')
        || r.ends_with('.')
        || r.ends_with(".lock")
        || r.contains("..")
        || r.contains("//")
        || !r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '+'))
    {
        return bad();
    }
    Ok(())
}

/// What the UI needs to decide whether the button is clickable, and to
/// explain it when it isn't.
#[derive(serde::Serialize)]
pub struct ReachabilityJson {
    /// False when the deployment has no analyser configured at all.
    pub enabled: bool,
    /// `null` when nothing blocks an analysis. Otherwise a sentence the UI
    /// shows as the disabled button's tooltip — the reason must reach the
    /// user, since "greyed out with no explanation" is the failure mode this
    /// field exists to prevent.
    pub blocked_reason: Option<String>,
    pub repo_url: Option<String>,
    pub subpath: Option<String>,
    /// The exact commit analysed (or, before any analysis, the manifest's
    /// own commit when it has one).
    pub commit: Option<String>,
    /// `"manifest"` or `"namespace_revision"`: whether `commit` is the
    /// revision the SBOM was built from, or one resolved from the
    /// namespace's default. The UI must say which — a resolved branch head
    /// may not be the code the SBOM describes.
    pub commit_source: Option<String>,
    /// The namespace revision (branch/tag) in play when `commit_source` is
    /// `"namespace_revision"`.
    pub revision: Option<String>,
    /// True when the background loop queued the analysis, not a person.
    pub requested_automatically: bool,
    /// The most recent analysis for this finding, if any.
    pub analysis_id: Option<uuid::Uuid>,
    pub status: Option<String>,
    pub requested_by: Option<String>,
    pub requested_at: Option<String>,
    /// The analyser's report, verbatim. AISE does not reshape it.
    pub report: Option<serde_json::Value>,
    /// Set when the analysis failed, or when the analyser could not be
    /// reached just now — the two are distinguished by `status`.
    pub error: Option<String>,
}

/// Loads a finding and its manifest after checking the manifest belongs to
/// the caller's tenant and namespace scope — 404 otherwise, so another
/// tenant's hashes cannot be probed.
async fn authorized_finding(
    state: &AppState,
    grant: &AuthGrant,
    tenant_id: uuid::Uuid,
    cross_tenant: bool,
    manifest_hash: &str,
    finding_key: &str,
) -> Result<(magnolia_db::ManifestRecord, DtrackFindingRecord), ApiError> {
    let record = state
        .db
        .get_manifest(manifest_hash)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant
            && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    {
        return Err(ApiError::NotFound);
    }
    let finding = state
        .db
        .get_dtrack_finding(manifest_hash, finding_key)
        .await
        .map_err(db_err)?
        .ok_or(ApiError::NotFound)?;
    Ok((record, finding))
}

fn reachability_disabled() -> ReachabilityJson {
    ReachabilityJson {
        enabled: false,
        blocked_reason: Some(
            "This deployment has no reachability analyser configured (AISE_REACH_BASE_URL / AISE_REACH_TOKEN)."
                .to_string(),
        ),
        repo_url: None,
        subpath: None,
        commit: None,
        commit_source: None,
        revision: None,
        requested_automatically: false,
        analysis_id: None,
        status: None,
        requested_by: None,
        requested_at: None,
        report: None,
        error: None,
    }
}

/// `GET /api/v1/manifest/:manifest_hash/findings/:finding_key/reachability`
///
/// Status for the UI. Proxies the analyser when an analysis exists; an
/// analyser that is down degrades to "status unavailable" with the stored
/// handle intact, never a 500 — same convention as every other optional
/// signal in this codebase. Each successful poll also refreshes the cached
/// status the findings list shows.
pub async fn finding_reachability(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<TenantOverrideQuery>,
) -> Result<Json<ReachabilityJson>, ApiError> {
    require(&grant, Action::Read, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let Some(client) = state.reach.clone() else {
        return Ok(Json(reachability_disabled()));
    };

    let (manifest, finding) =
        authorized_finding(&state, &grant, tenant_id, cross_tenant, &manifest_hash, &finding_key).await?;
    let plan = crate::reachability::plan_analysis(&state.db, &manifest, finding)
        .await
        .map_err(db_err)?;

    let existing = state
        .db
        .latest_finding_reachability(&manifest_hash, &finding_key)
        .await
        .map_err(db_err)?;

    let Some(link) = existing else {
        let (repo_url, subpath, commit, commit_source, revision, blocked_reason) = match plan {
            Ok(p) => {
                let (commit, revision) = p.revision.commit_and_ref();
                let source = Some(p.revision.commit_source().to_string());
                (Some(p.repo_url), p.subpath, commit, source, revision, None)
            }
            Err(reason) => (None, None, None, None, None, Some(reason)),
        };
        return Ok(Json(ReachabilityJson {
            enabled: true,
            blocked_reason,
            repo_url,
            subpath,
            commit,
            commit_source,
            revision,
            requested_automatically: false,
            analysis_id: None,
            status: None,
            requested_by: None,
            requested_at: None,
            report: None,
            error: None,
        }));
    };

    // The analyser being unreachable is a degradation, not an error: the
    // request that queued this analysis still happened, and the UI should say
    // so rather than pretend the analysis never existed.
    // The archived copy, written the first time this analysis was seen in a
    // terminal state. It is what makes the two degraded branches below still
    // able to show evidence rather than only apologise.
    let archived = link.report_json.clone();

    let (status, report, error) = match client.get_analysis(link.analysis_id).await {
        Ok(view) => {
            let priority = crate::reachability::report_priority(&view);
            let to_archive = crate::reachability::archivable_report(&view);
            // Write when anything is new *or* when there is a report to
            // archive and we have not archived one yet — otherwise a status
            // that never changes (the analysis was already `completed` before
            // this column existed) would never get its report stored.
            if link.status.as_deref() != Some(view.status.as_str())
                || link.priority != priority
                || (to_archive.is_some() && archived.is_none())
            {
                crate::reachability::cache_status(
                    &state.db,
                    link.analysis_id,
                    &view.status,
                    priority.as_deref(),
                    to_archive,
                )
                .await;
            }
            (Some(view.status), view.report.or(archived), view.error)
        }
        Err(magnolia_reachability::ReachError::NotFound) => {
            crate::reachability::cache_status(&state.db, link.analysis_id, "missing", None, None).await;
            let error = if archived.is_some() {
                // The evidence survives AISE-side, so say that rather than
                // sending the analyst off to spend the inference again.
                "The analyser no longer has this analysis — its database may have been reset. \
                 The report below is AISE's archived copy; re-run to analyse the current code."
            } else {
                "The analyser no longer has this analysis — its database may have been reset. \
                 Run the analysis again."
            };
            (Some("missing".to_string()), archived, Some(error.to_string()))
        }
        Err(e) => {
            tracing::warn!(error = %e, analysis_id = %link.analysis_id, "could not poll the reachability analyser");
            let error = if archived.is_some() {
                "The reachability analyser could not be reached just now — showing AISE's \
                 archived copy of this report."
            } else {
                "The reachability analyser could not be reached just now."
            };
            (Some("unavailable".to_string()), archived, Some(error.to_string()))
        }
    };

    Ok(Json(ReachabilityJson {
        enabled: true,
        // A re-run can still be blocked (the mapping was removed since).
        blocked_reason: plan.err(),
        repo_url: Some(link.repo_url),
        subpath: link.subpath,
        commit: Some(link.commit_sha),
        commit_source: Some(link.commit_source),
        revision: link.requested_ref,
        requested_automatically: link.requested_by == crate::reachability::AUTO_PRINCIPAL,
        analysis_id: Some(link.analysis_id),
        status,
        requested_by: Some(link.requested_by),
        requested_at: Some(link.created_at.to_rfc3339()),
        report,
        error,
    }))
}

/// Query parameters for queueing an analysis.
#[derive(serde::Deserialize)]
pub struct RequestReachabilityQuery {
    #[serde(default)]
    pub tenant_id: Option<uuid::Uuid>,
    /// Queue a fresh analysis even though one is already in flight for this
    /// finding. Off by default — see the handler's doc comment.
    #[serde(default)]
    pub force: bool,
}

/// `POST /api/v1/manifest/:manifest_hash/findings/:finding_key/reachability`
///
/// Queues an analysis. `Action::Annotate`: this is per-finding investigative
/// work, the same permission tier as triaging one — it spends analyser
/// capacity but changes no tenant configuration and no triage state.
///
/// Refuses with `409` while an analysis for the same finding is still
/// `queued` or `running`, unless `?force=true`. The analyser processes one job
/// at a time and each is minutes of inference, so a duplicate is not a
/// harmless no-op: it takes the worker away from other findings for no new
/// information. The UI already disables the button while an analysis is
/// pending, but that is a client-side courtesy — a second tab, a stale page,
/// or a direct API call all reach here, and the background loop's own
/// concurrency budget does not cover this path.
pub async fn request_finding_reachability(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<RequestReachabilityQuery>,
) -> Result<Json<ReachabilityJson>, ApiError> {
    require(&grant, Action::Annotate, &grant.namespace_scope)?;
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;

    let client = state.reach.clone().ok_or_else(|| {
        ApiError::BadRequest(
            "This deployment has no reachability analyser configured.".to_string(),
        )
    })?;

    let (manifest, finding) =
        authorized_finding(&state, &grant, tenant_id, cross_tenant, &manifest_hash, &finding_key).await?;

    // Checked after authorization, so an unauthorized caller learns nothing
    // about whether an analysis exists.
    if !q.force {
        if let Some(existing) =
            state.db.latest_finding_reachability(&manifest_hash, &finding_key).await.map_err(db_err)?
        {
            if matches!(existing.status.as_deref(), Some("queued") | Some("running")) {
                return Err(ApiError::Conflict(format!(
                    "An analysis for this finding is already {} (analysis {}). Wait for it to \
                     finish, or re-send with ?force=true to queue another anyway.",
                    existing.status.as_deref().unwrap_or("in flight"),
                    existing.analysis_id
                )));
            }
        }
    }

    let plan = crate::reachability::plan_analysis(&state.db, &manifest, finding)
        .await
        .map_err(db_err)?
        .map_err(ApiError::BadRequest)?;

    let link = crate::reachability::queue_analysis(
        &state.db,
        &client,
        &manifest_hash,
        &plan,
        &grant.principal(),
    )
    .await
    .map_err(|e| match e {
        crate::reachability::QueueError::Unavailable => ApiError::InternalError(
            "The reachability analyser could not be reached.".to_string(),
        ),
        crate::reachability::QueueError::Rejected(reason) => {
            ApiError::BadRequest(format!("The analyser rejected the request: {reason}"))
        }
        crate::reachability::QueueError::Failed(reason) => {
            tracing::warn!(%reason, "reachability analysis failed to queue");
            ApiError::InternalError("The reachability analyser failed.".to_string())
        }
        crate::reachability::QueueError::Db(e) => db_err(e),
    })?;

    let _ = record_audit(
        &state,
        &grant,
        "reachability_requested",
        &format!("{manifest_hash}:{finding_key}"),
        true,
        Some(format!(
            "analysis_id={}; vuln={}; commit={}; commit_source={}{}",
            link.analysis_id,
            plan.finding.vulnerability_id,
            link.commit_sha,
            link.commit_source,
            link.requested_ref.as_deref().map(|r| format!("; ref={r}")).unwrap_or_default(),
        )),
    )
    .await;

    Ok(Json(ReachabilityJson {
        enabled: true,
        blocked_reason: None,
        repo_url: Some(link.repo_url),
        subpath: link.subpath,
        commit: Some(link.commit_sha),
        commit_source: Some(link.commit_source),
        revision: link.requested_ref,
        requested_automatically: false,
        analysis_id: Some(link.analysis_id),
        status: Some("queued".to_string()),
        requested_by: Some(link.requested_by),
        requested_at: Some(link.created_at.to_rfc3339()),
        report: None,
        error: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_declared_repo_is_the_normal_case_not_an_error() {
        assert_eq!(parse_declared_source_repo("", "", "").unwrap(), None);
        assert_eq!(parse_declared_source_repo("  ", "", " ").unwrap(), None);
    }

    #[test]
    fn a_declared_repo_is_trimmed_and_empty_parts_become_none() {
        let d = parse_declared_source_repo(" https://github.com/acme/api ", "services/api/", "")
            .unwrap()
            .unwrap();
        assert_eq!(d.repo_url, "https://github.com/acme/api");
        assert_eq!(d.subpath.as_deref(), Some("services/api"));
        assert_eq!(d.revision, None);
    }

    #[test]
    fn an_upload_may_not_point_the_analyser_at_a_local_path() {
        // Allowed in Settings for the offline demo, never from an upload key.
        assert!(parse_declared_source_repo("/data/fixture", "", "").is_err());
        assert!(parse_declared_source_repo("git@github.com:acme/api.git", "", "").is_err());
        assert!(parse_declared_source_repo("https://user:pw@github.com/acme/api", "", "").is_err());
    }

    #[test]
    fn subpath_and_revision_go_through_the_settings_validators() {
        let repo = "https://github.com/acme/api";
        assert!(parse_declared_source_repo(repo, "../etc", "").is_err());
        assert!(parse_declared_source_repo(repo, "", "--upload-pack=x").is_err());
        assert!(parse_declared_source_repo(repo, "", "main").unwrap().is_some());
    }

    #[test]
    fn subpath_or_revision_without_a_repo_is_rejected_rather_than_dropped() {
        assert!(parse_declared_source_repo("", "services/api", "").is_err());
        assert!(parse_declared_source_repo("", "", "main").is_err());
    }
}
