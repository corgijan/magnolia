// Typed client for the Magnolia API. In dev, requests go through the CRA
// proxy (see "proxy" in package.json) to the server on 127.0.0.1:3000.

export interface TreeHead {
  tree_size: number;
  root_hash: string;
  signature: string;
  frontier: string[];
  created_at: string;
  signature_verified: boolean;
}

export interface UploadResult {
  sbom_hash: string;
  manifest_hash: string;
  version: string;
  namespace: string;
  domain: string;
  tree_size: number;
  leaf_index: number;
  leaf_seq_id: number;
  signed_tree_head: TreeHead;
}

export interface Leaf {
  seq_id: number;
  leaf_index: number;
  tenant_id: string;
  namespace: string;
  sbom_s3_key: string;
  leaf_hash: string;
  status: string;
  created_at: string;
  manifest_hash: string | null;
  revoked: boolean;
  domain: string;
  version: string | null;
  document_type: string | null;
}

export interface ProofStep {
  hash: string;
  sibling_is_left: boolean;
}

export interface InclusionProof {
  leaf_index: number;
  tree_size: number;
  peak_index: number;
  peaks: string[];
  sibling_path: ProofStep[];
}

export interface PeakProof {
  leaf_start: number;
  level: number;
  peak_hash: string;
  new_peak_index: number;
  steps: ProofStep[];
}

export interface ConsistencyProof {
  old_tree_size: number;
  new_tree_size: number;
  peaks: string[];
  peak_proofs: PeakProof[];
}

export interface DsseSignature {
  keyid: string;
  sig: string;
}

export interface DsseEnvelope {
  payload: string;
  payloadType: string;
  signatures: DsseSignature[];
}

export interface Manifest {
  manifest_hash: string;
  leaf_seq_id: number;
  tenant_id: string;
  domain: string;
  version: string;
  sbom_hash: string;
  sbom_format: string;
  sbom_s3_key: string;
  namespace: string;
  previous_manifest_hash: string | null;
  // Legacy hex signature — only set for manifests signed before the DSSE
  // migration; null for anything with dsse_envelope.
  signature: string | null;
  // Canonical signed artifact for manifests signed after the DSSE
  // migration; null for legacy manifests (can't be retroactively upgraded).
  dsse_envelope: DsseEnvelope | null;
  // Set for a general technical-documentation upload (risk assessment,
  // test report, etc.); null for a regular SBOM manifest.
  document_type: string | null;
  created_by: string;
  created_at: string;
  sbom_hex: string;
  revoked: boolean;
  revoked_at: string | null;
  revoked_by: string | null;
  compliance: ComplianceReport[];
  vulnerability_findings: VulnerabilityFinding[];
  // Set once dtrack has actually refreshed this manifest's findings at
  // least once — null means "not synced yet, still pending", distinct
  // from a non-null value with vulnerability_findings still empty, which
  // means dtrack looked and genuinely found nothing.
  dtrack_synced_at: string | null;
  // Set when the most recent push to dtrack failed — e.g. dtrack rejected
  // the BOM as schema-invalid, which will never succeed on retry without
  // different content. null once a later push succeeds.
  dtrack_push_error: string | null;
  // Components matched against OSV's confirmed-malicious-package advisories,
  // checked once at upload time. Empty for almost every manifest.
  malicious_components: MaliciousComponent[];
  // Cached deps.dev/OpenSSF Scorecard results, filled in by a background
  // job — a freshly-uploaded manifest's components simply won't appear here
  // yet (not an error, just "not checked yet").
  component_reputation: ComponentReputation[];
  // This tenant's license-policy violations, recomputed live on every
  // fetch (not a stale snapshot from upload time) — empty whenever the
  // tenant's license policy enforce_level is "off".
  license_violations: LicenseViolation[];
  // Cached deps.dev latest-version results, filled in by a background job —
  // a freshly-uploaded manifest's components simply won't appear here yet.
  component_freshness: ComponentFreshness[];
}

export interface LicenseViolation {
  component_name: string;
  component_version: string | null;
  license_expr: string | null;
  reason: 'denied' | 'unknown';
  // The specific denied identifier matched — null for reason "unknown".
  denied_license: string | null;
}

export interface LicensePolicy {
  denied_licenses: string[];
  flag_unknown: boolean;
  enforce_level: 'off' | 'warn' | 'block';
}

export interface MaliciousComponent {
  component_name: string;
  component_version: string | null;
  purl: string | null;
  osv_id: string;
  summary: string | null;
  detected_at: string;
}

// Red/yellow/green classification of a scorecard_score — the boundaries
// live in the backend (crates/api/src/reputation_bucket.rs), computed once
// there so this app never has its own copy of the thresholds to drift.
export type ReputationBucket = 'red' | 'yellow' | 'green';

export interface ComponentReputation {
  component_name: string;
  component_version: string | null;
  scorecard_score: number | null;
  bucket: ReputationBucket | null;
  project_repo: string | null;
  // null means the reputation background job hasn't reached this component
  // yet — render as "pending", not an error or a zero score.
  checked_at: string | null;
  fetch_error: string | null;
}

// One package's cached score, deployment-wide — not scoped to any one
// manifest. Backs the "all scored packages" aggregation modal.
export interface ReputationComponentSummary {
  ecosystem: string;
  name: string;
  scorecard_score: number;
  bucket: ReputationBucket;
  project_repo: string | null;
  checked_at: string;
}

export interface ManifestVersion {
  manifest_hash: string;
  version: string;
  created_at: string;
  revoked: boolean;
}

export interface VulnerabilityFinding {
  finding_key: string;
  component_name: string;
  component_version: string | null;
  vulnerability_id: string;
  severity: string;
  description: string | null;
  // dtrack's own generic analysis state, synced verbatim — independent of
  // vex_status below (the two can legitimately disagree; dtrack has no
  // notion of Magnolia's product/manifest context).
  analysis_state: string | null;
  vex_status: 'affected' | 'not_affected' | 'fixed' | 'under_investigation' | null;
  vex_justification: string | null;
  // Free-text context alongside the triage, independent of vex_justification
  // (which is now a fixed VEX vocabulary, see VEX_JUSTIFICATIONS below).
  vex_comment: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
}

// The fixed OpenVEX justification vocabulary (https://github.com/openvex/spec)
// — mirrors the backend's VEX_JUSTIFICATIONS constant. Only valid, and only
// required, alongside vex_status "not_affected".
export const VEX_JUSTIFICATIONS = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
] as const;

// A finding plus enough manifest context to place it in the archive — the
// shape returned by the cross-manifest GET /api/v1/findings, distinct from
// VulnerabilityFinding (always scoped to one already-known manifest).
export interface FindingWithContext extends VulnerabilityFinding {
  manifest_hash: string;
  domain: string;
  namespace: string;
  release_version: string;
  revoked: boolean;
  comment_count: number;
}

export interface ComponentSummary {
  name: string;
  version: string | null;
  purl: string | null;
}

export interface ComponentVersionChange {
  name: string;
  purl: string | null;
  from_version: string | null;
  to_version: string | null;
}

export interface ManifestDiff {
  from_manifest_hash: string;
  from_version: string;
  to_manifest_hash: string;
  to_version: string;
  added: ComponentSummary[];
  removed: ComponentSummary[];
  changed: ComponentVersionChange[];
  unchanged_count: number;
}

export interface FindingComment {
  id: string;
  author: string;
  body: string;
  created_at: string;
}

export interface DtrackSyncResult {
  manifests_pushed: number;
  projects_refreshed: number;
}

export interface ComplianceProfileInfo {
  id: string;
  name: string;
  description: string;
}

export interface ComplianceSetting {
  profile_id: string;
  profile_name: string;
  description: string;
  enabled: boolean;
  enforce_level: 'off' | 'minimum' | 'full';
}

export interface ComplianceReport {
  profile_id: string;
  profile_name: string;
  applicable: boolean;
  meets_minimum: boolean;
  minimum_issues: string[];
  fully_compliant: boolean;
  missing_fields: string[];
}

// Mirrors the backend's `webhooks::ALL_EVENT_TYPES` (crates/api/src/webhooks.rs)
// — kept as a plain list here rather than fetched from the server since it
// almost never changes and the settings page needs it synchronously to
// render checkboxes.
export const WEBHOOK_EVENT_TYPES = [
  'manifest.uploaded',
  'manifest.revoked',
  'finding.new_critical',
  'malicious.match_found',
  'dtrack.push_failed',
] as const;

export interface WebhookEndpoint {
  id: string;
  url: string;
  event_types: string[];
  enabled: boolean;
  created_by: string;
  created_at: string;
}

export interface CreateWebhookResult {
  id: string;
  url: string;
  event_types: string[];
  /** Shown exactly once, in this creation response — there is no "reveal
   * secret" endpoint afterward. */
  secret: string;
}

export interface WebhookTestResult {
  ok: boolean;
  error: string | null;
}

export interface WebhookDelivery {
  id: number;
  event_type: string;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  created_at: string;
  delivered_at: string | null;
}

export interface VexImportUnmatched {
  vuln_id: string;
  reason: string;
}

export interface VexImportResult {
  applied: number;
  skipped_manual: number;
  unmatched: VexImportUnmatched[];
}

export interface VerifyCheck {
  id: string;
  status: 'pass' | 'fail' | 'warn' | 'not_evaluated';
  enforce_level: string;
  details: string[];
}

export interface VerifyCompliance {
  profile_id: string;
  profile_name: string;
  enforce_level: string;
  meets_minimum: boolean;
  minimum_issues: string[];
  fully_compliant: boolean;
  missing_fields: string[];
}

export interface VerifyResult {
  verdict: 'pass' | 'fail';
  checks: VerifyCheck[];
  compliance: VerifyCompliance[];
}

export interface ComponentSearchResult {
  name: string;
  version: string | null;
  purl: string | null;
  cpe: string | null;
  is_primary: boolean;
  manifest_hash: string;
  domain: string;
  namespace: string;
  release_version: string;
  revoked: boolean;
  document_type: string | null;
  license_expr: string | null;
}

export interface ReindexResult {
  manifests_indexed: number;
  components_indexed: number;
}

/** One manifest in a "blast radius" answer — which manifests contain a
 * given component, or are affected by a given vulnerability/advisory id. */
export interface AffectedManifest {
  manifest_hash: string;
  domain: string;
  namespace: string;
  release_version: string;
  revoked: boolean;
}

export interface CurrentManifest {
  namespace: string;
  domain: string;
  version: string;
  manifest_hash: string;
  sbom_hash: string;
  sbom_format: string;
  created_at: string;
}

export interface ApiKeyInfo {
  id: string;
  tenant_id: string;
  domain: string;
  namespace_scope: string;
  role: string;
  expires_at: string | null;
  revoked: boolean;
  created_at: string;
}

export interface CreateKeyResponse {
  key: string;
  key_id: string;
  tenant_id: string;
  domain: string;
  namespace_scope: string;
  role: string;
  expires_at: string | null;
}

export interface Tenant {
  id: string;
  domain: string;
  name: string;
  created_by: string;
  created_at: string;
  is_platform: boolean;
}

export interface CreateTenantResponse {
  tenant: Tenant;
  initial_key: CreateKeyResponse;
}

export interface WhoAmI {
  key_id: string;
  tenant_id: string;
  domain: string;
  namespace_scope: string;
  role: string;
  is_platform_tenant: boolean;
}

export interface BackendConfig {
  storage_backend: string;
  signer_backend: string;
  dev_mode: boolean;
  dtrack_enabled: boolean;
  // Present only when dtrack_enabled.
  dtrack_sync_interval_secs: number | null;
  reputation_enabled: boolean;
  // Currently always equal to reputation_enabled — see the backend's
  // ConfigJson.freshness_enabled doc comment.
  freshness_enabled: boolean;
  malicious_check_enabled: boolean;
}

export interface ReputationSyncResult {
  components_processed: number;
}

export type FreshnessStatusValue = 'current' | 'behind' | 'major_behind' | 'unknown';

export interface ComponentFreshness {
  component_name: string;
  component_version: string | null;
  latest_version: string | null;
  // null means the freshness background job hasn't reached this component
  // yet — render as "pending", not an error.
  status: FreshnessStatusValue | null;
  checked_at: string | null;
  fetch_error: string | null;
}

export interface FreshnessSyncResult {
  components_processed: number;
}

export interface FreshnessStatus {
  pending: number;
  checked: number;
  failed: number;
}

export interface ReputationStatus {
  pending: number;
  checked: number;
  failed: number;
}

export interface MaliciousSyncResult {
  manifests_processed: number;
}

// Same shape as ReputationStatus minus "failed" — a failed rescan attempt
// just stays counted under "pending" until it succeeds (see the backend's
// MaliciousCheckStatus field docs).
export interface MaliciousCheckStatus {
  pending: number;
  checked: number;
}

// This tenant's own opt-out of the deployment-wide dtrack sync — distinct
// from BackendConfig.dtrack_enabled, which is deployment-wide/read-only.
export interface DtrackSyncSetting {
  disabled: boolean;
}

// This tenant's opt-in requiring uploaded SBOMs' `version` field to be
// SemVer 2.0.0-compliant.
export interface SemverSetting {
  required: boolean;
}

// This tenant's opt-out of the "Package reputation" panel appearing on its
// own SBOM detail views — has no effect on the background job itself.
export interface ReputationTenantSetting {
  disabled: boolean;
}

// This tenant's opt-out of the "malicious package" panel appearing on its
// own SBOM detail views — has no effect on detection at upload time.
export interface MaliciousCheckTenantSetting {
  disabled: boolean;
}

// This tenant's opt-in requiring upload_sbom's target namespace to already
// be registered (see RegisteredNamespace below).
export interface NamespaceRegistrationSetting {
  required: boolean;
}

export interface RegisteredNamespace {
  namespace: string;
  created_by: string;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  tenant_id: string;
  principal: string;
  action: string;
  resource: string;
  result: string;
  reason: string | null;
  created_at: string;
}

const KEY_STORAGE = 'magnolia_api_key';

export function getApiKey(): string {
  return localStorage.getItem(KEY_STORAGE) ?? '';
}

export function setApiKey(key: string): void {
  if (key) {
    localStorage.setItem(KEY_STORAGE, key);
  } else {
    localStorage.removeItem(KEY_STORAGE);
  }
}

export class ApiHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string> | undefined) ?? {}),
  };
  const key = getApiKey();
  if (key) {
    headers['Authorization'] = `Bearer ${key}`;
  }
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // non-JSON error body
    }
    throw new ApiHttpError(res.status, message);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

// Appends `?tenant_id=` when set — the cross-tenant override that only
// super_admin keys are allowed to use (enforced server-side; the frontend
// only ever sends it when a tenant is explicitly selected).
function tenantQs(tenantId?: string, extra: Record<string, string | number> = {}): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(extra)) params.set(k, String(v));
  if (tenantId) params.set('tenant_id', tenantId);
  const s = params.toString();
  return s ? `?${s}` : '';
}

export const api = {
  health: (): Promise<boolean> =>
    fetch('/health').then((res) => res.ok).catch(() => false),

  whoami: (): Promise<WhoAmI> => request('/api/v1/whoami'),

  config: (): Promise<BackendConfig> => request('/api/v1/config'),

  treeHead: (tenantId?: string): Promise<TreeHead> =>
    request(`/api/v1/tree-head/latest${tenantQs(tenantId)}`),

  treeHeadAt: (treeSize: number, tenantId?: string): Promise<TreeHead> =>
    request(`/api/v1/tree-head/${treeSize}${tenantQs(tenantId)}`),

  upload: (
    file: File,
    format: 'cyclonedx' | 'spdx' | 'document',
    namespace: string,
    version: string,
    tenantId?: string,
    documentType?: string
  ): Promise<UploadResult> => {
    const form = new FormData();
    form.append('sbom_file', file);
    form.append('format', format);
    form.append('namespace', namespace);
    form.append('version', version);
    if (documentType) form.append('document_type', documentType);
    return request(`/api/v1/upload${tenantQs(tenantId)}`, { method: 'POST', body: form });
  },

  // CI policy gate — the dry-run version of upload: same schema/compliance/
  // license-policy/malicious-package checks, but nothing is stored,
  // indexed, or added to the Merkle log. Every registered compliance
  // profile and this tenant's configured license policy are always
  // previewed here, even when a profile isn't enabled or a policy's
  // enforce_level is "off" — a check that isn't actually enforced can
  // still "warn" from real findings but never flips the verdict to "fail".
  verifySbom: (file: File, format: 'cyclonedx' | 'spdx', tenantId?: string): Promise<VerifyResult> => {
    const form = new FormData();
    form.append('sbom_file', file);
    form.append('format', format);
    return request(`/api/v1/verify${tenantQs(tenantId)}`, { method: 'POST', body: form });
  },

  leaves: (limit = 50, offset = 0, tenantId?: string): Promise<Leaf[]> =>
    request(`/api/v1/leaves${tenantQs(tenantId, { limit, offset })}`),

  inclusionProof: (leafIndex: number, tenantId?: string): Promise<InclusionProof> =>
    request(`/api/v1/proof/inclusion/${leafIndex}${tenantQs(tenantId)}`),

  consistencyProof: (
    oldSize: number,
    newSize: number,
    tenantId?: string
  ): Promise<ConsistencyProof> =>
    request(`/api/v1/proof/consistency/${oldSize}/${newSize}${tenantQs(tenantId)}`),

  manifest: (manifestHash: string, tenantId?: string): Promise<Manifest> =>
    request(`/api/v1/manifest/${manifestHash}${tenantQs(tenantId)}`),

  revokeManifest: (manifestHash: string, tenantId?: string): Promise<void> =>
    request(`/api/v1/manifest/${manifestHash}/revoke${tenantQs(tenantId)}`, { method: 'POST' }),

  triageFinding: (
    manifestHash: string,
    findingKey: string,
    vexStatus: string,
    justification: string | undefined,
    comment: string | undefined,
    tenantId?: string
  ): Promise<VulnerabilityFinding> =>
    request(`/api/v1/manifest/${manifestHash}/findings/${findingKey}/triage${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vex_status: vexStatus, justification, comment }),
    }),

  manifestVex: (manifestHash: string, tenantId?: string): Promise<Record<string, unknown>> =>
    request(`/api/v1/manifest/${manifestHash}/vex${tenantQs(tenantId)}`),

  importVex: (
    manifestHash: string,
    file: File,
    overwrite: boolean,
    tenantId?: string
  ): Promise<VexImportResult> => {
    const form = new FormData();
    form.append('vex_file', file);
    return request(
      `/api/v1/manifest/${manifestHash}/vex/import${tenantQs(tenantId, overwrite ? { overwrite: 'true' } : {})}`,
      { method: 'POST', body: form }
    );
  },

  manifestDiff: (manifestHash: string, against: string | undefined, tenantId?: string): Promise<ManifestDiff> =>
    request(
      `/api/v1/manifest/${manifestHash}/diff${tenantQs(tenantId, against ? { against } : {})}`
    ),

  namespaceManifestVersions: (namespace: string, tenantId?: string): Promise<ManifestVersion[]> =>
    request(`/api/v1/namespaces/manifests${tenantQs(tenantId, { namespace })}`),

  listFindings: (
    opts: {
      severity?: string;
      manifestHash?: string;
      namespace?: string;
      releaseVersion?: string;
      vexStatus?: string;
      currentOnly?: boolean;
      hideStale?: boolean;
      limit?: number;
      offset?: number;
    },
    tenantId?: string
  ): Promise<FindingWithContext[]> => {
    const extra: Record<string, string | number> = {};
    if (opts.severity) extra.severity = opts.severity;
    if (opts.manifestHash) extra.manifest_hash = opts.manifestHash;
    if (opts.namespace) extra.namespace = opts.namespace;
    if (opts.releaseVersion) extra.release_version = opts.releaseVersion;
    if (opts.vexStatus) extra.vex_status = opts.vexStatus;
    if (opts.currentOnly) extra.current_only = 'true';
    if (opts.hideStale) extra.hide_stale = 'true';
    if (opts.limit) extra.limit = opts.limit;
    if (opts.offset) extra.offset = opts.offset;
    return request(`/api/v1/findings${tenantQs(tenantId, extra)}`);
  },

  listFindingComments: (
    manifestHash: string,
    findingKey: string,
    tenantId?: string
  ): Promise<FindingComment[]> =>
    request(`/api/v1/manifest/${manifestHash}/findings/${findingKey}/comments${tenantQs(tenantId)}`),

  addFindingComment: (
    manifestHash: string,
    findingKey: string,
    body: string,
    tenantId?: string
  ): Promise<FindingComment> =>
    request(`/api/v1/manifest/${manifestHash}/findings/${findingKey}/comments${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ body }),
    }),

  forceDtrackSync: (tenantId?: string): Promise<DtrackSyncResult> =>
    request(`/api/v1/dtrack/sync${tenantQs(tenantId)}`, { method: 'POST' }),

  // Deployment-global, unlike forceDtrackSync — no tenant to scope this to.
  forceReputationSync: (): Promise<ReputationSyncResult> =>
    request('/api/v1/reputation/sync', { method: 'POST' }),

  reputationStatus: (): Promise<ReputationStatus> => request('/api/v1/reputation/status'),

  reputationComponents: (): Promise<ReputationComponentSummary[]> => request('/api/v1/reputation/components'),

  // Deployment-global, unlike forceDtrackSync — no tenant to scope this to.
  forceFreshnessSync: (): Promise<FreshnessSyncResult> =>
    request('/api/v1/freshness/sync', { method: 'POST' }),

  freshnessStatus: (): Promise<FreshnessStatus> => request('/api/v1/freshness/status'),

  // Deployment-global, unlike forceDtrackSync — no tenant to scope this to.
  forceMaliciousSync: (): Promise<MaliciousSyncResult> =>
    request('/api/v1/malicious/sync', { method: 'POST' }),

  maliciousCheckStatus: (): Promise<MaliciousCheckStatus> => request('/api/v1/malicious/status'),

  currentManifests: (tenantId?: string): Promise<CurrentManifest[]> =>
    request(`/api/v1/manifests/current${tenantQs(tenantId)}`),

  hiddenNamespaces: (tenantId?: string): Promise<string[]> =>
    request(`/api/v1/namespaces/hidden${tenantQs(tenantId)}`),

  setNamespaceHidden: (namespace: string, hidden: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/namespaces/hidden${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace, hidden }),
    }),

  dtrackSyncSetting: (tenantId?: string): Promise<DtrackSyncSetting> =>
    request(`/api/v1/settings/dtrack-sync${tenantQs(tenantId)}`),

  setDtrackSyncSetting: (disabled: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/dtrack-sync${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled }),
    }),

  semverSetting: (tenantId?: string): Promise<SemverSetting> =>
    request(`/api/v1/settings/semver-version${tenantQs(tenantId)}`),

  setSemverSetting: (required: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/semver-version${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ required }),
    }),

  reputationTenantSetting: (tenantId?: string): Promise<ReputationTenantSetting> =>
    request(`/api/v1/settings/reputation-sync${tenantQs(tenantId)}`),

  setReputationTenantSetting: (disabled: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/reputation-sync${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled }),
    }),

  freshnessTenantSetting: (tenantId?: string): Promise<ReputationTenantSetting> =>
    request(`/api/v1/settings/freshness${tenantQs(tenantId)}`),

  setFreshnessTenantSetting: (disabled: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/freshness${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled }),
    }),

  maliciousCheckTenantSetting: (tenantId?: string): Promise<MaliciousCheckTenantSetting> =>
    request(`/api/v1/settings/malicious-check${tenantQs(tenantId)}`),

  setMaliciousCheckTenantSetting: (disabled: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/malicious-check${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled }),
    }),

  namespaceRegistrationSetting: (tenantId?: string): Promise<NamespaceRegistrationSetting> =>
    request(`/api/v1/settings/namespace-registration${tenantQs(tenantId)}`),

  setNamespaceRegistrationSetting: (required: boolean, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/namespace-registration${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ required }),
    }),

  listRegisteredNamespaces: (tenantId?: string): Promise<RegisteredNamespace[]> =>
    request(`/api/v1/namespaces/registered${tenantQs(tenantId)}`),

  createNamespace: (namespace: string, tenantId?: string): Promise<void> =>
    request(`/api/v1/namespaces/registered${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ namespace }),
    }),

  deleteNamespace: (namespace: string, tenantId?: string): Promise<void> =>
    request(`/api/v1/namespaces/registered${tenantQs(tenantId, { namespace })}`, {
      method: 'DELETE',
    }),

  complianceProfiles: (): Promise<ComplianceProfileInfo[]> =>
    request('/api/v1/compliance/profiles'),

  complianceSettings: (tenantId?: string): Promise<ComplianceSetting[]> =>
    request(`/api/v1/compliance/settings${tenantQs(tenantId)}`),

  setComplianceSetting: (
    profileId: string,
    enabled: boolean,
    enforceLevel: 'off' | 'minimum' | 'full',
    tenantId?: string
  ): Promise<void> =>
    request(`/api/v1/compliance/settings${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId, enabled, enforce_level: enforceLevel }),
    }),

  licensePolicy: (tenantId?: string): Promise<LicensePolicy> =>
    request(`/api/v1/settings/license-policy${tenantQs(tenantId)}`),

  setLicensePolicy: (policy: LicensePolicy, tenantId?: string): Promise<void> =>
    request(`/api/v1/settings/license-policy${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    }),

  // Not routed through request() — that always parses the response as
  // JSON, but this endpoint returns a tar file. Mirrors request()'s own
  // auth-header/error-handling logic instead.
  pullSnapshot: async (
    opts: { namespace?: string; version?: string },
    tenantId?: string
  ): Promise<Blob> => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const key = getApiKey();
    if (key) headers['Authorization'] = `Bearer ${key}`;
    const res = await fetch(`/api/v1/snapshot${tenantQs(tenantId)}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ namespace: opts.namespace || undefined, version: opts.version || undefined }),
    });
    if (!res.ok) {
      let message = `${res.status} ${res.statusText}`;
      try {
        const body = (await res.json()) as { error?: string };
        if (body.error) message = body.error;
      } catch {
        // non-JSON error body
      }
      throw new ApiHttpError(res.status, message);
    }
    return res.blob();
  },

  searchComponents: (
    opts: {
      name?: string;
      version?: string;
      namespace?: string;
      purl?: string;
      currentOnly?: boolean;
      limit?: number;
      offset?: number;
    },
    tenantId?: string
  ): Promise<ComponentSearchResult[]> => {
    const extra: Record<string, string | number> = {};
    if (opts.name) extra.name = opts.name;
    if (opts.version) extra.version = opts.version;
    if (opts.namespace) extra.namespace = opts.namespace;
    if (opts.purl) extra.purl = opts.purl;
    if (opts.currentOnly) extra.current_only = 'true';
    if (opts.limit) extra.limit = opts.limit;
    if (opts.offset) extra.offset = opts.offset;
    return request(`/api/v1/search/components${tenantQs(tenantId, extra)}`);
  },

  reindexComponents: (tenantId?: string): Promise<ReindexResult> =>
    request(`/api/v1/search/reindex${tenantQs(tenantId)}`, { method: 'POST' }),

  componentsAffected: (
    opts: { purl?: string; name?: string; version?: string; currentOnly?: boolean },
    tenantId?: string
  ): Promise<AffectedManifest[]> => {
    const extra: Record<string, string | number> = {};
    if (opts.purl) extra.purl = opts.purl;
    if (opts.name) extra.name = opts.name;
    if (opts.version) extra.version = opts.version;
    if (opts.currentOnly) extra.current_only = 'true';
    return request(`/api/v1/components/affected${tenantQs(tenantId, extra)}`);
  },

  vulnerabilityAffected: (
    vulnId: string,
    opts: { currentOnly?: boolean } = {},
    tenantId?: string
  ): Promise<AffectedManifest[]> => {
    const extra: Record<string, string | number> = {};
    if (opts.currentOnly) extra.current_only = 'true';
    return request(`/api/v1/vulnerabilities/${encodeURIComponent(vulnId)}/affected${tenantQs(tenantId, extra)}`);
  },

  listKeys: (tenantId?: string): Promise<ApiKeyInfo[]> =>
    request(`/api/v1/keys${tenantQs(tenantId)}`),

  createKey: (body: {
    namespace_scope: string;
    role: string;
    expires_at?: string | null;
    tenant_id?: string;
  }): Promise<CreateKeyResponse> =>
    request('/api/v1/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  revokeKey: (keyId: string, tenantId?: string): Promise<void> =>
    request(`/api/v1/keys/${keyId}/revoke${tenantQs(tenantId)}`, { method: 'POST' }),

  listTenants: (): Promise<Tenant[]> => request('/api/v1/tenants'),

  createTenant: (body: { domain: string; name: string }): Promise<CreateTenantResponse> =>
    request('/api/v1/tenants', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  deleteTenant: (tenantId: string): Promise<void> =>
    request(`/api/v1/tenants/${tenantId}`, { method: 'DELETE' }),

  auditLogs: (limit = 100, tenantId?: string): Promise<AuditEntry[]> =>
    request(`/api/v1/audit-logs${tenantQs(tenantId, { limit })}`),

  listWebhooks: (tenantId?: string): Promise<WebhookEndpoint[]> =>
    request(`/api/v1/webhooks${tenantQs(tenantId)}`),

  createWebhook: (url: string, eventTypes: string[], tenantId?: string): Promise<CreateWebhookResult> =>
    request(`/api/v1/webhooks${tenantQs(tenantId)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, event_types: eventTypes }),
    }),

  updateWebhook: (
    id: string,
    url: string,
    eventTypes: string[],
    enabled: boolean,
    tenantId?: string
  ): Promise<void> =>
    request(`/api/v1/webhooks/${id}${tenantQs(tenantId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, event_types: eventTypes, enabled }),
    }),

  deleteWebhook: (id: string, tenantId?: string): Promise<void> =>
    request(`/api/v1/webhooks/${id}${tenantQs(tenantId)}`, { method: 'DELETE' }),

  testWebhook: (id: string, tenantId?: string): Promise<WebhookTestResult> =>
    request(`/api/v1/webhooks/${id}/test${tenantQs(tenantId)}`, { method: 'POST' }),

  webhookDeliveries: (id: string, tenantId?: string): Promise<WebhookDelivery[]> =>
    request(`/api/v1/webhooks/${id}/deliveries${tenantQs(tenantId)}`),
};