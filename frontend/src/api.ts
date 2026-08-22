// Typed client for the sbomStash API. In dev, requests go through the CRA
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
  signature: string;
  created_by: string;
  created_at: string;
  sbom_hex: string;
  revoked: boolean;
  revoked_at: string | null;
  revoked_by: string | null;
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

const KEY_STORAGE = 'sbomstash_api_key';

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

  treeHead: (tenantId?: string): Promise<TreeHead> =>
    request(`/api/v1/tree-head/latest${tenantQs(tenantId)}`),

  treeHeadAt: (treeSize: number, tenantId?: string): Promise<TreeHead> =>
    request(`/api/v1/tree-head/${treeSize}${tenantQs(tenantId)}`),

  upload: (
    file: File,
    format: 'cyclonedx' | 'spdx',
    namespace: string,
    version: string,
    tenantId?: string
  ): Promise<UploadResult> => {
    const form = new FormData();
    form.append('sbom_file', file);
    form.append('format', format);
    form.append('namespace', namespace);
    form.append('version', version);
    return request(`/api/v1/upload${tenantQs(tenantId)}`, { method: 'POST', body: form });
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
};