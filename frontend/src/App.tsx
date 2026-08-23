import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  api,
  ApiHttpError,
  ApiKeyInfo,
  AuditEntry,
  ConsistencyProof,
  BackendConfig,
  ComplianceSetting,
  CreateKeyResponse,
  CreateTenantResponse,
  CurrentManifest,
  InclusionProof,
  Leaf,
  Manifest,
  setApiKey,
  Tenant,
  TreeHead,
  UploadResult,
  WhoAmI,
} from './api';
import {
  foldPeaks,
  shortHash,
  verifyConsistency,
  verifyInclusion,
} from './merkle';
import './App.css';

type Tab = 'dashboard' | 'upload' | 'leaves' | 'proofs' | 'keys' | 'tenants' | 'audit' | 'settings';

// Mirrors the backend RBAC matrix (crates/auth/src/rbac.rs) so the UI only
// ever shows tabs/actions the current key is actually allowed to use.
// 'annotate' mirrors Action::Annotate; 'manage_settings' mirrors the
// stricter Action::ManageSettings (persistent tenant-wide configuration —
// namespace visibility, compliance enforcement) which, unlike Annotate,
// auditor does NOT hold, so it can view but never change settings.
type RbacAction = 'upload' | 'read' | 'manage_keys' | 'manage_tenants' | 'annotate' | 'manage_settings';

const ROLE_ACTIONS: Record<string, RbacAction[]> = {
  super_admin: ['upload', 'read', 'manage_keys', 'manage_tenants', 'annotate', 'manage_settings'],
  domain_admin: ['upload', 'read', 'manage_keys', 'annotate', 'manage_settings'],
  uploader: ['upload'],
  auditor: ['read', 'annotate'],
};

function roleCan(role: string, action: RbacAction): boolean {
  return ROLE_ACTIONS[role]?.includes(action) ?? false;
}

// The tenant a super_admin has chosen to act on instead of its own ('' =
// its own tenant). Only super_admin keys can set this; the backend enforces
// that independently — this is purely so nested tabs (Leaves, Proofs, Keys,
// Audit) don't need the selection threaded through as a prop.
const TenantOverrideContext = createContext<{
  tenantId: string;
  setTenantId: (id: string) => void;
}>({ tenantId: '', setTenantId: () => {} });

function useTenantOverride(): string | undefined {
  const { tenantId } = useContext(TenantOverrideContext);
  return tenantId || undefined;
}

// "workspace" = day-to-day SBOM work; "admin" = key/tenant/audit
// administration — kept visually separate in the nav so the two don't blur
// together (this is the "pull out user management" grouping).
type TabGroup = 'workspace' | 'admin';

const TABS: { id: Tab; label: string; requires: RbacAction; group: TabGroup }[] = [
  { id: 'leaves', label: 'Dashboard', requires: 'read', group: 'workspace' },
  { id: 'dashboard', label: 'Info', requires: 'read', group: 'workspace' },
  { id: 'upload', label: 'Upload', requires: 'upload', group: 'workspace' },
  { id: 'proofs', label: 'Proofs', requires: 'read', group: 'workspace' },
  { id: 'settings', label: 'Settings', requires: 'manage_settings', group: 'workspace' },
  { id: 'keys', label: 'API Keys', requires: 'manage_keys', group: 'admin' },
  { id: 'tenants', label: 'Tenants', requires: 'manage_tenants', group: 'admin' },
  { id: 'audit', label: 'Audit Log', requires: 'read', group: 'admin' },
];

function Hash({ value, chars = 16 }: { value: string; chars?: number }) {
  return (
    <code className="hash" title={value}>
      {shortHash(value, chars)}
    </code>
  );
}

function Badge({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return <span className={`badge ${ok ? 'badge-ok' : 'badge-err'}`}>{children}</span>;
}

// Small monochrome icons (currentColor) for the tree views — deliberately
// plain line icons rather than emoji, which render inconsistently (size,
// color, style) across platforms.
function FolderIcon() {
  return (
    <svg className="tree-icon tree-icon-folder" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M1.75 3.75c0-.55.45-1 1-1h3.1c.24 0 .47.1.64.27l.98.98h5.78c.55 0 1 .45 1 1v6.25c0 .55-.45 1-1 1h-10.5c-.55 0-1-.45-1-1v-7.5z"
        fill="currentColor"
        fillOpacity="0.15"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg className="tree-icon tree-icon-file" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M4.25 1.75h4.5l3 3v8.5a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5v-11a.5.5 0 0 1 .5-.5z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
      <path d="M8.75 1.75v3h3" fill="none" stroke="currentColor" strokeWidth="1.1" strokeLinejoin="round" />
    </svg>
  );
}

// Package/crate glyph — distinguishes a plain SBOM upload (no document_type)
// from a generic document (FileIcon) in tree/version-picker rows.
function SbomIcon() {
  return (
    <svg className="tree-icon tree-icon-sbom" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <path
        d="M8 1.75l5.5 3.2v6.1L8 14.25l-5.5-3.2v-6.1L8 1.75z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
      <path
        d="M2.5 4.95L8 8.15l5.5-3.2M8 8.15v6.1"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// Branch glyph — flags a git-repo upload (GIT_REPO_DOCUMENT_TYPE) in
// tree/version-picker rows.
function GitRepoIcon() {
  return (
    <svg className="tree-icon tree-icon-git" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M4 3.75v8.5" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" />
      <path d="M4 8c3.2 0 4.8 0 7.3 0" stroke="currentColor" strokeWidth="1.2" fill="none" strokeLinecap="round" />
      <circle cx="4" cy="3.75" r="1.5" fill="currentColor" fillOpacity="0.15" stroke="currentColor" strokeWidth="1.1" />
      <circle cx="4" cy="12.25" r="1.5" fill="currentColor" fillOpacity="0.15" stroke="currentColor" strokeWidth="1.1" />
      <circle cx="12.5" cy="8" r="1.5" fill="currentColor" fillOpacity="0.15" stroke="currentColor" strokeWidth="1.1" />
    </svg>
  );
}

// Picks the tree row icon for a leaf/manifest by document_type: git-repo
// uploads get the branch glyph, other tagged documents get the plain file
// glyph, and untagged uploads (a straight SBOM) get the package glyph.
function TreeEntryIcon({ documentType }: { documentType?: string | null }) {
  if (isGitRepoDocumentType(documentType)) return <GitRepoIcon />;
  if (documentType) return <FileIcon />;
  return <SbomIcon />;
}

function ErrorBox({ message }: { message: string }) {
  return <div className="error-box">{message}</div>;
}

function Spinner({ label }: { label: string }) {
  return <div className="spinner">{label}</div>;
}

function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box card" onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <h2>{title}</h2>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn"
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function DownloadButton({ filename, data }: { filename: string; data: unknown }) {
  return (
    <button type="button" className="btn" onClick={() => downloadJson(filename, data)}>
      Download JSON
    </button>
  );
}

function NewKeyReveal({ newKey }: { newKey: CreateKeyResponse }) {
  return (
    <div className="result-box">
      <strong>Shown once — copy it now, it cannot be retrieved again.</strong>
      <div className="form-row">
        <code className="new-key">{newKey.key}</code>
        <CopyButton text={newKey.key} />
      </div>
      <div className="kv-row">
        <span className="kv-label">role</span>
        <span>{newKey.role}</span>
      </div>
      <div className="kv-row">
        <span className="kv-label">namespace scope</span>
        <span>{newKey.namespace_scope}</span>
      </div>
      <div className="kv-row">
        <span className="kv-label">expires</span>
        <span>{newKey.expires_at ? new Date(newKey.expires_at).toLocaleString() : 'never'}</span>
      </div>
    </div>
  );
}

// ---------- Dashboard ----------

function Dashboard({
  treeHead,
  onRefresh,
  headError,
}: {
  treeHead: TreeHead | null;
  onRefresh: () => void;
  headError: string;
}) {
  const [health, setHealth] = useState<boolean | null>(null);
  const [config, setConfig] = useState<BackendConfig | null>(null);

  useEffect(() => {
    let mounted = true;
    api.health().then((ok) => mounted && setHealth(ok));
    api.config().then((c) => mounted && setConfig(c)).catch(() => mounted && setConfig(null));
    return () => {
      mounted = false;
    };
  }, []);

  return (
    <>
      {config && (
        <div className="card">
          <h2>Backend Configuration</h2>
          <div className="kv-row">
            <span className="kv-label">Storage backend</span>
            <Badge ok={config.storage_backend !== 'in-memory'}>{config.storage_backend}</Badge>
            {config.storage_backend === 'in-memory' && (
              <span className="muted"> — uploaded SBOM content will not survive a server restart</span>
            )}
          </div>
          <div className="kv-row">
            <span className="kv-label">Signer backend</span>
            <span>{config.signer_backend}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">DEV_MODE</span>
            <Badge ok={!config.dev_mode}>{config.dev_mode ? 'on — RBAC relaxed' : 'off'}</Badge>
          </div>
        </div>
      )}
      <div className="card">
        <div className="card-header">
          <h2>Signed Tree Head</h2>
          <button className="btn" onClick={onRefresh}>Refresh</button>
        </div>
      <div className="kv-row">
        <span className="kv-label">Server</span>
        {health === null ? <span>checking…</span> : <Badge ok={health}>{health ? 'online' : 'offline'}</Badge>}
      </div>
      {treeHead ? (
        <>
          <div className="kv-row">
            <span className="kv-label">Tree size</span>
            <span>{treeHead.tree_size} leaves</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">Root hash</span>
            <Hash value={treeHead.root_hash} chars={32} />
          </div>
          <div className="kv-row">
            <span className="kv-label">Signature</span>
            <Hash value={treeHead.signature} chars={24} />
          </div>
          <div className="kv-row">
            <span className="kv-label">STH signature</span>
            <Badge ok={treeHead.signature_verified}>
              {treeHead.signature_verified ? 'verified' : 'FAILED'}
            </Badge>
          </div>
          <div className="kv-row">
            <span className="kv-label">Signed at</span>
            <span>{new Date(treeHead.created_at).toLocaleString()}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">Frontier ({treeHead.frontier.length} peaks)</span>
          </div>
          <ul className="peak-list">
            {treeHead.frontier.map((peak, i) => (
              <li key={i} title={peak}>
                peak {i}: <Hash value={peak} chars={24} />
              </li>
            ))}
          </ul>
        </>
      ) : headError ? (
        <ErrorBox message={headError} />
      ) : (
        <div className="muted">
          No tree head yet — this tenant hasn't uploaded anything.
        </div>
      )}
      </div>
    </>
  );
}

// ---------- Upload ----------

// A git-repo upload is just a "document" on the wire (format=document,
// document_type="git-repo") — no backend format value of its own. The UI
// treats it as a distinct file type: the upload form presets the document
// type instead of asking for it, and the detail panel routes it to
// GitRepoArtifact instead of the generic download-only DocumentArtifact.
const GIT_REPO_DOCUMENT_TYPE = 'git-repo';

function isGitRepoDocumentType(documentType: string | null | undefined): boolean {
  return (documentType ?? '').trim().toLowerCase() === GIT_REPO_DOCUMENT_TYPE;
}

function Upload({ onUploaded }: { onUploaded: (result: UploadResult) => void }) {
  const tenantId = useTenantOverride();
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState<'cyclonedx' | 'spdx' | 'document' | 'git-repo'>('cyclonedx');
  const [namespace, setNamespace] = useState('/');
  const [version, setVersion] = useState('');
  const [documentType, setDocumentType] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState('');

  const isGitRepo = format === 'git-repo';
  const isCustomDocument = format === 'document';
  const canUpload = !!file && !!version.trim() && (!isCustomDocument || !!documentType.trim());

  const upload = async () => {
    if (!canUpload || !file) return;
    setBusy(true);
    setError('');
    try {
      const res = await api.upload(
        file,
        isGitRepo ? 'document' : format,
        namespace,
        version.trim(),
        tenantId,
        isGitRepo ? GIT_REPO_DOCUMENT_TYPE : isCustomDocument ? documentType.trim() : undefined
      );
      setResult(res);
      onUploaded(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>Upload</h2>
      <label className="field">
        <span>File</span>
        <input
          type="file"
          onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
        />
      </label>
      <label className="field">
        <span>Format</span>
        <select
          value={format}
          onChange={(e) => setFormat(e.target.value as 'cyclonedx' | 'spdx' | 'document' | 'git-repo')}
        >
          <option value="cyclonedx">CycloneDX (JSON)</option>
          <option value="spdx">SPDX (JSON)</option>
          <option value="document">Other technical documentation</option>
          <option value="git-repo">Git repo (.tar / .tar.gz)</option>
        </select>
      </label>
      {isGitRepo && (
        <div className="muted upload-hint">
          Archive is browsable file-by-file in the detail view after upload — no need to unpack it yourself.
        </div>
      )}
      {isCustomDocument && (
        <label className="field">
          <span>Document type</span>
          <input
            value={documentType}
            onChange={(e) => setDocumentType(e.target.value)}
            placeholder="e.g. risk-assessment, test-report, cvd-policy"
          />
        </label>
      )}
      <label className="field">
        <span>Namespace</span>
        <input
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
          placeholder="/product/v1"
        />
      </label>
      <label className="field">
        <span>Version</span>
        <input
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          placeholder="e.g. 1.2.3"
        />
      </label>
      <button className="btn primary" disabled={!canUpload || busy} onClick={upload}>
        {busy ? 'Uploading…' : 'Upload'}
      </button>
      {error && <ErrorBox message={error} />}
      {result && (
        <div className="result-box">
          <Badge ok>accepted</Badge>
          <div className="kv-row">
            <span className="kv-label">version</span>
            <span>{result.version}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">namespace</span>
            <span>{result.domain}{result.namespace}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">leaf_index</span>
            <span>{result.leaf_index}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">tree_size</span>
            <span>{result.tree_size}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">sbom_hash</span>
            <Hash value={result.sbom_hash} chars={24} />
          </div>
          <div className="kv-row">
            <span className="kv-label">manifest_hash</span>
            <Hash value={result.manifest_hash} chars={24} />
          </div>
          <div className="kv-row">
            <span className="kv-label">new root</span>
            <Hash value={result.signed_tree_head.root_hash} chars={24} />
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Manifest lookup / SBOM artifact view ----------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function hexToText(hex: string): string {
  return new TextDecoder('utf-8').decode(hexToBytes(hex));
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

// "risk-assessment" -> "Risk Assessment V1.0" — document_type is stored as
// a free-form slug (kebab/snake case), so this is a display-only humanizer,
// not something round-tripped back to the API.
function documentDisplayName(documentType: string, version: string): string {
  const name = documentType
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(' ');
  return version ? `${name} V${version}` : name;
}

// "created_by"/"principal" is `apikey:<full key_id uuid>` — only show the
// last 5 characters so it doesn't dump the full identifier everywhere; the
// full value is still available on hover.
function shortPrincipal(value: string): string {
  if (!value) return '';
  return `…${value.slice(-5)}`;
}

interface SbomTreeNode {
  id: string;
  label: string;
  detail?: string;
  children: SbomTreeNode[];
}

// CycloneDX component fields vary a lot; pull whatever's useful for the
// detail line without assuming a strict shape.
function cycloneDxDetail(c: unknown): string | undefined {
  if (!c || typeof c !== 'object') return undefined;
  const obj = c as Record<string, unknown>;
  const bits = [obj.version, obj.type, obj.purl].filter((v) => typeof v === 'string') as string[];
  return bits.length ? bits.join(' · ') : undefined;
}

/// Prefers the real dependency graph (`dependencies[]`: bom-ref -> dependsOn)
/// over the `components[]` nesting, which is more about physical grouping
/// than "depends on." Falls back to nested `components[]`, then a flat list.
/// Circular refs (a real possibility in a dependency graph) are cut off
/// rather than recursed into.
function buildCycloneDxTree(doc: Record<string, unknown>): SbomTreeNode[] {
  const byRef = new Map<string, Record<string, unknown>>();
  const collect = (comps: unknown): void => {
    if (!Array.isArray(comps)) return;
    for (const c of comps) {
      if (c && typeof c === 'object') {
        const obj = c as Record<string, unknown>;
        if (typeof obj['bom-ref'] === 'string') byRef.set(obj['bom-ref'] as string, obj);
        collect(obj.components);
      }
    }
  };
  collect(doc.components);
  const metaComponent = (doc.metadata as Record<string, unknown> | undefined)?.component as
    | Record<string, unknown>
    | undefined;
  if (metaComponent && typeof metaComponent['bom-ref'] === 'string') {
    byRef.set(metaComponent['bom-ref'] as string, metaComponent);
  }

  const nodeFor = (ref: string): SbomTreeNode => {
    const c = byRef.get(ref);
    const name = (c?.name as string | undefined) ?? ref;
    return { id: ref, label: name, detail: cycloneDxDetail(c), children: [] };
  };

  const deps = doc.dependencies;
  if (Array.isArray(deps) && deps.length > 0) {
    const childrenOf = new Map<string, string[]>();
    for (const d of deps) {
      if (!d || typeof d !== 'object') continue;
      const obj = d as Record<string, unknown>;
      if (typeof obj.ref === 'string') {
        childrenOf.set(obj.ref, Array.isArray(obj.dependsOn) ? (obj.dependsOn as string[]) : []);
      }
    }
    const referenced = new Set<string>();
    Array.from(childrenOf.values()).forEach((list) => list.forEach((r) => referenced.add(r)));
    let roots = Array.from(childrenOf.keys()).filter((ref) => !referenced.has(ref));
    if (roots.length === 0) roots = Array.from(childrenOf.keys());

    const build = (ref: string, ancestors: Set<string>): SbomTreeNode => {
      const node = nodeFor(ref);
      if (ancestors.has(ref)) {
        return { ...node, label: `${node.label} (circular reference)`, children: [] };
      }
      const nextAncestors = new Set(ancestors).add(ref);
      node.children = (childrenOf.get(ref) ?? []).map((child) => build(child, nextAncestors));
      return node;
    };
    return roots.map((ref) => build(ref, new Set()));
  }

  // No dependency graph: fall back to whatever nesting components[] has.
  const fromComponents = (comps: unknown): SbomTreeNode[] => {
    if (!Array.isArray(comps)) return [];
    return comps.map((c) => {
      const obj = (c ?? {}) as Record<string, unknown>;
      const id = (obj['bom-ref'] as string | undefined) ?? (obj.name as string | undefined) ?? '?';
      return {
        id,
        label: (obj.name as string | undefined) ?? id,
        detail: cycloneDxDetail(obj),
        children: fromComponents(obj.components),
      };
    });
  };
  return fromComponents(doc.components);
}

/// SPDX has no inherent hierarchy on packages[] — it's reconstructed from
/// relationships[] (spdxElementId -> relatedSpdxElement). Falls back to a
/// flat package list if there are no relationships to build a tree from.
function buildSpdxTree(doc: Record<string, unknown>): SbomTreeNode[] {
  const byId = new Map<string, Record<string, unknown>>();
  if (Array.isArray(doc.packages)) {
    for (const p of doc.packages) {
      if (p && typeof p === 'object' && typeof (p as Record<string, unknown>).SPDXID === 'string') {
        byId.set((p as Record<string, unknown>).SPDXID as string, p as Record<string, unknown>);
      }
    }
  }

  const nodeFor = (id: string): SbomTreeNode => {
    const p = byId.get(id);
    const name = (p?.name as string | undefined) ?? id;
    const version = p?.versionInfo as string | undefined;
    return { id, label: name, detail: version, children: [] };
  };

  const rels = doc.relationships;
  if (Array.isArray(rels) && rels.length > 0) {
    const childrenOf = new Map<string, string[]>();
    for (const r of rels) {
      if (!r || typeof r !== 'object') continue;
      const obj = r as Record<string, unknown>;
      const parent = obj.spdxElementId as string | undefined;
      const child = obj.relatedSpdxElement as string | undefined;
      if (!parent || !child) continue;
      if (!childrenOf.has(parent)) childrenOf.set(parent, []);
      childrenOf.get(parent)!.push(child);
    }
    const referenced = new Set<string>();
    Array.from(childrenOf.values()).forEach((list) => list.forEach((c) => referenced.add(c)));
    let roots = Array.from(childrenOf.keys()).filter((id) => !referenced.has(id));
    if (roots.length === 0) roots = Array.from(byId.keys());

    const build = (id: string, ancestors: Set<string>): SbomTreeNode => {
      const node = nodeFor(id);
      if (ancestors.has(id)) {
        return { ...node, label: `${node.label} (circular reference)`, children: [] };
      }
      const nextAncestors = new Set(ancestors).add(id);
      node.children = (childrenOf.get(id) ?? []).map((c) => build(c, nextAncestors));
      return node;
    };
    return roots.map((id) => build(id, new Set()));
  }

  return Array.from(byId.keys()).map((id) => nodeFor(id));
}

interface SbomSummary {
  label: string;
  count: number;
  name?: string;
  pretty: string | null;
  tree: SbomTreeNode[] | null;
}

function summarizeSbom(hex: string, format: string): SbomSummary {
  let text: string;
  try {
    text = hexToText(hex);
  } catch {
    return { label: 'components', count: 0, pretty: null, tree: null };
  }
  try {
    const doc = JSON.parse(text);
    const pretty = JSON.stringify(doc, null, 2);
    if (format === 'cyclonedx' && Array.isArray(doc.components)) {
      return {
        label: 'components',
        count: doc.components.length,
        name: doc.metadata?.component?.name,
        pretty,
        tree: buildCycloneDxTree(doc),
      };
    }
    if (format === 'spdx' && Array.isArray(doc.packages)) {
      return {
        label: 'packages',
        count: doc.packages.length,
        name: doc.name,
        pretty,
        tree: buildSpdxTree(doc),
      };
    }
    return { label: 'top-level keys', count: Object.keys(doc).length, pretty, tree: null };
  } catch {
    return { label: 'components', count: 0, pretty: text, tree: null };
  }
}

function SbomTreeRow({ node, depth }: { node: SbomTreeNode; depth: number }) {
  const [open, setOpen] = useState(depth < 1);
  const hasChildren = node.children.length > 0;
  return (
    <div>
      <div
        className={`sbom-tree-row${hasChildren ? ' clickable' : ''}`}
        style={{ paddingLeft: depth * 18 }}
        onClick={() => hasChildren && setOpen((o) => !o)}
      >
        <span className="sbom-tree-toggle">{hasChildren ? (open ? '▾' : '▸') : '·'}</span>
        <span className="sbom-tree-label">{node.label}</span>
        {node.detail && <span className="sbom-tree-detail">{node.detail}</span>}
        {hasChildren && <span className="muted"> ({node.children.length})</span>}
      </div>
      {hasChildren && open && node.children.map((child, i) => (
        <SbomTreeRow key={`${child.id}-${i}`} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

function SbomTree({ roots }: { roots: SbomTreeNode[] }) {
  if (roots.length === 0) {
    return <div className="muted">No components/packages found to build a tree from.</div>;
  }
  return (
    <div className="sbom-tree sbom-content-tree">
      {roots.map((r, i) => (
        <SbomTreeRow key={`${r.id}-${i}`} node={r} depth={0} />
      ))}
    </div>
  );
}

function downloadBytes(filename: string, bytes: Uint8Array, mimeType = 'application/json') {
  const blob = new Blob([bytes as BlobPart], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function SbomArtifact({ manifest }: { manifest: Manifest }) {
  const bytes = manifest.sbom_hex.length / 2;
  const summary = summarizeSbom(manifest.sbom_hex, manifest.sbom_format);
  const hasTree = summary.tree !== null;
  const [view, setView] = useState<'tree' | 'raw' | 'none'>(hasTree ? 'tree' : 'raw');

  return (
    <div className="sbom-artifact">
      <div className="sbom-artifact-header">
        <div>
          <strong>{summary.name || 'SBOM artifact'}</strong>
          <span className="muted">
            {' '}
            · {manifest.sbom_format} · {formatBytes(bytes)}
            {summary.pretty !== null && ` · ${summary.count} ${summary.label}`}
          </span>
        </div>
        <div className="form-row">
          {hasTree && (
            <button
              className="btn"
              disabled={view === 'tree'}
              onClick={() => setView(view === 'tree' ? 'none' : 'tree')}
            >
              Tree view
            </button>
          )}
          {summary.pretty !== null && (
            <button className="btn" onClick={() => setView(view === 'raw' ? 'none' : 'raw')}>
              {view === 'raw' ? 'Hide raw SBOM' : 'Show raw SBOM'}
            </button>
          )}
          <button
            className="btn"
            onClick={() =>
              downloadBytes(`${manifest.sbom_hash.slice(0, 16)}.sbom.json`, hexToBytes(manifest.sbom_hex))
            }
          >
            Download SBOM
          </button>
        </div>
      </div>
      {view === 'tree' && hasTree && <SbomTree roots={summary.tree as SbomTreeNode[]} />}
      {view === 'raw' && summary.pretty !== null && <pre className="json sbom-json">{summary.pretty}</pre>}
    </div>
  );
}

const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46, 0x2d]; // "%PDF-"

function isPdf(bytes: Uint8Array): boolean {
  return PDF_MAGIC.every((b, i) => bytes[i] === b);
}

// Documents carry no stored MIME type, so "is this text worth rendering
// inline" is a heuristic: it must decode as valid UTF-8 (no replacement
// characters, ruling out arbitrary binary), and not be dominated by
// non-printable control bytes (ruling out binary that happens to decode).
function displayableText(bytes: Uint8Array): string | null {
  if (bytes.length === 0) return '';
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  let controlCount = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 32 && c !== 9 && c !== 10 && c !== 13) controlCount++;
  }
  if (controlCount / text.length > 0.01) return null;
  return text;
}

function DocumentArtifact({ manifest }: { manifest: Manifest }) {
  const bytes = useMemo(() => hexToBytes(manifest.sbom_hex), [manifest.sbom_hex]);
  const pdf = useMemo(() => isPdf(bytes), [bytes]);
  const text = useMemo(() => (pdf ? null : displayableText(bytes)), [pdf, bytes]);

  const pdfUrl = useMemo(() => {
    if (!pdf) return null;
    const blob = new Blob([bytes as BlobPart], { type: 'application/pdf' });
    return URL.createObjectURL(blob);
  }, [pdf, bytes]);

  useEffect(() => {
    return () => {
      if (pdfUrl) URL.revokeObjectURL(pdfUrl);
    };
  }, [pdfUrl]);

  return (
    <div className="sbom-artifact">
      <div className="sbom-artifact-header">
        <div>
          <strong>{documentDisplayName(manifest.document_type ?? '', manifest.version)}</strong>
          <span className="muted"> · document · {formatBytes(bytes.length)}</span>
        </div>
        <div className="form-row">
          <button
            className="btn"
            onClick={() =>
              downloadBytes(
                `${manifest.sbom_hash.slice(0, 16)}.${manifest.document_type}`,
                bytes,
                pdf ? 'application/pdf' : 'application/octet-stream'
              )
            }
          >
            Download document
          </button>
        </div>
      </div>
      {pdf && pdfUrl && <iframe title="document preview" src={pdfUrl} className="document-pdf-preview" />}
      {!pdf && text !== null && <pre className="json sbom-json">{text}</pre>}
      {!pdf && text === null && (
        <div className="muted">No preview available for this file type — download to view.</div>
      )}
    </div>
  );
}

// ---------- Git repo (tar/tar.gz) browsing ----------

// TypeScript 4.9's DOM lib predates the Compression Streams API — it's a
// real, widely-supported browser API (Chrome 80+, Firefox 113+, Safari
// 16.4+), just not in this project's lib.dom.d.ts yet.
declare global {
  interface DecompressionStream {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
  }
  // eslint-disable-next-line no-var
  var DecompressionStream: {
    prototype: DecompressionStream;
    new (format: 'gzip' | 'deflate' | 'deflate-raw'): DecompressionStream;
  };
}

interface TarEntry {
  name: string;
  size: number;
  isDirectory: boolean;
  dataStart: number;
}

function isGzip(bytes: Uint8Array): boolean {
  return bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
}

async function gunzipIfNeeded(bytes: Uint8Array): Promise<Uint8Array> {
  if (!isGzip(bytes)) return bytes;
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('this browser cannot decompress gzip — try a Chromium/Firefox/Safari from the last couple of years');
  }
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function readTarString(bytes: Uint8Array, offset: number, length: number): string {
  let end = offset;
  const stop = Math.min(offset + length, bytes.length);
  while (end < stop && bytes[end] !== 0) end++;
  return new TextDecoder('utf-8').decode(bytes.subarray(offset, end));
}

function readTarOctal(bytes: Uint8Array, offset: number, length: number): number {
  const s = readTarString(bytes, offset, length).trim();
  return s ? parseInt(s, 8) || 0 : 0;
}

function isZeroBlock(bytes: Uint8Array, offset: number): boolean {
  for (let i = 0; i < 512; i++) {
    if (bytes[offset + i] !== 0) return false;
  }
  return true;
}

// Routing to the git-repo browser shouldn't depend on someone having typed
// the document_type exactly as "git-repo" — a gzip magic byte or a ustar
// header is effectively unambiguous, so any document (regardless of its
// label) that looks like a tar/tar.gz gets the browsable view instead of
// the plain download-only fallback.
function looksLikeTarArchive(bytes: Uint8Array): boolean {
  if (isGzip(bytes)) return true;
  if (bytes.length < 512) return false;
  return readTarString(bytes, 257, 6).startsWith('ustar');
}

// Minimal ustar/GNU/pax tar reader — enough to list and extract the
// entries a real repo archive (e.g. `git archive`) produces: fixed 100-byte
// names plus the ustar "prefix" field for longer ones, GNU long-name
// ('L') headers, and pax extended ('x') headers for unicode/very long
// paths. Base-256 (>8GB) size encoding isn't handled — not a real case for
// source trees.
function parseTar(bytes: Uint8Array): TarEntry[] {
  const entries: TarEntry[] = [];
  let offset = 0;
  let longNameOverride: string | null = null;
  let paxPathOverride: string | null = null;

  while (offset + 512 <= bytes.length) {
    if (isZeroBlock(bytes, offset)) break;

    const typeflag = String.fromCharCode(bytes[offset + 156]);
    let name = readTarString(bytes, offset, 100);
    const prefix = readTarString(bytes, offset + 345, 155);
    if (prefix) name = `${prefix}/${name}`;
    const size = readTarOctal(bytes, offset + 124, 12);
    const dataStart = offset + 512;
    const dataBlocks = Math.ceil(size / 512);
    let nextOffset = dataStart + dataBlocks * 512;
    if (nextOffset <= offset) break; // malformed — avoid an infinite loop

    if (typeflag === 'L') {
      longNameOverride = readTarString(bytes, dataStart, size);
      offset = nextOffset;
      continue;
    }
    if (typeflag === 'x') {
      const text = new TextDecoder('utf-8').decode(bytes.subarray(dataStart, Math.min(dataStart + size, bytes.length)));
      const match = text.match(/\d+ path=([^\n]*)\n/);
      if (match) paxPathOverride = match[1];
      offset = nextOffset;
      continue;
    }
    if (typeflag === 'g' || typeflag === 'K') {
      offset = nextOffset;
      continue;
    }

    if (longNameOverride) {
      name = longNameOverride;
      longNameOverride = null;
    } else if (paxPathOverride) {
      name = paxPathOverride;
      paxPathOverride = null;
    }

    if (name && (typeflag === '0' || typeflag === '\0' || typeflag === '5')) {
      entries.push({
        name,
        size,
        isDirectory: typeflag === '5' || name.endsWith('/'),
        dataStart,
      });
    }
    offset = nextOffset;
  }
  return entries;
}

// macOS's tar (and Finder/zip) sprinkle sidecar/metadata entries into
// archives that carry no real repo content — AppleDouble resource-fork
// files ("._foo" next to "foo"), Finder's ".DS_Store", and zip's
// "__MACOSX/" folder. Noise, not files anyone uploading a repo meant to
// include, so they're filtered out of the browser entirely.
function isMacOsJunkTarEntry(name: string): boolean {
  const base = name.split('/').pop() ?? name;
  return base.startsWith('._') || base === '.DS_Store' || name.startsWith('__MACOSX/') || name.includes('/__MACOSX/');
}

function GitRepoArtifact({ manifest }: { manifest: Manifest }) {
  const rawBytes = useMemo(() => hexToBytes(manifest.sbom_hex), [manifest.sbom_hex]);
  const [tarBytes, setTarBytes] = useState<Uint8Array | null>(null);
  const [entries, setEntries] = useState<TarEntry[] | null>(null);
  const [parseError, setParseError] = useState('');
  const [selected, setSelected] = useState<TarEntry | null>(null);

  useEffect(() => {
    let cancelled = false;
    setTarBytes(null);
    setEntries(null);
    setParseError('');
    setSelected(null);
    gunzipIfNeeded(rawBytes)
      .then((bytes) => {
        if (cancelled) return;
        const files = parseTar(bytes)
          .filter((e) => !e.isDirectory && !isMacOsJunkTarEntry(e.name))
          .sort((a, b) => a.name.localeCompare(b.name));
        setTarBytes(bytes);
        setEntries(files);
      })
      .catch((e) => {
        if (!cancelled) setParseError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [rawBytes]);

  const selectedBytes = useMemo(() => {
    if (!selected || !tarBytes) return null;
    return tarBytes.subarray(selected.dataStart, selected.dataStart + selected.size);
  }, [selected, tarBytes]);

  const selectedPdf = useMemo(() => (selectedBytes ? isPdf(selectedBytes) : false), [selectedBytes]);
  const selectedText = useMemo(
    () => (selectedBytes && !selectedPdf ? displayableText(selectedBytes) : null),
    [selectedBytes, selectedPdf]
  );
  const selectedPdfUrl = useMemo(() => {
    if (!selectedBytes || !selectedPdf) return null;
    const blob = new Blob([selectedBytes as BlobPart], { type: 'application/pdf' });
    return URL.createObjectURL(blob);
  }, [selectedBytes, selectedPdf]);
  useEffect(() => {
    return () => {
      if (selectedPdfUrl) URL.revokeObjectURL(selectedPdfUrl);
    };
  }, [selectedPdfUrl]);

  return (
    <div className="sbom-artifact">
      <div className="sbom-artifact-header">
        <div>
          <strong>{documentDisplayName(manifest.document_type ?? '', manifest.version)}</strong>
          <span className="muted">
            {' '}
            · git repo · {formatBytes(rawBytes.length)}
            {entries ? ` · ${entries.length} file${entries.length === 1 ? '' : 's'}` : ''}
          </span>
        </div>
        <div className="form-row">
          <button
            className="btn"
            onClick={() =>
              downloadBytes(
                `${manifest.sbom_hash.slice(0, 16)}.tar`,
                rawBytes,
                isGzip(rawBytes) ? 'application/gzip' : 'application/x-tar'
              )
            }
          >
            Download archive
          </button>
        </div>
      </div>
      {parseError && <ErrorBox message={`Could not read this as a tar archive: ${parseError}`} />}
      {!parseError && entries === null && <Spinner label="Reading archive…" />}
      {!parseError && entries !== null && entries.length === 0 && (
        <div className="muted">Archive contains no files.</div>
      )}
      {!parseError && entries !== null && entries.length > 0 && (
        <div className="git-repo-browser">
          <div className="git-repo-files sbom-tree">
            {entries.map((e) => (
              <div
                key={e.name}
                className={`sbom-tree-row clickable${selected?.name === e.name ? ' git-repo-file-active' : ''}`}
                onClick={() => setSelected(e)}
                title={e.name}
              >
                <FileIcon />
                <span className="sbom-tree-label">{e.name}</span>
                <span className="sbom-tree-detail">{formatBytes(e.size)}</span>
              </div>
            ))}
          </div>
          <div className="git-repo-preview">
            {!selected && <div className="muted">Select a file on the left to preview it.</div>}
            {selected && selectedPdf && selectedPdfUrl && (
              <iframe title="repo file preview" src={selectedPdfUrl} className="document-pdf-preview" />
            )}
            {selected && !selectedPdf && selectedText !== null && (
              <pre className="json sbom-json">{selectedText || '(empty file)'}</pre>
            )}
            {selected && !selectedPdf && selectedText === null && (
              <div className="git-repo-file-fallback">
                <div className="muted">No preview available for this file type.</div>
                <button
                  className="btn"
                  onClick={() =>
                    selectedBytes && downloadBytes(selected.name.split('/').pop() || 'file', selectedBytes)
                  }
                >
                  Download file
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Live filter over the tree/table below — matches namespace or file name,
// not an exact-hash jump (a manifest hash pasted in place of a URL-based
// deep link is still reachable directly, e.g. via initialSelectedHash).
function SbomSearchBox({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return (
    <div className="form-row">
      <label className="field">
        <span>Search</span>
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="filter by namespace or file name"
        />
      </label>
      {value && (
        <button className="btn" onClick={() => onChange('')}>
          Clear
        </button>
      )}
    </div>
  );
}

function VersionPicker({ leaves, onSelect }: { leaves: Leaf[]; onSelect: (hash: string) => void }) {
  return (
    <div className="card">
      <h2>Select a version</h2>
      <div className="sbom-tree">
        {leaves.map((leaf) => (
          <div
            key={leaf.seq_id}
            className={`sbom-tree-row${leaf.manifest_hash ? ' clickable' : ''}`}
            onClick={() => leaf.manifest_hash && onSelect(leaf.manifest_hash)}
            title={leaf.manifest_hash ? 'View this version' : 'No manifest available'}
          >
            <TreeEntryIcon documentType={leaf.document_type} />
            <span className="sbom-tree-label" title={leaf.leaf_hash}>
              {leaf.document_type
                ? documentDisplayName(leaf.document_type, leaf.version ?? '')
                : documentDisplayName('SBOM', leaf.version ?? '')}
            </span>
            <span className="sbom-tree-detail">
              {new Date(leaf.created_at).toLocaleString()}
            </span>
            {leaf.revoked && <Badge ok={false}>revoked</Badge>}
          </div>
        ))}
      </div>
    </div>
  );
}

function SbomDetailPanel({
  hash,
  tenantId,
  onRevoked,
}: {
  hash: string;
  tenantId?: string;
  /** Called after a successful revoke so the caller can refresh whatever
   * list this detail view was opened from (e.g. the Explorer tree), which
   * otherwise keeps showing the now-revoked item until manually refreshed. */
  onRevoked?: () => void;
}) {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState('');
  const [complianceReportFor, setComplianceReportFor] = useState<string | null>(null);

  // Only bothers sniffing document uploads — a real SBOM is validated
  // CycloneDX/SPDX JSON server-side already, so it can never collide with
  // a tar/gzip signature.
  const looksLikeTar = useMemo(
    () => (manifest?.document_type ? looksLikeTarArchive(hexToBytes(manifest.sbom_hex)) : false),
    [manifest?.document_type, manifest?.sbom_hex]
  );

  const load = useCallback(async () => {
    setBusy(true);
    setError('');
    try {
      setManifest(await api.manifest(hash, tenantId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setManifest(null);
    } finally {
      setBusy(false);
    }
  }, [hash, tenantId]);

  useEffect(() => {
    load();
  }, [load]);

  const revoke = async () => {
    if (!manifest) return;
    if (
      !window.confirm(
        'This revocation is final and cannot be undone. The manifest stays in the log (nothing is deleted), but it will be permanently marked as revoked/superseded.\n\nRevoke this manifest?'
      )
    ) {
      return;
    }
    setRevoking(true);
    setRevokeError('');
    try {
      await api.revokeManifest(manifest.manifest_hash, tenantId);
      await load(); // refresh to pick up revoked status
      onRevoked?.();
    } catch (e) {
      setRevokeError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevoking(false);
    }
  };

  return (
    <div className="card">
      <h2>{manifest?.document_type ? 'Document Details' : 'SBOM Details'}</h2>
      {busy && <Spinner label="Loading…" />}
      {error && <ErrorBox message={error} />}
      {!busy && manifest && (
        <div className="result-box">
          {isGitRepoDocumentType(manifest.document_type) || looksLikeTar ? (
            <GitRepoArtifact key={manifest.manifest_hash} manifest={manifest} />
          ) : manifest.document_type ? (
            <DocumentArtifact key={manifest.manifest_hash} manifest={manifest} />
          ) : (
            <SbomArtifact key={manifest.manifest_hash} manifest={manifest} />
          )}
          <div className="kv-row">
            <span className="kv-label">status</span>
            <Badge ok={!manifest.revoked}>{manifest.revoked ? 'revoked' : 'active'}</Badge>
            {!manifest.revoked && (
              <button className="btn" disabled={revoking} onClick={revoke}>
                {revoking ? 'Revoking…' : 'Revoke'}
              </button>
            )}
          </div>
          {revokeError && <ErrorBox message={revokeError} />}
          {manifest.revoked && (
            <>
              <div className="kv-row">
                <span className="kv-label">revoked_by</span>
                <span title={manifest.revoked_by ?? ''}>
                  {manifest.revoked_by ? shortPrincipal(manifest.revoked_by) : '—'}
                </span>
              </div>
              <div className="kv-row">
                <span className="kv-label">revoked_at</span>
                <span>{manifest.revoked_at ? new Date(manifest.revoked_at).toLocaleString() : '—'}</span>
              </div>
            </>
          )}
          {manifest.compliance.length > 0 && (
            <div className="compliance-block">
              <h3>Compliance</h3>
              {manifest.compliance.map((c) => {
                const hasIssues = c.minimum_issues.length > 0 || c.missing_fields.length > 0;
                return (
                  <div key={c.profile_id} className="compliance-profile">
                    <div className="kv-row">
                      <span className="kv-label">{c.profile_name}</span>
                      <Badge ok={c.meets_minimum}>{c.meets_minimum ? 'meets minimum' : 'below minimum'}</Badge>
                      <Badge ok={c.fully_compliant}>
                        {c.fully_compliant ? 'fully compliant' : 'not fully compliant'}
                      </Badge>
                      {hasIssues && (
                        <button className="btn" onClick={() => setComplianceReportFor(c.profile_id)}>
                          View non-compliance report
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          {complianceReportFor && (() => {
            const c = manifest.compliance.find((p) => p.profile_id === complianceReportFor);
            if (!c) return null;
            return (
              <Modal title={`Non-compliance report — ${c.profile_name}`} onClose={() => setComplianceReportFor(null)}>
                {c.minimum_issues.length > 0 && (
                  <div className="muted">
                    Missing for minimum compliance:
                    <ul>
                      {c.minimum_issues.map((m, i) => (
                        <li key={i}>{m}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {c.meets_minimum && !c.fully_compliant && c.missing_fields.length > 0 && (
                  <div className="muted">
                    Missing for full compliance:
                    <ul>
                      {c.missing_fields.map((m, i) => (
                        <li key={i}>{m}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </Modal>
            );
          })()}
          <div className="kv-row">
            <span className="kv-label">version</span>
            <span>{manifest.version}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">namespace</span>
            <span>{manifest.domain}{manifest.namespace}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">sbom_hash</span>
            <Hash value={manifest.sbom_hash} chars={24} />
          </div>
          <div className="kv-row">
            <span className="kv-label">previous_manifest_hash</span>
            <span>{manifest.previous_manifest_hash ? <Hash value={manifest.previous_manifest_hash} chars={24} /> : 'none (first upload)'}</span>
          </div>
          {manifest.dsse_envelope ? (
            <>
              <div className="kv-row">
                <span className="kv-label">dsse signature</span>
                <Hash value={manifest.dsse_envelope.signatures[0]?.sig ?? ''} chars={24} />
              </div>
              <div className="kv-row">
                <span className="kv-label">attestation</span>
                <DownloadButton filename={`${manifest.manifest_hash}.dsse.json`} data={manifest.dsse_envelope} />
                <span className="muted"> — verify with cosign/openssl against this SBOM's hash</span>
              </div>
            </>
          ) : (
            <div className="kv-row">
              <span className="kv-label">signature</span>
              <span>
                {manifest.signature ? <Hash value={manifest.signature} chars={24} /> : 'none'}
                {' '}<em>(signed under legacy scheme, not third-party verifiable)</em>
              </span>
            </div>
          )}
          <div className="kv-row">
            <span className="kv-label">created_by</span>
            <span>{manifest.created_by}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">created_at</span>
            <span>{new Date(manifest.created_at).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Namespace tree (folders = path segments, SBOMs = leaves) ----------

interface NamespaceTreeNode {
  id: string;
  name: string;
  children: NamespaceTreeNode[];
  leaves: Leaf[];
}

/// Turns namespaces like "/products/v1" into nested folders ("products" >
/// "v1"), with each leaf placed as a file under the folder matching its
/// exact namespace. Multiple leaves can share one folder (repeat uploads to
/// the same namespace); a leaf at "/" lands at the root, not in a folder.
function buildNamespaceTree(leaves: Leaf[], domain: string): NamespaceTreeNode {
  const root: NamespaceTreeNode = { id: domain || '/', name: domain || '/', children: [], leaves: [] };
  for (const leaf of leaves) {
    const parts = leaf.namespace.split('/').filter(Boolean);
    let node = root;
    let path = '';
    for (const part of parts) {
      path += '/' + part;
      let child = node.children.find((c) => c.name === part);
      if (!child) {
        child = { id: path, name: part, children: [], leaves: [] };
        node.children.push(child);
      }
      node = child;
    }
    node.leaves.push(leaf);
  }
  const sortRec = (n: NamespaceTreeNode) => {
    n.children.sort((a, b) => a.name.localeCompare(b.name));
    n.children.forEach(sortRec);
  };
  sortRec(root);
  return root;
}

// Splits one namespace's leaves into per-file groups — SBOM uploads (no
// document_type) are one file, and each distinct document_type is its own
// file, so a namespace holding both an SBOM and a risk-assessment doc
// shows two rows, not one merged row. Leaves arrive newest-first (API
// order) and that order is preserved within each group.
//
// document_type is free text typed on each upload, so the grouping key is
// normalized (trimmed, case-folded) — "Risk Assesment" and "risk assesment"
// are the same file typed inconsistently, not two different files. The
// displayed label still uses the newest leaf's original casing.
function groupLeavesByFile(leaves: Leaf[]): Leaf[][] {
  const groups = new Map<string, Leaf[]>();
  for (const leaf of leaves) {
    const key = leaf.document_type ? leaf.document_type.trim().toLowerCase() : '__sbom__';
    const group = groups.get(key);
    if (group) {
      group.push(leaf);
    } else {
      groups.set(key, [leaf]);
    }
  }
  return Array.from(groups.values());
}

// Matches the Explorer search box against namespace and file name — the
// same label shown on each tree row (document_type, or "SBOM" when unset).
function leafMatchesSearch(leaf: Leaf, term: string): boolean {
  const t = term.trim().toLowerCase();
  if (!t) return true;
  const namespace = `${leaf.domain}${leaf.namespace}`.toLowerCase();
  const fileName = (leaf.document_type ?? 'SBOM').toLowerCase();
  return namespace.includes(t) || fileName.includes(t);
}

function SbomLeafRow({
  leaf,
  depth,
  onViewSbom,
}: {
  leaf: Leaf;
  depth: number;
  onViewSbom: (hash: string) => void;
}) {
  return (
    <div
      className={`sbom-tree-row${leaf.manifest_hash ? ' clickable' : ''}`}
      style={{ paddingLeft: depth * 18 }}
      onClick={() => leaf.manifest_hash && onViewSbom(leaf.manifest_hash)}
      title={leaf.manifest_hash ? (leaf.document_type ? 'View document' : 'View SBOM') : 'No manifest available'}
    >
      <TreeEntryIcon documentType={leaf.document_type} />
      <span className="sbom-tree-label" title={leaf.leaf_hash}>
        {leaf.document_type
          ? documentDisplayName(leaf.document_type, leaf.version ?? '')
          : documentDisplayName('SBOM', leaf.version ?? '')}
      </span>
      <span className="sbom-tree-detail">
        {new Date(leaf.created_at).toLocaleDateString()}
      </span>
      {leaf.revoked && <Badge ok={false}>revoked</Badge>}
    </div>
  );
}

// Collapses every version of one file (all leaves sharing the same
// document_type, or all plain SBOM uploads when null) into a single row —
// clicking it opens a version picker in the right pane instead of jumping
// straight to a manifest, since there's more than one to choose from.
// `leaves` is already newest-first (API order) and, per groupLeavesByFile,
// all share the same document_type.
function SbomFileGroupRow({
  leaves,
  depth,
  onViewGroup,
}: {
  leaves: Leaf[];
  depth: number;
  onViewGroup: (leaves: Leaf[]) => void;
}) {
  const documentType = leaves[0]?.document_type;
  const revokedCount = leaves.filter((l) => l.revoked).length;
  return (
    <div
      className="sbom-tree-row clickable"
      style={{ paddingLeft: depth * 18 }}
      onClick={() => onViewGroup(leaves)}
      title="Select a version to view"
    >
      <TreeEntryIcon documentType={documentType} />
      <span className="sbom-tree-label">
        {documentType ? documentDisplayName(documentType, '') : 'SBOM'}
      </span>
      <span className="sbom-tree-detail">{leaves.length} versions</span>
      {revokedCount > 0 && (
        <Badge ok={false}>{revokedCount} revoked</Badge>
      )}
    </div>
  );
}

function NamespaceFolderRow({
  node,
  depth,
  onViewSbom,
  onViewGroup,
  forceOpen = false,
}: {
  node: NamespaceTreeNode;
  depth: number;
  onViewSbom: (hash: string) => void;
  onViewGroup: (leaves: Leaf[]) => void;
  /** True while an active search filter is narrowing the tree — expands
   * every folder so filtered matches are visible without manually clicking
   * through each collapsed level, overriding the local toggle below. */
  forceOpen?: boolean;
}) {
  // depth 0 is the org/domain root — expand it by default so the first
  // real namespace level (depth 1) is visible immediately, but leave that
  // first level (and everything under it) collapsed by default rather
  // than auto-expanding the whole tree.
  const [open, setOpen] = useState(depth < 1);
  const isOpen = forceOpen || open;
  const hasContent = node.children.length > 0 || node.leaves.length > 0;
  return (
    <div>
      <div
        className={`sbom-tree-row${hasContent ? ' clickable' : ''}${depth === 1 ? ' sbom-tree-row-top' : ''}`}
        style={{ paddingLeft: depth * 18 }}
        onClick={() => hasContent && setOpen((o) => !o)}
      >
        <span className="sbom-tree-toggle">{hasContent ? (isOpen ? '▾' : '▸') : '·'}</span>
        <FolderIcon />
        <span className="sbom-tree-label">{node.name}</span>
        <span className="muted">
          {' '}
          ({node.leaves.length} item{node.leaves.length === 1 ? '' : 's'}
          {node.children.length > 0 ? `, ${node.children.length} sub` : ''})
        </span>
      </div>
      {isOpen && (
        <>
          {groupLeavesByFile(node.leaves).map((group) =>
            group.length === 1 ? (
              <SbomLeafRow key={group[0].seq_id} leaf={group[0]} depth={depth + 1} onViewSbom={onViewSbom} />
            ) : (
              <SbomFileGroupRow
                key={group[0].document_type ?? '__sbom__'}
                leaves={group}
                depth={depth + 1}
                onViewGroup={onViewGroup}
              />
            )
          )}
          {node.children.map((child) => (
            <NamespaceFolderRow
              key={child.id}
              node={child}
              depth={depth + 1}
              onViewSbom={onViewSbom}
              onViewGroup={onViewGroup}
              forceOpen={forceOpen}
            />
          ))}
        </>
      )}
    </div>
  );
}

function NamespaceTree({
  leaves,
  onViewSbom,
  onViewGroup,
  forceOpen = false,
}: {
  leaves: Leaf[];
  onViewSbom: (hash: string) => void;
  onViewGroup: (leaves: Leaf[]) => void;
  forceOpen?: boolean;
}) {
  // All leaves in one call belong to one tenant, so they share one domain —
  // shown as the tree's root folder, e.g. "myorg.example" > "products" >
  // "v1" > (SBOM), which reads the same as "myorg.example/products/v1".
  const domain = leaves[0]?.domain ?? '';
  const root = buildNamespaceTree(leaves, domain);
  if (root.children.length === 0 && root.leaves.length === 0) {
    return <div className="muted">No leaves yet.</div>;
  }
  return (
    <div className="sbom-tree">
      <NamespaceFolderRow
        node={root}
        depth={0}
        onViewSbom={onViewSbom}
        onViewGroup={onViewGroup}
        forceOpen={forceOpen}
      />
    </div>
  );
}

// ---------- Leaves ----------

// Whether the "Currently running" button/view shows in the Explorer at
// all, toggled from Settings. Per-browser (localStorage), not a tenant
// setting on the server — this hides a UI affordance, it doesn't change
// what any API call returns, so there's nothing server-side to gate.
// Defaults off — an opt-in view, unlike the per-namespace visibility
// feature it sits on top of (that one's still on by default).
const CURRENTLY_RUNNING_VIEW_KEY = 'magnolia_currently_running_view_enabled';

function readCurrentlyRunningViewEnabled(): boolean {
  return localStorage.getItem(CURRENTLY_RUNNING_VIEW_KEY) === 'true';
}

function writeCurrentlyRunningViewEnabled(enabled: boolean): void {
  localStorage.setItem(CURRENTLY_RUNNING_VIEW_KEY, String(enabled));
}

function Leaves({ initialSelectedHash }: { initialSelectedHash?: string }) {
  const tenantId = useTenantOverride();
  const [leaves, setLeaves] = useState<Leaf[] | null>(null);
  const [error, setError] = useState('');
  // Leaves fully remounts each time you switch to this tab (App renders it
  // conditionally), so this lazy init correctly re-seeds the selection when
  // jumping here right after an upload, without needing to track/clear a
  // "consumed" flag.
  const [selectedHash, setSelectedHash] = useState<string | undefined>(initialSelectedHash);
  // Set when a multi-version namespace row is clicked — the right pane
  // shows a version picker instead of jumping straight to a manifest.
  // Cleared by any selection that already names a specific manifest
  // directly (search box, table row, "currently running" row, or a
  // single-version tree row), so a stale "← All versions" link never
  // points at an unrelated group.
  const [selectedGroup, setSelectedGroup] = useState<Leaf[] | null>(null);
  const selectHash = useCallback((hash: string) => {
    setSelectedGroup(null);
    setSelectedHash(hash);
  }, []);
  const [view, setView] = useState<'tree' | 'table' | 'current'>('tree');
  const [showRevoked, setShowRevoked] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [current, setCurrent] = useState<CurrentManifest[] | null>(null);
  // Read once per mount — Leaves fully remounts on every tab switch (see
  // above), so toggling this in Settings and switching back here picks up
  // the new value without needing a live cross-tab subscription.
  const [currentlyRunningViewEnabled] = useState(() => readCurrentlyRunningViewEnabled());

  const load = useCallback(() => {
    setError('');
    api.leaves(50, 0, tenantId)
      .then(setLeaves)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    // Non-fatal: the tree/table views still work if this fails. Skipped
    // entirely when the view is turned off — nothing would use it.
    if (currentlyRunningViewEnabled) {
      api.currentManifests(tenantId).then(setCurrent).catch(() => {});
    }
  }, [tenantId, currentlyRunningViewEnabled]);

  useEffect(load, [load]);

  // Revoked SBOMs are superseded/invalid, so they're hidden from the browse
  // views by default — "Show revoked" brings them back (visually marked).
  // Either way they're still fully retrievable directly by hash; nothing is
  // ever deleted.
  const visibleLeaves = leaves ? (showRevoked ? leaves : leaves.filter((l) => !l.revoked)) : null;
  const filteredLeaves = visibleLeaves
    ? searchTerm.trim()
      ? visibleLeaves.filter((l) => leafMatchesSearch(l, searchTerm))
      : visibleLeaves
    : null;
  // Namespace tree groups by namespace inherently; the flat table doesn't,
  // so it's sorted by namespace (then file name) to match the tree's order.
  const tableLeaves = useMemo(() => {
    if (!filteredLeaves) return null;
    return [...filteredLeaves].sort((a, b) => {
      const nsCompare = `${a.domain}${a.namespace}`.localeCompare(`${b.domain}${b.namespace}`);
      if (nsCompare !== 0) return nsCompare;
      return (a.document_type ?? '').localeCompare(b.document_type ?? '');
    });
  }, [filteredLeaves]);

  return (
    <div className="explorer-layout">
      <div className="card explorer-left">
        <div className="card-header">
          <h2>Archive Explorer</h2>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        <SbomSearchBox value={searchTerm} onChange={setSearchTerm} />
        <div className="form-row explorer-filters">
          <button className="btn" disabled={view === 'tree'} onClick={() => setView('tree')}>
            Namespace tree
          </button>
          <button className="btn" disabled={view === 'table'} onClick={() => setView('table')}>
            Table
          </button>
          {currentlyRunningViewEnabled && (
            <button className="btn" disabled={view === 'current'} onClick={() => setView('current')}>
              Currently running
            </button>
          )}
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={showRevoked}
              onChange={(e) => setShowRevoked(e.target.checked)}
            />
            Show revoked
          </label>
        </div>
        {error && <ErrorBox message={error} />}
        {visibleLeaves === null && !error && <Spinner label="Loading leaves…" />}
        {visibleLeaves && visibleLeaves.length === 0 && <div className="muted">No leaves yet.</div>}
        {visibleLeaves && visibleLeaves.length > 0 && filteredLeaves && filteredLeaves.length === 0 && (
          <div className="muted">No matches for "{searchTerm.trim()}".</div>
        )}
        {filteredLeaves && filteredLeaves.length > 0 && view === 'tree' && (
          <NamespaceTree
            leaves={filteredLeaves}
            onViewSbom={selectHash}
            onViewGroup={(g) => {
              setSelectedGroup(g);
              // Leaves within a group arrive newest-first (groupLeavesByFile),
              // so jump straight to the newest version instead of forcing a
              // picker click — "All versions" (rendered whenever selectedGroup
              // is set) still reaches the rest.
              setSelectedHash(g.find((l) => l.manifest_hash)?.manifest_hash ?? undefined);
            }}
            forceOpen={searchTerm.trim().length > 0}
          />
        )}
        {tableLeaves && tableLeaves.length > 0 && view === 'table' && (
          <table className="table">
            <thead>
              <tr>
                <th>seq</th>
                <th>leaf_index</th>
                <th>leaf_hash</th>
                <th>namespace</th>
                <th>status</th>
                <th>created</th>
              </tr>
            </thead>
            <tbody>
              {tableLeaves.map((leaf) => (
                <tr
                  key={leaf.seq_id}
                  className={leaf.manifest_hash ? 'row-clickable' : ''}
                  onClick={() => leaf.manifest_hash && selectHash(leaf.manifest_hash)}
                >
                  <td>{leaf.seq_id}</td>
                  <td>{leaf.leaf_index}</td>
                  <td><Hash value={leaf.leaf_hash} /></td>
                  <td>{leaf.domain}{leaf.namespace}</td>
                  <td>
                    <Badge ok={leaf.status === 'locked'}>{leaf.status}</Badge>
                    {leaf.revoked && <Badge ok={false}>revoked</Badge>}
                  </td>
                  <td>{new Date(leaf.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {view === 'current' && (
          current === null ? <Spinner label="Loading current versions…" /> :
          current.length === 0 ? <div className="muted">Nothing deployed yet.</div> :
          <table className="table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>version</th>
                <th>uploaded</th>
              </tr>
            </thead>
            <tbody>
              {current.map((c) => (
                <tr
                  key={c.namespace}
                  className="row-clickable"
                  onClick={() => selectHash(c.manifest_hash)}
                >
                  <td>{c.domain}{c.namespace}</td>
                  <td>{c.version}</td>
                  <td>{new Date(c.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="explorer-right">
        {selectedGroup && !selectedHash ? (
          <VersionPicker leaves={selectedGroup} onSelect={setSelectedHash} />
        ) : selectedHash ? (
          <>
            {selectedGroup && (
              <button className="btn back-to-versions" onClick={() => setSelectedHash(undefined)}>
                ← All versions
              </button>
            )}
            <SbomDetailPanel key={selectedHash} hash={selectedHash} tenantId={tenantId} onRevoked={load} />
          </>
        ) : (
          <div className="card">
            <div className="muted">Select an item on the left to view its details.</div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------- Proofs ----------

function InclusionCard({ treeHead }: { treeHead: TreeHead | null }) {
  const tenantId = useTenantOverride();
  const [leafIndex, setLeafIndex] = useState('0');
  const [leafHash, setLeafHash] = useState('');
  const [leaves, setLeaves] = useState<Leaf[]>([]);
  const [proof, setProof] = useState<InclusionProof | null>(null);
  const [root, setRoot] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [verified, setVerified] = useState<boolean | null>(null);

  useEffect(() => {
    if (treeHead && !root) setRoot(treeHead.root_hash);
  }, [treeHead, root]);

  useEffect(() => {
    api.leaves(50, 0, tenantId)
      .then(setLeaves)
      .catch(() => setLeaves([]));
  }, [tenantId]);

  const fetchProof = async () => {
    setBusy(true);
    setError('');
    setVerified(null);
    try {
      const p = await api.inclusionProof(Number(leafIndex), tenantId);
      setProof(p);
      const known = leaves.find((l) => String(l.leaf_index) === String(p.leaf_index));
      if (known) setLeafHash(known.leaf_hash);
      if (treeHead) setRoot(treeHead.root_hash);
    } catch (e) {
      setProof(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (!proof) return;
    setVerified(await verifyInclusion(proof, leafHash, root));
  };

  return (
    <div className="card">
      <h2>Inclusion Proof</h2>
      <div className="form-row">
        <label className="field">
          <span>Leaf index</span>
          <input
            type="number"
            min="0"
            value={leafIndex}
            onChange={(e) => setLeafIndex(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Leaf hash (hex)</span>
          <input
            value={leafHash}
            onChange={(e) => setLeafHash(e.target.value)}
            placeholder="auto-filled from Leaves tab"
          />
        </label>
        <label className="field">
          <span>Tree root (hex)</span>
          <input value={root} onChange={(e) => setRoot(e.target.value)} />
        </label>
      </div>
      <div className="form-row">
        <button className="btn primary" disabled={busy} onClick={fetchProof}>
          {busy ? 'Fetching…' : 'Fetch proof'}
        </button>
        <button
          className="btn"
          disabled={!proof || !leafHash || !root}
          onClick={verify}
        >
          Verify in browser
        </button>
        {verified !== null && (
          <Badge ok={verified}>{verified ? 'proof verifies against root' : 'verification FAILED'}</Badge>
        )}
        {proof && (
          <DownloadButton filename={`inclusion-proof-leaf-${proof.leaf_index}.json`} data={proof} />
        )}
      </div>
      {error && <ErrorBox message={error} />}
      {proof && (
        <pre className="json">
          {JSON.stringify(proof, null, 2)}
        </pre>
      )}
    </div>
  );
}

function ConsistencyCard({ treeHead }: { treeHead: TreeHead | null }) {
  const tenantId = useTenantOverride();
  const [oldSize, setOldSize] = useState('1');
  const [newSize, setNewSize] = useState('');
  const [oldRoot, setOldRoot] = useState('');
  const [proof, setProof] = useState<ConsistencyProof | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [verified, setVerified] = useState<boolean | null>(null);

  const newSizeValue = newSize || (treeHead ? String(treeHead.tree_size) : '');

  useEffect(() => {
    if (treeHead && !newSize) setNewSize(String(treeHead.tree_size));
  }, [treeHead, newSize]);

  const loadOldRoot = async () => {
    setError('');
    try {
      const head = await api.treeHeadAt(Number(oldSize), tenantId);
      setOldRoot(head.root_hash);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const fetchProof = async () => {
    setBusy(true);
    setError('');
    setVerified(null);
    try {
      setProof(await api.consistencyProof(Number(oldSize), Number(newSizeValue), tenantId));
    } catch (e) {
      setProof(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (!proof) return;
    const newRoot = await foldPeaks(proof.peaks);
    setVerified(await verifyConsistency(proof, oldRoot, newRoot));
  };

  return (
    <div className="card">
      <h2>Consistency Proof</h2>
      <div className="form-row">
        <label className="field">
          <span>Old tree size</span>
          <input
            type="number"
            min="1"
            value={oldSize}
            onChange={(e) => setOldSize(e.target.value)}
          />
        </label>
        <label className="field">
          <span>New tree size</span>
          <input
            type="number"
            min="1"
            value={newSizeValue}
            onChange={(e) => setNewSize(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Old root (hex)</span>
          <input value={oldRoot} onChange={(e) => setOldRoot(e.target.value)} />
        </label>
      </div>
      <div className="form-row">
        <button className="btn" disabled={!oldSize} onClick={loadOldRoot}>
          Load old root from STH
        </button>
        <button className="btn primary" disabled={busy} onClick={fetchProof}>
          {busy ? 'Fetching…' : 'Fetch proof'}
        </button>
        <button
          className="btn"
          disabled={!proof || !oldRoot}
          onClick={verify}
        >
          Verify in browser
        </button>
        {verified !== null && (
          <Badge ok={verified}>{verified ? 'tree extends old state' : 'verification FAILED'}</Badge>
        )}
        {proof && (
          <DownloadButton
            filename={`consistency-proof-${proof.old_tree_size}-${proof.new_tree_size}.json`}
            data={proof}
          />
        )}
      </div>
      {error && <ErrorBox message={error} />}
      {proof && (
        <pre className="json">
          {JSON.stringify(proof, null, 2)}
        </pre>
      )}
    </div>
  );
}

function Proofs({ treeHead }: { treeHead: TreeHead | null }) {
  return (
    <div className="stack">
      <InclusionCard treeHead={treeHead} />
      <ConsistencyCard treeHead={treeHead} />
    </div>
  );
}

// ---------- Keys ----------

function Keys() {
  const tenantId = useTenantOverride();
  const [keys, setKeys] = useState<ApiKeyInfo[] | null>(null);
  const [role, setRole] = useState('uploader');
  const [scope, setScope] = useState('/');
  const [expiresInDays, setExpiresInDays] = useState('');
  const [newKey, setNewKey] = useState<CreateKeyResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState('');

  const load = useCallback(() => {
    api.listKeys(tenantId)
      .then(setKeys)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [tenantId]);

  useEffect(load, [load]);

  const revoke = async (keyId: string) => {
    if (!window.confirm('Revoke this key? This cannot be undone.')) return;
    setRevokingId(keyId);
    setRevokeError('');
    try {
      await api.revokeKey(keyId, tenantId);
      load();
    } catch (e) {
      setRevokeError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevokingId(null);
    }
  };

  const create = async () => {
    setBusy(true);
    setError('');
    setNewKey(null);
    try {
      const days = Number(expiresInDays);
      const expires_at =
        expiresInDays && days > 0
          ? new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString()
          : null;
      const res = await api.createKey({ namespace_scope: scope, role, expires_at, tenant_id: tenantId });
      setNewKey(res);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <div className="card">
        <h2>Create API Key</h2>
        <div className="muted">
          {tenantId
            ? 'Creates a key for the tenant selected above.'
            : "Creates a key for your own tenant — the same tenant your current API key belongs to."}
        </div>
        <div className="form-row">
          <label className="field">
            <span>Role</span>
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="uploader">uploader — can upload SBOMs/documents</option>
              <option value="auditor">auditor — can read/verify</option>
              <option value="domain_admin">domain_admin — can manage keys</option>
              <option value="super_admin">super_admin — full tenant access</option>
            </select>
          </label>
          <label className="field">
            <span>Namespace scope</span>
            <input value={scope} onChange={(e) => setScope(e.target.value)} placeholder="/product/v1" />
          </label>
          <label className="field">
            <span>Expires in (days, blank = never)</span>
            <input
              type="number"
              min="1"
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
              placeholder="never"
            />
          </label>
        </div>
        <button className="btn primary" disabled={busy} onClick={create}>
          {busy ? 'Creating…' : 'Create key'}
        </button>
        {error && <ErrorBox message={error} />}
        {newKey && <NewKeyReveal newKey={newKey} />}
      </div>
      <div className="card">
        <div className="card-header">
          <h2>{tenantId ? 'Keys for selected tenant' : 'Keys for your tenant'}</h2>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        {revokeError && <ErrorBox message={revokeError} />}
        {keys === null && <Spinner label="Loading keys…" />}
        {keys && keys.length === 0 && <div className="muted">No keys.</div>}
        {keys && keys.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>key id</th>
                <th>scope</th>
                <th>role</th>
                <th>expires</th>
                <th>revoked</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td title={k.id}>{k.id.slice(0, 8)}</td>
                  <td>{k.namespace_scope}</td>
                  <td>{k.role}</td>
                  <td>{k.expires_at ? new Date(k.expires_at).toLocaleString() : 'never'}</td>
                  <td><Badge ok={!k.revoked}>{k.revoked ? 'yes' : 'no'}</Badge></td>
                  <td>
                    {!k.revoked && (
                      <button
                        className="btn"
                        disabled={revokingId === k.id}
                        onClick={() => revoke(k.id)}
                      >
                        {revokingId === k.id ? 'Revoking…' : 'Revoke'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------- Tenant selector (super_admin: act on another tenant) ----------

function TenantSelector({ tenants }: { tenants: Tenant[] | null }) {
  const { tenantId, setTenantId } = useContext(TenantOverrideContext);

  return (
    <select
      className="tenant-selector"
      value={tenantId}
      onChange={(e) => setTenantId(e.target.value)}
      title="Tenant to act as (platform super_admin only)"
    >
      {(tenants ?? []).map((t) => (
        <option key={t.id} value={t.id} title={t.domain}>
          {t.name}
        </option>
      ))}
    </select>
  );
}

// ---------- Tenants ----------

function Tenants({
  isPlatform,
  tenants,
  refreshTenants,
}: {
  isPlatform: boolean;
  tenants: Tenant[] | null;
  refreshTenants: () => void;
}) {
  const [domain, setDomain] = useState('');
  const [name, setName] = useState('');
  const [created, setCreated] = useState<CreateTenantResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState('');
  const [devMode, setDevMode] = useState(false);

  useEffect(() => {
    api.config().then((c) => setDevMode(c.dev_mode)).catch(() => setDevMode(false));
  }, []);

  const deleteTenant = async (t: Tenant) => {
    const confirmMessage = devMode
      ? `Delete tenant "${t.name}" (${t.domain})?\n\nDEV_MODE is on: this is final and cannot be undone. It permanently removes ALL of that tenant's data: every API key, every uploaded SBOM/document, its entire Merkle tree/signed-tree-head history, and its audit log.\n\nType nothing needed — click OK only if you're certain.`
      : `Hide tenant "${t.name}" (${t.domain})?\n\nThis removes it from tenant listings/selectors, but its data is NOT deleted — every API key, SBOM/document, and the Merkle tree/audit log stay fully intact and still reachable directly. (Full deletion is only available with DEV_MODE=true.)`;
    if (!window.confirm(confirmMessage)) {
      return;
    }
    setDeletingId(t.id);
    setDeleteError('');
    try {
      await api.deleteTenant(t.id);
      refreshTenants();
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingId(null);
    }
  };

  const create = async () => {
    setBusy(true);
    setError('');
    setCreated(null);
    try {
      const res = await api.createTenant({ domain, name });
      setCreated(res);
      setDomain('');
      setName('');
      refreshTenants();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <div className="card">
        <h2>Create Tenant</h2>
        <div className="muted">
          super_admin only. Creates a new tenant and its first key
          (domain_admin, full namespace scope) in one step.
        </div>
        <div className="form-row">
          <label className="field">
            <span>Domain</span>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="acme.example"
            />
          </label>
          <label className="field">
            <span>Display name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Corp"
            />
          </label>
        </div>
        <button className="btn primary" disabled={busy || !domain || !name} onClick={create}>
          {busy ? 'Creating…' : 'Create tenant'}
        </button>
        {error && <ErrorBox message={error} />}
        {created && (
          <div className="result-box">
            <Badge ok>tenant created</Badge>
            <div className="kv-row">
              <span className="kv-label">domain</span>
              <span>{created.tenant.domain}</span>
            </div>
            <div className="kv-row">
              <span className="kv-label">tenant id</span>
              <Hash value={created.tenant.id} chars={36} />
            </div>
            <p className="muted">Its first key (domain_admin):</p>
            <NewKeyReveal newKey={created.initial_key} />
          </div>
        )}
      </div>
      <div className="card">
        <div className="card-header">
          <h2>Tenants</h2>
          <button className="btn" onClick={refreshTenants}>Refresh</button>
        </div>
        {deleteError && <ErrorBox message={deleteError} />}
        {tenants === null && <Spinner label="Loading tenants…" />}
        {tenants && tenants.length === 0 && <div className="muted">No tenants yet.</div>}
        {tenants && tenants.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>domain</th>
                <th>name</th>
                <th>created by</th>
                <th>created</th>
                {isPlatform && <th></th>}
              </tr>
            </thead>
            <tbody>
              {tenants.map((t) => (
                <tr key={t.id}>
                  <td>{t.domain}</td>
                  <td>
                    {t.name}
                    {t.is_platform && <Badge ok>platform</Badge>}
                  </td>
                  <td title={t.created_by}>{shortPrincipal(t.created_by)}</td>
                  <td>{new Date(t.created_at).toLocaleString()}</td>
                  {isPlatform && (
                    <td>
                      {!t.is_platform && (
                        <button
                          className="btn"
                          disabled={deletingId === t.id}
                          onClick={() => deleteTenant(t)}
                        >
                          {deletingId === t.id ? (devMode ? 'Deleting…' : 'Hiding…') : devMode ? 'Delete' : 'Hide'}
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------- Audit ----------

function Audit() {
  const tenantId = useTenantOverride();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setError('');
    api.auditLogs(100, tenantId)
      .then(setEntries)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [tenantId]);

  useEffect(load, [load]);

  return (
    <div className="card">
      <div className="card-header">
        <h2>Audit Log</h2>
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      {error && <ErrorBox message={error} />}
      {entries === null && !error && <Spinner label="Loading audit log…" />}
      {entries && entries.length === 0 && <div className="muted">No audit entries.</div>}
      {entries && entries.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>time</th>
              <th>principal</th>
              <th>action</th>
              <th>resource</th>
              <th>result</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.created_at).toLocaleString()}</td>
                <td title={e.principal}>{shortPrincipal(e.principal)}</td>
                <td>{e.action}</td>
                <td title={e.resource}><Hash value={e.resource} chars={20} /></td>
                <td><Badge ok={e.result === 'success'}>{e.result}</Badge></td>
                <td>{e.reason ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ---------- Settings (per-namespace "Currently running" visibility) ----------

function Settings() {
  const tenantId = useTenantOverride();
  const [leaves, setLeaves] = useState<Leaf[] | null>(null);
  const [hiddenNamespaces, setHiddenNamespaces] = useState<Set<string>>(new Set());
  const [error, setError] = useState('');
  const [busyNamespace, setBusyNamespace] = useState<string | null>(null);
  const [currentlyRunningViewEnabled, setCurrentlyRunningViewEnabled] = useState(() =>
    readCurrentlyRunningViewEnabled()
  );
  const [complianceSettings, setComplianceSettings] = useState<ComplianceSetting[] | null>(null);
  const [busyProfile, setBusyProfile] = useState<string | null>(null);
  const [showNamespaceModal, setShowNamespaceModal] = useState(false);

  const toggleCurrentlyRunningView = (enabled: boolean) => {
    writeCurrentlyRunningViewEnabled(enabled);
    setCurrentlyRunningViewEnabled(enabled);
  };

  const load = useCallback(() => {
    setError('');
    // A larger limit than the Explorer tabs use — this page exists to be
    // the complete list, not a recent-activity view. Still bounded by the
    // same underlying pagination, so a tenant with more uploads than this
    // could have older namespaces missing here (matches the same
    // limitation the Explorer tree already has, just with more headroom).
    api.leaves(500, 0, tenantId)
      .then(setLeaves)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    api.hiddenNamespaces(tenantId).then((ns) => setHiddenNamespaces(new Set(ns))).catch(() => {});
    api.complianceSettings(tenantId)
      .then(setComplianceSettings)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [tenantId]);

  useEffect(load, [load]);

  const setCompliance = async (profileId: string, enabled: boolean, enforceLevel: 'off' | 'minimum' | 'full') => {
    // When disabling, always send enforce_level "off" regardless of what
    // the select currently shows — otherwise a previously-configured
    // "full" enforcement would stay live server-side even though the
    // checkbox now reads unchecked.
    const effectiveEnforceLevel = enabled ? enforceLevel : 'off';
    setBusyProfile(profileId);
    setError('');
    try {
      await api.setComplianceSetting(profileId, enabled, effectiveEnforceLevel, tenantId);
      setComplianceSettings((prev) =>
        (prev ?? []).map((s) =>
          s.profile_id === profileId ? { ...s, enabled, enforce_level: effectiveEnforceLevel } : s
        )
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyProfile(null);
    }
  };

  const namespaces = useMemo(() => {
    if (!leaves) return null;
    const set = new Set<string>();
    for (const leaf of leaves) set.add(leaf.namespace);
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [leaves]);

  const toggle = async (namespace: string, hidden: boolean) => {
    setBusyNamespace(namespace);
    setError('');
    try {
      await api.setNamespaceHidden(namespace, hidden, tenantId);
      setHiddenNamespaces((prev) => {
        const next = new Set(prev);
        if (hidden) next.add(namespace);
        else next.delete(namespace);
        return next;
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyNamespace(null);
    }
  };

  return (
    <div className="stack">
      {error && <ErrorBox message={error} />}

      <div className="card">
        <div className="card-header">
          <h2>Display preferences</h2>
        </div>
        <p className="muted">
          Per-browser, stored locally — these don't change what any API call returns, only what
          this browser shows.
        </p>
        <label className="checkbox-field settings-master-toggle">
          <input
            type="checkbox"
            checked={currentlyRunningViewEnabled}
            onChange={(e) => toggleCurrentlyRunningView(e.target.checked)}
          />
          Show the "Currently running" button and view in the Explorer
        </label>
        <button className="btn" onClick={() => setShowNamespaceModal(true)}>
          Manage namespace visibility…
        </button>
      </div>

      {showNamespaceModal && (
        <Modal title="Currently running visibility" onClose={() => setShowNamespaceModal(false)}>
          <p className="muted">
            Which namespaces appear in the "Currently running" view — a display filter only;
            uploads, revocation, and the Merkle log are unaffected either way.
          </p>
          {namespaces === null && !error && <Spinner label="Loading namespaces…" />}
          {namespaces !== null && namespaces.length === 0 && <div className="muted">No namespaces yet.</div>}
          {namespaces !== null && namespaces.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>namespace</th>
                  <th>in "Currently running"</th>
                </tr>
              </thead>
              <tbody>
                {namespaces.map((ns) => {
                  const isHidden = hiddenNamespaces.has(ns);
                  return (
                    <tr key={ns}>
                      <td>{ns}</td>
                      <td>
                        <label className="checkbox-field">
                          <input
                            type="checkbox"
                            checked={!isHidden}
                            disabled={busyNamespace === ns}
                            onChange={(e) => toggle(ns, !e.target.checked)}
                          />
                          {isHidden ? 'hidden' : 'visible'}
                        </label>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Modal>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Compliance profiles</h2>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        <p className="muted">
          Optional, off by default. When enabled, uploads are checked against the profile's rules
          and the result is shown on each SBOM's detail view. Enforcement can additionally reject
          uploads outright at the "minimum" or "full" bar — this affects every uploader on the
          tenant, not just you.
        </p>
        {complianceSettings === null && !error && <Spinner label="Loading compliance profiles…" />}
        {complianceSettings !== null && complianceSettings.length === 0 && (
          <div className="muted">No compliance profiles registered.</div>
        )}
        {complianceSettings !== null && complianceSettings.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>profile</th>
                <th>status</th>
                <th>enforcement</th>
              </tr>
            </thead>
            <tbody>
              {complianceSettings.map((s) => (
                <tr key={s.profile_id}>
                  <td>{s.profile_name}</td>
                  <td>
                    <label className="checkbox-field">
                      <input
                        type="checkbox"
                        checked={s.enabled}
                        disabled={busyProfile === s.profile_id}
                        onChange={(e) => setCompliance(s.profile_id, e.target.checked, s.enforce_level)}
                      />
                      {s.enabled ? 'enabled' : 'disabled'}
                    </label>
                  </td>
                  <td>
                    {s.enabled ? (
                      <select
                        value={s.enforce_level}
                        disabled={busyProfile === s.profile_id}
                        onChange={(e) =>
                          setCompliance(s.profile_id, s.enabled, e.target.value as 'off' | 'minimum' | 'full')
                        }
                      >
                        <option value="off">off (report only)</option>
                        <option value="minimum">reject below minimum</option>
                        <option value="full">reject below full compliance</option>
                      </select>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------- Connection gate (no valid key: nothing but server status) ----------

function useServerHealth(intervalMs = 10000): boolean | null {
  const [health, setHealth] = useState<boolean | null>(null);
  useEffect(() => {
    let mounted = true;
    const check = () => api.health().then((ok) => mounted && setHealth(ok));
    check();
    const id = setInterval(check, intervalMs);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, [intervalMs]);
  return health;
}

function ConnectionGate({
  apiKey,
  onKeyChange,
  checking,
  keyError,
}: {
  apiKey: string;
  onKeyChange: (value: string) => void;
  checking: boolean;
  keyError: string;
}) {
  const health = useServerHealth();

  return (
    <div className="card">
      <h2>Connection status</h2>
      <div className="kv-row">
        <span className="kv-label">Server</span>
        {health === null ? <span>checking…</span> : <Badge ok={health}>{health ? 'online' : 'offline'}</Badge>}
      </div>
      <div className="kv-row">
        <span className="kv-label">API key</span>
        {!apiKey && <span className="muted">not set</span>}
        {apiKey && checking && <span>checking…</span>}
        {apiKey && !checking && !keyError && <Badge ok>valid</Badge>}
        {apiKey && !checking && keyError && <Badge ok={false}>invalid</Badge>}
      </div>
      <label className="field">
        <span>API key  &lt;key_id&gt;:&lt;secret&gt;</span>
        <input
          type="password"
          value={apiKey}
          onChange={(e) => onKeyChange(e.target.value)}
          placeholder="API key  <key_id>:<secret>"
          spellCheck={false}
        />
      </label>
      {keyError && <ErrorBox message={keyError} />}
      <div className="muted">Enter a valid API key to unlock the rest of the app.</div>
    </div>
  );
}

// ---------- App ----------

// Reads ?tab=&tenant= from the current URL so the active tab/tenant survive
// a refresh or a shared link. Only trusted at startup — `tenant` is only
// ever actually applied once `whoami` confirms the key is a platform
// super_admin (see the whoami-success handler below); otherwise a stale or
// tampered URL param could make a non-platform key send an override the
// backend will reject on every request.
function readUrlState(): { tab: Tab | null; tenant: string | null } {
  const params = new URLSearchParams(window.location.search);
  const tabParam = params.get('tab');
  const validTabIds: string[] = TABS.map((t) => t.id);
  const tab = tabParam && validTabIds.includes(tabParam) ? (tabParam as Tab) : null;
  return { tab, tenant: params.get('tenant') };
}

export default function App() {
  const [tab, setTab] = useState<Tab>(() => readUrlState().tab ?? 'leaves');
  const [apiKey, setKey] = useState('');
  const [treeHead, setTreeHead] = useState<TreeHead | null>(null);
  const [headError, setHeadError] = useState('');
  const [pendingSbomHash, setPendingSbomHash] = useState<string | undefined>(undefined);
  const [whoami, setWhoami] = useState<WhoAmI | null>(null);
  const [checkingKey, setCheckingKey] = useState(false);
  const [keyError, setKeyError] = useState('');
  // Seeded from the URL, not '', so the URL-sync effect below doesn't
  // immediately strip a bookmarked ?tenant= before whoami gets a chance to
  // read and confirm it (that race made the tenant silently reset to the
  // default on every reload). This value is only ever a temporary guess
  // until whoami resolves and either keeps or clears it — see the
  // whoami-success handler, which is the actual authority on whether this
  // key may use a tenant override at all.
  const [viewTenantId, setViewTenantId] = useState(() => readUrlState().tenant ?? '');

  // Keeps the URL in sync with the active tab/tenant (via replaceState, so
  // switching tabs doesn't spam browser history) — makes the current view
  // bookmarkable, shareable, and refresh-safe.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    params.set('tab', tab);
    if (viewTenantId) {
      params.set('tenant', viewTenantId);
    } else {
      params.delete('tenant');
    }
    const newUrl = `${window.location.pathname}?${params.toString()}`;
    window.history.replaceState(null, '', newUrl);
  }, [tab, viewTenantId]);

  useEffect(() => {
    try {
      setKey(window.localStorage.getItem('magnolia_api_key') ?? '');
    } catch {
      setKey('');
    }
  }, []);

  // Verify the key actually authenticates (not just non-empty) before
  // unlocking anything beyond the connection-status view.
  useEffect(() => {
    if (!apiKey) {
      setWhoami(null);
      setKeyError('');
      setCheckingKey(false);
      return;
    }
    let mounted = true;
    setCheckingKey(true);
    api.whoami()
      .then((w) => {
        if (!mounted) return;
        setWhoami(w);
        setKeyError('');
        // Only the platform super_admin has a tenant selector at all — for
        // everyone else this must stay empty (no override ever sent), a URL
        // ?tenant= param included. A URL-supplied tenant is honored only
        // once that's confirmed here — trusting it before whoami resolves
        // would let a stale/tampered link make a non-platform key send an
        // override the backend rejects on every request. Falls back to the
        // key's own tenant, shown as a real entry in the list rather than a
        // separate "My tenant" option.
        setViewTenantId(w.is_platform_tenant ? readUrlState().tenant ?? w.tenant_id : '');
      })
      .catch((e) => {
        if (!mounted) return;
        setWhoami(null);
        setKeyError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => mounted && setCheckingKey(false));
    return () => {
      mounted = false;
    };
  }, [apiKey]);

  const refreshHead = useCallback(() => {
    if (!whoami || !roleCan(whoami.role, 'read')) {
      setTreeHead(null);
      setHeadError('');
      return;
    }
    api.treeHead(viewTenantId || undefined)
      .then((head) => {
        setTreeHead(head);
        setHeadError('');
      })
      .catch((e) => {
        setTreeHead(null);
        // A brand-new tenant with no uploads yet gets a 404 here — that's
        // an empty state, not an error; Dashboard already renders it as one.
        if (e instanceof ApiHttpError && e.status === 404) {
          setHeadError('');
        } else {
          setHeadError(e instanceof Error ? e.message : String(e));
        }
      });
  }, [whoami, viewTenantId]);

  useEffect(refreshHead, [refreshHead]);

  // Single source of truth for the tenant list — shared between the sidebar
  // TenantSelector and the Tenants admin tab, so creating/hiding a tenant in
  // one place is immediately reflected in the other instead of each holding
  // its own stale copy until a manual page reload. null = not loaded yet.
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const refreshTenants = useCallback(() => {
    if (!whoami?.is_platform_tenant) {
      setTenants(null);
      return;
    }
    api.listTenants().then(setTenants).catch(() => {});
  }, [whoami]);

  useEffect(refreshTenants, [refreshTenants]);

  const applyKey = (value: string) => {
    setKey(value);
    setApiKey(value);
  };

  const logOut = () => applyKey('');

  const visibleTabs = whoami ? TABS.filter((t) => roleCan(whoami.role, t.requires)) : [];
  const workspaceTabs = visibleTabs.filter((t) => t.group === 'workspace');
  const adminTabs = visibleTabs.filter((t) => t.group === 'admin');

  // If the current tab isn't allowed for this key's role (e.g. a different,
  // less-privileged key was just logged in), bounce to the first tab it can
  // actually use.
  useEffect(() => {
    if (!whoami) return;
    if (!visibleTabs.some((t) => t.id === tab) && visibleTabs.length > 0) {
      setTab(visibleTabs[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, whoami]);

  if (!whoami) {
    return (
      <div className="app">
        <header className="app-header">
          <div className="brand">
            <span className="brand-mark">◆</span> Magnolia
          </div>
        </header>
        <main className="content">
          <ConnectionGate
            apiKey={apiKey}
            onKeyChange={applyKey}
            checking={checkingKey}
            keyError={keyError}
          />
        </main>
      </div>
    );
  }

  return (
    <TenantOverrideContext.Provider value={{ tenantId: viewTenantId, setTenantId: setViewTenantId }}>
      <div className="app app-shell">
        <aside className="sidebar">
          <div className="sidebar-brand">
            <span className="brand-mark">◆</span> Magnolia
          </div>

          <nav className="sidebar-nav">
            {workspaceTabs.length > 0 && (
              <div className="sidebar-group">
                <div className="sidebar-group-label">Workspace</div>
                {workspaceTabs.map((t) => (
                  <button
                    key={t.id}
                    className={`sidebar-link ${tab === t.id ? 'active' : ''}`}
                    onClick={() => setTab(t.id)}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            )}
            {adminTabs.length > 0 && (
              <div className="sidebar-group">
                <div className="sidebar-group-label">Admin</div>
                {adminTabs.map((t) => (
                  <button
                    key={t.id}
                    className={`sidebar-link ${tab === t.id ? 'active' : ''}`}
                    onClick={() => setTab(t.id)}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            )}
          </nav>

          <div className="sidebar-footer">
            {whoami.is_platform_tenant && <TenantSelector tenants={tenants} />}
            <div className="tenant-badge" title="role · tenant domain + namespace scope">
              <span className="tenant-badge-role">{whoami.role}</span>
              <span className="tenant-badge-scope">{whoami.domain}{whoami.namespace_scope}</span>
            </div>
            <button className="btn" onClick={logOut}>
              Log out
            </button>
          </div>
        </aside>

        <div className="main-column">
          {viewTenantId !== '' && viewTenantId !== whoami.tenant_id && (
            <div className="viewing-banner">
              Acting on another tenant — changes here affect that tenant, not your own.
            </div>
          )}

          <main className="content">
            {tab === 'dashboard' && roleCan(whoami.role, 'read') && (
              <Dashboard treeHead={treeHead} onRefresh={refreshHead} headError={headError} />
            )}
            {tab === 'upload' && roleCan(whoami.role, 'upload') && (
              <Upload
                onUploaded={(result) => {
                  setTreeHead(result.signed_tree_head);
                  setPendingSbomHash(result.manifest_hash);
                  // An upload-only key can't see the Explorer (needs Read)
                  // — nothing to jump to in that case, so stay put.
                  if (roleCan(whoami.role, 'read')) {
                    setTab('leaves');
                  }
                }}
              />
            )}
            {tab === 'leaves' && roleCan(whoami.role, 'read') && (
              <Leaves initialSelectedHash={pendingSbomHash} />
            )}
            {tab === 'proofs' && roleCan(whoami.role, 'read') && <Proofs treeHead={treeHead} />}
            {tab === 'keys' && roleCan(whoami.role, 'manage_keys') && <Keys />}
            {tab === 'tenants' && roleCan(whoami.role, 'manage_tenants') && (
              <Tenants isPlatform={whoami.is_platform_tenant} tenants={tenants} refreshTenants={refreshTenants} />
            )}
            {tab === 'audit' && roleCan(whoami.role, 'read') && <Audit />}
            {tab === 'settings' && roleCan(whoami.role, 'manage_settings') && <Settings />}
          </main>
        </div>
      </div>
    </TenantOverrideContext.Provider>
  );
}