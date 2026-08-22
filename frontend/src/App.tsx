import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import {
  api,
  ApiHttpError,
  ApiKeyInfo,
  AuditEntry,
  ConsistencyProof,
  CreateKeyResponse,
  CreateTenantResponse,
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

type Tab = 'dashboard' | 'upload' | 'leaves' | 'proofs' | 'keys' | 'tenants' | 'audit';

// Mirrors the backend RBAC matrix (crates/auth/src/rbac.rs) so the UI only
// ever shows tabs/actions the current key is actually allowed to use.
type RbacAction = 'upload' | 'read' | 'manage_keys' | 'manage_tenants';

const ROLE_ACTIONS: Record<string, RbacAction[]> = {
  super_admin: ['upload', 'read', 'manage_keys', 'manage_tenants'],
  domain_admin: ['upload', 'read', 'manage_keys'],
  uploader: ['upload'],
  auditor: ['read'],
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

const TABS: { id: Tab; label: string; requires: RbacAction }[] = [
  { id: 'dashboard', label: 'Dashboard', requires: 'read' },
  { id: 'upload', label: 'Upload SBOM', requires: 'upload' },
  { id: 'leaves', label: 'Leaves', requires: 'read' },
  { id: 'proofs', label: 'Proofs', requires: 'read' },
  { id: 'keys', label: 'API Keys', requires: 'manage_keys' },
  { id: 'tenants', label: 'Tenants', requires: 'manage_tenants' },
  { id: 'audit', label: 'Audit Log', requires: 'read' },
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

function ErrorBox({ message }: { message: string }) {
  return <div className="error-box">{message}</div>;
}

function Spinner({ label }: { label: string }) {
  return <div className="spinner">{label}</div>;
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

  useEffect(() => {
    let mounted = true;
    api.health().then((ok) => mounted && setHealth(ok));
    return () => {
      mounted = false;
    };
  }, []);

  return (
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
          No tree head yet — this tenant hasn't uploaded an SBOM.
        </div>
      )}
    </div>
  );
}

// ---------- Upload ----------

function Upload({ onUploaded }: { onUploaded: (head: TreeHead) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');
  const [namespace, setNamespace] = useState('/');
  const [version, setVersion] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError] = useState('');

  const upload = async () => {
    if (!file || !version.trim()) return;
    setBusy(true);
    setError('');
    try {
      const res = await api.upload(file, format, namespace, version.trim());
      setResult(res);
      onUploaded(res.signed_tree_head);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>Upload SBOM</h2>
      <label className="field">
        <span>SBOM file</span>
        <input
          type="file"
          onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
        />
      </label>
      <label className="field">
        <span>Format</span>
        <select
          value={format}
          onChange={(e) => setFormat(e.target.value as 'cyclonedx' | 'spdx')}
        >
          <option value="cyclonedx">CycloneDX (JSON)</option>
          <option value="spdx">SPDX (JSON)</option>
        </select>
      </label>
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
      <button className="btn primary" disabled={!file || !version.trim() || busy} onClick={upload}>
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
            <span className="kv-label">domain</span>
            <span>{result.domain}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">namespace</span>
            <span>{result.namespace}</span>
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

interface SbomSummary {
  label: string;
  count: number;
  name?: string;
  pretty: string | null;
}

function summarizeSbom(hex: string, format: string): SbomSummary {
  let text: string;
  try {
    text = hexToText(hex);
  } catch {
    return { label: 'components', count: 0, pretty: null };
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
      };
    }
    if (format === 'spdx' && Array.isArray(doc.packages)) {
      return { label: 'packages', count: doc.packages.length, name: doc.name, pretty };
    }
    return { label: 'top-level keys', count: Object.keys(doc).length, pretty };
  } catch {
    return { label: 'components', count: 0, pretty: text };
  }
}

function downloadBytes(filename: string, bytes: Uint8Array) {
  const blob = new Blob([bytes as BlobPart], { type: 'application/json' });
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
  const [expanded, setExpanded] = useState(false);
  const bytes = manifest.sbom_hex.length / 2;
  const summary = summarizeSbom(manifest.sbom_hex, manifest.sbom_format);

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
          {summary.pretty !== null && (
            <button className="btn" onClick={() => setExpanded(!expanded)}>
              {expanded ? 'Hide raw SBOM' : 'Show raw SBOM'}
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
      {expanded && summary.pretty !== null && <pre className="json sbom-json">{summary.pretty}</pre>}
    </div>
  );
}

function ManifestLookup() {
  const tenantId = useTenantOverride();
  const [hash, setHash] = useState('');
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const lookup = async () => {
    if (!hash.trim()) return;
    setBusy(true);
    setError('');
    setManifest(null);
    try {
      setManifest(await api.manifest(hash.trim(), tenantId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>Manifest Lookup</h2>
      <div className="form-row">
        <label className="field">
          <span>Manifest hash</span>
          <input
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="paste a manifest_hash from an upload"
          />
        </label>
        <button className="btn primary" disabled={!hash.trim() || busy} onClick={lookup}>
          {busy ? 'Looking up…' : 'Look up'}
        </button>
      </div>
      {error && <ErrorBox message={error} />}
      {manifest && (
        <div className="result-box">
          <SbomArtifact manifest={manifest} />
          <div className="kv-row">
            <span className="kv-label">version</span>
            <span>{manifest.version}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">domain</span>
            <span>{manifest.domain}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">namespace</span>
            <span>{manifest.namespace}</span>
          </div>
          <div className="kv-row">
            <span className="kv-label">sbom_hash</span>
            <Hash value={manifest.sbom_hash} chars={24} />
          </div>
          <div className="kv-row">
            <span className="kv-label">previous_manifest_hash</span>
            <span>{manifest.previous_manifest_hash ? <Hash value={manifest.previous_manifest_hash} chars={24} /> : 'none (first upload)'}</span>
          </div>
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

// ---------- Leaves ----------

function Leaves() {
  const tenantId = useTenantOverride();
  const [leaves, setLeaves] = useState<Leaf[] | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setError('');
    api.leaves(50, 0, tenantId)
      .then(setLeaves)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [tenantId]);

  useEffect(load, [load]);

  return (
    <div className="stack">
    <ManifestLookup />
    <div className="card">
      <div className="card-header">
        <h2>Merkle Leaves</h2>
        <button className="btn" onClick={load}>Refresh</button>
      </div>
      {error && <ErrorBox message={error} />}
      {leaves === null && !error && <Spinner label="Loading leaves…" />}
      {leaves && leaves.length === 0 && <div className="muted">No leaves yet.</div>}
      {leaves && leaves.length > 0 && (
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
            {leaves.map((leaf) => (
              <tr key={leaf.seq_id}>
                <td>{leaf.seq_id}</td>
                <td>{leaf.leaf_index}</td>
                <td><Hash value={leaf.leaf_hash} /></td>
                <td>{leaf.namespace}</td>
                <td><Badge ok={leaf.status === 'locked'}>{leaf.status}</Badge></td>
                <td>{new Date(leaf.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
              <option value="uploader">uploader — can upload SBOMs</option>
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

function TenantSelector() {
  const { tenantId, setTenantId } = useContext(TenantOverrideContext);
  const [tenants, setTenants] = useState<Tenant[]>([]);

  useEffect(() => {
    api.listTenants().then(setTenants).catch(() => setTenants([]));
  }, []);

  return (
    <select
      className="tenant-selector"
      value={tenantId}
      onChange={(e) => setTenantId(e.target.value)}
      title="Act on another tenant (super_admin only)"
    >
      <option value="">My tenant</option>
      {tenants.map((t) => (
        <option key={t.id} value={t.id}>
          {t.domain}
        </option>
      ))}
    </select>
  );
}

// ---------- Tenants ----------

function Tenants() {
  const [tenants, setTenants] = useState<Tenant[] | null>(null);
  const [domain, setDomain] = useState('');
  const [name, setName] = useState('');
  const [created, setCreated] = useState<CreateTenantResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    api.listTenants()
      .then(setTenants)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(load, [load]);

  const create = async () => {
    setBusy(true);
    setError('');
    setCreated(null);
    try {
      const res = await api.createTenant({ domain, name });
      setCreated(res);
      setDomain('');
      setName('');
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
          <button className="btn" onClick={load}>Refresh</button>
        </div>
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
              </tr>
            </thead>
            <tbody>
              {tenants.map((t) => (
                <tr key={t.id}>
                  <td>{t.domain}</td>
                  <td>{t.name}</td>
                  <td title={t.created_by}>{t.created_by}</td>
                  <td>{new Date(t.created_at).toLocaleString()}</td>
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
                <td title={e.principal}>{e.principal.slice(0, 16)}</td>
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

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard');
  const [apiKey, setKey] = useState('');
  const [treeHead, setTreeHead] = useState<TreeHead | null>(null);
  const [headError, setHeadError] = useState('');
  const [whoami, setWhoami] = useState<WhoAmI | null>(null);
  const [checkingKey, setCheckingKey] = useState(false);
  const [keyError, setKeyError] = useState('');
  const [viewTenantId, setViewTenantId] = useState('');

  useEffect(() => {
    try {
      setKey(window.localStorage.getItem('sbomstash_api_key') ?? '');
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
        setViewTenantId('');
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

  const applyKey = (value: string) => {
    setKey(value);
    setApiKey(value);
  };

  const logOut = () => applyKey('');

  const visibleTabs = whoami ? TABS.filter((t) => roleCan(whoami.role, t.requires)) : [];

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
            <span className="brand-mark">◆</span> sbomStash
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
      <div className="app">
        <header className="app-header">
          <div className="brand">
            <span className="brand-mark">◆</span> sbomStash
            <span className="tenant-badge" title="tenant domain · role · namespace scope">
              {whoami.domain} · {whoami.role} · {whoami.namespace_scope}
            </span>
          </div>
          <div className="key-field">
            {whoami.role === 'super_admin' && <TenantSelector />}
            <button className="btn" onClick={logOut}>
              Log out
            </button>
          </div>
        </header>

        {viewTenantId && (
          <div className="viewing-banner">
            Acting on another tenant — changes here affect that tenant, not your own.
          </div>
        )}

        <nav className="tabs">
          {visibleTabs.map((t) => (
            <button
              key={t.id}
              className={`tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <main className="content">
          {tab === 'dashboard' && roleCan(whoami.role, 'read') && (
            <Dashboard treeHead={treeHead} onRefresh={refreshHead} headError={headError} />
          )}
          {tab === 'upload' && roleCan(whoami.role, 'upload') && <Upload onUploaded={setTreeHead} />}
          {tab === 'leaves' && roleCan(whoami.role, 'read') && <Leaves />}
          {tab === 'proofs' && roleCan(whoami.role, 'read') && <Proofs treeHead={treeHead} />}
          {tab === 'keys' && roleCan(whoami.role, 'manage_keys') && <Keys />}
          {tab === 'tenants' && roleCan(whoami.role, 'manage_tenants') && <Tenants />}
          {tab === 'audit' && roleCan(whoami.role, 'read') && <Audit />}
        </main>
      </div>
    </TenantOverrideContext.Provider>
  );
}