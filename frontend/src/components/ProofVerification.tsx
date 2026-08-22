import React, { useState } from 'react';
import { useApi } from '../context/ApiContext';
import './ProofVerification.css';

interface Proof {
  leaf_index: number;
  tree_size: number;
  path: string[];
}

const ProofVerification: React.FC = () => {
  const { masterKey, apiKeys, serverUrl } = useApi();
  const [proofType, setProofType] = useState<'inclusion' | 'consistency'>('inclusion');
  const [selectedKey, setSelectedKey] = useState<string>('');
  const [leafIndex, setLeafIndex] = useState<number>(0);
  const [treeSize, setTreeSize] = useState<number>(1);
  const [oldTreeSize, setOldTreeSize] = useState<number>(0);
  const [newTreeSize, setNewTreeSize] = useState<number>(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);

  if (!masterKey) {
    return (
      <div className="proof-verification">
        <div className="alert alert-warning">
          ⚠️ Master API key not configured. Please set it in Configuration tab.
        </div>
      </div>
    );
  }

  if (apiKeys.length === 0) {
    return (
      <div className="proof-verification">
        <div className="alert alert-warning">
          ⚠️ No API keys created yet. Create one in the API Key Management tab.
        </div>
      </div>
    );
  }

  const handleGenerateProof = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setProof(null);

    if (!selectedKey) {
      setError('Please select an API key');
      return;
    }

    setLoading(true);

    try {
      let url = '';
      if (proofType === 'inclusion') {
        if (leafIndex < 0 || leafIndex >= treeSize) {
          throw new Error('Leaf index must be between 0 and tree size - 1');
        }
        url = `${serverUrl}/api/v1/proof/inclusion/${leafIndex}`;
      } else {
        if (oldTreeSize >= newTreeSize) {
          throw new Error('New tree size must be greater than old tree size');
        }
        url = `${serverUrl}/api/v1/proof/consistency/${oldTreeSize}/${newTreeSize}`;
      }

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${selectedKey}`,
        },
      });

      if (!response.ok) {
        throw new Error(`Proof generation failed: ${response.statusText}`);
      }

      const data = await response.json();
      setProof(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate proof');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="proof-verification">
      <div className="proof-generator">
        <h2>Generate Cryptographic Proof</h2>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleGenerateProof}>
          <div className="form-group">
            <label htmlFor="api-key-select">Select API Key (Auditor/Admin):</label>
            <select
              id="api-key-select"
              value={selectedKey}
              onChange={(e) => setSelectedKey(e.target.value)}
            >
              <option value="">-- Choose a key --</option>
              {apiKeys
                .filter(
                  (key) => key.role === 'auditor' || key.role === 'super_admin'
                )
                .map((key, index) => (
                  <option key={index} value={key.key}>
                    {key.domain} / {key.namespace_scope} ({key.role})
                  </option>
                ))}
            </select>
          </div>

          <div className="form-group">
            <label>
              <input
                type="radio"
                value="inclusion"
                checked={proofType === 'inclusion'}
                onChange={(e) => setProofType(e.target.value as 'inclusion')}
              />
              Inclusion Proof (prove leaf in tree)
            </label>
          </div>

          {proofType === 'inclusion' && (
            <>
              <div className="form-group">
                <label htmlFor="leaf-index">Leaf Index:</label>
                <input
                  id="leaf-index"
                  type="number"
                  value={leafIndex}
                  onChange={(e) => setLeafIndex(parseInt(e.target.value))}
                  min="0"
                />
              </div>

              <div className="form-group">
                <label htmlFor="tree-size">Tree Size:</label>
                <input
                  id="tree-size"
                  type="number"
                  value={treeSize}
                  onChange={(e) => setTreeSize(parseInt(e.target.value))}
                  min="1"
                />
              </div>
            </>
          )}

          <div className="form-group">
            <label>
              <input
                type="radio"
                value="consistency"
                checked={proofType === 'consistency'}
                onChange={(e) => setProofType(e.target.value as 'consistency')}
              />
              Consistency Proof (prove append-only)
            </label>
          </div>

          {proofType === 'consistency' && (
            <>
              <div className="form-group">
                <label htmlFor="old-tree-size">Old Tree Size:</label>
                <input
                  id="old-tree-size"
                  type="number"
                  value={oldTreeSize}
                  onChange={(e) => setOldTreeSize(parseInt(e.target.value))}
                  min="0"
                />
              </div>

              <div className="form-group">
                <label htmlFor="new-tree-size">New Tree Size:</label>
                <input
                  id="new-tree-size"
                  type="number"
                  value={newTreeSize}
                  onChange={(e) => setNewTreeSize(parseInt(e.target.value))}
                  min="1"
                />
              </div>
            </>
          )}

          <button
            type="submit"
            className="btn btn-primary btn-large"
            disabled={loading}
          >
            {loading ? '🔄 Generating...' : '🔐 Generate Proof'}
          </button>
        </form>
      </div>

      {proof && (
        <div className="proof-result">
          <h2>Proof Result</h2>
          <div className="proof-card">
            <div className="proof-header">
              <span className="proof-type">
                {proofType === 'inclusion'
                  ? '✓ Inclusion Proof'
                  : '✓ Consistency Proof'}
              </span>
            </div>

            <div className="proof-details">
              {proofType === 'inclusion' && (
                <>
                  <div className="detail">
                    <span className="label">Leaf Index:</span>
                    <span className="value">{proof.leaf_index}</span>
                  </div>
                  <div className="detail">
                    <span className="label">Tree Size:</span>
                    <span className="value">{proof.tree_size}</span>
                  </div>
                </>
              )}

              <div className="detail full-width">
                <span className="label">Path Length:</span>
                <span className="value">{proof.path.length} hashes</span>
              </div>

              <div className="path-section">
                <h3>Merkle Path</h3>
                <div className="path-list">
                  {proof.path.map((hash, index) => (
                    <div key={index} className="path-item">
                      <span className="index">[{index}]</span>
                      <code className="hash">{hash.substring(0, 64)}...</code>
                    </div>
                  ))}
                </div>
              </div>

              <div className="info-box">
                <h4>🔍 What this means:</h4>
                {proofType === 'inclusion' ? (
                  <p>
                    This proof cryptographically demonstrates that the SBOM at leaf {proof.leaf_index} is
                    part of the tree at size {proof.tree_size}. The path consists of {proof.path.length} sibling
                    hashes needed to reconstruct the root.
                  </p>
                ) : (
                  <p>
                    This proof demonstrates that the tree grew only through appending (no deletion or
                    reordering). It's immutable evidence for auditors (e.g., TÜV, BSI) for compliance.
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="reference-section">
        <h2>Technical Reference</h2>
        <div className="reference-box">
          <h3>Inclusion Proof</h3>
          <p>
            Proves a specific SBOM (at leaf index) is in the Merkle tree. Uses O(log N) hashes. Auditors
            can verify offline without trusting the server.
          </p>
        </div>

        <div className="reference-box">
          <h3>Consistency Proof</h3>
          <p>
            Proves the tree grew only by appending (no deletion/reordering). Demonstrates WORM guarantee.
            Required by EU CRA for immutability evidence.
          </p>
        </div>

        <div className="reference-box">
          <h3>Why Merkle Proofs?</h3>
          <ul>
            <li>Compact: O(log N) path length instead of storing whole tree</li>
            <li>Fast verification: hash ~1KB of data locally</li>
            <li>Tamper-evident: any change breaks the proof</li>
            <li>Auditor-friendly: mathematically unquestionable proof</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default ProofVerification;
