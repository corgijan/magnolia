import React, { useState, useRef } from 'react';
import { useApi } from '../context/ApiContext';
import './SbomUpload.css';

interface UploadResult {
  manifest_hash: string;
  tree_size: number;
  leaf_index: number;
  signature: string;
}

const SbomUpload: React.FC = () => {
  const { masterKey, apiKeys, serverUrl } = useApi();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedKey, setSelectedKey] = useState<string>('');
  const [format, setFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null);
  const [uploadHistory, setUploadHistory] = useState<UploadResult[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!masterKey) {
    return (
      <div className="sbom-upload">
        <div className="alert alert-warning">
          ⚠️ Master API key not configured. Please set it in Configuration tab.
        </div>
      </div>
    );
  }

  if (apiKeys.length === 0) {
    return (
      <div className="sbom-upload">
        <div className="alert alert-warning">
          ⚠️ No API keys created yet. Create one in the API Key Management tab.
        </div>
      </div>
    );
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setUploadResult(null);

    if (!selectedFile) {
      setError('Please select a file');
      return;
    }

    if (!selectedKey) {
      setError('Please select an API key');
      return;
    }

    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('sbom_file', selectedFile);
      formData.append('format', format);

      const response = await fetch(`${serverUrl}/api/v1/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${selectedKey}`,
        },
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const data = await response.json();
      setUploadResult(data);
      setUploadHistory([data, ...uploadHistory.slice(0, 9)]);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="sbom-upload">
      <div className="upload-section">
        <h2>Upload SBOM</h2>

        {error && <div className="alert alert-error">{error}</div>}
        {uploadResult && (
          <div className="alert alert-success">
            ✅ SBOM uploaded successfully!
            <div className="result-details">
              <p>
                <strong>Manifest Hash:</strong>{' '}
                <code>{uploadResult.manifest_hash.substring(0, 32)}...</code>
              </p>
              <p>
                <strong>Tree Size:</strong> {uploadResult.tree_size}
              </p>
              <p>
                <strong>Leaf Index:</strong> {uploadResult.leaf_index}
              </p>
            </div>
          </div>
        )}

        <form onSubmit={handleUpload}>
          <div className="form-group">
            <label htmlFor="api-key-select">Select API Key:</label>
            <select
              id="api-key-select"
              value={selectedKey}
              onChange={(e) => setSelectedKey(e.target.value)}
            >
              <option value="">-- Choose a key --</option>
              {apiKeys.map((key, index) => (
                <option key={index} value={key.key}>
                  {key.domain} / {key.namespace_scope} ({key.role})
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="format-select">SBOM Format:</label>
            <select
              id="format-select"
              value={format}
              onChange={(e) => setFormat(e.target.value as 'cyclonedx' | 'spdx')}
            >
              <option value="cyclonedx">CycloneDX</option>
              <option value="spdx">SPDX</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="file-input">Select File:</label>
            <div className="file-input-wrapper">
              <input
                ref={fileInputRef}
                id="file-input"
                type="file"
                onChange={handleFileSelect}
                accept=".json,.xml,.txt"
              />
              <div className="file-preview">
                {selectedFile ? (
                  <>
                    <span>📄 {selectedFile.name}</span>
                    <span className="file-size">
                      ({(selectedFile.size / 1024).toFixed(2)} KB)
                    </span>
                  </>
                ) : (
                  <span className="placeholder">No file selected</span>
                )}
              </div>
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-large"
            disabled={loading || !selectedFile}
          >
            {loading ? '🔄 Uploading...' : '⬆️ Upload SBOM'}
          </button>
        </form>
      </div>

      {uploadHistory.length > 0 && (
        <div className="history-section">
          <h2>Upload History</h2>
          <div className="history-list">
            {uploadHistory.map((result, index) => (
              <div key={index} className="history-item">
                <div className="item-number">#{uploadHistory.length - index}</div>
                <div className="item-details">
                  <p className="hash">
                    Hash: <code>{result.manifest_hash.substring(0, 40)}...</code>
                  </p>
                  <p className="meta">
                    Tree Size: {result.tree_size} | Leaf Index: {result.leaf_index}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SbomUpload;
