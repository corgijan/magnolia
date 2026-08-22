import React, { useState } from 'react';
import { useApi, ApiKey } from '../context/ApiContext';
import './ApiKeyManagement.css';

const ApiKeyManagement: React.FC = () => {
  const { masterKey, apiKeys, addApiKey, serverUrl } = useApi();
  const [formData, setFormData] = useState({
    domain: 'acme-corp',
    namespace_scope: '/products/v1',
    role: 'uploader' as const,
    expires_in_days: 30,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successKey, setSuccessKey] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (!masterKey) {
    return (
      <div className="api-key-management">
        <div className="alert alert-warning">
          ⚠️ Master API key not configured. Please set it in Configuration tab.
        </div>
      </div>
    );
  }

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: name === 'expires_in_days' ? parseInt(value) : value,
    });
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessKey(null);

    try {
      const response = await fetch(`${serverUrl}/api/v1/admin/keys/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${masterKey}`,
        },
        body: JSON.stringify({
          domain: formData.domain,
          namespace_scope: formData.namespace_scope,
          role: formData.role,
          expires_at: new Date(
            Date.now() + formData.expires_in_days * 24 * 60 * 60 * 1000
          ).toISOString(),
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();
      const newKey: ApiKey = {
        id: data.id,
        key: data.api_key,
        domain: formData.domain,
        namespace_scope: formData.namespace_scope,
        role: formData.role,
        created_at: new Date().toISOString(),
        expires_at: data.expires_at,
      };

      addApiKey(newKey);
      setSuccessKey(data.api_key);

      setTimeout(() => setSuccessKey(null), 5000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create API key');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="api-key-management">
      <div className="create-section">
        <h2>Create API Key</h2>
        {error && <div className="alert alert-error">{error}</div>}
        {successKey && (
          <div className="alert alert-success">
            ✅ Key created! Copy it now (shown only once):
            <div className="success-key-box">
              <code>{successKey}</code>
              <button
                className="btn-copy"
                onClick={() => copyToClipboard(successKey, -1)}
              >
                📋 Copy
              </button>
            </div>
          </div>
        )}

        <form onSubmit={handleCreateKey}>
          <div className="form-grid">
            <div className="form-group">
              <label htmlFor="domain">Domain:</label>
              <input
                id="domain"
                name="domain"
                type="text"
                value={formData.domain}
                onChange={handleInputChange}
                placeholder="e.g., acme-corp"
              />
            </div>

            <div className="form-group">
              <label htmlFor="namespace_scope">Namespace Scope:</label>
              <input
                id="namespace_scope"
                name="namespace_scope"
                type="text"
                value={formData.namespace_scope}
                onChange={handleInputChange}
                placeholder="e.g., /products/v1"
              />
            </div>

            <div className="form-group">
              <label htmlFor="role">Role:</label>
              <select
                id="role"
                name="role"
                value={formData.role}
                onChange={handleInputChange}
              >
                <option value="super_admin">Super Admin</option>
                <option value="domain_admin">Domain Admin</option>
                <option value="uploader">Uploader</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="expires_in_days">Expires In (days):</label>
              <input
                id="expires_in_days"
                name="expires_in_days"
                type="number"
                value={formData.expires_in_days}
                onChange={handleInputChange}
                min="1"
                max="365"
              />
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-large"
            disabled={loading}
          >
            {loading ? '🔄 Creating...' : '➕ Create API Key'}
          </button>
        </form>
      </div>

      <div className="keys-list-section">
        <h2>Created Keys ({apiKeys.length})</h2>
        {apiKeys.length === 0 ? (
          <div className="empty-state">
            <p>No API keys created yet. Create one above to get started.</p>
          </div>
        ) : (
          <div className="keys-table">
            {apiKeys.map((key, index) => (
              <div key={index} className="key-card">
                <div className="key-header">
                  <span className={`role-badge role-${key.role}`}>{key.role}</span>
                  <span className="domain-badge">{key.domain}</span>
                </div>
                <div className="key-details">
                  <div className="detail-row">
                    <span className="label">Namespace Scope:</span>
                    <span className="value">{key.namespace_scope}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Key (hidden):</span>
                    <span className="value key-hidden">••••••••••••••••</span>
                    <button
                      className="btn-icon-sm"
                      title="This key was shown only at creation time"
                    >
                      🔒
                    </button>
                  </div>
                  <div className="detail-row">
                    <span className="label">Created:</span>
                    <span className="value">
                      {new Date(key.created_at).toLocaleString()}
                    </span>
                  </div>
                  {key.expires_at && (
                    <div className="detail-row">
                      <span className="label">Expires:</span>
                      <span className="value">
                        {new Date(key.expires_at).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ApiKeyManagement;
