import React, { useState } from 'react';
import { useApi } from '../context/ApiContext';
import './MasterKeySetup.css';

const MasterKeySetup: React.FC = () => {
  const { masterKey, setMasterKey, serverUrl, setServerUrl } = useApi();
  const [localKey, setLocalKey] = useState(masterKey || '');
  const [localUrl, setLocalUrl] = useState(serverUrl);
  const [showKey, setShowKey] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'checking' | 'connected' | 'failed' | null>(null);

  const handleSetKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (localKey.trim()) {
      setMasterKey(localKey);
      alert('Master API key saved locally');
    }
  };

  const handleSetUrl = (e: React.FormEvent) => {
    e.preventDefault();
    if (localUrl.trim()) {
      setServerUrl(localUrl);
      testConnection(localUrl);
    }
  };

  const testConnection = async (url: string) => {
    setConnectionStatus('checking');
    try {
      const response = await fetch(`${url}/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      if (response.ok) {
        setConnectionStatus('connected');
        setTimeout(() => setConnectionStatus(null), 3000);
      } else {
        setConnectionStatus('failed');
      }
    } catch (error) {
      setConnectionStatus('failed');
    }
  };

  const clearKey = () => {
    setMasterKey('');
    setLocalKey('');
  };

  return (
    <div className="master-key-setup">
      <div className="setup-card">
        <h2>Configuration</h2>

        <div className="form-section">
          <h3>Server Connection</h3>
          <form onSubmit={handleSetUrl}>
            <div className="form-group">
              <label htmlFor="server-url">Server URL:</label>
              <input
                id="server-url"
                type="text"
                value={localUrl}
                onChange={(e) => setLocalUrl(e.target.value)}
                placeholder="http://127.0.0.1:3000"
              />
            </div>
            <div className="button-group">
              <button type="submit" className="btn btn-primary">
                Save & Test
              </button>
            </div>
            {connectionStatus && (
              <div className={`status-message ${connectionStatus}`}>
                {connectionStatus === 'checking' && '🔄 Testing connection...'}
                {connectionStatus === 'connected' && '✅ Connected!'}
                {connectionStatus === 'failed' && '❌ Connection failed'}
              </div>
            )}
          </form>
        </div>

        <div className="form-section">
          <h3>Master API Key</h3>
          <form onSubmit={handleSetKey}>
            <div className="form-group">
              <label htmlFor="master-key">Master API Key:</label>
              <div className="input-group">
                <input
                  id="master-key"
                  type={showKey ? 'text' : 'password'}
                  value={localKey}
                  onChange={(e) => setLocalKey(e.target.value)}
                  placeholder="Enter your master API key"
                  className={masterKey ? 'has-value' : ''}
                />
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => setShowKey(!showKey)}
                  title={showKey ? 'Hide' : 'Show'}
                >
                  {showKey ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
              {masterKey && (
                <p className="info-text">
                  ✅ Master key configured (first 8 chars: {masterKey.substring(0, 8)}...)
                </p>
              )}
            </div>
            <div className="button-group">
              <button type="submit" className="btn btn-primary">
                Save Master Key
              </button>
              {masterKey && (
                <button type="button" className="btn btn-danger" onClick={clearKey}>
                  Clear Key
                </button>
              )}
            </div>
          </form>
        </div>

        <div className="info-box">
          <h4>💡 How to use:</h4>
          <ol>
            <li>Set your server URL (default: http://127.0.0.1:3000)</li>
            <li>Enter your master API key (saved securely in browser storage)</li>
            <li>Navigate to other tabs to create keys, upload SBOMs, and generate proofs</li>
          </ol>
        </div>
      </div>
    </div>
  );
};

export default MasterKeySetup;
