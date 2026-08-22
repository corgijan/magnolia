import React, { useState, createContext, ReactNode } from 'react';

export interface ApiKey {
  id: string;
  key: string;
  domain: string;
  namespace_scope: string;
  role: 'super_admin' | 'domain_admin' | 'uploader' | 'auditor';
  created_at: string;
  expires_at?: string;
}

export interface ApiContextType {
  masterKey: string | null;
  setMasterKey: (key: string) => void;
  apiKeys: ApiKey[];
  setApiKeys: (keys: ApiKey[]) => void;
  addApiKey: (key: ApiKey) => void;
  serverUrl: string;
  setServerUrl: (url: string) => void;
}

export const ApiContext = createContext<ApiContextType | undefined>(undefined);

interface ApiProviderProps {
  children: ReactNode;
}

export const ApiProvider: React.FC<ApiProviderProps> = ({ children }) => {
  const [masterKey, setMasterKey] = useState<string | null>(
    localStorage.getItem('sbomstash_master_key')
  );
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [serverUrl, setServerUrl] = useState(
    localStorage.getItem('sbomstash_server_url') || 'http://127.0.0.1:3000'
  );

  const handleSetMasterKey = (key: string) => {
    setMasterKey(key);
    localStorage.setItem('sbomstash_master_key', key);
  };

  const handleSetServerUrl = (url: string) => {
    setServerUrl(url);
    localStorage.setItem('sbomstash_server_url', url);
  };

  const addApiKey = (key: ApiKey) => {
    setApiKeys([...apiKeys, key]);
  };

  const value: ApiContextType = {
    masterKey,
    setMasterKey: handleSetMasterKey,
    apiKeys,
    setApiKeys,
    addApiKey,
    serverUrl,
    setServerUrl: handleSetServerUrl,
  };

  return <ApiContext.Provider value={value}>{children}</ApiContext.Provider>;
};

export const useApi = (): ApiContextType => {
  const context = React.useContext(ApiContext);
  if (!context) {
    throw new Error('useApi must be used within ApiProvider');
  }
  return context;
};
