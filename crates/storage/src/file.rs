use crate::{ObjectStore, StorageError};
use async_trait::async_trait;
use std::path::PathBuf;

/// Persists objects as files under a root directory, one file per key
/// (parent directories created as needed). Storage keys are always
/// server-generated (`tenants/{uuid}/sboms/{sha256}.sbom`), never derived
/// from user input, so no extra path-traversal handling is needed here.
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl ObjectStore for FileStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let path = self.path_for(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::IoError(e.to_string()))?;
        }
        tokio::fs::write(&path, data)
            .await
            .map_err(|e| StorageError::IoError(e.to_string()))
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        tokio::fs::read(self.path_for(key)).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::IoError(e.to_string())
            }
        })
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        tokio::fs::try_exists(self.path_for(key))
            .await
            .map_err(|e| StorageError::IoError(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        match tokio::fs::remove_file(self.path_for(key)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::IoError(e.to_string())),
        }
    }
}
