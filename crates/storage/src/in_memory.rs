use crate::{ObjectStore, StorageError};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

pub struct InMemoryStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ObjectStore for InMemoryStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut store = self.data.write().await;
        store.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let store = self.data.read().await;
        store
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let store = self.data.read().await;
        Ok(store.contains_key(key))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let mut store = self.data.write().await;
        store.remove(key);
        Ok(())
    }
}
