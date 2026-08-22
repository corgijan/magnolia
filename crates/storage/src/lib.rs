mod errors;
mod in_memory;

pub use errors::StorageError;
pub use in_memory::InMemoryStore;

use async_trait::async_trait;

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), StorageError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    async fn exists(&self, key: &str) -> Result<bool, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}
