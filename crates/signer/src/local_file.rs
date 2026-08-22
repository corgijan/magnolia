use crate::{Signer, SignerError};
use async_trait::async_trait;
use sha2::{Sha256, Digest};
use std::path::PathBuf;

pub struct LocalFileSigner {
    private_key_path: PathBuf,
}

impl LocalFileSigner {
    pub fn new(private_key_path: PathBuf) -> Self {
        Self { private_key_path }
    }

    async fn read_key(&self) -> Result<Vec<u8>, SignerError> {
        tokio::fs::read(&self.private_key_path)
            .await
            .map_err(|e| SignerError::IoError(e.to_string()))
    }
}

#[async_trait]
impl Signer for LocalFileSigner {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignerError> {
        let key = self.read_key().await?;
        
        let mut hasher = Sha256::new();
        hasher.update(&key);
        hasher.update(data);
        let signature = hasher.finalize().to_vec();
        
        Ok(signature)
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignerError> {
        let computed_sig = self.sign(data).await?;
        Ok(computed_sig == signature)
    }
}
