mod local_file;
mod errors;

pub use local_file::LocalFileSigner;
pub use errors::SignerError;

use async_trait::async_trait;

#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignerError>;
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignerError>;
    /// The raw public key bytes corresponding to this signer's private
    /// key, so it can be exported for third-party verification.
    async fn public_key(&self) -> Result<Vec<u8>, SignerError>;
}
