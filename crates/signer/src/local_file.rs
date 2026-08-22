use crate::{Signer, SignerError};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Ed25519 signing backed by a local key file. A real asymmetric signature
/// (not the `SHA256(key || data)` keyed hash this replaces): `sign`
/// produces a signature only the holder of the private key could produce,
/// and `verify` checks it against the derived public key using actual
/// signature-verification math, not by re-signing and comparing bytes.
///
/// MVP-only, same caveat as before: the private key lives on disk here,
/// not in an HSM/Vault/KMS. `Signer` is a trait specifically so this can be
/// swapped for `VaultSigner`/`AwsKmsSigner` without touching call sites.
pub struct LocalFileSigner {
    private_key_path: PathBuf,
}

impl LocalFileSigner {
    pub fn new(private_key_path: PathBuf) -> Self {
        Self { private_key_path }
    }

    /// The key file holds arbitrary secret bytes — a random UUID pair from
    /// the bootstrap path, or manually-generated hex from `openssl rand`,
    /// not necessarily 32 bytes. Hashing it down to a fixed-size seed lets
    /// any existing key file work unmodified as an Ed25519 identity; no
    /// key rotation or file-format migration needed to adopt real signing.
    async fn signing_key(&self) -> Result<SigningKey, SignerError> {
        let raw = tokio::fs::read(&self.private_key_path)
            .await
            .map_err(|e| SignerError::IoError(e.to_string()))?;
        let seed: [u8; 32] = Sha256::digest(&raw).into();
        Ok(SigningKey::from_bytes(&seed))
    }
}

#[async_trait]
impl Signer for LocalFileSigner {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signing_key = self.signing_key().await?;
        Ok(signing_key.sign(data).to_bytes().to_vec())
    }

    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, SignerError> {
        let signing_key = self.signing_key().await?;
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            // Wrong length can't be a valid Ed25519 signature — including
            // pre-migration signatures from the old 32-byte keyed-hash
            // scheme, which are structurally incompatible with this one
            // and correctly report as unverified rather than erroring.
            Err(_) => return Ok(false),
        };
        let signature = Signature::from_bytes(&sig_bytes);
        Ok(signing_key.verifying_key().verify(data, &signature).is_ok())
    }
}
