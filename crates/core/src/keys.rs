use crate::errors::CoreError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// RFC 8410 SubjectPublicKeyInfo prefix for an Ed25519 public key — fixed,
/// 12 bytes, the same for every Ed25519 key (only the 32 key bytes that
/// follow vary), so this needs no ASN.1 library to construct correctly.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// PEM-encodes a raw 32-byte Ed25519 public key as a standard SPKI public
/// key, loadable by `openssl`, `cosign`, or any other tool that reads PEM
/// public keys — no bespoke format for third-party verifiers to handle.
pub fn ed25519_public_key_pem(raw_32: &[u8]) -> Result<String, CoreError> {
    if raw_32.len() != 32 {
        return Err(CoreError::InvalidHash(
            "ed25519 public key must be 32 bytes".to_string(),
        ));
    }
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw_32);
    let b64 = B64.encode(der);

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Ok(pem)
}

pub fn ed25519_public_key_base64(raw_32: &[u8]) -> String {
    B64.encode(raw_32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trips_through_der_with_correct_prefix() {
        let raw = [9u8; 32];
        let pem = ed25519_public_key_pem(&raw).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));

        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = B64.decode(b64).unwrap();
        assert_eq!(der.len(), 12 + 32);
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
        assert_eq!(&der[12..], &raw);
    }

    #[test]
    fn rejects_wrong_length_key() {
        assert!(ed25519_public_key_pem(&[1u8; 31]).is_err());
        assert!(ed25519_public_key_pem(&[1u8; 33]).is_err());
    }

    #[test]
    fn base64_key_round_trips() {
        let raw = [3u8; 32];
        let b64 = ed25519_public_key_base64(&raw);
        assert_eq!(B64.decode(b64).unwrap(), raw);
    }
}
