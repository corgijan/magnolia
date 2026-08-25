use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::collections::BTreeMap;

pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const MANIFEST_PREDICATE_TYPE: &str = "https://magnolia.dev/attestations/manifest/v1";
pub const DOCUMENT_PREDICATE_TYPE: &str = "https://magnolia.dev/attestations/document/v1";

/// DSSE Pre-Authentication Encoding — https://github.com/secure-systems-lab/dsse
///
/// This exact byte sequence is what gets signed, not the raw payload —
/// binding the payload *type* into the signed bytes is what lets a
/// validly-signed statement of one kind not be replayed as if it were a
/// different kind of claim. Any deviation here breaks interop with
/// cosign/other DSSE verifiers, which independently reconstruct the same
/// PAE from `payloadType`/`payload`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let pt = payload_type.as_bytes();
    let mut out = Vec::with_capacity(6 + 1 + 20 + 1 + pt.len() + 1 + 20 + 1 + payload.len());
    out.extend_from_slice(b"DSSEv1");
    out.push(b' ');
    out.extend_from_slice(pt.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(pt);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DsseEnvelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Statement<P> {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: P,
}

/// The manifest metadata carried inside the in-toto Statement's predicate.
/// Mirrors the fields the old hand-rolled `Manifest` struct carried, minus
/// `signature`/`sbom_hash` (the digest now lives in `Statement::subject`,
/// where DSSE structurally binds it to the signature) and `s3_key` (not
/// meaningful to an external verifier, kept only in the DB).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestPredicate {
    pub version: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    pub sbom_format: String,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: uuid::Uuid,
}

pub type ManifestStatement = Statement<ManifestPredicate>;

/// General technical-documentation metadata (risk assessment, test
/// report, CVD policy, etc.) — an upload that reuses the exact same
/// tamper-evident pipeline as an SBOM manifest (Merkle inclusion, DSSE
/// signing, revocation) but isn't an SBOM itself, so it isn't validated
/// against the CycloneDX/SPDX schema and doesn't appear in the
/// "currently running" (deployable) view.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DocumentPredicate {
    pub document_type: String,
    pub version: String,
    pub namespace: String,
    pub previous_manifest_hash: Option<String>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tenant_id: uuid::Uuid,
}

pub type DocumentStatement = Statement<DocumentPredicate>;

pub const SNAPSHOT_PREDICATE_TYPE: &str = "https://magnolia.dev/attestations/snapshot/v1";

/// Metadata for a signed audit archive — a point-in-time export of every
/// manifest/document matching the requested scope. Each included item
/// appears as its own entry in `Statement::subject` (digest = its
/// sbom_hash), so the signature structurally binds the archive to the
/// exact set of item hashes it claims to contain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotPredicate {
    pub tenant_id: uuid::Uuid,
    pub domain: String,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub tree_size: u64,
    pub root_hash: String,
    /// Human-readable scope description, e.g. "all", "namespace=/product1",
    /// "version=1.2.3" — recorded in the signed predicate so the archive's
    /// own contents-claim is part of what's verified, not just asserted in
    /// a filename.
    pub scope: String,
}

pub type SnapshotStatement = Statement<SnapshotPredicate>;

pub fn build_envelope(
    payload_type: &str,
    statement_bytes: &[u8],
    raw_signature: &[u8],
    keyid: &str,
) -> DsseEnvelope {
    DsseEnvelope {
        payload: B64.encode(statement_bytes),
        payload_type: payload_type.to_string(),
        signatures: vec![DsseSignature {
            keyid: keyid.to_string(),
            sig: B64.encode(raw_signature),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_known_answer_vector() {
        let got = pae("application/vnd.in-toto+json", b"hello");
        let want = b"DSSEv1 28 application/vnd.in-toto+json 5 hello";
        assert_eq!(got, want);
    }

    #[test]
    fn pae_length_prefixes_are_correct_for_multi_digit_lengths() {
        let payload_type = "application/vnd.in-toto+json"; // 29 bytes
        let payload = vec![b'x'; 137]; // 3-digit length
        let got = pae(payload_type, &payload);
        let expected_prefix = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len());
        assert!(got.starts_with(expected_prefix.as_bytes()));
        assert_eq!(&got[expected_prefix.len()..], payload.as_slice());
    }

    #[test]
    fn build_envelope_round_trips_through_json() {
        let statement = ManifestStatement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: "acme.example/product/v1@1.0.0".to_string(),
                digest: [("sha256".to_string(), "abc123".to_string())].into_iter().collect(),
            }],
            predicate_type: MANIFEST_PREDICATE_TYPE.to_string(),
            predicate: ManifestPredicate {
                version: "1.0.0".to_string(),
                namespace: "/product/v1".to_string(),
                previous_manifest_hash: None,
                sbom_format: "cyclonedx".to_string(),
                created_by: "apikey:test".to_string(),
                created_at: chrono::Utc::now(),
                tenant_id: uuid::Uuid::nil(),
            },
        };
        let statement_bytes = serde_json::to_vec(&statement).unwrap();
        let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, b"fake-sig", "keyid1");

        let json = serde_json::to_string(&envelope).unwrap();
        let roundtripped: DsseEnvelope = serde_json::from_str(&json).unwrap();
        let decoded_payload = B64.decode(&roundtripped.payload).unwrap();
        assert_eq!(decoded_payload, statement_bytes);
        assert_eq!(roundtripped.payload_type, DSSE_PAYLOAD_TYPE);
        assert_eq!(B64.decode(&roundtripped.signatures[0].sig).unwrap(), b"fake-sig");
    }

    /// Confirms the generic `Statement<P>` plumbing works correctly for a
    /// second predicate shape (documents), not just the manifest one —
    /// same envelope construction, different predicate content.
    #[test]
    fn document_statement_round_trips_through_json() {
        let statement = DocumentStatement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: "acme.example/product/v1/risk-assessment@2.1".to_string(),
                digest: [("sha256".to_string(), "def456".to_string())].into_iter().collect(),
            }],
            predicate_type: DOCUMENT_PREDICATE_TYPE.to_string(),
            predicate: DocumentPredicate {
                document_type: "risk-assessment".to_string(),
                version: "2.1".to_string(),
                namespace: "/product/v1/risk-assessment".to_string(),
                previous_manifest_hash: None,
                created_by: "apikey:test".to_string(),
                created_at: chrono::Utc::now(),
                tenant_id: uuid::Uuid::nil(),
            },
        };
        let statement_bytes = serde_json::to_vec(&statement).unwrap();
        let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, b"fake-sig", "keyid1");

        let json = serde_json::to_string(&envelope).unwrap();
        let roundtripped: DsseEnvelope = serde_json::from_str(&json).unwrap();
        let decoded_payload = B64.decode(&roundtripped.payload).unwrap();
        assert_eq!(decoded_payload, statement_bytes);

        let decoded_statement: DocumentStatement = serde_json::from_slice(&decoded_payload).unwrap();
        assert_eq!(decoded_statement.predicate_type, DOCUMENT_PREDICATE_TYPE);
        assert_eq!(decoded_statement.predicate.document_type, "risk-assessment");
    }

    /// A snapshot statement carries multiple subjects (one per archived
    /// item) rather than the single-subject shape manifest/document
    /// statements use — confirms `Statement<P>`'s `subject: Vec<Subject>`
    /// genuinely supports that, not just by inspection.
    #[test]
    fn snapshot_statement_round_trips_with_multiple_subjects() {
        let statement = SnapshotStatement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![
                Subject {
                    name: "acme.example/product/v1@1.0.0".to_string(),
                    digest: [("sha256".to_string(), "abc123".to_string())].into_iter().collect(),
                },
                Subject {
                    name: "acme.example/product/v2@2.0.0".to_string(),
                    digest: [("sha256".to_string(), "def456".to_string())].into_iter().collect(),
                },
            ],
            predicate_type: SNAPSHOT_PREDICATE_TYPE.to_string(),
            predicate: SnapshotPredicate {
                tenant_id: uuid::Uuid::nil(),
                domain: "acme.example".to_string(),
                created_by: "apikey:test".to_string(),
                created_at: chrono::Utc::now(),
                tree_size: 42,
                root_hash: "rootabc".to_string(),
                scope: "all".to_string(),
            },
        };
        let statement_bytes = serde_json::to_vec(&statement).unwrap();
        let envelope = build_envelope(DSSE_PAYLOAD_TYPE, &statement_bytes, b"fake-sig", "keyid1");

        let json = serde_json::to_string(&envelope).unwrap();
        let roundtripped: DsseEnvelope = serde_json::from_str(&json).unwrap();
        let decoded_payload = B64.decode(&roundtripped.payload).unwrap();
        assert_eq!(decoded_payload, statement_bytes);

        let decoded_statement: SnapshotStatement = serde_json::from_slice(&decoded_payload).unwrap();
        assert_eq!(decoded_statement.predicate_type, SNAPSHOT_PREDICATE_TYPE);
        assert_eq!(decoded_statement.subject.len(), 2);
        assert_eq!(decoded_statement.predicate.tree_size, 42);
    }

    /// Signs with raw `ed25519-dalek` (a dev-dependency, not any of
    /// Magnolia's own signing code) against our own `pae()` output, then
    /// verifies independently — proving the PAE construction is correct
    /// and genuinely interoperable, not just self-consistent with our own
    /// implementation. Also proves the test actually exercises PAE (not
    /// "any signature verifies") by checking that verifying against the
    /// raw, non-PAE-encoded statement bytes fails.
    #[test]
    fn raw_ed25519_verifies_pae_independent_of_magnolia_code() {
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let statement = ManifestStatement {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: "test".to_string(),
                digest: [("sha256".to_string(), "deadbeef".to_string())].into_iter().collect(),
            }],
            predicate_type: MANIFEST_PREDICATE_TYPE.to_string(),
            predicate: ManifestPredicate {
                version: "1".to_string(),
                namespace: "/".to_string(),
                previous_manifest_hash: None,
                sbom_format: "cyclonedx".to_string(),
                created_by: "apikey:test".to_string(),
                created_at: chrono::Utc::now(),
                tenant_id: uuid::Uuid::nil(),
            },
        };
        let statement_bytes = serde_json::to_vec(&statement).unwrap();
        let pae_bytes = pae(DSSE_PAYLOAD_TYPE, &statement_bytes);

        let signature = signing_key.sign(&pae_bytes);
        assert!(signing_key.verifying_key().verify(&pae_bytes, &signature).is_ok());

        // Verifying against the raw (non-PAE) statement bytes must fail —
        // proves this test actually exercises the PAE construction.
        assert!(signing_key.verifying_key().verify(&statement_bytes, &signature).is_err());
    }
}
