use crate::errors::CoreError;
use crate::manifest::SbomFormat;
use jsonschema::{Draft, Validator};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

// CycloneDX bom-*.schema.json $ref two auxiliary documents by these exact
// URIs (their own declared $id) — must be registered so $ref resolution
// stays fully offline; nothing here ever fetches over the network.
const CDX_SPDX_LICENSES_URI: &str = "http://cyclonedx.org/schema/spdx.schema.json";
const CDX_JSF_URI: &str = "http://cyclonedx.org/schema/jsf-0.82.schema.json";

const CDX_1_4: &str = include_str!("../schemas/cyclonedx/bom-1.4.schema.json");
const CDX_1_5: &str = include_str!("../schemas/cyclonedx/bom-1.5.schema.json");
const CDX_1_6: &str = include_str!("../schemas/cyclonedx/bom-1.6.schema.json");
const CDX_SPDX_LICENSES: &str = include_str!("../schemas/cyclonedx/spdx.schema.json");
const CDX_JSF: &str = include_str!("../schemas/cyclonedx/jsf-0.82.schema.json");
const SPDX_2_2: &str = include_str!("../schemas/spdx/spdx-2.2.schema.json");
const SPDX_2_3: &str = include_str!("../schemas/spdx/spdx-2.3.schema.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SchemaKey {
    CycloneDx14,
    CycloneDx15,
    CycloneDx16,
    Spdx22,
    Spdx23,
}

static REGISTRY: OnceLock<HashMap<SchemaKey, Validator>> = OnceLock::new();

fn compile_cyclonedx(schema_src: &str) -> Validator {
    let schema: Value = serde_json::from_str(schema_src)
        .expect("embedded CycloneDX schema must be valid JSON");
    let spdx_licenses: Value = serde_json::from_str(CDX_SPDX_LICENSES)
        .expect("embedded spdx.schema.json must be valid JSON");
    let jsf: Value =
        serde_json::from_str(CDX_JSF).expect("embedded jsf-0.82.schema.json must be valid JSON");

    let registry = jsonschema::Registry::new()
        .add(CDX_SPDX_LICENSES_URI, spdx_licenses)
        .expect("failed to register embedded spdx.schema.json resource")
        .add(CDX_JSF_URI, jsf)
        .expect("failed to register embedded jsf-0.82.schema.json resource")
        .prepare()
        .expect("failed to prepare embedded CycloneDX schema registry");

    jsonschema::options()
        .with_draft(Draft::Draft7)
        .with_registry(&registry)
        .build(&schema)
        .expect("embedded CycloneDX schema must compile")
}

fn compile_simple(schema_src: &str) -> Validator {
    let schema: Value =
        serde_json::from_str(schema_src).expect("embedded SPDX schema must be valid JSON");
    jsonschema::options()
        .with_draft(Draft::Draft7)
        .build(&schema)
        .expect("embedded SPDX schema must compile")
}

fn registry() -> &'static HashMap<SchemaKey, Validator> {
    REGISTRY.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(SchemaKey::CycloneDx14, compile_cyclonedx(CDX_1_4));
        m.insert(SchemaKey::CycloneDx15, compile_cyclonedx(CDX_1_5));
        m.insert(SchemaKey::CycloneDx16, compile_cyclonedx(CDX_1_6));
        m.insert(SchemaKey::Spdx22, compile_simple(SPDX_2_2));
        m.insert(SchemaKey::Spdx23, compile_simple(SPDX_2_3));
        m
    })
}

/// Validates that `data` is a genuinely well-formed CycloneDX or SPDX
/// document — not just JSON with the right marker field — against the
/// official vendored schema for its own declared spec version. Rejects an
/// unrecognized/missing version explicitly rather than silently skipping
/// validation.
pub fn validate_sbom_schema(data: &[u8], format: SbomFormat) -> Result<(), CoreError> {
    let doc: Value = serde_json::from_slice(data)
        .map_err(|e| CoreError::SchemaValidation(format!("must be valid JSON: {}", e)))?;
    if !doc.is_object() {
        return Err(CoreError::SchemaValidation(
            "must be a JSON object".to_string(),
        ));
    }

    let key = match format {
        SbomFormat::CycloneDx => {
            let v = doc.get("specVersion").and_then(|v| v.as_str()).unwrap_or("");
            match v {
                "1.4" => SchemaKey::CycloneDx14,
                "1.5" => SchemaKey::CycloneDx15,
                "1.6" => SchemaKey::CycloneDx16,
                other => {
                    return Err(CoreError::SchemaValidation(format!(
                        "unsupported CycloneDX specVersion \"{}\" (supported: 1.4, 1.5, 1.6)",
                        other
                    )))
                }
            }
        }
        SbomFormat::Spdx => {
            let v = doc.get("spdxVersion").and_then(|v| v.as_str()).unwrap_or("");
            match v {
                "SPDX-2.2" => SchemaKey::Spdx22,
                "SPDX-2.3" => SchemaKey::Spdx23,
                other => {
                    return Err(CoreError::SchemaValidation(format!(
                        "unsupported SPDX spdxVersion \"{}\" (supported: SPDX-2.2, SPDX-2.3)",
                        other
                    )))
                }
            }
        }
    };

    let validator = registry().get(&key).expect("registered at init");
    let errors: Vec<String> = validator
        .iter_errors(&doc)
        .take(5)
        .map(|e| format!("{} (at {})", e, e.instance_path()))
        .collect();
    if !errors.is_empty() {
        return Err(CoreError::SchemaValidation(format!(
            "document does not conform to the schema: {}",
            errors.join("; ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Same minimal payload used for live testing throughout the session
    // this feature was built in.
    const VALID_CDX_15: &str =
        r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}"#;

    const VALID_SPDX_23: &str = r#"{
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "name": "test-doc",
        "dataLicense": "CC0-1.0",
        "creationInfo": {
            "created": "2026-08-23T00:00:00Z",
            "creators": ["Tool: magnolia-test"]
        }
    }"#;

    // The repo's own real-world fixture, CycloneDX 1.6, ~250KB. Only
    // embedded in test builds (this module is `#[cfg(test)]`), never in
    // the release binary.
    const REAL_CDX_16: &str = include_str!("../../../sbom_test.json");

    // test-sboms/ -- real SBOMs generated by `syft` (see
    // test-sboms/README.md) against this repo's own real dependency
    // manifests (Cargo.lock, frontend/package-lock.json), not hand-crafted
    // fixtures: genuine component graphs, real purls/licenses, at every
    // spec version this validator claims to support. Same "test build
    // only" reasoning as REAL_CDX_16 above.
    const REAL_REPO_MIXED_CDX_16: &str = include_str!("../../../test-sboms/repo-mixed.cdx16.json");
    const REAL_FRONTEND_CDX_15: &str = include_str!("../../../test-sboms/frontend-npm.cdx15.json");
    const REAL_FRONTEND_SPDX_23: &str = include_str!("../../../test-sboms/frontend-npm.spdx23.json");
    const REAL_RUST_WORKSPACE_SPDX_22: &str =
        include_str!("../../../test-sboms/rust-workspace.spdx22.json");

    #[test]
    fn valid_cyclonedx_1_5_passes() {
        assert!(validate_sbom_schema(VALID_CDX_15.as_bytes(), SbomFormat::CycloneDx).is_ok());
    }

    #[test]
    fn real_world_cyclonedx_1_6_fixture_passes() {
        assert!(validate_sbom_schema(REAL_CDX_16.as_bytes(), SbomFormat::CycloneDx).is_ok());
    }

    #[test]
    fn real_syft_generated_sboms_pass_schema_validation() {
        // Every real fixture in test-sboms/ must clear schema validation
        // regardless of format/spec-version — a real generator's output
        // being rejected here would mean our schema bundling has drifted
        // from the actual spec, not that the fixture is bad.
        for (name, doc, format) in [
            ("repo-mixed.cdx16.json", REAL_REPO_MIXED_CDX_16, SbomFormat::CycloneDx),
            ("frontend-npm.cdx15.json", REAL_FRONTEND_CDX_15, SbomFormat::CycloneDx),
            ("frontend-npm.spdx23.json", REAL_FRONTEND_SPDX_23, SbomFormat::Spdx),
            ("rust-workspace.spdx22.json", REAL_RUST_WORKSPACE_SPDX_22, SbomFormat::Spdx),
        ] {
            assert!(
                validate_sbom_schema(doc.as_bytes(), format).is_ok(),
                "{name} failed schema validation"
            );
        }
    }

    #[test]
    fn cyclonedx_missing_required_field_fails_with_bounded_message() {
        let bad = r#"{"bomFormat":"CycloneDX"}"#; // missing required specVersion
        let err = validate_sbom_schema(bad.as_bytes(), SbomFormat::CycloneDx).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.is_empty());
        // bounded to at most 5 joined errors, not a wall of hundreds
        assert!(msg.matches(" (at ").count() <= 5);
    }

    #[test]
    fn cyclonedx_unsupported_version_is_rejected_clearly() {
        let doc = r#"{"bomFormat":"CycloneDX","specVersion":"1.2"}"#;
        let err = validate_sbom_schema(doc.as_bytes(), SbomFormat::CycloneDx).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("1.2"));
        assert!(msg.contains("1.4, 1.5, 1.6"));
    }

    #[test]
    fn valid_spdx_2_3_passes() {
        assert!(validate_sbom_schema(VALID_SPDX_23.as_bytes(), SbomFormat::Spdx).is_ok());
    }

    #[test]
    fn spdx_unsupported_version_is_rejected_clearly() {
        let doc = r#"{"spdxVersion":"SPDX-2.1"}"#;
        let err = validate_sbom_schema(doc.as_bytes(), SbomFormat::Spdx).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("SPDX-2.1"));
        assert!(msg.contains("SPDX-2.2, SPDX-2.3"));
    }

    #[test]
    fn non_json_input_fails_clearly() {
        let err = validate_sbom_schema(b"not json", SbomFormat::CycloneDx).unwrap_err();
        assert!(err.to_string().contains("valid JSON"));
    }

    #[test]
    fn non_object_json_fails_clearly() {
        let err = validate_sbom_schema(b"[1,2,3]", SbomFormat::CycloneDx).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }
}
