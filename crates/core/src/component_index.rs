use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub is_primary: bool,
}

/// Infallible by design — extraction is best-effort and must never be the
/// reason an upload fails. Unparseable/unrecognized input just yields an
/// empty list, same spirit as `compliance.rs`'s `applicable: false` for
/// formats it has nothing to say about.
pub fn extract_components(format: &str, sbom_bytes: &[u8]) -> Vec<ExtractedComponent> {
    match format {
        "cyclonedx" => extract_cyclonedx(sbom_bytes),
        "spdx" => extract_spdx(sbom_bytes),
        _ => Vec::new(),
    }
}

fn non_empty(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn extract_cyclonedx(sbom_bytes: &[u8]) -> Vec<ExtractedComponent> {
    let doc: Value = match serde_json::from_slice(sbom_bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    if let Some(primary) = doc["metadata"].get("component") {
        if let Some(c) = component_from_cyclonedx_value(primary, true) {
            out.push(c);
        }
    }
    if let Some(components) = doc["components"].as_array() {
        for c in components {
            if let Some(extracted) = component_from_cyclonedx_value(c, false) {
                out.push(extracted);
            }
        }
    }
    out
}

fn component_from_cyclonedx_value(v: &Value, is_primary: bool) -> Option<ExtractedComponent> {
    let name = non_empty(&v["name"])?;
    Some(ExtractedComponent {
        name,
        version: non_empty(&v["version"]),
        purl: non_empty(&v["purl"]),
        cpe: non_empty(&v["cpe"]),
        is_primary,
    })
}

fn extract_spdx(sbom_bytes: &[u8]) -> Vec<ExtractedComponent> {
    let doc: Value = match serde_json::from_slice(sbom_bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let Some(packages) = doc["packages"].as_array() else {
        return Vec::new();
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = non_empty(&pkg["name"])?;
            let mut purl = None;
            let mut cpe = None;
            if let Some(refs) = pkg["externalRefs"].as_array() {
                for r in refs {
                    match r["referenceType"].as_str() {
                        Some("purl") => purl = purl.or_else(|| non_empty(&r["referenceLocator"])),
                        Some("cpe23Type") | Some("cpe22Type") => {
                            cpe = cpe.or_else(|| non_empty(&r["referenceLocator"]))
                        }
                        _ => {}
                    }
                }
            }
            Some(ExtractedComponent {
                name,
                version: non_empty(&pkg["versionInfo"]),
                purl,
                cpe,
                // SPDX has no single "primary component" concept as clean
                // as CycloneDX's metadata.component — treat every package
                // the same rather than guessing which one is the root.
                is_primary: false,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cyclonedx_extracts_primary_and_sub_components() {
        let doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "component": { "type": "application", "name": "acme-app", "version": "1.0.0" }
            },
            "components": [
                { "type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15" },
                { "type": "library", "name": "left-pad", "version": "1.3.0" }
            ]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let components = extract_components("cyclonedx", &bytes);
        assert_eq!(components.len(), 3);
        assert!(components[0].is_primary);
        assert_eq!(components[0].name, "acme-app");
        assert!(!components[1].is_primary);
        assert_eq!(components[1].name, "lodash");
        assert_eq!(components[1].purl.as_deref(), Some("pkg:npm/lodash@4.17.15"));
        assert_eq!(components[2].name, "left-pad");
        assert_eq!(components[2].purl, None);
    }

    #[test]
    fn spdx_extracts_purl_from_external_refs() {
        let doc = json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [
                    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0" }
                ]
            }]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        let components = extract_components("spdx", &bytes);
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "requests");
        assert_eq!(components[0].version.as_deref(), Some("2.31.0"));
        assert_eq!(components[0].purl.as_deref(), Some("pkg:pypi/requests@2.31.0"));
        assert!(!components[0].is_primary);
    }

    #[test]
    fn document_format_extracts_nothing() {
        assert!(extract_components("document", b"whatever bytes").is_empty());
    }

    #[test]
    fn malformed_json_does_not_panic() {
        assert!(extract_components("cyclonedx", b"not json at all").is_empty());
        assert!(extract_components("spdx", b"{ broken").is_empty());
    }

    #[test]
    fn components_without_a_name_are_skipped() {
        let doc = json!({
            "components": [{ "type": "library", "version": "1.0.0" }]
        });
        let bytes = serde_json::to_vec(&doc).unwrap();
        assert!(extract_components("cyclonedx", &bytes).is_empty());
    }
}
