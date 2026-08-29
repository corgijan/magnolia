use serde_json::Value;

/// One normalized VEX statement — "vulnerability X has status Y for these
/// products" — independent of the source format (OpenVEX today; CSAF 2.0 is
/// a documented follow-up, same "format enum with room to grow" shape as
/// `component_index::extract_components`'s `format` argument).
#[derive(Debug, Clone, PartialEq)]
pub struct VexStatement {
    pub vuln_id: String,
    /// Product identifiers from this statement's `products[]`, treated as
    /// purls (OpenVEX's own common convention, though the spec allows
    /// arbitrary IRIs for `@id`) — the API layer resolves these against a
    /// manifest's indexed `sbom_components.purl` to find which findings a
    /// statement actually applies to. Empty means the statement didn't name
    /// any specific product and should be matched by vulnerability id alone
    /// against every finding in the target manifest.
    pub purls: Vec<String>,
    /// One of OpenVEX's four statuses — `"affected"`, `"not_affected"`,
    /// `"fixed"`, `"under_investigation"` — or, for a document that omits
    /// or misuses the field, whatever raw string was present; validating
    /// this against Magnolia's own fixed vocabulary is left to the API
    /// layer (`crates/api/src/handlers.rs`'s `VEX_JUSTIFICATIONS`-adjacent
    /// checks), matching this module's "extraction never fails" philosophy
    /// — an unrecognized status becomes an "unmatched" result there, not a
    /// parse error here.
    pub status: String,
    /// Only meaningful (and only OpenVEX-valid) alongside `status ==
    /// "not_affected"` — carried through verbatim, not validated against
    /// Magnolia's fixed justification vocabulary here for the same reason
    /// `status` isn't.
    pub justification: Option<String>,
    pub status_notes: Option<String>,
}

/// Parses an OpenVEX JSON document (https://github.com/openvex/spec,
/// `@context` `https://openvex.dev/ns/...`) into normalized statements.
/// Deliberately permissive, same "never let extraction itself fail on a
/// per-item basis" philosophy as `component_index::extract_components`:
/// a statement missing `vulnerability.name` (nothing to key a finding match
/// on) is silently dropped rather than failing the whole document, and a
/// missing `status` defaults to `"under_investigation"` (OpenVEX's own
/// default for "not yet analyzed"). Only the document's overall shape (valid
/// JSON with a `statements` array) is a hard failure.
pub fn parse_openvex(bytes: &[u8]) -> Result<Vec<VexStatement>, String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    let statements =
        doc["statements"].as_array().ok_or_else(|| "document has no \"statements\" array".to_string())?;

    Ok(statements
        .iter()
        .filter_map(|s| {
            let vuln_id = non_empty_str(&s["vulnerability"]["name"])?;
            let purls = s["products"]
                .as_array()
                .map(|products| {
                    products
                        .iter()
                        .filter_map(|p| non_empty_str(&p["@id"]).or_else(|| non_empty_str(p)))
                        .collect()
                })
                .unwrap_or_default();
            let status = s["status"].as_str().filter(|s| !s.is_empty()).unwrap_or("under_investigation").to_string();
            Some(VexStatement {
                vuln_id,
                purls,
                status,
                justification: non_empty_str(&s["justification"]),
                status_notes: non_empty_str(&s["status_notes"]),
            })
        })
        .collect())
}

fn non_empty_str(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_well_formed_document() {
        let doc = json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:example:vex",
            "author": "Acme Security",
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": { "name": "CVE-2024-1234" },
                    "products": [{ "@id": "pkg:npm/lodash@4.17.15" }],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                    "status_notes": "confirmed via manual review"
                }
            ]
        });
        let statements = parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].vuln_id, "CVE-2024-1234");
        assert_eq!(statements[0].purls, vec!["pkg:npm/lodash@4.17.15".to_string()]);
        assert_eq!(statements[0].status, "not_affected");
        assert_eq!(statements[0].justification.as_deref(), Some("vulnerable_code_not_present"));
        assert_eq!(statements[0].status_notes.as_deref(), Some("confirmed via manual review"));
    }

    #[test]
    fn statement_without_vulnerability_name_is_dropped() {
        let doc = json!({ "statements": [{ "status": "affected" }] });
        assert!(parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap().is_empty());
    }

    #[test]
    fn missing_status_defaults_to_under_investigation() {
        let doc = json!({ "statements": [{ "vulnerability": { "name": "CVE-2024-9999" } }] });
        let statements = parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(statements[0].status, "under_investigation");
    }

    #[test]
    fn statement_with_no_products_has_empty_purls() {
        let doc = json!({
            "statements": [{ "vulnerability": { "name": "CVE-2024-1111" }, "status": "affected" }]
        });
        let statements = parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(statements[0].purls.is_empty());
    }

    #[test]
    fn multiple_products_all_collected() {
        let doc = json!({
            "statements": [{
                "vulnerability": { "name": "CVE-2024-2222" },
                "status": "fixed",
                "products": [{ "@id": "pkg:npm/a@1.0.0" }, { "@id": "pkg:pypi/b@2.0.0" }]
            }]
        });
        let statements = parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(statements[0].purls, vec!["pkg:npm/a@1.0.0".to_string(), "pkg:pypi/b@2.0.0".to_string()]);
    }

    #[test]
    fn malformed_json_is_rejected() {
        assert!(parse_openvex(b"not json").is_err());
    }

    #[test]
    fn missing_statements_array_is_rejected() {
        let doc = json!({ "@context": "https://openvex.dev/ns/v0.2.0" });
        assert!(parse_openvex(&serde_json::to_vec(&doc).unwrap()).is_err());
    }

    #[test]
    fn multiple_statements_parsed_independently() {
        let doc = json!({
            "statements": [
                { "vulnerability": { "name": "CVE-1" }, "status": "affected" },
                { "vulnerability": { "name": "CVE-2" }, "status": "fixed" }
            ]
        });
        let statements = parse_openvex(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(statements.len(), 2);
        assert_eq!(statements[0].vuln_id, "CVE-1");
        assert_eq!(statements[1].vuln_id, "CVE-2");
    }
}
