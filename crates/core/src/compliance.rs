use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ComplianceReport {
    pub profile_id: String,
    pub profile_name: String,
    /// False when the profile has nothing to say about this format at all
    /// (e.g. a `document` upload) — callers should skip reports where this
    /// is false rather than surface a misleading "compliant" or "missing".
    pub applicable: bool,
    pub meets_minimum: bool,
    pub minimum_issues: Vec<String>,
    pub fully_compliant: bool,
    pub missing_fields: Vec<String>,
}

/// A pluggable conformance profile (BSI TR-03183-2 today; a hypothetical
/// NTIA/US-equivalent profile later). Identity is a string `id()`, never a
/// hardcoded enum, so adding a profile means adding one file plus one
/// registry entry — no call site outside this module needs to change.
pub trait ComplianceProfile: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    /// One-line summary of what this profile actually automates, surfaced
    /// in the frontend next to the profile's name so a tenant admin knows
    /// its scope *before* enabling it — not every requirement a source
    /// document names is mechanically checkable from a single SBOM file.
    fn description(&self) -> &'static str;
    /// `format` is the lowercased upload-format string already used
    /// elsewhere in the API (`"cyclonedx"` / `"spdx"` / `"document"`).
    /// `sbom_bytes` is assumed to already be schema-valid JSON for
    /// `cyclonedx`/`spdx` — schema validation always runs before this in
    /// `upload_sbom`, and only ever-valid content is stored, so reads back
    /// out of storage are guaranteed valid too.
    fn check(&self, format: &str, sbom_bytes: &[u8]) -> ComplianceReport;
}

static PROFILES: OnceLock<Vec<Box<dyn ComplianceProfile>>> = OnceLock::new();

/// All registered profiles, compiled once. Add a new profile by pushing it
/// into this `vec!` — nothing else in this module or its callers changes.
pub fn registered_profiles() -> &'static [Box<dyn ComplianceProfile>] {
    PROFILES.get_or_init(|| vec![Box::new(Tr03183Profile), Box::new(NtiaProfile)])
}

pub fn profile_by_id(id: &str) -> Option<&'static dyn ComplianceProfile> {
    registered_profiles().iter().find(|p| p.id() == id).map(|p| p.as_ref())
}

// ---------------- BSI TR-03183-2 v2.1.0 profile ----------------

pub struct Tr03183Profile;

const TR_ID: &str = "tr-03183-2";
const TR_NAME: &str = "BSI TR-03183-2 (CRA SBOM)";

impl ComplianceProfile for Tr03183Profile {
    fn id(&self) -> &'static str {
        TR_ID
    }

    fn name(&self) -> &'static str {
        TR_NAME
    }

    fn description(&self) -> &'static str {
        "Checks CycloneDX SBOMs against BSI TR-03183-2 Annex 8.2's data-field requirements (SPDX support pending SPDX 3.x parsing)."
    }

    fn check(&self, format: &str, sbom_bytes: &[u8]) -> ComplianceReport {
        match format {
            "cyclonedx" => check_cyclonedx(sbom_bytes),
            "spdx" => check_spdx(sbom_bytes),
            _ => ComplianceReport {
                profile_id: TR_ID.to_string(),
                profile_name: TR_NAME.to_string(),
                applicable: false,
                meets_minimum: false,
                minimum_issues: Vec::new(),
                fully_compliant: false,
                missing_fields: Vec::new(),
            },
        }
    }
}

fn check_cyclonedx(sbom_bytes: &[u8]) -> ComplianceReport {
    let mut minimum_issues = Vec::new();
    let mut missing = Vec::new();

    let doc: Value = match serde_json::from_slice(sbom_bytes) {
        Ok(v) => v,
        Err(_) => {
            minimum_issues.push("sbom_file is not valid JSON".to_string());
            return ComplianceReport {
                profile_id: TR_ID.to_string(),
                profile_name: TR_NAME.to_string(),
                applicable: true,
                meets_minimum: false,
                minimum_issues,
                fully_compliant: false,
                missing_fields: missing,
            };
        }
    };

    // ---- minimum: format/version floor ----
    // Only 1.6 exactly is accepted — 1.7+ doesn't exist yet, and Magnolia's
    // own schema validator (crates/core/src/schema_validation.rs) doesn't
    // support anything past 1.6 either, so this can never silently claim a
    // floor the rest of the system couldn't even validate.
    let spec_version = doc.get("specVersion").and_then(Value::as_str).unwrap_or("");
    if spec_version != "1.6" {
        minimum_issues.push(format!(
            "CycloneDX specVersion must be 1.6 for TR-03183-2 minimum compliance (found: {})",
            if spec_version.is_empty() { "missing".to_string() } else { spec_version.to_string() }
        ));
    }
    let meets_minimum = minimum_issues.is_empty();

    // ---- full: field-level checks (TR Appendix 8.2) ----
    // SBOM-level, once, in metadata.
    if !has_manufacturer_creator(&doc["metadata"]) {
        missing.push(
            "metadata.manufacturer.url or metadata.manufacturer.contact[].email is required (creator of the SBOM)"
                .to_string(),
        );
    }
    if !non_empty_str(&doc["metadata"]["timestamp"]) {
        missing.push("metadata.timestamp is required".to_string());
    }

    let dependency_refs = collect_dependency_refs(&doc);

    match doc["metadata"].get("component") {
        Some(primary) => check_component(primary, "metadata.component", &dependency_refs, &mut missing),
        None => missing.push("metadata.component (primary component) is required".to_string()),
    }
    if let Some(components) = doc["components"].as_array() {
        for (i, c) in components.iter().enumerate() {
            check_component(c, &format!("components[{}]", i), &dependency_refs, &mut missing);
        }
    }

    let fully_compliant = meets_minimum && missing.is_empty();
    ComplianceReport {
        profile_id: TR_ID.to_string(),
        profile_name: TR_NAME.to_string(),
        applicable: true,
        meets_minimum,
        minimum_issues,
        fully_compliant,
        missing_fields: missing,
    }
}

fn non_empty_str(v: &Value) -> bool {
    v.as_str().map(|s| !s.is_empty()).unwrap_or(false)
}

fn has_manufacturer_creator(node: &Value) -> bool {
    // CycloneDX 1.6's organizationalEntity.url is an array of strings, not
    // a bare string (unlike the TR's own illustrative appendix example) —
    // matched against the real schema shape here, since that's what
    // Magnolia's schema validator actually enforces upstream of this check.
    let url = &node["manufacturer"]["url"];
    let has_url = non_empty_str(url)
        || url.as_array().map(|urls| urls.iter().any(non_empty_str)).unwrap_or(false);
    has_url
        || node["manufacturer"]["contact"]
            .as_array()
            .map(|contacts| contacts.iter().any(|c| non_empty_str(&c["email"])))
            .unwrap_or(false)
}

fn collect_dependency_refs(doc: &Value) -> HashSet<String> {
    doc["dependencies"]
        .as_array()
        .map(|deps| deps.iter().filter_map(|d| d["ref"].as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn has_property(component: &Value, name: &str) -> bool {
    component["properties"]
        .as_array()
        .map(|props| props.iter().any(|p| p["name"].as_str() == Some(name)))
        .unwrap_or(false)
}

fn check_component(component: &Value, path: &str, dependency_refs: &HashSet<String>, missing: &mut Vec<String>) {
    if !has_manufacturer_creator(component) {
        missing.push(format!(
            "{path}.manufacturer.url or {path}.manufacturer.contact[].email is required (component creator)"
        ));
    }
    if !non_empty_str(&component["name"]) {
        missing.push(format!("{path}.name is required"));
    }
    if !non_empty_str(&component["version"]) {
        missing.push(format!("{path}.version is required"));
    }
    if !has_property(component, "bsi:component:filename") {
        missing.push(format!(
            "{path}.properties[] must include name=\"bsi:component:filename\" (filename of the component)"
        ));
    }
    let bom_ref = component["bom-ref"].as_str();
    let has_dependency_entry = bom_ref.map(|r| dependency_refs.contains(r)).unwrap_or(false);
    if !has_dependency_entry {
        missing.push(format!(
            "top-level dependencies[] must have an entry for {path}'s bom-ref (explicit dependsOn, even if empty)"
        ));
    }
    let has_concluded_license = component["licenses"]
        .as_array()
        .map(|licenses| {
            licenses
                .iter()
                .any(|l| non_empty_str(&l["expression"]) && l["acknowledgement"].as_str() == Some("concluded"))
        })
        .unwrap_or(false);
    if !has_concluded_license {
        missing.push(format!(
            "{path}.licenses[] must include an entry with an SPDX \"expression\" and acknowledgement=\"concluded\" (distribution licences)"
        ));
    }
    let has_sha512_distribution_hash = component["externalReferences"]
        .as_array()
        .map(|refs| {
            refs.iter().any(|r| {
                r["type"].as_str() == Some("distribution")
                    && r["hashes"]
                        .as_array()
                        .map(|hashes| hashes.iter().any(|h| h["alg"].as_str() == Some("SHA-512")))
                        .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    if !has_sha512_distribution_hash {
        missing.push(format!(
            "{path}.externalReferences[] must include type=\"distribution\" with hashes[] alg=\"SHA-512\" (hash of the deployable component)"
        ));
    }
    for (prop, label) in [
        ("bsi:component:executable", "executable"),
        ("bsi:component:archive", "archive"),
        ("bsi:component:structured", "structured"),
    ] {
        if !has_property(component, prop) {
            missing.push(format!("{path}.properties[] must include name=\"{prop}\" ({label} property)"));
        }
    }
}

fn check_spdx(sbom_bytes: &[u8]) -> ComplianceReport {
    let doc: Value = serde_json::from_slice(sbom_bytes).unwrap_or(Value::Null);
    let spdx_version = doc.get("spdxVersion").and_then(Value::as_str).unwrap_or("");
    // TR-03183-2 requires SPDX >= 3.0.1 (JSON-LD, structurally different
    // from 2.x). Magnolia's schema validator only supports SPDX 2.2/2.3
    // (crates/core/src/schema_validation.rs) — SPDX 3.x parsing doesn't
    // exist anywhere in this codebase yet, so this check can never
    // currently pass. Deliberately not attempting field-level checks for
    // SPDX at all, rather than pretending partial support.
    ComplianceReport {
        profile_id: TR_ID.to_string(),
        profile_name: TR_NAME.to_string(),
        applicable: true,
        meets_minimum: false,
        minimum_issues: vec![format!(
            "SPDX minimum compliance requires spdxVersion SPDX-3.0.1 or later (JSON-LD format); Magnolia currently only validates/accepts SPDX 2.2/2.3, so no SPDX SBOM can currently meet TR-03183-2 minimum compliance (found: {})",
            if spdx_version.is_empty() { "missing".to_string() } else { spdx_version.to_string() }
        )],
        fully_compliant: false,
        missing_fields: vec!["SPDX 3.x field-level compliance checking not yet implemented in Magnolia".to_string()],
    }
}

// ---------------- NTIA "Minimum Elements for an SBOM" profile ----------------
//
// Maps directly onto the source document's own two-tier structure:
// "minimum" = the 7 required Data Fields (§IV) plus the Automation Support
// element (satisfied by applicability itself — this is only ever called
// with format cyclonedx/spdx); "full" = minimum + the subset of §V's
// "Recommended Data Fields" that are cleanly checkable from standard
// SPDX/CycloneDX fields (Hash of the Component, License Information).
// Practices and Processes (§IV: Frequency, Depth, Known Unknowns,
// Distribution, Access Control, Accommodation of Mistakes) are
// organizational requirements, not data-verifiable from one SBOM file, and
// are deliberately not attempted here — see description() below, surfaced
// in the frontend so this scope gap isn't silently implied.

pub struct NtiaProfile;

const NTIA_ID: &str = "ntia-minimum-elements";
const NTIA_NAME: &str = "NTIA Minimum Elements for an SBOM";

impl ComplianceProfile for NtiaProfile {
    fn id(&self) -> &'static str {
        NTIA_ID
    }

    fn name(&self) -> &'static str {
        NTIA_NAME
    }

    fn description(&self) -> &'static str {
        "Checks NTIA's Data Fields and Automation Support elements (EO 14028). Practices and Processes \
         (frequency, depth, known-unknowns marking, distribution/access control, accommodation of \
         mistakes) are organizational requirements this tool cannot verify from SBOM content alone."
    }

    fn check(&self, format: &str, sbom_bytes: &[u8]) -> ComplianceReport {
        match format {
            "cyclonedx" => check_ntia_cyclonedx(sbom_bytes),
            "spdx" => check_ntia_spdx(sbom_bytes),
            _ => ComplianceReport {
                profile_id: NTIA_ID.to_string(),
                profile_name: NTIA_NAME.to_string(),
                applicable: false,
                meets_minimum: false,
                minimum_issues: Vec::new(),
                fully_compliant: false,
                missing_fields: Vec::new(),
            },
        }
    }
}

/// NTIA's "supplier" is deliberately broad (manufacturer/vendor/developer/
/// integrator/maintainer/provider — see the source document's glossary), so
/// CycloneDX's `supplier.name` and `manufacturer.name` are treated as
/// interchangeable: the schema's own doc comment on `metadata.authors` notes
/// manual processes tend to populate `authors` where automated tooling
/// populates `manufacturer`, and the same manual/automated split applies to
/// per-component `supplier` vs `manufacturer`.
fn ntia_supplier_name(entity: &Value) -> bool {
    non_empty_str(&entity["supplier"]["name"]) || non_empty_str(&entity["manufacturer"]["name"])
}

fn ntia_check_component_cyclonedx(component: &Value, path: &str, missing: &mut Vec<String>, full: &mut Vec<String>) {
    if !ntia_supplier_name(component) {
        missing.push(format!("{path}.supplier.name or {path}.manufacturer.name is required (Supplier Name)"));
    }
    if !non_empty_str(&component["name"]) {
        missing.push(format!("{path}.name is required (Component Name)"));
    }
    if !non_empty_str(&component["version"]) {
        missing.push(format!("{path}.version is required (Version of the Component)"));
    }
    if !non_empty_str(&component["purl"]) && !non_empty_str(&component["cpe"]) {
        missing.push(format!("{path}.purl or {path}.cpe is required (Other Unique Identifiers)"));
    }
    if component["hashes"].as_array().map(|h| h.is_empty()).unwrap_or(true) {
        full.push(format!("{path}.hashes[] is empty (recommended: Hash of the Component)"));
    }
    if component["licenses"].as_array().map(|l| l.is_empty()).unwrap_or(true) {
        full.push(format!("{path}.licenses[] is empty (recommended: License Information)"));
    }
}

fn check_ntia_cyclonedx(sbom_bytes: &[u8]) -> ComplianceReport {
    let mut minimum_issues = Vec::new();

    let doc: Value = match serde_json::from_slice(sbom_bytes) {
        Ok(v) => v,
        Err(_) => {
            minimum_issues.push("sbom_file is not valid JSON".to_string());
            return ComplianceReport {
                profile_id: NTIA_ID.to_string(),
                profile_name: NTIA_NAME.to_string(),
                applicable: true,
                meets_minimum: false,
                minimum_issues,
                fully_compliant: false,
                missing_fields: Vec::new(),
            };
        }
    };

    // SBOM-level minimum fields: Author of SBOM Data, Timestamp.
    let has_author =
        doc["metadata"]["authors"].as_array().map(|a| a.iter().any(|au| non_empty_str(&au["name"]))).unwrap_or(false)
            || non_empty_str(&doc["metadata"]["manufacturer"]["name"]);
    if !has_author {
        minimum_issues.push(
            "metadata.authors[].name or metadata.manufacturer.name is required (Author of SBOM Data)".to_string(),
        );
    }
    if !non_empty_str(&doc["metadata"]["timestamp"]) {
        minimum_issues.push("metadata.timestamp is required (Timestamp)".to_string());
    }
    // SBOM-level minimum field: Dependency Relationship — some dependency
    // graph is captured at all. Per-component graph-membership (depth,
    // known-unknowns) is out of scope, matching the source document's own
    // "Practices and Processes" being excluded from this profile.
    if doc["dependencies"].as_array().map(|d| d.is_empty()).unwrap_or(true) {
        minimum_issues
            .push("top-level dependencies[] must be present and non-empty (Dependency Relationship)".to_string());
    }

    let mut full = Vec::new();
    match doc["metadata"].get("component") {
        Some(primary) => ntia_check_component_cyclonedx(primary, "metadata.component", &mut minimum_issues, &mut full),
        None => minimum_issues.push("metadata.component (primary component) is required".to_string()),
    }
    if let Some(components) = doc["components"].as_array() {
        for (i, c) in components.iter().enumerate() {
            ntia_check_component_cyclonedx(c, &format!("components[{}]", i), &mut minimum_issues, &mut full);
        }
    }

    let meets_minimum = minimum_issues.is_empty();
    let fully_compliant = meets_minimum && full.is_empty();
    ComplianceReport {
        profile_id: NTIA_ID.to_string(),
        profile_name: NTIA_NAME.to_string(),
        applicable: true,
        meets_minimum,
        minimum_issues,
        fully_compliant,
        missing_fields: full,
    }
}

/// SPDX's own convention for "value intentionally not asserted" — a naive
/// non-empty check would trivially pass `"NOASSERTION"` while it carries
/// zero information, the opposite of what a Supplier/License field check is
/// meant to verify.
fn non_noassertion_str(v: &Value) -> bool {
    v.as_str().map(|s| !s.is_empty() && s != "NOASSERTION").unwrap_or(false)
}

fn ntia_check_package_spdx(pkg: &Value, path: &str, missing: &mut Vec<String>, full: &mut Vec<String>) {
    if !non_noassertion_str(&pkg["supplier"]) {
        missing.push(format!("{path}.supplier is required and must not be NOASSERTION (Supplier Name)"));
    }
    if !non_empty_str(&pkg["name"]) {
        missing.push(format!("{path}.name is required (Component Name)"));
    }
    if !non_empty_str(&pkg["versionInfo"]) {
        missing.push(format!("{path}.versionInfo is required (Version of the Component)"));
    }
    let has_identifier = pkg["externalRefs"]
        .as_array()
        .map(|refs| {
            refs.iter().any(|r| {
                matches!(r["referenceType"].as_str(), Some("purl") | Some("cpe23Type") | Some("cpe22Type"))
                    && non_empty_str(&r["referenceLocator"])
            })
        })
        .unwrap_or(false);
    if !has_identifier {
        missing.push(format!("{path}.externalRefs[] must include a purl or cpe entry (Other Unique Identifiers)"));
    }
    if pkg["checksums"].as_array().map(|c| c.is_empty()).unwrap_or(true) {
        full.push(format!("{path}.checksums[] is empty (recommended: Hash of the Component)"));
    }
    if !non_noassertion_str(&pkg["licenseConcluded"]) && !non_noassertion_str(&pkg["licenseDeclared"]) {
        full.push(format!("{path}.licenseConcluded or {path}.licenseDeclared is missing/NOASSERTION (recommended: License Information)"));
    }
}

fn check_ntia_spdx(sbom_bytes: &[u8]) -> ComplianceReport {
    let doc: Value = match serde_json::from_slice(sbom_bytes) {
        Ok(v) => v,
        Err(_) => {
            return ComplianceReport {
                profile_id: NTIA_ID.to_string(),
                profile_name: NTIA_NAME.to_string(),
                applicable: true,
                meets_minimum: false,
                minimum_issues: vec!["sbom_file is not valid JSON".to_string()],
                fully_compliant: false,
                missing_fields: Vec::new(),
            };
        }
    };

    let mut minimum_issues = Vec::new();
    // NTIA has no SPDX version floor (unlike BSI TR-03183-2's SPDX 3.0.1
    // requirement) — Magnolia's schema validator accepts SPDX 2.2/2.3, and
    // this profile checks field-level content directly against that shape.
    if !doc["creationInfo"]["creators"]
        .as_array()
        .map(|c| c.iter().any(non_empty_str))
        .unwrap_or(false)
    {
        minimum_issues.push("creationInfo.creators[] is required (Author of SBOM Data)".to_string());
    }
    if !non_empty_str(&doc["creationInfo"]["created"]) {
        minimum_issues.push("creationInfo.created is required (Timestamp)".to_string());
    }
    if doc["relationships"].as_array().map(|r| r.is_empty()).unwrap_or(true) {
        minimum_issues.push("relationships[] must be present and non-empty (Dependency Relationship)".to_string());
    }

    let mut full = Vec::new();
    match doc["packages"].as_array() {
        Some(packages) if !packages.is_empty() => {
            for (i, p) in packages.iter().enumerate() {
                ntia_check_package_spdx(p, &format!("packages[{}]", i), &mut minimum_issues, &mut full);
            }
        }
        _ => minimum_issues.push("packages[] is required and must be non-empty".to_string()),
    }

    let meets_minimum = minimum_issues.is_empty();
    let fully_compliant = meets_minimum && full.is_empty();
    ComplianceReport {
        profile_id: NTIA_ID.to_string(),
        profile_name: NTIA_NAME.to_string(),
        applicable: true,
        meets_minimum,
        minimum_issues,
        fully_compliant,
        missing_fields: full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn complete_cyclonedx() -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "timestamp": "2026-08-23T00:00:00Z",
                "manufacturer": { "contact": [{ "email": "sbom@acme.example" }] },
                "component": {
                    "bom-ref": "primary",
                    "name": "acme-app",
                    "version": "1.0.0",
                    "manufacturer": { "url": "https://acme.example" },
                    "properties": [
                        { "name": "bsi:component:filename", "value": "acme-app" },
                        { "name": "bsi:component:executable", "value": "executable" },
                        { "name": "bsi:component:archive", "value": "no archive" },
                        { "name": "bsi:component:structured", "value": "unstructured" }
                    ],
                    "licenses": [{ "expression": "MIT", "acknowledgement": "concluded" }],
                    "externalReferences": [{
                        "type": "distribution",
                        "hashes": [{ "alg": "SHA-512", "content": "abc" }]
                    }]
                }
            },
            "components": [{
                "bom-ref": "lib-a",
                "name": "lib-a",
                "version": "2.3.4",
                "manufacturer": { "url": "https://libs.example" },
                "properties": [
                    { "name": "bsi:component:filename", "value": "lib-a.so" },
                    { "name": "bsi:component:executable", "value": "non-executable" },
                    { "name": "bsi:component:archive", "value": "no archive" },
                    { "name": "bsi:component:structured", "value": "unstructured" }
                ],
                "licenses": [{ "expression": "Apache-2.0", "acknowledgement": "concluded" }],
                "externalReferences": [{
                    "type": "distribution",
                    "hashes": [{ "alg": "SHA-512", "content": "def" }]
                }]
            }],
            "dependencies": [
                { "ref": "primary", "dependsOn": ["lib-a"] },
                { "ref": "lib-a", "dependsOn": [] }
            ]
        })
    }

    #[test]
    fn fully_populated_cyclonedx_1_6_is_fully_compliant() {
        let bytes = serde_json::to_vec(&complete_cyclonedx()).unwrap();
        let report = Tr03183Profile.check("cyclonedx", &bytes);
        assert!(report.applicable);
        assert!(report.meets_minimum, "minimum issues: {:?}", report.minimum_issues);
        assert!(report.fully_compliant, "missing fields: {:?}", report.missing_fields);
        assert!(report.missing_fields.is_empty());
    }

    #[test]
    fn missing_component_filename_is_reported_specifically() {
        let mut doc = complete_cyclonedx();
        doc["components"][0]["properties"] = json!([
            { "name": "bsi:component:executable", "value": "non-executable" },
            { "name": "bsi:component:archive", "value": "no archive" },
            { "name": "bsi:component:structured", "value": "unstructured" }
        ]);
        let bytes = serde_json::to_vec(&doc).unwrap();
        let report = Tr03183Profile.check("cyclonedx", &bytes);
        assert!(report.meets_minimum);
        assert!(!report.fully_compliant);
        assert!(report
            .missing_fields
            .iter()
            .any(|m| m.contains("components[0]") && m.contains("bsi:component:filename")));
    }

    #[test]
    fn spec_version_below_1_6_fails_minimum_and_full() {
        let mut doc = complete_cyclonedx();
        doc["specVersion"] = json!("1.5");
        let bytes = serde_json::to_vec(&doc).unwrap();
        let report = Tr03183Profile.check("cyclonedx", &bytes);
        assert!(!report.meets_minimum);
        assert!(!report.fully_compliant);
        assert!(report.minimum_issues.iter().any(|m| m.contains("1.6")));
    }

    #[test]
    fn spdx_always_fails_minimum_with_explicit_scoping_message() {
        let bytes = serde_json::to_vec(&json!({ "spdxVersion": "SPDX-2.3" })).unwrap();
        let report = Tr03183Profile.check("spdx", &bytes);
        assert!(report.applicable);
        assert!(!report.meets_minimum);
        assert!(report.minimum_issues.iter().any(|m| m.contains("3.0.1")));
        assert!(report.missing_fields.iter().any(|m| m.contains("not yet implemented")));
    }

    #[test]
    fn generic_document_upload_is_not_applicable() {
        let report = Tr03183Profile.check("document", b"whatever bytes");
        assert!(!report.applicable);
    }

    // ---------------- NTIA profile tests ----------------

    fn complete_cyclonedx_ntia() -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "timestamp": "2026-08-23T00:00:00Z",
                "authors": [{ "name": "Acme SBOM Team" }],
                "component": {
                    "bom-ref": "primary",
                    "name": "acme-app",
                    "version": "1.0.0",
                    "supplier": { "name": "Acme Corp" },
                    "purl": "pkg:generic/acme-app@1.0.0",
                    "hashes": [{ "alg": "SHA-256", "content": "abc" }],
                    "licenses": [{ "expression": "MIT" }]
                }
            },
            "components": [{
                "bom-ref": "lib-a",
                "name": "lib-a",
                "version": "2.3.4",
                "supplier": { "name": "Lib Publisher" },
                "purl": "pkg:npm/lib-a@2.3.4",
                "hashes": [{ "alg": "SHA-256", "content": "def" }],
                "licenses": [{ "expression": "Apache-2.0" }]
            }],
            "dependencies": [
                { "ref": "primary", "dependsOn": ["lib-a"] }
            ]
        })
    }

    fn complete_spdx_ntia() -> Value {
        json!({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "acme-app-sbom",
            "dataLicense": "CC0-1.0",
            "creationInfo": {
                "created": "2026-08-23T00:00:00Z",
                "creators": ["Organization: Acme Corp", "Tool: syft-1.0"]
            },
            "packages": [{
                "SPDXID": "SPDXRef-Package-acme-app",
                "name": "acme-app",
                "versionInfo": "1.0.0",
                "supplier": "Organization: Acme Corp",
                "checksums": [{ "algorithm": "SHA256", "checksumValue": "abc" }],
                "licenseConcluded": "MIT",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:generic/acme-app@1.0.0"
                }]
            }],
            "relationships": [{
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package-acme-app",
                "relationshipType": "DESCRIBES"
            }]
        })
    }

    #[test]
    fn fully_populated_cyclonedx_meets_ntia_minimum_and_full() {
        let bytes = serde_json::to_vec(&complete_cyclonedx_ntia()).unwrap();
        let report = NtiaProfile.check("cyclonedx", &bytes);
        assert!(report.applicable);
        assert!(report.meets_minimum, "minimum issues: {:?}", report.minimum_issues);
        assert!(report.fully_compliant, "missing fields: {:?}", report.missing_fields);
    }

    #[test]
    fn fully_populated_spdx_meets_ntia_minimum_and_full() {
        let bytes = serde_json::to_vec(&complete_spdx_ntia()).unwrap();
        let report = NtiaProfile.check("spdx", &bytes);
        assert!(report.applicable);
        assert!(report.meets_minimum, "minimum issues: {:?}", report.minimum_issues);
        assert!(report.fully_compliant, "missing fields: {:?}", report.missing_fields);
    }

    #[test]
    fn missing_cyclonedx_supplier_fails_ntia_minimum() {
        let mut doc = complete_cyclonedx_ntia();
        doc["components"][0].as_object_mut().unwrap().remove("supplier");
        let bytes = serde_json::to_vec(&doc).unwrap();
        let report = NtiaProfile.check("cyclonedx", &bytes);
        assert!(!report.meets_minimum);
        assert!(report.minimum_issues.iter().any(|m| m.contains("components[0]") && m.contains("Supplier")));
    }

    #[test]
    fn missing_sbom_author_and_timestamp_fails_ntia_minimum() {
        let mut doc = complete_cyclonedx_ntia();
        doc["metadata"].as_object_mut().unwrap().remove("authors");
        doc["metadata"].as_object_mut().unwrap().remove("timestamp");
        let bytes = serde_json::to_vec(&doc).unwrap();
        let report = NtiaProfile.check("cyclonedx", &bytes);
        assert!(!report.meets_minimum);
        assert!(report.minimum_issues.iter().any(|m| m.contains("Author of SBOM Data")));
        assert!(report.minimum_issues.iter().any(|m| m.contains("Timestamp")));
    }

    #[test]
    fn spdx_noassertion_supplier_is_treated_as_missing() {
        let mut doc = complete_spdx_ntia();
        doc["packages"][0]["supplier"] = json!("NOASSERTION");
        let bytes = serde_json::to_vec(&doc).unwrap();
        let report = NtiaProfile.check("spdx", &bytes);
        assert!(!report.meets_minimum);
        assert!(report.minimum_issues.iter().any(|m| m.contains("Supplier")));
    }

    #[test]
    fn ntia_generic_document_upload_is_not_applicable() {
        let report = NtiaProfile.check("document", b"whatever bytes");
        assert!(!report.applicable);
    }
}
