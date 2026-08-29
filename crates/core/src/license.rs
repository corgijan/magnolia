use crate::component_index::ExtractedComponent;

/// One tenant's license policy, as configured in `tenant_license_policies` —
/// deliberately independent of `magnolia_db`'s row type (same "plain
/// primitives, no cross-crate struct dependency" convention as
/// `magnolia_db::NewSbomComponent`'s own doc comment).
#[derive(Debug, Clone)]
pub struct LicensePolicy {
    /// SPDX identifiers (or opaque strings, for non-SPDX license text) a
    /// tenant has chosen to reject — matched case-insensitively against
    /// each individual identifier resolved out of a component's license
    /// expression, not against the whole expression string.
    pub denied_licenses: Vec<String>,
    /// Whether a component with no usable license information at all
    /// counts as a violation in its own right.
    pub flag_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum LicenseViolationReason {
    /// `denied` names the specific identifier from the component's
    /// (possibly compound) expression that matched the deny-list — not
    /// necessarily the whole expression string, e.g. only "GPL-3.0-only"
    /// out of "MIT AND GPL-3.0-only".
    Denied { denied: String },
    /// No license expression at all, and the policy has `flag_unknown` set.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct LicenseViolation {
    pub component_name: String,
    pub component_version: Option<String>,
    /// The component's raw, un-normalized license expression — `None` only
    /// for `LicenseViolationReason::Unknown`.
    pub license_expr: Option<String>,
    pub reason: LicenseViolationReason,
}

/// Resolves a license expression into its individual SPDX identifiers —
/// `"MIT OR Apache-2.0"` yields `["MIT", "Apache-2.0"]`. Falls back to
/// treating the whole input as one opaque identifier when it isn't a valid
/// SPDX expression (free-text license strings are common in the wild,
/// especially from SPDX's `licenseDeclared`) — never dropped, so a
/// tenant's deny-list can still match it verbatim.
pub fn normalize_license_expr(expr: &str) -> Vec<String> {
    match spdx::Expression::parse(expr) {
        Ok(parsed) => parsed.requirements().map(|r| r.req.license.to_string()).collect(),
        Err(_) => {
            let trimmed = expr.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                vec![trimmed.to_string()]
            }
        }
    }
}

/// Whether `id` is a recognized SPDX license identifier — an exact,
/// case-sensitive match against the same license list
/// `spdx::Expression::parse` resolves compound expressions against (the
/// `+`/`-or-later` suffix conventions included). Used to validate a
/// tenant's deny-list entries at policy-save time: the Settings page's own
/// copy tells an admin denied licenses must be SPDX identifiers, so a typo
/// should be caught immediately rather than silently matching nothing
/// forever. Deliberately not used by `normalize_license_expr` above, which
/// stays lenient about a *component's* license text (SBOMs commonly carry
/// free-text/non-SPDX strings there, and dropping them would lose real
/// deny-list matches for opaque strings a tenant explicitly listed).
pub fn is_valid_spdx_license_id(id: &str) -> bool {
    spdx::license_id(id).is_some()
}

/// Pure policy check — no I/O, no knowledge of upload/verify call sites, so
/// it can run identically at upload time (blocking when `enforce_level` is
/// `block`) and inside `/verify`'s dry-run gate.
pub fn evaluate_license_policy(
    components: &[ExtractedComponent],
    policy: &LicensePolicy,
) -> Vec<LicenseViolation> {
    let denied_lower: std::collections::HashSet<String> =
        policy.denied_licenses.iter().map(|s| s.to_lowercase()).collect();

    let mut violations = Vec::new();
    for c in components {
        match &c.license {
            None => {
                if policy.flag_unknown {
                    violations.push(LicenseViolation {
                        component_name: c.name.clone(),
                        component_version: c.version.clone(),
                        license_expr: None,
                        reason: LicenseViolationReason::Unknown,
                    });
                }
            }
            Some(expr) => {
                for id in normalize_license_expr(expr) {
                    if denied_lower.contains(&id.to_lowercase()) {
                        violations.push(LicenseViolation {
                            component_name: c.name.clone(),
                            component_version: c.version.clone(),
                            license_expr: Some(expr.clone()),
                            reason: LicenseViolationReason::Denied { denied: id },
                        });
                    }
                }
            }
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(name: &str, license: Option<&str>) -> ExtractedComponent {
        ExtractedComponent {
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            purl: None,
            cpe: None,
            is_primary: false,
            license: license.map(str::to_string),
        }
    }

    #[test]
    fn normalize_splits_compound_expressions() {
        let mut ids = normalize_license_expr("MIT OR Apache-2.0");
        ids.sort();
        assert_eq!(ids, vec!["Apache-2.0".to_string(), "MIT".to_string()]);
    }

    #[test]
    fn normalize_falls_back_to_opaque_string_for_free_text() {
        assert_eq!(normalize_license_expr("Acme Proprietary License"), vec!["Acme Proprietary License".to_string()]);
    }

    #[test]
    fn spdx_id_validation_accepts_known_identifiers() {
        assert!(is_valid_spdx_license_id("MIT"));
        assert!(is_valid_spdx_license_id("GPL-3.0-only"));
        assert!(is_valid_spdx_license_id("AGPL-3.0-only"));
    }

    #[test]
    fn spdx_id_validation_is_case_sensitive() {
        assert!(!is_valid_spdx_license_id("mit"));
        assert!(!is_valid_spdx_license_id("Gpl-3.0-Only"));
    }

    #[test]
    fn spdx_id_validation_rejects_free_text_and_compound_expressions() {
        assert!(!is_valid_spdx_license_id("Acme Proprietary License"));
        assert!(!is_valid_spdx_license_id("MIT OR Apache-2.0"));
        assert!(!is_valid_spdx_license_id(""));
    }

    #[test]
    fn denied_license_in_compound_expression_is_flagged() {
        let components = vec![component("lib-a", Some("MIT AND GPL-3.0-only"))];
        let policy = LicensePolicy { denied_licenses: vec!["GPL-3.0-only".to_string()], flag_unknown: false };
        let violations = evaluate_license_policy(&components, &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].component_name, "lib-a");
        assert_eq!(violations[0].reason, LicenseViolationReason::Denied { denied: "GPL-3.0-only".to_string() });
    }

    #[test]
    fn deny_match_is_case_insensitive() {
        let components = vec![component("lib-a", Some("gpl-3.0-only"))];
        let policy = LicensePolicy { denied_licenses: vec!["GPL-3.0-ONLY".to_string()], flag_unknown: false };
        assert_eq!(evaluate_license_policy(&components, &policy).len(), 1);
    }

    #[test]
    fn unknown_license_only_flagged_when_policy_opts_in() {
        let components = vec![component("lib-a", None)];
        let off = LicensePolicy { denied_licenses: vec![], flag_unknown: false };
        assert!(evaluate_license_policy(&components, &off).is_empty());

        let on = LicensePolicy { denied_licenses: vec![], flag_unknown: true };
        let violations = evaluate_license_policy(&components, &on);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].reason, LicenseViolationReason::Unknown);
        assert_eq!(violations[0].license_expr, None);
    }

    #[test]
    fn compliant_component_yields_no_violation() {
        let components = vec![component("lib-a", Some("MIT"))];
        let policy = LicensePolicy { denied_licenses: vec!["GPL-3.0-only".to_string()], flag_unknown: true };
        assert!(evaluate_license_policy(&components, &policy).is_empty());
    }
}
