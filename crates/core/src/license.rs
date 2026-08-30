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
    /// How a component with no usable license information at all is
    /// treated — see `UnknownLicenseHandling`.
    pub unknown_license_handling: UnknownLicenseHandling,
}

/// How a component with no usable license information at all (missing, or
/// SPDX "NOASSERTION") is treated — deliberately a 3-way choice rather than
/// a bool, since "missing license metadata" and "a component whose license
/// is affirmatively on the deny-list" are different severities of problem
/// even when a tenant wants both surfaced: `Warn` reports it without ever
/// blocking an upload (even under `enforce_level == "block"`), while `Flag`
/// gives it the same blocking weight as a denied license. See
/// `license_policy_status`, which is where that distinction actually bites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownLicenseHandling {
    /// Not a violation at all — the default.
    Ignore,
    /// A violation, but capped at "warn": never fails an upload/verify
    /// check on its own, regardless of the policy's `enforce_level`.
    Warn,
    /// A violation with the same severity as a denied license — follows
    /// `enforce_level` like any other violation, including `block`.
    Flag,
}

impl UnknownLicenseHandling {
    /// Parses the DB/API's plain-string representation ("ignore" | "warn" |
    /// "flag") — anything else (including absent/legacy data) falls back to
    /// `Ignore`, the same default `LicensePolicy` has always had.
    pub fn parse(s: &str) -> Self {
        match s {
            "warn" => Self::Warn,
            "flag" => Self::Flag,
            _ => Self::Ignore,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ignore => "ignore",
            Self::Warn => "warn",
            Self::Flag => "flag",
        }
    }
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
                if policy.unknown_license_handling != UnknownLicenseHandling::Ignore {
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

/// Combines already-computed `violations` with this tenant's `enforce_level`
/// ("off" | "warn" | "block") and `unknown_license_handling` into a single
/// check status — "pass" | "warn" | "fail". The one subtlety this
/// centralizes so upload enforcement and `/verify`'s preview can't drift
/// apart: an `Unknown`-reason violation under `Warn` handling never
/// contributes to "fail", even when `enforce_level == "block"` — only a
/// `Denied` violation, or an `Unknown` one under `Flag` handling, can
/// actually block.
pub fn license_policy_status(
    violations: &[LicenseViolation],
    enforce_level: &str,
    unknown_handling: UnknownLicenseHandling,
) -> &'static str {
    if violations.is_empty() {
        return "pass";
    }
    let blockable = violations.iter().any(|v| match &v.reason {
        LicenseViolationReason::Denied { .. } => true,
        LicenseViolationReason::Unknown => unknown_handling == UnknownLicenseHandling::Flag,
    });
    if enforce_level == "block" && blockable {
        "fail"
    } else {
        "warn"
    }
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
        let policy = LicensePolicy {
            denied_licenses: vec!["GPL-3.0-only".to_string()],
            unknown_license_handling: UnknownLicenseHandling::Ignore,
        };
        let violations = evaluate_license_policy(&components, &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].component_name, "lib-a");
        assert_eq!(violations[0].reason, LicenseViolationReason::Denied { denied: "GPL-3.0-only".to_string() });
    }

    #[test]
    fn deny_match_is_case_insensitive() {
        let components = vec![component("lib-a", Some("gpl-3.0-only"))];
        let policy = LicensePolicy {
            denied_licenses: vec!["GPL-3.0-ONLY".to_string()],
            unknown_license_handling: UnknownLicenseHandling::Ignore,
        };
        assert_eq!(evaluate_license_policy(&components, &policy).len(), 1);
    }

    #[test]
    fn unknown_license_ignored_by_default() {
        let components = vec![component("lib-a", None)];
        let off = LicensePolicy { denied_licenses: vec![], unknown_license_handling: UnknownLicenseHandling::Ignore };
        assert!(evaluate_license_policy(&components, &off).is_empty());
    }

    #[test]
    fn unknown_license_flagged_under_warn_or_flag_handling() {
        let components = vec![component("lib-a", None)];
        for handling in [UnknownLicenseHandling::Warn, UnknownLicenseHandling::Flag] {
            let policy = LicensePolicy { denied_licenses: vec![], unknown_license_handling: handling };
            let violations = evaluate_license_policy(&components, &policy);
            assert_eq!(violations.len(), 1);
            assert_eq!(violations[0].reason, LicenseViolationReason::Unknown);
            assert_eq!(violations[0].license_expr, None);
        }
    }

    #[test]
    fn compliant_component_yields_no_violation() {
        let components = vec![component("lib-a", Some("MIT"))];
        let policy = LicensePolicy {
            denied_licenses: vec!["GPL-3.0-only".to_string()],
            unknown_license_handling: UnknownLicenseHandling::Flag,
        };
        assert!(evaluate_license_policy(&components, &policy).is_empty());
    }

    fn unknown_violation() -> Vec<LicenseViolation> {
        vec![LicenseViolation {
            component_name: "lib-a".to_string(),
            component_version: None,
            license_expr: None,
            reason: LicenseViolationReason::Unknown,
        }]
    }

    fn denied_violation() -> Vec<LicenseViolation> {
        vec![LicenseViolation {
            component_name: "lib-a".to_string(),
            component_version: None,
            license_expr: Some("GPL-3.0-only".to_string()),
            reason: LicenseViolationReason::Denied { denied: "GPL-3.0-only".to_string() },
        }]
    }

    #[test]
    fn status_is_pass_when_no_violations() {
        assert_eq!(license_policy_status(&[], "block", UnknownLicenseHandling::Flag), "pass");
    }

    #[test]
    fn status_never_fails_for_unknown_under_warn_handling_even_when_blocking() {
        let violations = unknown_violation();
        assert_eq!(license_policy_status(&violations, "block", UnknownLicenseHandling::Warn), "warn");
        assert_eq!(license_policy_status(&violations, "warn", UnknownLicenseHandling::Warn), "warn");
    }

    #[test]
    fn status_fails_for_unknown_under_flag_handling_when_blocking() {
        let violations = unknown_violation();
        assert_eq!(license_policy_status(&violations, "block", UnknownLicenseHandling::Flag), "fail");
        assert_eq!(license_policy_status(&violations, "warn", UnknownLicenseHandling::Flag), "warn");
    }

    #[test]
    fn status_fails_for_denied_license_when_blocking_regardless_of_unknown_handling() {
        let violations = denied_violation();
        assert_eq!(license_policy_status(&violations, "block", UnknownLicenseHandling::Warn), "fail");
        assert_eq!(license_policy_status(&violations, "block", UnknownLicenseHandling::Ignore), "fail");
    }
}
