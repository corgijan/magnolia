//! The non-AI baseline.
//!
//! The course's evaluation deliverable requires a baseline comparison, and a
//! baseline is only honest if it is a real attempt at the same job rather
//! than a strawman. This is the best heuristic extraction that can be
//! written without a model: pull out the things advisories conventionally
//! mark as code — backticked spans, `name()` call forms, and identifiers
//! with internal capitals or underscores — and filter the same generic-noise
//! list stage B uses.
//!
//! It does well on advisories that name their symbols in code formatting and
//! badly on advisories that describe the flaw in prose, which is exactly the
//! contrast `eval/` is meant to quantify.

/// Same filter stage B applies, so the comparison isolates *extraction*
/// rather than measuring one side's cleanup step.
fn is_noise(t: &str) -> bool {
    t.len() < 3
        || t.len() > 60
        || t.chars().next().is_some_and(|c| c.is_ascii_digit())
        || matches!(
            t.to_ascii_lowercase().as_str(),
            "the" | "and" | "for" | "this" | "that" | "with" | "from" | "when" | "not" | "all"
                | "can" | "may" | "has" | "was" | "are" | "cve" | "ghsa" | "get" | "set" | "new"
                | "run" | "use" | "via" | "any" | "but" | "its" | "who" | "how" | "why" | "you"
                | "version" | "versions" | "affected" | "vulnerability" | "attacker" | "remote"
                | "code" | "execution" | "input" | "user" | "users" | "before" | "after" | "fix"
                | "fixed" | "issue" | "allows" | "allow" | "prior" | "later" | "than" | "note"
        )
}

/// Heuristic symbol extraction. No model, no network.
pub fn extract_symbols_heuristic(advisory: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        let t = t.trim().trim_end_matches("()").trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '$');
        if !t.is_empty() && !is_noise(t) && !out.iter().any(|e: &String| e == t) {
            out.push(t.to_string());
        }
    };

    // 1. Backticked spans — the strongest signal an advisory gives.
    let mut rest = advisory;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        match after.find('`') {
            Some(end) => {
                push(&after[..end]);
                rest = &after[end + 1..];
            }
            None => break,
        }
    }

    // 2. Call forms and identifiers with internal capitals or underscores.
    let mut token = String::new();
    for c in advisory.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            token.push(c);
            continue;
        }
        if !token.is_empty() {
            let called = c == '(';
            let has_internal_capital =
                token.chars().skip(1).any(|ch| ch.is_ascii_uppercase()) && !token.chars().all(|ch| ch.is_ascii_uppercase());
            let has_underscore = token.contains('_');
            if called || has_internal_capital || has_underscore {
                push(&token);
            }
            token.clear();
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_up_backticked_symbols() {
        let got = extract_symbols_heuristic("The `unsafeLoad` helper is affected.");
        assert!(got.contains(&"unsafeLoad".to_string()));
    }

    #[test]
    fn picks_up_call_forms_and_camel_case() {
        let got = extract_symbols_heuristic("Calling doRender() on the parser, or deep_merge, is unsafe.");
        assert!(got.contains(&"doRender".to_string()));
        assert!(got.contains(&"deep_merge".to_string()));
    }

    #[test]
    fn skips_ordinary_prose_words() {
        // The heuristic's real weakness, and the thing the eval measures:
        // an advisory that never marks its symbols yields nothing at all.
        let got = extract_symbols_heuristic(
            "A remote attacker can execute arbitrary code by sending a crafted request.",
        );
        assert!(got.is_empty(), "got {got:?}");
    }

    #[test]
    fn does_not_emit_identifier_noise_or_the_cve_id() {
        let got = extract_symbols_heuristic("CVE-2021-44228 affects the `version` field.");
        assert!(!got.iter().any(|t| t.eq_ignore_ascii_case("cve")));
        assert!(!got.contains(&"version".to_string()));
    }

    #[test]
    fn is_deterministic_and_deduplicated() {
        let a = extract_symbols_heuristic("`lookup` and lookup() and `lookup`");
        assert_eq!(a, vec!["lookup"]);
    }

    #[test]
    fn an_unterminated_backtick_does_not_loop_forever() {
        assert!(extract_symbols_heuristic("an `unclosed span").is_empty());
    }
}
