//! Stage B — advisory to ruleset (LLM #1).
//!
//! Standing alone this is the project's declared **fallback feature**:
//! AI-assisted extraction and grounded summarisation of a CVE advisory. An
//! analysis with no `repo_url` runs exactly this and returns the ruleset as
//! its report.
//!
//! # Grounding
//!
//! The model's answer is not trusted as written. Every extracted symbol must
//! actually *appear in the advisory text* — a mechanical substring check
//! against the input, the extraction-side analogue of stage D's citation
//! verification. A symbol the advisory never mentions is a fabrication, and
//! a fabricated symbol is worse than a missing one: it sends an analyst
//! hunting through their code for something that was never at issue. Dropped
//! symbols are counted, and that count is the report's visible hallucination
//! signal.

use crate::ai::{prompts, AiError, CallStats, ChatClient};
use crate::models::{NestedCallPattern, Ruleset};

/// Symbols so common that searching for them **as a bare name** would bury
/// the report in noise regardless of what the advisory says.
///
/// Not an unconditional denylist. Several entries here are also the real,
/// only symbol named by a famous CVE — `yaml.load` (CVE-2017-18342),
/// `pickle.load`, `Marshal.load` are the canonical deserialization flaws, and
/// dropping `load` outright turned those advisories into "no searchable
/// symbols" and a `package_present_only` report. A name on this list survives
/// when the advisory writes it in a **qualified** form (see
/// [`appears_qualified`]), which is exactly how those advisories write it and
/// is not how a passing mention of the English word "load" reads.
const USELESS_SYMBOLS: &[&str] = &[
    "get", "set", "new", "run", "main", "init", "read", "write", "open", "close", "load", "save",
    "parse", "value", "data", "name", "type", "string", "object", "array", "list", "map", "true",
    "false", "null", "none", "self", "this", "function", "class", "return", "if", "for", "while",
];

/// Longest a plausible symbol name is. Anything longer is a sentence the
/// model put in the wrong field.
const MAX_SYMBOL_LEN: usize = 80;

#[derive(Debug, Clone)]
pub struct RulesetOutcome {
    pub ruleset: Ruleset,
    /// Symbols the model produced that the advisory never mentions.
    pub ungrounded_dropped: usize,
    /// Symbols dropped for being too generic or malformed.
    pub noise_dropped: usize,
    pub stats: CallStats,
}

/// Runs the extraction. Errors are the caller's to degrade on — this returns
/// them rather than swallowing them, so the pipeline can record which of the
/// four failure modes occurred.
pub async fn extract_ruleset(
    client: &ChatClient,
    advisory_text: &str,
    osv_id: Option<&str>,
    package_name: Option<&str>,
    ecosystem: Option<&str>,
    max_advisory_chars: usize,
) -> Result<RulesetOutcome, AiError> {
    let advisory = crate::ai::truncate(advisory_text, max_advisory_chars);
    let messages = prompts::ruleset_messages(&advisory, osv_id, package_name, ecosystem);

    let (result, stats) = client.complete_json::<Ruleset>(&messages).await;
    let raw = result?;

    let (ruleset, ungrounded_dropped, noise_dropped) = ground_and_clean(raw, &advisory);
    Ok(RulesetOutcome { ruleset, ungrounded_dropped, noise_dropped, stats })
}

/// Drops anything the model invented or anything too generic to search for.
/// Pure, so the anti-hallucination rule is testable without an inference
/// server.
///
/// Returns `(cleaned, ungrounded_dropped, noise_dropped)`.
pub fn ground_and_clean(mut rs: Ruleset, advisory_text: &str) -> (Ruleset, usize, usize) {
    let haystack = advisory_text.to_ascii_lowercase();
    let mut ungrounded = 0usize;
    let mut noise = 0usize;

    let mut keep = |terms: Vec<String>, check_grounding: bool| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for term in terms {
            if let Some(t) =
                normalize_symbol(&term, &haystack, check_grounding, &mut noise, &mut ungrounded)
            {
                if !out.iter().any(|e: &String| e == &t) {
                    out.push(t);
                }
            }
        }
        out
    };

    rs.vulnerable_symbols = keep(std::mem::take(&mut rs.vulnerable_symbols), true);
    // Patterns are allowed to contain punctuation and spaces (`jndi:ldap://`,
    // a format string), so only the grounding rule applies to them.
    rs.search_patterns = keep(std::mem::take(&mut rs.search_patterns), false)
        .into_iter()
        .filter(|p| {
            let grounded = haystack.contains(&p.to_ascii_lowercase());
            if !grounded {
                ungrounded += 1;
            }
            grounded
        })
        .collect();

    rs.summary = crate::ai::truncate(rs.summary.trim(), 1200);
    rs.preconditions =
        rs.preconditions.into_iter().map(|p| crate::ai::truncate(p.trim(), 400)).collect();
    rs.notes = rs.notes.into_iter().map(|n| crate::ai::truncate(n.trim(), 400)).collect();

    // Both names go through the same grounding as vulnerable_symbols -- a
    // pattern is only as trustworthy as its weaker half, so either side
    // failing drops the whole pattern rather than keeping a dangling name.
    // Also required to be plain identifier shape (unlike vulnerable_symbols,
    // which only rejects whitespace): both names are substituted directly
    // into a tree-sitter query as `(identifier)` node text, so anything else
    // could not structurally match regardless, making it noise here even
    // where it would have been acceptable prose-adjacent text elsewhere.
    rs.nested_calls = std::mem::take(&mut rs.nested_calls)
        .into_iter()
        .filter_map(|pattern| {
            let outer = normalize_symbol(&pattern.outer, &haystack, true, &mut noise, &mut ungrounded)?;
            let inner = normalize_symbol(&pattern.inner, &haystack, true, &mut noise, &mut ungrounded)?;
            if !is_plain_identifier(&outer) || !is_plain_identifier(&inner) {
                noise += 1;
                return None;
            }
            Some(NestedCallPattern { outer, inner })
        })
        .collect();

    (rs, ungrounded, noise)
}

/// Normalizes and grounds one symbol name: trims quoting, strips a trailing
/// call form, drops generic noise and anything too long, and — when
/// `check_grounding` — drops anything absent from the advisory text or
/// containing whitespace (prose landed in the wrong field). `None` means
/// dropped; the matching counter has already been bumped.
fn normalize_symbol(
    term: &str,
    haystack: &str,
    check_grounding: bool,
    noise: &mut usize,
    ungrounded: &mut usize,
) -> Option<String> {
    let t = term.trim().trim_matches(|c| c == '`' || c == '"' || c == '\'').to_string();
    // Strip a trailing call form: models write `lookup()` about half the
    // time, and `lookup` is what the index holds.
    let t = t.trim_end_matches("()").trim().to_string();

    if t.is_empty() || t.len() > MAX_SYMBOL_LEN {
        *noise += 1;
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if USELESS_SYMBOLS.contains(&lower.as_str()) && !appears_qualified(&lower, haystack) {
        *noise += 1;
        return None;
    }
    if check_grounding && t.chars().any(char::is_whitespace) {
        *noise += 1;
        return None;
    }
    if check_grounding && !haystack.contains(&t.to_ascii_lowercase()) {
        // The fabrication case: the advisory never says this.
        tracing::warn!(symbol = %t, "dropping symbol absent from the advisory text");
        *ungrounded += 1;
        return None;
    }
    Some(t)
}

/// Whether the advisory names `term_lower` in a **qualified** form —
/// `yaml.load`, `Marshal::load`, `obj->load`, `Yaml#load` — rather than as a
/// bare word. This is what rescues a [`USELESS_SYMBOLS`] entry that happens to
/// be the genuine subject of an advisory.
///
/// `haystack` is already lowercased by [`ground_and_clean`], which is also the
/// only caller, so the comparison is case-insensitive like every other
/// grounding check.
///
/// Deliberately generous: the separator set includes `-`, so "pre-load" reads
/// as qualified too. That asymmetry is intended. A false accept costs a
/// noisier occurrence list that stage D then labels and the analyst can skim;
/// a false reject silently removes the only symbol the advisory named and
/// turns a real finding into "package present, no symbol references". The
/// second failure is much worse, and much harder to notice.
fn appears_qualified(term_lower: &str, haystack: &str) -> bool {
    /// Characters that can sit between an owner and a member name across the
    /// languages advisories are written about.
    const SEPARATORS: [char; 5] = ['.', ':', '>', '-', '#'];

    let mut from = 0usize;
    while let Some(rel) = haystack[from..].find(term_lower) {
        let at = from + rel;
        from = at + term_lower.len();

        // The match must be a whole name, not the prefix of a longer one:
        // `.loader` is not an occurrence of `load`.
        let next = haystack[from..].chars().next();
        if matches!(next, Some(c) if c.is_alphanumeric() || c == '_') {
            continue;
        }

        // Walk backwards over the separator run, then require something that
        // could be an owner. A separator with nothing in front of it (a `-`
        // opening a bullet point, a `.` ending the previous sentence) is
        // punctuation, not a qualification.
        let mut saw_separator = false;
        let mut owner = None;
        for c in haystack[..at].chars().rev() {
            if SEPARATORS.contains(&c) {
                saw_separator = true;
                continue;
            }
            owner = Some(c);
            break;
        }
        if saw_separator && matches!(owner, Some(c) if c.is_alphanumeric() || c == '_') {
            return true;
        }
    }
    false
}

/// Whether `s` could ever match a tree-sitter `(identifier)` node — the only
/// shape [`crate::treesitter::find_nested_calls`] can look for a name as.
fn is_plain_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True when the ruleset gives stage C something to look for — either
/// independent names, or a structural composition.
pub fn is_searchable(rs: &Ruleset) -> bool {
    !rs.search_terms().is_empty() || !rs.nested_calls.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(symbols: &[&str], patterns: &[&str]) -> Ruleset {
        Ruleset {
            vulnerable_symbols: symbols.iter().map(|s| s.to_string()).collect(),
            search_patterns: patterns.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_symbol_the_advisory_never_mentions_is_dropped() {
        // The failure that matters most: a plausible-sounding invented
        // symbol sends an analyst hunting for something that was never at
        // issue.
        let advisory = "A flaw in the lookup() routine of the parser allows RCE.";
        let (out, ungrounded, _) = ground_and_clean(rs(&["lookup", "deserializeUnsafe"], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["lookup"]);
        assert_eq!(ungrounded, 1);
    }

    #[test]
    fn call_parentheses_and_quoting_are_normalised_to_bare_names() {
        let advisory = "The lookup() function and `evaluate` are affected.";
        let (out, _, _) = ground_and_clean(rs(&["lookup()", "`evaluate`"], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["lookup", "evaluate"]);
    }

    #[test]
    fn generic_names_are_dropped_even_when_the_advisory_uses_them() {
        // `get` appears in almost every file ever written; searching for it
        // would bury the real evidence.
        let advisory = "Calling get on the parser is unsafe; see doRender.";
        let (out, _, noise) = ground_and_clean(rs(&["get", "doRender"], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["doRender"]);
        assert_eq!(noise, 1);
    }

    #[test]
    fn a_generic_name_survives_when_the_advisory_qualifies_it() {
        // CVE-2017-18342's shape. `load` is on the noise list, and dropping it
        // here used to turn PyYAML's actual vulnerability into "no searchable
        // symbols" -- a false negative on one of the best-known advisories in
        // the corpus.
        let advisory = "PyYAML before 5.1 allows arbitrary code execution when yaml.load is \
                        called with untrusted input; use yaml.safe_load instead.";
        let (out, _, noise) = ground_and_clean(rs(&["load"], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["load"]);
        assert_eq!(noise, 0);
    }

    #[test]
    fn the_qualified_form_is_recognised_across_language_conventions() {
        for advisory in [
            "Ruby's Marshal::load is affected.",
            "Calling obj->load on the handle is unsafe.",
            "The Yaml#load helper deserializes arbitrary types.",
        ] {
            let (out, _, _) = ground_and_clean(rs(&["load"], &[]), advisory);
            assert_eq!(out.vulnerable_symbols, vec!["load"], "failed for: {advisory}");
        }
    }

    #[test]
    fn a_generic_name_used_as_an_english_word_is_still_dropped() {
        // The reason the list exists in the first place: searching a whole
        // repository for `load` because an advisory used the word in a
        // sentence would bury every real occurrence.
        for advisory in [
            "An attacker can load arbitrary classes through the parser.",
            "The flaw appears under heavy load.",
            "- load is mentioned after a bullet, not qualified.",
        ] {
            let (out, _, noise) = ground_and_clean(rs(&["load"], &[]), advisory);
            assert!(out.vulnerable_symbols.is_empty(), "kept for: {advisory}");
            assert_eq!(noise, 1);
        }
    }

    #[test]
    fn a_qualified_longer_name_does_not_rescue_the_generic_prefix() {
        // `yaml.loader` contains "load", but the advisory is not naming
        // `load`; treating it as qualified would resurrect the noise this
        // filter exists to remove.
        let advisory = "The yaml.loader module is affected.";
        let (out, _, noise) = ground_and_clean(rs(&["load"], &[]), advisory);
        assert!(out.vulnerable_symbols.is_empty());
        assert_eq!(noise, 1);
    }

    #[test]
    fn prose_placed_in_the_symbol_field_is_dropped() {
        let advisory = "the function that parses user input is affected";
        let (out, _, noise) = ground_and_clean(rs(&["the function that parses user input"], &[]), advisory);
        assert!(out.vulnerable_symbols.is_empty());
        assert_eq!(noise, 1);
    }

    #[test]
    fn duplicates_are_collapsed() {
        let advisory = "lookup is affected";
        let (out, _, _) = ground_and_clean(rs(&["lookup", "lookup()", " lookup "], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["lookup"]);
    }

    #[test]
    fn patterns_may_contain_punctuation_but_must_still_be_grounded() {
        let advisory = "Payloads of the form ${jndi:ldap://host/a} trigger the flaw.";
        let (out, ungrounded, _) =
            ground_and_clean(rs(&[], &["jndi:ldap://", "not-in-the-advisory"]), advisory);
        assert_eq!(out.search_patterns, vec!["jndi:ldap://"]);
        assert_eq!(ungrounded, 1);
    }

    #[test]
    fn grounding_is_case_insensitive() {
        let advisory = "The DoLookup helper is affected.";
        let (out, ungrounded, _) = ground_and_clean(rs(&["dolookup"], &[]), advisory);
        assert_eq!(out.vulnerable_symbols, vec!["dolookup"]);
        assert_eq!(ungrounded, 0);
    }

    #[test]
    fn an_empty_ruleset_is_a_valid_outcome_not_an_error() {
        // Many advisories describe a flaw purely in prose. "No symbols" is
        // the correct answer there, and the pipeline must be able to say so.
        let (out, _, _) = ground_and_clean(rs(&[], &[]), "A memory corruption issue.");
        assert!(!is_searchable(&out));
    }

    #[test]
    fn summary_and_notes_are_length_bounded() {
        // Untrusted advisory text can be arbitrarily long; a model can echo
        // it back. These fields end up in a database row and a UI.
        let long = "x".repeat(5000);
        let candidate =
            Ruleset { summary: long.clone(), notes: vec![long], ..Default::default() };
        let (out, _, _) = ground_and_clean(candidate, "x");
        assert!(out.summary.len() < 1300);
        assert!(out.notes[0].len() < 500);
    }

    // ------------------------------------------------------ nested_calls

    fn with_nested(pattern: (&str, &str)) -> Ruleset {
        Ruleset {
            nested_calls: vec![NestedCallPattern {
                outer: pattern.0.to_string(),
                inner: pattern.1.to_string(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn a_fully_grounded_nested_call_pattern_survives() {
        let advisory = "The construction of print(test(x)) is exploitable.";
        let (out, ungrounded, _) = ground_and_clean(with_nested(("print", "test")), advisory);
        assert_eq!(out.nested_calls, vec![NestedCallPattern { outer: "print".into(), inner: "test".into() }]);
        assert_eq!(ungrounded, 0);
    }

    #[test]
    fn a_pattern_with_one_ungrounded_name_drops_the_whole_pattern() {
        // A pattern is only as trustworthy as its weaker half -- keeping
        // "print(...INVENTED(...)...)" would point an analyst at a
        // composition that was never in the advisory at all.
        let advisory = "The function print is involved.";
        let (out, ungrounded, _) = ground_and_clean(with_nested(("print", "invented")), advisory);
        assert!(out.nested_calls.is_empty());
        assert_eq!(ungrounded, 1);
    }

    #[test]
    fn a_pattern_naming_a_non_identifier_is_dropped_as_noise() {
        // Both names are substituted into a tree-sitter query as
        // `(identifier)` node text; anything else could never structurally
        // match, so it is noise for this field specifically even though the
        // same text would be fine as a bare vulnerable_symbols entry.
        let advisory = "The construction of print(a-b(x)) is exploitable.";
        let (out, _, noise) = ground_and_clean(with_nested(("print", "a-b")), advisory);
        assert!(out.nested_calls.is_empty());
        assert_eq!(noise, 1);
    }

    #[test]
    fn call_parens_are_normalised_in_nested_call_names_too() {
        let advisory = "The construction of print()(test()) is exploitable.";
        let (out, _, _) = ground_and_clean(with_nested(("print()", "test()")), advisory);
        assert_eq!(out.nested_calls[0].outer, "print");
        assert_eq!(out.nested_calls[0].inner, "test");
    }

    #[test]
    fn a_nested_calls_only_ruleset_is_searchable() {
        let rs = Ruleset {
            nested_calls: vec![NestedCallPattern { outer: "a".into(), inner: "b".into() }],
            ..Default::default()
        };
        assert!(is_searchable(&rs));
    }

    #[test]
    fn an_empty_nested_calls_list_is_the_correct_answer_for_most_advisories() {
        // The prompt is explicit that this field is empty in every case but
        // the composition one; a normal single-symbol advisory must not
        // spuriously populate it.
        let advisory = "The `unsafeLoad` function is vulnerable.";
        let (out, _, _) = ground_and_clean(rs(&["unsafeLoad"], &[]), advisory);
        assert!(out.nested_calls.is_empty());
    }
}
