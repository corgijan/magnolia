//! Stage E — the rubric.
//!
//! A pure function from what the earlier stages established to an ordinal
//! priority label plus the trace of which rules fired. No I/O, no model, no
//! randomness: given the same counts it always returns the same label, and
//! the trace makes the label auditable rather than something the analyst has
//! to take on trust.
//!
//! **The label is not a probability.** It names which rules fired. The only
//! number that may legitimately be attached to it is the per-label precision
//! the eval suite measures over the fixture corpus, and that number belongs
//! next to the label wherever it is displayed — never a percentage invented
//! here or by a model.
//!
//! The ceiling rule matters as much as the ordering: when stage D could not
//! run (inference down, or every answer dropped for an unverifiable
//! citation), the label is capped at `ReferencesUnclear`. Deterministic
//! evidence alone can establish that a symbol is *referenced*; it cannot
//! establish that the reference is a real use, and claiming the top label
//! without the model's input would overstate what was actually checked.

use crate::models::PriorityLabel;

/// Everything the rubric is allowed to look at.
#[derive(Debug, Clone, Default)]
pub struct RubricInput {
    /// Stage A. `None` = could not be determined (no package name given).
    pub package_present: Option<bool>,
    /// Did stage B produce a ruleset with at least one term to search?
    pub ruleset_available: bool,
    /// Did an actual repository get fetched and indexed?
    pub repo_analysed: bool,
    /// Terms stage C searched for.
    pub terms_searched: usize,
    /// Occurrences stage C found (uncapped).
    pub occurrences_found: usize,
    /// Stage D outcomes.
    pub relevant: usize,
    pub unclear: usize,
    pub irrelevant: usize,
    /// Occurrences stage D actually managed to label.
    pub scored: usize,
}

/// The rubric. Returns the label and the ordered trace of rules that fired.
pub fn evaluate(input: &RubricInput) -> (PriorityLabel, Vec<String>) {
    let mut trace: Vec<String> = Vec::new();

    if !input.repo_analysed {
        trace.push(
            "R0: no repository was analysed (advisory extraction only) — no reachability \
             evidence either way."
                .to_string(),
        );
        return (PriorityLabel::Inconclusive, trace);
    }

    if input.package_present == Some(false) {
        trace.push(
            "R1: stage A found no lexical trace of the affected package in the scanned revision."
                .to_string(),
        );
        return (PriorityLabel::NoPackageEvidence, trace);
    }
    if input.package_present == Some(true) {
        trace.push("R2: stage A found the affected package in the scanned revision.".to_string());
    } else {
        trace.push(
            "R2': package presence could not be determined (no package name supplied); \
             the symbol search ran over the whole revision anyway."
                .to_string(),
        );
    }

    if !input.ruleset_available || input.terms_searched == 0 {
        trace.push(
            "R3: no searchable symbols were available (the advisory names none, or extraction \
             failed), so no symbol-level search could run."
                .to_string(),
        );
        return (PriorityLabel::PackagePresentOnly, trace);
    }
    trace.push(format!("R4: searched {} term(s) from the ruleset.", input.terms_searched));

    if input.occurrences_found == 0 {
        trace.push(
            "R5: no occurrence of any searched term appears in the scanned revision.".to_string(),
        );
        return (PriorityLabel::PackagePresentOnly, trace);
    }
    trace.push(format!("R6: found {} occurrence(s) of searched terms.", input.occurrences_found));

    // Ceiling: without stage D, "referenced" is as far as the evidence goes.
    if input.scored == 0 {
        trace.push(
            "R7: no occurrence could be classified (inference unavailable, or every answer was \
             dropped for an unverifiable citation) — capped at 'unclear'; the occurrences \
             themselves are still listed."
                .to_string(),
        );
        return (PriorityLabel::ReferencesUnclear, trace);
    }

    if input.relevant > 0 {
        trace.push(format!(
            "R8: {} occurrence(s) were labelled a real reference to a symbol the advisory names.",
            input.relevant
        ));
        return (PriorityLabel::DirectReferences, trace);
    }
    if input.unclear > 0 {
        trace.push(format!(
            "R9: {} occurrence(s) could not be classified from their surrounding code.",
            input.unclear
        ));
        return (PriorityLabel::ReferencesUnclear, trace);
    }

    trace.push(format!(
        "R10: all {} classified occurrence(s) were labelled likely false matches; the \
         occurrences remain listed for review.",
        input.irrelevant
    ));
    (PriorityLabel::ReferencesLikelyIrrelevant, trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-successful run with one relevant hit — the base every test
    /// below mutates one field of.
    fn full_run() -> RubricInput {
        RubricInput {
            package_present: Some(true),
            ruleset_available: true,
            repo_analysed: true,
            terms_searched: 2,
            occurrences_found: 3,
            relevant: 1,
            unclear: 1,
            irrelevant: 1,
            scored: 3,
        }
    }

    #[test]
    fn advisory_only_runs_are_inconclusive_not_negative() {
        // Extraction without a repository says nothing about reachability;
        // reporting "no evidence of use" here would be a fabricated finding.
        let (label, trace) =
            evaluate(&RubricInput { repo_analysed: false, ..Default::default() });
        assert_eq!(label, PriorityLabel::Inconclusive);
        assert!(trace[0].starts_with("R0"));
    }

    #[test]
    fn an_absent_package_short_circuits() {
        let input = RubricInput {
            package_present: Some(false),
            repo_analysed: true,
            ..Default::default()
        };
        let (label, trace) = evaluate(&input);
        assert_eq!(label, PriorityLabel::NoPackageEvidence);
        assert_eq!(trace.len(), 1, "later rules must not run once R1 fires");
    }

    #[test]
    fn a_present_package_with_no_extractable_symbols_stops_at_package_present() {
        let input = RubricInput {
            ruleset_available: false,
            terms_searched: 0,
            occurrences_found: 0,
            relevant: 0,
            unclear: 0,
            irrelevant: 0,
            scored: 0,
            ..full_run()
        };
        assert_eq!(evaluate(&input).0, PriorityLabel::PackagePresentOnly);
    }

    #[test]
    fn a_present_package_whose_symbols_appear_nowhere_stops_at_package_present() {
        let input = RubricInput {
            occurrences_found: 0,
            relevant: 0,
            unclear: 0,
            irrelevant: 0,
            scored: 0,
            ..full_run()
        };
        let (label, trace) = evaluate(&input);
        assert_eq!(label, PriorityLabel::PackagePresentOnly);
        assert!(trace.iter().any(|t| t.starts_with("R5")));
    }

    #[test]
    fn one_relevant_label_outweighs_any_number_of_others() {
        let input = RubricInput { relevant: 1, unclear: 40, irrelevant: 40, scored: 81, ..full_run() };
        assert_eq!(evaluate(&input).0, PriorityLabel::DirectReferences);
    }

    #[test]
    fn unclear_outranks_irrelevant() {
        let input = RubricInput { relevant: 0, unclear: 1, irrelevant: 9, scored: 10, ..full_run() };
        assert_eq!(evaluate(&input).0, PriorityLabel::ReferencesUnclear);
    }

    #[test]
    fn all_irrelevant_is_its_own_label_and_still_lists_the_occurrences() {
        let input = RubricInput { relevant: 0, unclear: 0, irrelevant: 3, scored: 3, ..full_run() };
        let (label, trace) = evaluate(&input);
        assert_eq!(label, PriorityLabel::ReferencesLikelyIrrelevant);
        assert!(trace.last().unwrap().contains("remain listed"));
    }

    #[test]
    fn inference_failure_caps_the_label_at_unclear() {
        // The degradation contract: with the model down, deterministic
        // evidence can say "referenced", never "real reference".
        let input = RubricInput { relevant: 0, unclear: 0, irrelevant: 0, scored: 0, ..full_run() };
        let (label, trace) = evaluate(&input);
        assert_eq!(label, PriorityLabel::ReferencesUnclear);
        assert!(trace.iter().any(|t| t.starts_with("R7")));
    }

    #[test]
    fn unknown_presence_does_not_block_the_symbol_search() {
        // No package name supplied: presence is unknown, but occurrences are
        // still real evidence and must still be reported.
        let input = RubricInput { package_present: None, ..full_run() };
        let (label, trace) = evaluate(&input);
        assert_eq!(label, PriorityLabel::DirectReferences);
        assert!(trace.iter().any(|t| t.starts_with("R2'")));
    }

    #[test]
    fn the_trace_always_explains_the_label() {
        // Every path must leave the analyst something to read; an
        // unexplained label is exactly the "trust me" output this project
        // rules out.
        for input in [
            RubricInput { repo_analysed: false, ..Default::default() },
            RubricInput { package_present: Some(false), repo_analysed: true, ..Default::default() },
            full_run(),
            RubricInput { scored: 0, relevant: 0, unclear: 0, irrelevant: 0, ..full_run() },
        ] {
            let (_, trace) = evaluate(&input);
            assert!(!trace.is_empty());
        }
    }

    #[test]
    fn evaluation_is_deterministic() {
        let input = full_run();
        let first = evaluate(&input);
        for _ in 0..20 {
            assert_eq!(evaluate(&input), first);
        }
    }
}
