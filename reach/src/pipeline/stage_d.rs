//! Stage D — label one occurrence (LLM #2), and check that it cited a real
//! line.
//!
//! One inference call per occurrence, capped by `REACH_MAX_SCORED_SITES`.
//! Per-site rather than one batched call: a 4-8B model asked to label five
//! snippets in a single response drifts between them and drops citations,
//! and a per-site call means one bad answer degrades one site instead of the
//! whole batch.
//!
//! # Citation verification
//!
//! The model must cite a line number from the snippet it was shown. That
//! citation is then checked against the file on disk: the line must exist,
//! and it must be inside the range that was actually shown. A claim whose
//! citation cannot be resolved is **dropped, not displayed** — an assertion
//! about code that points nowhere is exactly the failure mode that makes
//! LLM-assisted security tooling untrustworthy. Drops are counted into
//! [`crate::models::Counters::dropped_uncited_claims`] so the rate is
//! visible in every report rather than buried.
//!
//! # Citation collisions
//!
//! The reported line for a scored occurrence is whatever line the model
//! *cited*, not necessarily the line it was originally handed — citation
//! verification only requires the cite to fall inside the snippet shown,
//! which since stage C started widening snippets to real function
//! boundaries can span far more than the one matched line. Two different
//! occurrences of the same term in the same function (a definition and a
//! call, say) are scored independently, and can both legitimately cite the
//! *same* line if the model decides that is the one that actually matters —
//! observed live: an occurrence at a `defun` line and one at the call two
//! lines later both correctly cited the call site. [`score_sites`] collapses
//! these after scoring rather than reporting the same location twice with
//! two independently-worded opinions.

use std::path::Path;

use serde::Deserialize;

use crate::ai::{prompts, AiError, ChatClient};
use crate::lexer::Context;
use crate::models::{EvidenceSite, RelevanceLabel, Ruleset};
use crate::pipeline::stage_c::RawSite;

/// What the model is asked to return per occurrence.
#[derive(Debug, Deserialize)]
struct SiteVerdict {
    label: String,
    /// A line number from the snippet.
    #[serde(default)]
    cited_line: Option<u32>,
    #[serde(default)]
    reasoning: String,
}

#[derive(Debug, Default)]
pub struct ScoringOutcome {
    pub sites: Vec<EvidenceSite>,
    pub relevant: usize,
    pub unclear: usize,
    pub irrelevant: usize,
    /// Answers thrown away because their citation could not be verified.
    pub dropped_uncited: usize,
    /// Answers thrown away for a different reason — a label outside the three
    /// the prompt defines. Counted apart from `dropped_uncited` so the stage
    /// detail names the real cause: that counter is the report's headline
    /// citation-trustworthiness signal and must mean only what it says.
    pub dropped_invalid: usize,
    /// Calls that failed after their single retry.
    pub inference_failures: usize,
    /// Inference attempts made (including repair retries).
    pub calls: usize,
    /// Answers that needed the repair retry.
    pub repairs: usize,
    /// The first inference error seen, for the stage's detail line.
    pub first_error: Option<String>,
    pub total_latency_ms: u64,
    /// Two independently-scored occurrences whose model-cited line converged
    /// on the same final `(path, line, term)` — collapsed to one, keeping
    /// the strongest label. See the module docs on why this happens.
    pub collapsed_duplicates: usize,
}

impl ScoringOutcome {
    pub fn scored(&self) -> usize {
        self.relevant + self.unclear + self.irrelevant
    }
}

/// Labels up to `max_scored` occurrences; the rest are carried into the
/// report unlabelled, because a deterministic hit is evidence on its own.
pub async fn score_sites(
    client: &ChatClient,
    ruleset: &Ruleset,
    raw_sites: &[RawSite],
    scan_root: &Path,
    max_scored: usize,
    job_id: uuid::Uuid,
) -> ScoringOutcome {
    let mut out = ScoringOutcome::default();
    let total_to_score = raw_sites.len().min(max_scored);

    for (i, site) in raw_sites.iter().enumerate() {
        if i >= max_scored {
            out.sites.push(unlabelled(site));
            continue;
        }

        tracing::info!(
            id = %job_id, site = i + 1, of = total_to_score,
            path = %site.path, line = site.line, term = %site.term,
            "stage D: scoring one occurrence"
        );
        let messages =
            prompts::site_messages(ruleset, &site.term, &site.path, site.line, &site.snippet);
        let (result, stats) = client.complete_json::<SiteVerdict>(&messages).await;
        out.total_latency_ms += stats.latency_ms;
        out.calls += stats.attempts as usize;
        if stats.repaired {
            out.repairs += 1;
        }

        let verdict = match result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(path = %site.path, line = site.line, error = %e, "site scoring failed");
                out.inference_failures += 1;
                out.first_error.get_or_insert_with(|| format!("{}: {e}", e.kind()));
                out.sites.push(unlabelled(site));
                // An outage will not fix itself between two sequential calls;
                // stop spending the timeout budget on the remaining sites and
                // let the rubric's ceiling rule do its job.
                if is_outage(&e) {
                    for rest in &raw_sites[i + 1..] {
                        out.sites.push(unlabelled(rest));
                    }
                    break;
                }
                continue;
            }
        };

        let Some(label) = RelevanceLabel::parse(&verdict.label) else {
            // A label outside the three we defined is unusable; treating it
            // as `unclear` would silently launder an invalid answer.
            tracing::warn!(label = %verdict.label, "model returned an unknown label; dropping");
            out.dropped_invalid += 1;
            out.sites.push(unlabelled(site));
            continue;
        };

        let cited = verdict.cited_line.unwrap_or(site.line);
        let verified = verify_citation(scan_root, &site.path, cited, site);
        if !verified {
            tracing::warn!(
                path = %site.path,
                cited,
                "model cited a line outside the snippet it was shown; dropping the claim"
            );
            out.dropped_uncited += 1;
            out.sites.push(unlabelled(site));
            continue;
        }

        tracing::info!(
            id = %job_id, path = %site.path, line = cited, label = ?label,
            "stage D: occurrence scored"
        );
        match label {
            RelevanceLabel::LikelyRelevant => out.relevant += 1,
            RelevanceLabel::Unclear => out.unclear += 1,
            RelevanceLabel::LikelyIrrelevant => out.irrelevant += 1,
        }
        out.sites.push(EvidenceSite {
            path: site.path.clone(),
            line: cited,
            term: site.term.clone(),
            snippet: site.snippet.clone(),
            label: Some(label),
            reasoning: crate::ai::truncate(verdict.reasoning.trim(), 600),
            citation_verified: true,
        });
    }

    collapse_citation_collisions(&mut out);
    out
}

/// Collapses labelled sites that converged on the same `(path, line, term)`
/// after citation reassignment — see the module docs on why two
/// independently-scored occurrences can legitimately end up there. Keeps
/// the strongest label (`likely_relevant` > `unclear` > `likely_irrelevant`)
/// among the colliding entries, breaking any further tie by keeping
/// whichever was scored first, so the result is deterministic. Unlabelled
/// sites are untouched: their line comes straight from the deterministic
/// index, so they cannot collide this way, and leaving them alone keeps
/// every original occurrence visible in the report.
///
/// `relevant`/`unclear`/`irrelevant` are recomputed from the surviving set
/// afterwards rather than patched incrementally — simpler to get right than
/// threading a running adjustment through a replace-or-keep decision, and
/// it can't drift out of sync with what is actually in `sites`.
fn collapse_citation_collisions(out: &mut ScoringOutcome) {
    fn label_strength(label: RelevanceLabel) -> u8 {
        match label {
            RelevanceLabel::LikelyRelevant => 2,
            RelevanceLabel::Unclear => 1,
            RelevanceLabel::LikelyIrrelevant => 0,
        }
    }

    let mut kept: Vec<EvidenceSite> = Vec::with_capacity(out.sites.len());
    for site in std::mem::take(&mut out.sites) {
        let Some(label) = site.label else {
            kept.push(site);
            continue;
        };
        let existing = kept
            .iter_mut()
            .find(|k| k.label.is_some() && k.path == site.path && k.line == site.line && k.term == site.term);
        match existing {
            None => kept.push(site),
            Some(existing) => {
                out.collapsed_duplicates += 1;
                let existing_label = existing.label.expect("checked above");
                if label_strength(label) > label_strength(existing_label) {
                    *existing = site;
                }
            }
        }
    }

    out.relevant = kept.iter().filter(|s| s.label == Some(RelevanceLabel::LikelyRelevant)).count();
    out.unclear = kept.iter().filter(|s| s.label == Some(RelevanceLabel::Unclear)).count();
    out.irrelevant = kept.iter().filter(|s| s.label == Some(RelevanceLabel::LikelyIrrelevant)).count();
    out.sites = kept;
}

/// A transport-level failure, as opposed to the model producing something
/// unusable. Only the former means "stop trying".
fn is_outage(e: &AiError) -> bool {
    matches!(e, AiError::Unavailable { .. } | AiError::Timeout(_) | AiError::Upstream { .. })
}

/// An occurrence reported without a model label. Note `citation_verified` is
/// still true: the location came from the deterministic index, which is the
/// most reliable source of a `file:line` in this whole pipeline.
fn unlabelled(site: &RawSite) -> EvidenceSite {
    EvidenceSite {
        path: site.path.clone(),
        line: site.line,
        term: site.term.clone(),
        snippet: site.snippet.clone(),
        label: None,
        reasoning: match site.context {
            Context::Comment => "Found in a comment (not classified).".to_string(),
            Context::StringLiteral => "Found in a string literal (not classified).".to_string(),
            Context::Code => "Found in code (not classified).".to_string(),
        },
        citation_verified: true,
    }
}

/// Confirms a cited line is real.
///
/// Two conditions, both necessary. The line must exist in the file as
/// checked out — that catches a fabricated location. And it must fall within
/// the window the model was actually shown — that catches the subtler case
/// of a real line the model never saw, which it cannot have had grounds to
/// reason about.
pub fn verify_citation(scan_root: &Path, path: &str, cited_line: u32, site: &RawSite) -> bool {
    if cited_line == 0 {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(scan_root.join(path)) else { return false };
    let total = text.lines().count() as u32;
    if cited_line > total {
        return false;
    }
    snippet_line_numbers(&site.snippet).contains(&cited_line)
}

/// The real file line numbers a snippet displayed. Parsed back out of the
/// rendered snippet rather than recomputed, so verification checks what the
/// model was *shown*, not what we believe we showed it.
fn snippet_line_numbers(snippet: &str) -> Vec<u32> {
    snippet
        .lines()
        .filter_map(|l| l.split('|').next()?.trim().parse::<u32>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site_with(path: &str, line: u32, snippet: &str) -> RawSite {
        RawSite {
            path: path.to_string(),
            line,
            term: "lookup".to_string(),
            context: Context::Code,
            snippet: snippet.to_string(),
            rank: 100,
        }
    }

    #[test]
    fn snippet_line_numbers_are_recovered_from_the_rendered_text() {
        let snippet = "    3 | a\n    4 | lookup()\n    5 | b";
        assert_eq!(snippet_line_numbers(snippet), vec![3, 4, 5]);
    }

    #[test]
    fn a_citation_inside_the_shown_window_verifies() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "1\n2\nlookup()\n4\n5\n").unwrap();
        let site = site_with("a.js", 3, "    2 | 2\n    3 | lookup()\n    4 | 4");
        assert!(verify_citation(dir.path(), "a.js", 3, &site));
        assert!(verify_citation(dir.path(), "a.js", 2, &site));
    }

    #[test]
    fn a_line_beyond_the_end_of_the_file_is_rejected() {
        // The plain fabrication case.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "1\n2\n").unwrap();
        let site = site_with("a.js", 1, "    1 | 1\n    2 | 2");
        assert!(!verify_citation(dir.path(), "a.js", 999, &site));
    }

    #[test]
    fn a_real_line_the_model_was_never_shown_is_rejected() {
        // Subtler than fabrication and just as wrong: the model cannot have
        // had grounds to reason about a line outside its context window.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n").unwrap();
        let site = site_with("a.js", 3, "    2 | 2\n    3 | 3\n    4 | 4");
        assert!(!verify_citation(dir.path(), "a.js", 9, &site));
    }

    #[test]
    fn a_zero_or_missing_file_citation_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let site = site_with("gone.js", 1, "    1 | x");
        assert!(!verify_citation(dir.path(), "gone.js", 1, &site));
        std::fs::write(dir.path().join("a.js"), "x\n").unwrap();
        let site = site_with("a.js", 1, "    1 | x");
        assert!(!verify_citation(dir.path(), "a.js", 0, &site));
    }

    #[test]
    fn an_unlabelled_site_still_carries_a_trustworthy_location() {
        // When inference is down the occurrence is still evidence; its
        // location came from the deterministic index, so it is marked
        // verified even though no model looked at it.
        let s = unlabelled(&site_with("a.js", 7, "    7 | lookup()"));
        assert_eq!(s.label, None);
        assert!(s.citation_verified);
        assert_eq!(s.line, 7);
        assert!(s.reasoning.contains("not classified"));
    }

    #[test]
    fn unlabelled_reasoning_records_the_lexical_context() {
        let mut site = site_with("a.js", 1, "    1 | // lookup");
        site.context = Context::Comment;
        assert!(unlabelled(&site).reasoning.contains("comment"));
    }

    #[test]
    fn outage_errors_are_distinguished_from_bad_model_output() {
        // Only the former justifies abandoning the remaining sites.
        assert!(is_outage(&AiError::Timeout(std::time::Duration::from_secs(1))));
        assert!(is_outage(&AiError::Upstream { status: 503, body: String::new() }));
        assert!(!is_outage(&AiError::InvalidOutput("bad json".into())));
        assert!(!is_outage(&AiError::EmptyResponse));
    }

    // -------------------------------------------- citation collision dedup

    mod collision_tests {
        use super::*;
        use crate::config::AiConfig;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn client_for(base_url: &str) -> ChatClient {
            ChatClient::new(AiConfig {
                base_url: base_url.to_string(),
                model: "m".to_string(),
                api_key: None,
                timeout: std::time::Duration::from_secs(10),
                max_tokens: 512,
                temperature: 0.0,
            })
        }

        /// Reproduces the exact scenario observed live against `lispr`: a
        /// `defun test` at line 10 and a `(test 5)` call at line 11, both
        /// inside one widened function-boundary snippet spanning lines
        /// 8-18, scored independently. Both mocked responses cite line 11
        /// -- the model deciding, correctly, that the call site is what
        /// actually matters -- which is legitimate for citation
        /// verification (11 is inside the shown window either way) but
        /// must not produce two report entries for the same location.
        fn wide_snippet() -> String {
            (8..=18)
                .map(|n| format!("{n:>5} | line {n}"))
                .collect::<Vec<_>>()
                .join("\n")
        }

        async fn respond_citing_11(server: &MockServer, distinguishing_text: &str, label: &str) {
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(body_string_contains(distinguishing_text))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": format!(
                        "{{\"label\": \"{label}\", \"cited_line\": 11, \"reasoning\": \"matches the advisory\"}}"
                    )}}]
                })))
                .mount(server)
                .await;
        }

        #[tokio::test]
        async fn two_independent_occurrences_citing_the_same_line_are_collapsed_to_one() {
            let server = MockServer::start().await;
            // `site_messages` embeds "at line {N}" verbatim, distinguishing
            // the two calls so each gets routed to its own mocked answer.
            respond_citing_11(&server, "at line 10", "likely_relevant").await;
            respond_citing_11(&server, "at line 11", "likely_relevant").await;

            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/main.rs"), (1..=20).map(|n| format!("line {n}")).collect::<Vec<_>>().join("\n")).unwrap();

            let sites = vec![
                site_with("src/main.rs", 10, &wide_snippet()),
                site_with("src/main.rs", 11, &wide_snippet()),
            ];
            let out = score_sites(&client_for(&server.uri()), &Ruleset::default(), &sites, dir.path(), 5, uuid::Uuid::nil()).await;

            assert_eq!(out.sites.len(), 1, "two occurrences collapsed to the one location they agreed on");
            assert_eq!(out.sites[0].line, 11);
            assert_eq!(out.collapsed_duplicates, 1);
            assert_eq!(out.relevant, 1, "must not double-count the collapsed pair as two relevant hits");
            assert_eq!(out.scored(), 1);
        }

        #[tokio::test]
        async fn the_stronger_label_survives_a_collision() {
            let server = MockServer::start().await;
            respond_citing_11(&server, "at line 10", "unclear").await;
            respond_citing_11(&server, "at line 11", "likely_relevant").await;

            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/main.rs"), (1..=20).map(|n| format!("line {n}")).collect::<Vec<_>>().join("\n")).unwrap();

            let sites = vec![
                site_with("src/main.rs", 10, &wide_snippet()),
                site_with("src/main.rs", 11, &wide_snippet()),
            ];
            let out = score_sites(&client_for(&server.uri()), &Ruleset::default(), &sites, dir.path(), 5, uuid::Uuid::nil()).await;

            assert_eq!(out.sites.len(), 1);
            assert_eq!(out.sites[0].label, Some(RelevanceLabel::LikelyRelevant));
            assert_eq!(out.relevant, 1);
            assert_eq!(out.unclear, 0, "the weaker label must not linger in the counts once collapsed");
        }

        #[tokio::test]
        async fn distinct_final_citations_are_never_collapsed() {
            // The sanity check against over-eager merging: two occurrences
            // that genuinely cite different lines must both survive.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(body_string_contains("at line 10"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": "{\"label\": \"likely_relevant\", \"cited_line\": 10, \"reasoning\": \"x\"}"}}]
                })))
                .mount(&server)
                .await;
            respond_citing_11(&server, "at line 11", "likely_relevant").await;

            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/main.rs"), (1..=20).map(|n| format!("line {n}")).collect::<Vec<_>>().join("\n")).unwrap();

            let sites = vec![
                site_with("src/main.rs", 10, &wide_snippet()),
                site_with("src/main.rs", 11, &wide_snippet()),
            ];
            let out = score_sites(&client_for(&server.uri()), &Ruleset::default(), &sites, dir.path(), 5, uuid::Uuid::nil()).await;

            assert_eq!(out.sites.len(), 2);
            assert_eq!(out.collapsed_duplicates, 0);
            assert_eq!(out.relevant, 2);
        }

        #[tokio::test]
        async fn an_invented_label_is_counted_apart_from_a_citation_failure() {
            // `dropped_uncited` is the report's headline signal for "the model
            // pointed at a line it could not have known about". A label
            // outside the three defined ones is a different defect, and
            // folding it in here would make the stage detail tell an analyst
            // their citations were unverifiable when they were never checked.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content":
                        "{\"label\": \"definitely_exploitable\", \"cited_line\": 11, \"reasoning\": \"x\"}"
                    }}]
                })))
                .mount(&server)
                .await;

            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(
                dir.path().join("src/main.rs"),
                (1..=20).map(|n| format!("line {n}")).collect::<Vec<_>>().join("\n"),
            )
            .unwrap();

            let out = score_sites(
                &client_for(&server.uri()),
                &Ruleset::default(),
                &[site_with("src/main.rs", 11, &wide_snippet())],
                dir.path(),
                5,
                uuid::Uuid::nil(),
            )
            .await;

            assert_eq!(out.dropped_invalid, 1);
            assert_eq!(out.dropped_uncited, 0, "an invented label is not a citation failure");
            // The occurrence itself survives, unlabelled — it is still a real
            // deterministic hit.
            assert_eq!(out.sites.len(), 1);
            assert_eq!(out.sites[0].label, None);
            assert_eq!(out.scored(), 0);
        }

        #[tokio::test]
        async fn a_collision_between_different_terms_on_the_same_line_is_not_collapsed() {
            // `(print (test 5))`: both `print` and `test` legitimately cite
            // the same physical line -- that is two distinct pieces of
            // evidence (different advisory symbols), not a duplicate, and
            // must both be kept.
            let server = MockServer::start().await;
            respond_citing_11(&server, "`print`", "likely_relevant").await;
            respond_citing_11(&server, "`test`", "likely_relevant").await;

            let mut print_site = site_with("src/main.rs", 11, &wide_snippet());
            print_site.term = "print".to_string();
            let mut test_site = site_with("src/main.rs", 11, &wide_snippet());
            test_site.term = "test".to_string();

            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("src")).unwrap();
            std::fs::write(dir.path().join("src/main.rs"), (1..=20).map(|n| format!("line {n}")).collect::<Vec<_>>().join("\n")).unwrap();

            let out = score_sites(
                &client_for(&server.uri()),
                &Ruleset::default(),
                &[print_site, test_site],
                dir.path(),
                5,
                uuid::Uuid::nil(),
            )
            .await;

            assert_eq!(out.sites.len(), 2);
            assert_eq!(out.collapsed_duplicates, 0);
        }
    }
}
