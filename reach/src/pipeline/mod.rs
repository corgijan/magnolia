//! The pipeline: stage A -> B -> C -> D -> E.
//!
//! # Degradation contract
//!
//! Every stage either produces its output or records a
//! [`StageOutcome`] and lets the next stage proceed with less. The only
//! thing that ends an analysis without a report is being unable to obtain
//! the source that was asked for — the caller asked about *their* code, and
//! answering about nothing would be worse than saying "I could not fetch
//! it". Everything else degrades:
//!
//! | What broke | What the analyst still gets |
//! |---|---|
//! | Inference server down/timing out | Deterministic occurrences, unlabelled, capped at `references_unclear` |
//! | Model returns unparseable JSON twice | Same as above, with the failure named in the stage record |
//! | Advisory names no symbols | Package-presence evidence, `package_present_only` |
//! | Model cites a line it was not shown | That claim dropped and counted; the others stand |
//! | Repository larger than the cap | Truncation stated in the report, partial index used |
//!
//! No path returns a 500 to the caller because of a model.

pub mod baseline;
pub mod rubric;
pub mod stage_a;
pub mod stage_b;
pub mod stage_c;
pub mod stage_d;
pub mod test_mode;

pub use stage_d::verify_citation;

use std::sync::Arc;
use std::time::Instant;

use crate::ai::ChatClient;
use crate::config::Limits;
use crate::fetcher::{resolve_subpath, Checkout, FetchError, RepoFetcher, RepoTarget};
use crate::lexer::IdentifierIndex;
use crate::models::{
    Counters, Report, Ruleset, StageOutcome, StageStatus, EVIDENCE_DISCLAIMER,
    REPORT_SCHEMA_VERSION,
};

/// One unit of work, as stored.
#[derive(Debug, Clone)]
pub struct AnalysisJob {
    pub id: uuid::Uuid,
    pub advisory_text: String,
    pub osv_id: Option<String>,
    pub package_name: Option<String>,
    pub ecosystem: Option<String>,
    pub repo_url: Option<String>,
    pub commit: Option<String>,
    pub subpath: Option<String>,
}

/// Collaborators the pipeline needs. Fetchers are trait objects so the eval
/// suite can drive the whole pipeline against fixture repositories with no
/// network.
pub struct PipelineDeps {
    pub client: ChatClient,
    pub git: Arc<dyn RepoFetcher>,
    pub local: Arc<dyn RepoFetcher>,
    pub limits: Limits,
    /// `REACH_TEST_MODE`: return [`test_mode::canned_report`] instead of
    /// running anything.
    pub test_mode: bool,
}

/// Runs the pipeline. `Err` only for "could not obtain the requested
/// source"; every other failure is inside the returned report.
pub async fn run(deps: &PipelineDeps, job: &AnalysisJob) -> Result<Report, FetchError> {
    if deps.test_mode {
        // Short pause so the caller's queued -> running -> completed polling
        // path is exercised, not skipped.
        tokio::time::sleep(test_mode::DELAY).await;
        tracing::warn!(id = %job.id, "REACH_TEST_MODE: returning a canned report, nothing analysed");
        return Ok(test_mode::canned_report(job));
    }

    let mut stages: Vec<StageOutcome> = Vec::new();
    let mut counters = Counters::default();

    // ---- fetch + stage A ---------------------------------------------
    let started = Instant::now();
    let checkout = match &job.repo_url {
        Some(url) => {
            let commit = job.commit.as_deref().ok_or_else(|| {
                // Never analyse a moving ref: evidence that cannot be
                // reproduced later is not evidence.
                FetchError::InvalidCommit(
                    "no commit supplied; a repository analysis needs an exact revision".to_string(),
                )
            })?;
            Some(fetch(deps, url, commit, job.subpath.as_deref()).await?)
        }
        None => None,
    };

    let mut index: Option<IdentifierIndex> = None;
    let mut presence = stage_a::PresenceResult::default();

    match &checkout {
        None => {
            let outcome = StageOutcome::new(
                "A",
                "package presence",
                StageStatus::Skipped,
                "No repository was supplied — this is an advisory-extraction-only analysis.",
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &outcome);
            stages.push(outcome);
        }
        Some(co) => {
            tracing::info!(id = %job.id, "stage A: indexing checkout and checking package presence");
            let idx = IdentifierIndex::build(
                &co.scan_root,
                deps.limits.max_file_kb,
                deps.limits.max_repo_mb,
            );
            counters.files_indexed = idx.files.len();
            counters.identifiers_indexed = idx.identifier_count();

            presence = stage_a::check_presence(
                &idx,
                &co.scan_root,
                job.package_name.as_deref(),
                deps.limits.max_file_kb,
            );

            let mut detail = format!(
                "Indexed {} file(s), {} distinct identifier(s).",
                idx.files.len(),
                idx.identifier_count()
            );
            if idx.skipped_large > 0 {
                detail.push_str(&format!(" {} file(s) skipped as oversized.", idx.skipped_large));
            }
            let status = if idx.truncated {
                detail.push_str(
                    " Indexing stopped at the repository size cap — the scan is incomplete, so \
                     an absence of occurrences below is not conclusive.",
                );
                StageStatus::Degraded
            } else {
                StageStatus::Ok
            };
            let outcome = StageOutcome::new(
                "A",
                "package presence",
                status,
                detail,
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &outcome);
            stages.push(outcome);
            index = Some(idx);
        }
    }

    // The plan's short circuit: no trace of the package means no LLM call.
    if presence.present == Some(false) {
        tracing::info!(id = %job.id, "stages B/C/D skipped: stage A found no trace of the package");
        for (stage, name) in [("B", "advisory ruleset"), ("C", "occurrence search"), ("D", "occurrence scoring")] {
            let outcome = StageOutcome::new(
                stage,
                name,
                StageStatus::Skipped,
                "Stage A found no trace of the affected package, so this stage would have \
                 nothing to work on.",
                0,
            );
            log_stage(job.id, &outcome);
            stages.push(outcome);
        }
        return Ok(finish(
            job,
            None,
            presence,
            Vec::new(),
            stages,
            counters,
            &rubric::RubricInput {
                package_present: Some(false),
                repo_analysed: true,
                ..Default::default()
            },
        ));
    }

    // ---- stage B ------------------------------------------------------
    let started = Instant::now();
    tracing::info!(id = %job.id, "stage B: extracting a search ruleset from the advisory via LLM");
    let mut ruleset: Option<Ruleset> = None;
    match stage_b::extract_ruleset(
        &deps.client,
        &job.advisory_text,
        job.osv_id.as_deref(),
        job.package_name.as_deref(),
        job.ecosystem.as_deref(),
        deps.limits.max_advisory_chars,
    )
    .await
    {
        Ok(outcome) => {
            counters.inference_calls += outcome.stats.attempts as usize;
            if outcome.stats.repaired {
                counters.inference_repairs += 1;
            }
            let mut detail = format!(
                "Extracted {} symbol(s) and {} pattern(s) in {} attempt(s).",
                outcome.ruleset.vulnerable_symbols.len(),
                outcome.ruleset.search_patterns.len(),
                outcome.stats.attempts
            );
            let mut status = if outcome.stats.repaired { StageStatus::Degraded } else { StageStatus::Ok };
            if outcome.ungrounded_dropped > 0 {
                detail.push_str(&format!(
                    " Dropped {} extracted term(s) that do not appear in the advisory text.",
                    outcome.ungrounded_dropped
                ));
                counters.dropped_uncited_claims += outcome.ungrounded_dropped;
                status = StageStatus::Degraded;
            }
            if outcome.noise_dropped > 0 {
                detail.push_str(&format!(
                    " Dropped {} term(s) as too generic to search for.",
                    outcome.noise_dropped
                ));
            }
            let stage_outcome = StageOutcome::new(
                "B",
                "advisory ruleset",
                status,
                detail,
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &stage_outcome);
            stages.push(stage_outcome);
            ruleset = Some(outcome.ruleset);
        }
        Err(e) => {
            counters.inference_calls += 1;
            counters.inference_failures += 1;
            let stage_outcome = StageOutcome::new(
                "B",
                "advisory ruleset",
                StageStatus::Failed,
                format!(
                    "Inference failed ({}): {e}. No symbol list could be extracted, so no \
                     symbol-level search ran; any package-presence evidence above still stands.",
                    e.kind()
                ),
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &stage_outcome);
            stages.push(stage_outcome);
        }
    }

    let searchable = ruleset.as_ref().map(stage_b::is_searchable).unwrap_or(false);
    let terms = ruleset.as_ref().map(Ruleset::search_terms).unwrap_or_default();
    let nested_calls = ruleset.as_ref().map(|r| r.nested_calls.clone()).unwrap_or_default();

    // ---- stage C ------------------------------------------------------
    let started = Instant::now();
    tracing::info!(
        id = %job.id, terms = terms.len(), nested_calls = nested_calls.len(),
        "stage C: searching the checkout for ruleset terms"
    );
    let (raw_sites, occurrences_found) = match (&index, &checkout, searchable) {
        (Some(idx), Some(co), true) => {
            let scan =
                stage_c::find_occurrences(idx, &co.scan_root, &terms, &nested_calls, deps.limits.max_sites);
            counters.occurrences_found = scan.total_found;
            counters.occurrences_reported = scan.sites.len();

            let mut detail = format!(
                "Searched {} term(s); found {} occurrence(s), reporting {}.",
                terms.len(),
                scan.total_found,
                scan.sites.len()
            );
            if !scan.terms_without_hits.is_empty() {
                detail.push_str(&format!(
                    " No occurrence of: {}.",
                    scan.terms_without_hits.join(", ")
                ));
            }
            let status = if scan.total_found > scan.sites.len() {
                detail.push_str(" The list was capped by REACH_MAX_SITES.");
                StageStatus::Degraded
            } else {
                StageStatus::Ok
            };
            let outcome = StageOutcome::new(
                "C",
                "occurrence search",
                status,
                detail,
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &outcome);
            stages.push(outcome);
            let total = scan.total_found;
            (scan.sites, total)
        }
        _ => {
            let outcome = StageOutcome::new(
                "C",
                "occurrence search",
                StageStatus::Skipped,
                if index.is_none() {
                    "No repository was supplied."
                } else {
                    "No searchable symbols were available from stage B."
                },
                started.elapsed().as_millis() as u64,
            );
            log_stage(job.id, &outcome);
            stages.push(outcome);
            (Vec::new(), 0)
        }
    };

    // ---- stage D ------------------------------------------------------
    let started = Instant::now();
    let mut scoring = stage_d::ScoringOutcome::default();
    if raw_sites.is_empty() {
        let outcome = StageOutcome::new(
            "D",
            "occurrence scoring",
            StageStatus::Skipped,
            "No occurrences to classify.",
            0,
        );
        log_stage(job.id, &outcome);
        stages.push(outcome);
    } else {
        let scored_count = raw_sites.len().min(deps.limits.max_scored_sites);
        tracing::info!(
            id = %job.id, occurrences = raw_sites.len(), to_score = scored_count,
            "stage D: scoring occurrences via LLM, one call per site"
        );
        let rs = ruleset.clone().unwrap_or_default();
        let scan_root = checkout.as_ref().map(|c| c.scan_root.clone()).unwrap_or_default();
        scoring = stage_d::score_sites(
            &deps.client,
            &rs,
            &raw_sites,
            &scan_root,
            deps.limits.max_scored_sites,
            job.id,
        )
        .await;

        counters.occurrences_scored = scoring.scored();
        counters.dropped_uncited_claims += scoring.dropped_uncited;
        counters.dropped_invalid_answers += scoring.dropped_invalid;
        counters.inference_failures += scoring.inference_failures;
        counters.inference_calls += scoring.calls;
        counters.inference_repairs += scoring.repairs;
        counters.collapsed_duplicate_citations += scoring.collapsed_duplicates;

        let mut detail = format!(
            "Classified {} of {} occurrence(s) ({} relevant, {} unclear, {} likely irrelevant).",
            scoring.scored(),
            raw_sites.len(),
            scoring.relevant,
            scoring.unclear,
            scoring.irrelevant
        );
        let status = if scoring.inference_failures > 0 {
            detail.push_str(&format!(
                " {} call(s) failed ({}). Unclassified occurrences are still listed below.",
                scoring.inference_failures,
                scoring.first_error.clone().unwrap_or_default()
            ));
            if scoring.scored() == 0 {
                StageStatus::Failed
            } else {
                StageStatus::Degraded
            }
        } else if scoring.dropped_uncited > 0 || scoring.dropped_invalid > 0 {
            if scoring.dropped_uncited > 0 {
                detail.push_str(&format!(
                    " {} answer(s) were dropped because their file:line citation could not be \
                     verified against the checkout.",
                    scoring.dropped_uncited
                ));
            }
            // Named separately from the citation failures above: conflating
            // the two would tell an analyst their citations were unverifiable
            // when the real problem was a label the model invented.
            if scoring.dropped_invalid > 0 {
                detail.push_str(&format!(
                    " {} answer(s) were dropped for returning a label outside the three defined \
                     ones.",
                    scoring.dropped_invalid
                ));
            }
            StageStatus::Degraded
        } else {
            StageStatus::Ok
        };
        if scoring.collapsed_duplicates > 0 {
            detail.push_str(&format!(
                " {} occurrence(s) converged on the same cited location as another and were \
                 collapsed into one entry.",
                scoring.collapsed_duplicates
            ));
        }
        let outcome = StageOutcome::new(
            "D",
            "occurrence scoring",
            status,
            detail,
            started.elapsed().as_millis() as u64,
        );
        log_stage(job.id, &outcome);
        stages.push(outcome);
    }

    // ---- stage E ------------------------------------------------------
    let rubric_input = rubric::RubricInput {
        package_present: presence.present,
        ruleset_available: searchable,
        repo_analysed: checkout.is_some(),
        terms_searched: terms.len(),
        occurrences_found,
        relevant: scoring.relevant,
        unclear: scoring.unclear,
        irrelevant: scoring.irrelevant,
        scored: scoring.scored(),
    };

    Ok(finish(job, ruleset, presence, scoring.sites, stages, counters, &rubric_input))
}

/// Runs the rubric and assembles the report. Kept separate so both the
/// short-circuit path and the full path produce an identically-shaped
/// result.
fn finish(
    job: &AnalysisJob,
    ruleset: Option<Ruleset>,
    presence: stage_a::PresenceResult,
    sites: Vec<crate::models::EvidenceSite>,
    mut stages: Vec<StageOutcome>,
    counters: Counters,
    rubric_input: &rubric::RubricInput,
) -> Report {
    let started = Instant::now();
    let (priority, trace) = rubric::evaluate(rubric_input);
    let outcome = StageOutcome::new(
        "E",
        "rubric",
        StageStatus::Ok,
        format!("{} rule(s) fired.", trace.len()),
        started.elapsed().as_millis() as u64,
    );
    log_stage(job.id, &outcome);
    stages.push(outcome);
    tracing::info!(id = %job.id, priority = ?priority, "pipeline finished");

    Report {
        schema_version: REPORT_SCHEMA_VERSION,
        analysis_id: job.id,
        priority,
        priority_description: priority.describe().to_string(),
        rubric_trace: trace,
        ruleset,
        package_present: presence.present,
        package_evidence: presence.evidence,
        sites,
        stages,
        counters,
        disclaimer: EVIDENCE_DISCLAIMER.to_string(),
        test_mode: false,
    }
}

/// Emits a live log line for one stage's outcome — status decides the
/// level — so an operator tailing the log can follow a slow analysis
/// stage-by-stage instead of waiting in silence for the whole report.
fn log_stage(id: uuid::Uuid, outcome: &StageOutcome) {
    match outcome.status {
        StageStatus::Failed => tracing::error!(
            %id, stage = %outcome.stage, name = %outcome.name,
            duration_ms = outcome.duration_ms, detail = %outcome.detail,
            "stage failed"
        ),
        StageStatus::Degraded => tracing::warn!(
            %id, stage = %outcome.stage, name = %outcome.name,
            duration_ms = outcome.duration_ms, detail = %outcome.detail,
            "stage degraded"
        ),
        StageStatus::Ok | StageStatus::Skipped => tracing::info!(
            %id, stage = %outcome.stage, name = %outcome.name,
            duration_ms = outcome.duration_ms, detail = %outcome.detail,
            "stage finished"
        ),
    }
}

/// Routes to the right fetcher and applies the subpath.
async fn fetch(
    deps: &PipelineDeps,
    repo_url: &str,
    commit: &str,
    subpath: Option<&str>,
) -> Result<Checkout, FetchError> {
    let fetcher: &Arc<dyn RepoFetcher> = match crate::fetcher::validate_repo_url(repo_url)? {
        RepoTarget::Https(_) => &deps.git,
        RepoTarget::Local(_) => &deps.local,
    };
    let mut checkout = fetcher.fetch(repo_url, commit).await?;
    checkout.scan_root = resolve_subpath(&checkout.root, subpath)?;
    Ok(checkout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AiConfig;
    use crate::models::PriorityLabel;
    use async_trait::async_trait;
    use std::path::PathBuf;

    /// A fetcher that hands back a directory prepared by the test — lets the
    /// whole pipeline run with no git and no network.
    struct FixedCheckout(PathBuf);

    #[async_trait]
    impl RepoFetcher for FixedCheckout {
        async fn fetch(&self, _url: &str, _commit: &str) -> Result<Checkout, FetchError> {
            Ok(Checkout { root: self.0.clone(), scan_root: self.0.clone() })
        }
    }

    struct AlwaysFails(FetchError);

    #[async_trait]
    impl RepoFetcher for AlwaysFails {
        async fn fetch(&self, _url: &str, _commit: &str) -> Result<Checkout, FetchError> {
            Err(match &self.0 {
                FetchError::RepoNotFound => FetchError::RepoNotFound,
                FetchError::AuthFailed => FetchError::AuthFailed,
                other => FetchError::Other(other.to_string()),
            })
        }
    }

    /// Points at a port nothing is listening on — the "inference server
    /// unavailable" failure mode, without needing to stop a real server.
    fn dead_client() -> ChatClient {
        ChatClient::new(AiConfig {
            base_url: "http://127.0.0.1:1".to_string(),
            model: "test".to_string(),
            api_key: None,
            timeout: std::time::Duration::from_millis(300),
            max_tokens: 256,
            temperature: 0.0,
        })
    }

    fn deps_for(dir: &std::path::Path) -> PipelineDeps {
        PipelineDeps {
            client: dead_client(),
            git: Arc::new(FixedCheckout(dir.to_path_buf())),
            local: Arc::new(FixedCheckout(dir.to_path_buf())),
            test_mode: false,
            limits: Limits {
                max_repo_mb: 64,
                max_sites: 50,
                max_scored_sites: 5,
                max_file_kb: 512,
                max_advisory_chars: 4000,
            },
        }
    }

    fn job_for(dir: &std::path::Path, package: Option<&str>) -> AnalysisJob {
        let _ = dir;
        AnalysisJob {
            id: uuid::Uuid::new_v4(),
            advisory_text: "A flaw in lookup() allows remote code execution.".to_string(),
            osv_id: Some("CVE-2021-0000".to_string()),
            package_name: package.map(str::to_string),
            ecosystem: Some("npm".to_string()),
            repo_url: Some("/fixture".to_string()),
            commit: Some("a".repeat(40)),
            subpath: None,
        }
    }

    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            let p = dir.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        dir
    }

    #[tokio::test]
    async fn an_absent_package_short_circuits_before_any_inference_call() {
        // The client points at a dead port; if stage B ran, the stage record
        // would say "Failed" rather than "Skipped".
        let dir = fixture(&[("package.json", "{\"dependencies\":{\"other\":\"1\"}}")]);
        let report = run(&deps_for(dir.path()), &job_for(dir.path(), Some("leftpad")))
            .await
            .unwrap();

        assert_eq!(report.priority, PriorityLabel::NoPackageEvidence);
        let b = report.stages.iter().find(|s| s.stage == "B").unwrap();
        assert_eq!(b.status, StageStatus::Skipped);
        assert_eq!(report.counters.inference_failures, 0);
    }

    #[tokio::test]
    async fn an_inference_outage_still_produces_a_report() {
        // The graded requirement: an inference failure must never break the
        // flow. Stage B fails, C and D are skipped for want of symbols, and
        // the analyst still gets stage A's evidence.
        let dir = fixture(&[
            ("package.json", "{\"dependencies\":{\"leftpad\":\"1.0.0\"}}"),
            ("src/app.js", "const v = lookup(1);\n"),
        ]);
        let report = run(&deps_for(dir.path()), &job_for(dir.path(), Some("leftpad")))
            .await
            .unwrap();

        assert_eq!(report.package_present, Some(true));
        let b = report.stages.iter().find(|s| s.stage == "B").unwrap();
        assert_eq!(b.status, StageStatus::Failed);
        assert!(b.detail.contains("unavailable") || b.detail.contains("timeout"));
        assert_eq!(report.priority, PriorityLabel::PackagePresentOnly);
        assert!(report.counters.inference_failures >= 1);
        // The degradation is stated, not hidden.
        assert!(report.rubric_trace.iter().any(|t| t.starts_with("R3")));
    }

    #[tokio::test]
    async fn every_report_carries_the_evidence_disclaimer_and_a_trace() {
        let dir = fixture(&[("src/app.js", "lookup();\n")]);
        let report = run(&deps_for(dir.path()), &job_for(dir.path(), None)).await.unwrap();
        assert_eq!(report.disclaimer, EVIDENCE_DISCLAIMER);
        assert!(!report.rubric_trace.is_empty());
        assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn an_advisory_only_analysis_is_inconclusive_about_reachability() {
        let dir = fixture(&[("a.js", "x\n")]);
        let mut job = job_for(dir.path(), None);
        job.repo_url = None;
        job.commit = None;

        let report = run(&deps_for(dir.path()), &job).await.unwrap();
        assert_eq!(report.priority, PriorityLabel::Inconclusive);
        assert_eq!(report.stages.iter().find(|s| s.stage == "A").unwrap().status, StageStatus::Skipped);
    }

    #[tokio::test]
    async fn a_repository_analysis_without_a_commit_is_refused() {
        // Analysing a moving ref would produce evidence nobody could
        // reproduce or audit.
        let dir = fixture(&[("a.js", "x\n")]);
        let mut job = job_for(dir.path(), None);
        job.commit = None;
        assert!(matches!(
            run(&deps_for(dir.path()), &job).await.unwrap_err(),
            FetchError::InvalidCommit(_)
        ));
    }

    #[tokio::test]
    async fn a_fetch_failure_is_an_error_not_a_misleadingly_clean_report() {
        let dir = fixture(&[("a.js", "x\n")]);
        let mut deps = deps_for(dir.path());
        deps.local = Arc::new(AlwaysFails(FetchError::AuthFailed));
        let err = run(&deps, &job_for(dir.path(), None)).await.unwrap_err();
        assert!(matches!(err, FetchError::AuthFailed));
    }

    #[tokio::test]
    async fn stage_records_cover_every_stage_exactly_once() {
        let dir = fixture(&[("src/app.js", "lookup();\n")]);
        let report = run(&deps_for(dir.path()), &job_for(dir.path(), None)).await.unwrap();
        let mut seen: Vec<&str> = report.stages.iter().map(|s| s.stage.as_str()).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec!["A", "B", "C", "D", "E"]);
    }
}
