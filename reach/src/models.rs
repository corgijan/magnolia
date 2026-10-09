//! Wire and report types.
//!
//! Everything here is part of the service's public contract, so each type
//! derives `ToSchema` and shows up in `/openapi.json`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The sentence that must accompany every report wherever it is rendered.
/// Kept here rather than in the frontend so it cannot be dropped by an
/// integrator: the report carries its own framing.
pub const EVIDENCE_DISCLAIMER: &str = "Evidence for a human analyst, not a verdict. \
This report says where a vulnerable symbol is referenced in the scanned revision. \
It does not determine whether the vulnerability is exploitable, and the priority \
label is an ordinal name for which rules fired — not a probability.";

/// Report format version. Bump on any breaking change to [`Report`]; stored
/// alongside each report so an old row stays interpretable.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------- requests

/// `POST /api/v1/analyses`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateAnalysis {
    /// Advisory prose (OSV/NVD description, GHSA text). Required unless
    /// `osv_id` is given *and* the caller accepts an identifier-only run.
    #[serde(default)]
    pub advisory_text: Option<String>,
    /// Advisory identifier, e.g. `GHSA-xxxx-xxxx-xxxx` or `CVE-2021-44228`.
    #[serde(default)]
    pub osv_id: Option<String>,
    /// Affected package name, when the caller already knows it (from the
    /// SBOM component the finding hangs off). Improves stage A's presence
    /// check considerably; the ruleset falls back to extracting it.
    #[serde(default)]
    pub package_name: Option<String>,
    /// Package ecosystem (`npm`, `PyPI`, `Maven`, `crates.io`, ...).
    #[serde(default)]
    pub ecosystem: Option<String>,
    /// `https://` URL or, for the offline/demo fetcher, an absolute local
    /// path. Omitting it runs advisory extraction only (stage B) — which is
    /// a complete, useful result on its own.
    #[serde(default)]
    pub repo_url: Option<String>,
    /// Exact revision to analyse. Required whenever `repo_url` is set,
    /// unless `ref` is given instead: analysing a moving `HEAD` would
    /// produce evidence that cannot be reproduced or audited later.
    #[serde(default)]
    pub commit: Option<String>,
    /// A branch or tag name (`main`, `v1.2.3`, `HEAD`), accepted **only**
    /// when `commit` is absent. It is resolved once, when the request is
    /// accepted, to the exact commit it points at; the analysis runs against
    /// that commit and the response returns it. The ref is stored alongside
    /// purely as a record of what was asked for — re-reading the analysis
    /// later never re-resolves it.
    #[serde(default, rename = "ref")]
    #[schema(rename = "ref")]
    pub git_ref: Option<String>,
    /// Monorepo sub-directory to restrict the scan to.
    #[serde(default)]
    pub subpath: Option<String>,
}

/// `POST /api/v1/analyses` response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreateAnalysisResponse {
    pub id: Uuid,
    pub status: AnalysisStatus,
    /// The exact commit the analysis will run against — the request's
    /// `commit`, or what its `ref` resolved to. `null` for an advisory-only
    /// analysis.
    pub commit: Option<String>,
    /// The `ref` this commit was resolved from, when one was given.
    pub requested_ref: Option<String>,
}

// ----------------------------------------------------------------- status

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Queued,
    Running,
    /// Finished and produced a report. A report may still be *degraded* —
    /// see [`Report::stages`]; "completed" means the pipeline ran to the
    /// end, not that every stage succeeded.
    Completed,
    /// Finished without a report at all (the analysis could not start —
    /// e.g. the repository could not be fetched).
    Failed,
}

impl AnalysisStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalysisStatus::Queued => "queued",
            AnalysisStatus::Running => "running",
            AnalysisStatus::Completed => "completed",
            AnalysisStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "queued" => Some(AnalysisStatus::Queued),
            "running" => Some(AnalysisStatus::Running),
            "completed" => Some(AnalysisStatus::Completed),
            "failed" => Some(AnalysisStatus::Failed),
            _ => None,
        }
    }
}

/// `GET /api/v1/analyses/{id}`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AnalysisView {
    pub id: Uuid,
    pub status: AnalysisStatus,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub osv_id: Option<String>,
    pub package_name: Option<String>,
    pub repo_url: Option<String>,
    pub commit: Option<String>,
    /// Set when `commit` was resolved from a branch or tag name at request
    /// time rather than given exactly.
    pub requested_ref: Option<String>,
    pub subpath: Option<String>,
    /// Present once `status` is `completed`.
    pub report: Option<Report>,
    /// Present when `status` is `failed`: an analyst-facing reason, from the
    /// fetch failure taxonomy where applicable.
    pub error: Option<String>,
}

/// One row of `GET /api/v1/analyses`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AnalysisSummary {
    pub id: Uuid,
    pub status: AnalysisStatus,
    pub created_at: String,
    pub osv_id: Option<String>,
    pub package_name: Option<String>,
    pub repo_url: Option<String>,
    pub priority: Option<PriorityLabel>,
}

// ---------------------------------------------------------------- stage B

/// Structured extraction of an advisory — stage B's output, and on its own
/// the submitted *fallback* feature (AI-assisted extraction and grounded
/// summarisation of CVE advisories). Every field is validated app-side
/// before it is trusted; see [`crate::pipeline::stage_b`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct Ruleset {
    /// Identifiers the advisory names as vulnerable: functions, methods,
    /// classes, macros, CLI flags. These drive the stage C search.
    #[serde(default)]
    pub vulnerable_symbols: Vec<String>,
    /// Additional literal strings worth searching for (config keys, URL
    /// paths, format strings) that are not identifiers.
    #[serde(default)]
    pub search_patterns: Vec<String>,
    /// Conditions the advisory states must hold for the code to be affected
    /// ("only when the parser is called with untrusted input"). Shown to the
    /// analyst; never evaluated automatically.
    #[serde(default)]
    pub preconditions: Vec<String>,
    /// Package names the advisory names as affected.
    #[serde(default)]
    pub affected_packages: Vec<String>,
    /// Affected version range, verbatim from the advisory if stated.
    #[serde(default)]
    pub affected_versions: Option<String>,
    /// One or two sentences, grounded in the advisory text only.
    #[serde(default)]
    pub summary: String,
    /// Anything the model flagged as uncertain or absent from the advisory.
    #[serde(default)]
    pub notes: Vec<String>,
    /// Structural relationships the advisory describes as a *composition*
    /// rather than a single named symbol — "the construction of
    /// `(print (test 5))` is exploitable" names two symbols in a specific
    /// nesting, not one vulnerable function. A flat list of independent
    /// names can't express that; this can, for the languages
    /// [`crate::treesitter`] has a grammar for. Both `outer` and `inner`
    /// go through the same grounding check as `vulnerable_symbols` — see
    /// `pipeline::stage_b::ground_and_clean`.
    #[serde(default)]
    pub nested_calls: Vec<NestedCallPattern>,
}

/// One relationship stage C can search for structurally instead of by
/// independent name: a call to `outer` whose argument list contains a call
/// to `inner`. See [`crate::treesitter`] for how this is actually matched —
/// this type only ever carries two already-grounded symbol names, never
/// query syntax, so it stays exactly as safe to construct from model output
/// as `vulnerable_symbols` already is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NestedCallPattern {
    pub outer: String,
    pub inner: String,
}

impl NestedCallPattern {
    /// Human-readable form, used in prompts and as `EvidenceSite.term` for
    /// a structural match — an analyst reading the report should see this
    /// is a composition, not a bare name hit.
    pub fn describe(&self) -> String {
        format!("{}(...{}(...)...)", self.outer, self.inner)
    }
}

impl Ruleset {
    /// Everything stage C should search for, de-duplicated. Symbols and
    /// patterns are searched the same way; the split exists for the report,
    /// not for the search.
    pub fn search_terms(&self) -> Vec<String> {
        let mut terms: Vec<String> = Vec::new();
        for t in self.vulnerable_symbols.iter().chain(self.search_patterns.iter()) {
            let t = t.trim();
            if !t.is_empty() && !terms.iter().any(|e| e == t) {
                terms.push(t.to_string());
            }
        }
        terms
    }
}

// ---------------------------------------------------------------- stage D

/// Ordinal relevance label for one occurrence. Three levels on purpose:
/// a 4-8B local model cannot support finer gradations reliably, and an
/// analyst only needs "look here first / unclear / probably noise".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RelevanceLabel {
    /// A lexical match that is not a real use of the vulnerable API — a
    /// comment, an unrelated same-named local, a string.
    LikelyIrrelevant,
    /// A real reference whose relationship to the advisory the model could
    /// not establish from the snippet.
    Unclear,
    /// A real reference to the symbol the advisory names.
    LikelyRelevant,
}

impl RelevanceLabel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "likely_irrelevant" => Some(Self::LikelyIrrelevant),
            "unclear" => Some(Self::Unclear),
            "likely_relevant" => Some(Self::LikelyRelevant),
            _ => None,
        }
    }
}

/// One place in the source worth an analyst's attention.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvidenceSite {
    /// Repo-relative path, as checked out.
    pub path: String,
    /// 1-indexed.
    pub line: u32,
    /// Which ruleset term matched here.
    pub term: String,
    /// The matching line plus a little context.
    pub snippet: String,
    /// `None` when stage D did not run (inference unavailable) or dropped
    /// this site's answer as unusable — the occurrence is still reported,
    /// unlabelled, because a deterministic hit is evidence on its own.
    pub label: Option<RelevanceLabel>,
    /// The model's stated reason. Empty when unlabelled.
    #[serde(default)]
    pub reasoning: String,
    /// True when the model cited a `path:line` that actually exists in the
    /// checkout and actually contains the term. A false here means the
    /// reasoning was kept but is unverified; claims whose citation could not
    /// be resolved at all are dropped and counted in
    /// [`Counters::dropped_uncited_claims`].
    #[serde(default)]
    pub citation_verified: bool,
}

// ---------------------------------------------------------------- stage E

/// Ordinal priority label produced by the rubric. **Not a probability and
/// not an exploitability judgement** — each variant names which
/// deterministic rules fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PriorityLabel {
    /// Stage A found no lexical trace of the package in the scanned tree.
    NoPackageEvidence,
    /// The package appears, but no occurrence of any vulnerable symbol was
    /// found.
    PackagePresentOnly,
    /// Occurrences exist, but stage D labelled them all likely irrelevant.
    ReferencesLikelyIrrelevant,
    /// Occurrences exist and at least one could not be classified.
    ReferencesUnclear,
    /// At least one occurrence was labelled a real reference to a symbol the
    /// advisory names.
    DirectReferences,
    /// Too little of the pipeline ran to say anything. Distinct from
    /// `NoPackageEvidence`, which is a real finding.
    Inconclusive,
}

impl PriorityLabel {
    /// Analyst-facing one-liner. Phrased as observation, never judgement.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::NoPackageEvidence => {
                "No lexical trace of the affected package in the scanned revision."
            }
            Self::PackagePresentOnly => {
                "Package appears in the scanned revision, but no reference to a vulnerable symbol was found."
            }
            Self::ReferencesLikelyIrrelevant => {
                "Occurrences found; each was labelled a likely false match (comment, string, unrelated name)."
            }
            Self::ReferencesUnclear => {
                "Occurrences found that could not be classified from their surrounding code — needs a human look."
            }
            Self::DirectReferences => {
                "Direct references to symbols the advisory names were found — start here."
            }
            Self::Inconclusive => {
                "Not enough of the analysis completed to report evidence either way."
            }
        }
    }
}

// ---------------------------------------------------------------- stages

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Ok,
    /// Ran, but produced less than it should have (partial LLM failure,
    /// caps hit). Downstream stages continue.
    Degraded,
    /// Deliberately not run — an earlier stage made it pointless (no
    /// package present) or its input was absent (no repo given).
    Skipped,
    /// Ran and failed. Downstream stages that depend on it are skipped; the
    /// report is still returned.
    Failed,
}

/// Per-stage outcome record. This is the course's graded failure-handling
/// story made inspectable: whatever went wrong, the client can see which
/// stage it was and what the pipeline did about it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StageOutcome {
    /// `"A"` .. `"E"`.
    pub stage: String,
    pub name: String,
    pub status: StageStatus,
    pub detail: String,
    pub duration_ms: u64,
}

impl StageOutcome {
    pub fn new(
        stage: &str,
        name: &str,
        status: StageStatus,
        detail: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            stage: stage.to_string(),
            name: name.to_string(),
            status,
            detail: detail.into(),
            duration_ms,
        }
    }
}

// ---------------------------------------------------------------- report

/// Counts that make the report auditable rather than merely readable.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct Counters {
    /// Source files the lexer indexed.
    pub files_indexed: usize,
    /// Distinct identifiers in the index.
    pub identifiers_indexed: usize,
    /// Occurrences stage C found, before the [`crate::config::Limits`] cap.
    pub occurrences_found: usize,
    /// Occurrences carried into the report.
    pub occurrences_reported: usize,
    /// Occurrences stage D actually scored.
    pub occurrences_scored: usize,
    /// Model answers thrown away because their `file:line` citation could
    /// not be verified against the checkout. A non-zero value here is the
    /// hallucination rate made visible.
    ///
    /// Deliberately *only* citation failures. An answer rejected for some
    /// other reason (a label outside the three defined ones, say) is counted
    /// in [`Self::dropped_invalid_answers`] instead: this counter is the
    /// report's headline trustworthiness signal, and folding unrelated
    /// rejections into it would misattribute the cause to an analyst reading
    /// the stage detail.
    pub dropped_uncited_claims: usize,
    /// Model answers thrown away for a reason other than an unverifiable
    /// citation — currently only a `label` outside the three the prompt
    /// defines. Separate from [`Self::dropped_uncited_claims`] so the stage
    /// detail can name the real cause; the occurrence itself is still
    /// reported, unlabelled.
    pub dropped_invalid_answers: usize,
    /// Inference calls that failed after their retry.
    pub inference_failures: usize,
    /// Inference calls attempted in total. Zero is a meaningful value: it
    /// means a stage short-circuited before any model was asked anything.
    pub inference_calls: usize,
    /// Calls that needed the one repair retry because the model's first
    /// answer did not validate. The structured-output reliability of
    /// whichever model is configured, measured rather than assumed.
    pub inference_repairs: usize,
    /// Two independently-scored occurrences whose model-cited line
    /// converged on the same final location and were collapsed into one —
    /// see `pipeline::stage_d`'s module docs. Non-zero is not a problem on
    /// its own; it means two calls were spent to learn one thing.
    pub collapsed_duplicate_citations: usize,
}

/// The deliverable.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Report {
    pub schema_version: u32,
    pub analysis_id: Uuid,
    pub priority: PriorityLabel,
    /// Human-readable expansion of `priority`.
    pub priority_description: String,
    /// Which rubric rules fired, in order. Makes the label auditable.
    pub rubric_trace: Vec<String>,
    /// Stage B's extraction. Present even when no repository was analysed —
    /// that is the fallback feature standing alone.
    pub ruleset: Option<Ruleset>,
    /// Did stage A find the package at all, and on what basis.
    pub package_present: Option<bool>,
    pub package_evidence: Vec<String>,
    pub sites: Vec<EvidenceSite>,
    pub stages: Vec<StageOutcome>,
    pub counters: Counters,
    /// Always [`EVIDENCE_DISCLAIMER`].
    pub disclaimer: String,
    /// True when this report was produced by `REACH_TEST_MODE` — canned
    /// content, no advisory read and no code scanned. Carried on the report
    /// itself (not only on `/health`) because AISE archives reports: a
    /// canned one must stay recognisable long after the mode is switched off.
    #[serde(default)]
    pub test_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_terms_dedupes_and_merges_symbols_with_patterns() {
        let rs = Ruleset {
            vulnerable_symbols: vec!["lookup".into(), "  lookup  ".into(), "".into()],
            search_patterns: vec!["jndi:ldap".into(), "lookup".into()],
            ..Default::default()
        };
        assert_eq!(rs.search_terms(), vec!["lookup", "jndi:ldap"]);
    }

    #[test]
    fn relevance_label_parsing_is_case_insensitive_and_rejects_junk() {
        assert_eq!(RelevanceLabel::parse("LIKELY_RELEVANT"), Some(RelevanceLabel::LikelyRelevant));
        assert_eq!(RelevanceLabel::parse(" unclear "), Some(RelevanceLabel::Unclear));
        // A model that invents its own label must not silently become a
        // valid one -- the answer gets dropped instead.
        assert_eq!(RelevanceLabel::parse("definitely_exploitable"), None);
    }

    #[test]
    fn analysis_status_roundtrips_through_its_database_string() {
        for s in [
            AnalysisStatus::Queued,
            AnalysisStatus::Running,
            AnalysisStatus::Completed,
            AnalysisStatus::Failed,
        ] {
            assert_eq!(AnalysisStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(AnalysisStatus::parse("bogus"), None);
    }
}
