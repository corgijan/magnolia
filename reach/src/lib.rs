//! `reach` — CVE reachability **evidence** analyzer.
//!
//! Contract: `(advisory, repo_url, commit) -> evidence report`. Given a
//! vulnerability advisory and an exact source revision, the service reports
//! *where in that source the advisory's vulnerable symbols are referenced*,
//! with every claim cited as `file:line` and every citation mechanically
//! verified against the checked-out tree.
//!
//! # The hard line
//!
//! This service produces **evidence for a human analyst, never a verdict**.
//! "Symbol `X` is referenced at `src/a.rs:41`" is evidence. "This CVE is not
//! exploitable" is a verdict and is deliberately out of scope — no code path
//! here emits one, and the priority labels in [`pipeline::rubric`] are
//! ordinal *evidence-strength* labels, not exploitability judgements. The
//! labels are also **not probabilities**: they are names for which
//! deterministic rules fired, and the only meaningful number attached to
//! them is the per-label precision measured by the eval suite in `eval/`.
//!
//! # Pipeline
//!
//! | Stage | Who | What |
//! |---|---|---|
//! | A | deterministic | Is the package present at all? Language-agnostic lexical identifier index. Zero hits short-circuits with no LLM call. |
//! | B | LLM #1 | Advisory -> ruleset (vulnerable symbols, search patterns, preconditions). Schema-validated, one retry. |
//! | C | deterministic | Every occurrence of the ruleset's symbols, capped, with context snippets. |
//! | D | LLM #2, per occurrence | Ordinal relevance label + reasoning + a cited line. |
//! | E | pure function | Rubric: fired rules -> priority label + trace. |
//!
//! Every stage degrades rather than aborts: a failed stage is recorded in
//! [`models::StageOutcome`] and the report is returned with whatever earlier
//! stages established. An inference outage yields a deterministic-only
//! report, never a 500.

pub mod ai;
pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod fetcher;
pub mod lexer;
pub mod models;
pub mod pipeline;
pub mod treesitter;
pub mod worker;

pub use config::Config;
pub use error::{ApiError, ReachError};
