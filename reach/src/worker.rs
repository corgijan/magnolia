//! The background worker.
//!
//! Burst-then-back-off, the same shape as AISE's `sync_loop`: while jobs keep
//! turning up, poll again immediately; when the queue empties, wait out the
//! full interval instead of hammering SQLite. One worker task, sequential
//! jobs — a local 4-8B model serves one request at a time anyway, so
//! parallelism here would only queue at the inference server instead.

use std::sync::Arc;
use std::time::Duration;

use crate::db::Db;
use crate::pipeline::{self, PipelineDeps};

/// How long to wait when the queue came up empty.
const IDLE_INTERVAL: Duration = Duration::from_secs(5);
/// How long to wait after finishing a job (there may be another).
const BURST_INTERVAL: Duration = Duration::from_millis(200);

pub async fn run_worker(db: Arc<Db>, deps: Arc<PipelineDeps>) {
    // A job left `running` by a crash or redeploy is nobody's now; put it
    // back so the UI stops polling a job that will never finish.
    match db.requeue_orphaned_jobs().await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(count = n, "requeued jobs orphaned by a previous run"),
        Err(e) => tracing::error!(error = %e, "could not requeue orphaned jobs"),
    }

    loop {
        let delay = match run_one(&db, &deps).await {
            Ok(true) => BURST_INTERVAL,
            Ok(false) => IDLE_INTERVAL,
            Err(e) => {
                // A database error here is the loop's own problem, not a
                // job's; backing off is right, dying is not.
                tracing::error!(error = %e, "worker pass failed");
                IDLE_INTERVAL
            }
        };
        tokio::time::sleep(delay).await;
    }
}

/// A job never returns this to the caller — it is folded into a
/// [`crate::error::ReachError`] wrapper by way of `db.fail_analysis`, but the
/// text itself must never include the panic payload verbatim: this service
/// parses arbitrary, untrusted repository content, and Rust's default panic
/// payload for an indexing/slicing bug is frequently a chunk of the actual
/// text being processed (see the em-dash panic this replaced — its message
/// quoted a whole doc comment from the scanned repository). An analyst-
/// facing error field is not the place for that.
const PANIC_DURING_ANALYSIS: &str = "an internal error occurred while scanning this revision \
     (a bug in the analyser, not in your repository or the advisory); this job could not \
     complete, but no other job — running or queued — was affected. Try again, and consider \
     reporting this repository as a test case.";

/// Claims and runs at most one job. `Ok(true)` means one was processed.
async fn run_one(db: &Db, deps: &Arc<PipelineDeps>) -> Result<bool, crate::error::ReachError> {
    let Some(job) = db.claim_next_job().await? else { return Ok(false) };
    let id = job.id;
    tracing::info!(%id, osv_id = ?job.osv_id, repo = ?job.repo_url, "starting analysis");

    let started = std::time::Instant::now();

    // `pipeline::run` scans arbitrary, untrusted repository content — a
    // parsing bug tripped by some real-world file's encoding, formatting, or
    // sheer size is a "when", not an "if". Running it as its own task rather
    // than inline is what turns a panic there into "this one job failed"
    // instead of "the worker loop that processes every future job for this
    // deployment is now dead until someone notices and restarts the
    // container" — `run_worker`'s `loop {}` calls this function directly, in
    // the same task, forever; an uncaught panic would unwind straight out of
    // it. `tokio::spawn` gives a real panic boundary (the runtime already
    // wraps a spawned task in `catch_unwind`) without reaching for a
    // hand-rolled one.
    let deps = Arc::clone(deps);
    let task_job = job.clone();
    let outcome = tokio::spawn(async move { pipeline::run(&deps, &task_job).await }).await;

    match outcome {
        Ok(Ok(report)) => {
            tracing::info!(
                %id,
                priority = ?report.priority,
                sites = report.sites.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "analysis completed"
            );
            db.complete_analysis(id, &report).await?;
        }
        Ok(Err(e)) => {
            // Only "could not obtain the source" reaches here; the pipeline
            // handles every other failure internally. The message is from
            // the analyst-facing fetch taxonomy, so it is safe and useful to
            // store verbatim.
            tracing::warn!(%id, error = %e, kind = e.kind(), "analysis could not run");
            db.fail_analysis(id, &e.to_string()).await?;
        }
        Err(join_err) => {
            // `is_panic()` is the only realistic case here — nothing ever
            // calls `.abort()` on this handle — but both are folded into the
            // same bounded, generic message rather than distinguished, since
            // neither carries anything an analyst should see verbatim.
            tracing::error!(%id, panicked = join_err.is_panic(), "analysis task ended abnormally");
            db.fail_analysis(id, PANIC_DURING_ANALYSIS).await?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AiConfig, Limits};
    use crate::fetcher::{Checkout, FetchError, RepoFetcher};
    use crate::models::{AnalysisStatus, CreateAnalysis};
    use async_trait::async_trait;

    struct FixedCheckout(std::path::PathBuf);

    #[async_trait]
    impl RepoFetcher for FixedCheckout {
        async fn fetch(&self, _u: &str, _c: &str) -> Result<Checkout, FetchError> {
            Ok(Checkout { root: self.0.clone(), scan_root: self.0.clone() })
        }
    }

    struct Unreachable;

    #[async_trait]
    impl RepoFetcher for Unreachable {
        async fn fetch(&self, _u: &str, _c: &str) -> Result<Checkout, FetchError> {
            Err(FetchError::RepoNotFound)
        }
    }

    /// Stands in for any unanticipated panic deep in the pipeline — this one
    /// happens to panic in the fetcher, but the point being tested is
    /// `run_one`'s own contract, not any particular bug: nothing this
    /// service scans is trusted, so a parsing panic on some real repository
    /// is a certainty over time, and the worker loop must survive it.
    struct PanicsMidFetch;

    #[async_trait]
    impl RepoFetcher for PanicsMidFetch {
        async fn fetch(&self, _u: &str, _c: &str) -> Result<Checkout, FetchError> {
            panic!("simulated panic containing repository secrets: sk-should-never-leak")
        }
    }

    fn deps(git: Arc<dyn RepoFetcher>, local: Arc<dyn RepoFetcher>) -> PipelineDeps {
        PipelineDeps {
            // Dead port: the whole worker path runs with inference down,
            // which is the case that must still produce a stored report.
            client: crate::ai::ChatClient::new(AiConfig {
                base_url: "http://127.0.0.1:1".into(),
                model: "test".into(),
                api_key: None,
                timeout: Duration::from_millis(200),
                max_tokens: 128,
                temperature: 0.0,
            }),
            git,
            local,
            test_mode: false,
            limits: Limits {
                max_repo_mb: 64,
                max_sites: 20,
                max_scored_sites: 3,
                max_file_kb: 256,
                max_advisory_chars: 2000,
            },
        }
    }

    async fn db_in(dir: &std::path::Path) -> Db {
        Db::connect(dir.join("w.db").to_str().unwrap()).await.unwrap()
    }

    fn request(repo: &str) -> CreateAnalysis {
        CreateAnalysis {
            advisory_text: Some("A flaw in lookup() allows RCE.".into()),
            osv_id: Some("CVE-2021-2".into()),
            package_name: Some("leftpad".into()),
            ecosystem: Some("npm".into()),
            repo_url: Some(repo.to_string()),
            commit: Some("a".repeat(40)),
            git_ref: None,
            subpath: None,
        }
    }

    #[tokio::test]
    async fn a_job_is_processed_and_its_report_stored_even_with_inference_down() {
        let dir = tempfile::tempdir().unwrap();
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("package.json"), "{\"dependencies\":{\"leftpad\":\"1\"}}")
            .unwrap();
        std::fs::write(repo.path().join("app.js"), "lookup();\n").unwrap();

        let db = db_in(dir.path()).await;
        let id = db.insert_analysis(&request("/fixture"), "A flaw in lookup() allows RCE.").await.unwrap();
        let checkout: Arc<dyn RepoFetcher> = Arc::new(FixedCheckout(repo.path().to_path_buf()));

        assert!(run_one(&db, &Arc::new(deps(checkout.clone(), checkout))).await.unwrap());

        let view = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(view.status, AnalysisStatus::Completed);
        let report = view.report.unwrap();
        assert_eq!(report.package_present, Some(true));
        assert!(report.counters.inference_failures >= 1, "the outage should be recorded");
    }

    #[tokio::test]
    async fn an_unfetchable_repository_marks_the_job_failed_with_a_usable_message() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_in(dir.path()).await;
        let id = db.insert_analysis(&request("https://h/gone"), "x").await.unwrap();

        let unreachable: Arc<dyn RepoFetcher> = Arc::new(Unreachable);
        assert!(run_one(&db, &Arc::new(deps(unreachable.clone(), unreachable))).await.unwrap());

        let view = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(view.status, AnalysisStatus::Failed);
        assert!(view.error.unwrap().contains("could not be reached"));
    }

    #[tokio::test]
    async fn a_panic_anywhere_in_the_pipeline_fails_only_that_job_and_the_loop_keeps_going() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_in(dir.path()).await;
        let panicking: Arc<dyn RepoFetcher> = Arc::new(PanicsMidFetch);

        let panicked_id =
            db.insert_analysis(&request("https://h/panics"), "x").await.unwrap();
        // `run_one` must itself return `Ok(true)` -- a panic in the spawned
        // pipeline task must not propagate out and it must not be mistaken
        // for "nothing to do".
        assert!(run_one(&db, &Arc::new(deps(panicking.clone(), panicking))).await.unwrap());

        let panicked_view = db.get_analysis(panicked_id).await.unwrap().unwrap();
        assert_eq!(panicked_view.status, AnalysisStatus::Failed);
        let error = panicked_view.error.unwrap();
        // The bounded message is stored, not the raw panic payload -- which
        // in a real crash frequently contains a slice of whatever
        // repository content triggered it.
        assert!(!error.contains("sk-should-never-leak"), "raw panic payload leaked: {error}");
        assert!(error.contains("internal error"));

        // The worker loop's actual contract: a second, ordinary job queued
        // right after the panicking one is processed normally in the very
        // next call -- proving the panic did not take the loop down.
        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("package.json"), "{\"dependencies\":{\"leftpad\":\"1\"}}")
            .unwrap();
        let checkout: Arc<dyn RepoFetcher> = Arc::new(FixedCheckout(repo.path().to_path_buf()));
        let healthy_id = db.insert_analysis(&request("/fixture"), "x").await.unwrap();
        assert!(run_one(&db, &Arc::new(deps(checkout.clone(), checkout))).await.unwrap());

        let healthy_view = db.get_analysis(healthy_id).await.unwrap().unwrap();
        assert_eq!(healthy_view.status, AnalysisStatus::Completed);
    }

    #[tokio::test]
    async fn an_empty_queue_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = db_in(dir.path()).await;
        let none: Arc<dyn RepoFetcher> = Arc::new(Unreachable);
        assert!(!run_one(&db, &Arc::new(deps(none.clone(), none))).await.unwrap());
    }
}
