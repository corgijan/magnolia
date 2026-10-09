//! Persistence.
//!
//! Runtime-checked sqlx (`query`/`query_as` with binds), matching AISE's
//! convention — which means SQL errors surface at runtime, so any new query
//! here needs to be exercised against a real database before it is called
//! done. The integration tests at the bottom of this file do exactly that
//! against a temporary SQLite file.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::ReachError;
use crate::models::{AnalysisStatus, AnalysisSummary, AnalysisView, CreateAnalysis, PriorityLabel, Report};
use crate::pipeline::AnalysisJob;

#[derive(Clone)]
pub struct Db {
    pub pool: SqlitePool,
}

impl Db {
    /// Opens (creating if needed) the database file and applies migrations.
    ///
    /// WAL plus a busy timeout because the worker writes while HTTP handlers
    /// read; without them SQLite returns `SQLITE_BUSY` to whichever loses,
    /// which would surface as a spurious 500 on a status poll.
    pub async fn connect(path: &str) -> Result<Self, ReachError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(10));

        let pool = SqlitePoolOptions::new().max_connections(5).connect_with(options).await?;
        sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| {
            ReachError::Db(sqlx::Error::Configuration(Box::new(std::io::Error::other(
                e.to_string(),
            ))))
        })?;
        Ok(Self { pool })
    }

    /// Queues a request. Returns the new id.
    pub async fn insert_analysis(&self, req: &CreateAnalysis, advisory_text: &str) -> Result<Uuid, ReachError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO analyses
               (id, status, created_at, advisory_text, osv_id, package_name, ecosystem,
                repo_url, commit_sha, subpath, requested_ref)
             VALUES (?1, 'queued', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(id.to_string())
        .bind(now())
        .bind(advisory_text)
        .bind(&req.osv_id)
        .bind(&req.package_name)
        .bind(&req.ecosystem)
        .bind(&req.repo_url)
        .bind(&req.commit)
        .bind(&req.subpath)
        .bind(&req.git_ref)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Atomically claims the oldest queued job.
    ///
    /// Select-then-conditional-update inside one transaction, rather than a
    /// single `UPDATE ... RETURNING`: sqlx consumes a `RETURNING` statement
    /// lazily, and `fetch_optional` stops stepping after the first row, so
    /// the update was observed *not* to be applied at all (the row came
    /// back, the status stayed `queued`, and the job was handed out again on
    /// the next poll). The `AND status = 'queued'` on the update is what
    /// keeps this atomic anyway: a second worker that read the same row
    /// before the first committed affects zero rows and correctly sees no
    /// job, so the same job is never handed to two workers.
    pub async fn claim_next_job(&self) -> Result<Option<AnalysisJob>, ReachError> {
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query(
            "SELECT id, advisory_text, osv_id, package_name, ecosystem,
                    repo_url, commit_sha, subpath
               FROM analyses
              WHERE status = 'queued'
              ORDER BY created_at
              LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let id: String = row.try_get("id")?;

        let claimed = sqlx::query(
            "UPDATE analyses SET status = 'running', started_at = ?1
              WHERE id = ?2 AND status = 'queued'",
        )
        .bind(now())
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if claimed == 0 {
            // Another worker got there first.
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;

        Ok(Some(AnalysisJob {
            id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
            advisory_text: row.try_get("advisory_text")?,
            osv_id: row.try_get("osv_id")?,
            package_name: row.try_get("package_name")?,
            ecosystem: row.try_get("ecosystem")?,
            repo_url: row.try_get("repo_url")?,
            commit: row.try_get("commit_sha")?,
            subpath: row.try_get("subpath")?,
        }))
    }

    pub async fn complete_analysis(&self, id: Uuid, report: &Report) -> Result<(), ReachError> {
        let json = serde_json::to_string(report)?;
        let priority = serde_json::to_value(report.priority)?
            .as_str()
            .unwrap_or("inconclusive")
            .to_string();
        sqlx::query(
            "UPDATE analyses
                SET status = 'completed', finished_at = ?1, report_json = ?2, priority = ?3,
                    error = NULL
              WHERE id = ?4",
        )
        .bind(now())
        .bind(json)
        .bind(priority)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn fail_analysis(&self, id: Uuid, error: &str) -> Result<(), ReachError> {
        sqlx::query(
            "UPDATE analyses SET status = 'failed', finished_at = ?1, error = ?2 WHERE id = ?3",
        )
        .bind(now())
        .bind(crate::ai::truncate(error, 1000))
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_analysis(&self, id: Uuid) -> Result<Option<AnalysisView>, ReachError> {
        let row = sqlx::query(
            "SELECT id, status, created_at, started_at, finished_at, osv_id, package_name,
                    repo_url, commit_sha, requested_ref, subpath, report_json, error
               FROM analyses WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        let status_str: String = row.try_get("status")?;
        let report_json: Option<String> = row.try_get("report_json")?;

        Ok(Some(AnalysisView {
            id,
            status: AnalysisStatus::parse(&status_str).unwrap_or(AnalysisStatus::Failed),
            created_at: row.try_get("created_at")?,
            started_at: row.try_get("started_at")?,
            finished_at: row.try_get("finished_at")?,
            osv_id: row.try_get("osv_id")?,
            package_name: row.try_get("package_name")?,
            repo_url: row.try_get("repo_url")?,
            commit: row.try_get("commit_sha")?,
            requested_ref: row.try_get("requested_ref")?,
            subpath: row.try_get("subpath")?,
            // A report that no longer deserializes (schema drift after an
            // upgrade) is reported as absent rather than taking the endpoint
            // down -- the row's status and error still tell the analyst what
            // happened.
            report: report_json.and_then(|j| match serde_json::from_str::<Report>(&j) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(%id, error = %e, "stored report could not be deserialized");
                    None
                }
            }),
            error: row.try_get("error")?,
        }))
    }

    pub async fn list_analyses(&self, limit: i64) -> Result<Vec<AnalysisSummary>, ReachError> {
        let rows = sqlx::query(
            "SELECT id, status, created_at, osv_id, package_name, repo_url, priority
               FROM analyses ORDER BY created_at DESC LIMIT ?1",
        )
        .bind(limit.clamp(1, 500))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id")?;
                let status: String = row.try_get("status")?;
                let priority: Option<String> = row.try_get("priority")?;
                Ok(AnalysisSummary {
                    id: Uuid::parse_str(&id).unwrap_or_else(|_| Uuid::nil()),
                    status: AnalysisStatus::parse(&status).unwrap_or(AnalysisStatus::Failed),
                    created_at: row.try_get("created_at")?,
                    osv_id: row.try_get("osv_id")?,
                    package_name: row.try_get("package_name")?,
                    repo_url: row.try_get("repo_url")?,
                    priority: priority
                        .and_then(|p| serde_json::from_value::<PriorityLabel>(serde_json::Value::String(p)).ok()),
                })
            })
            .collect()
    }

    /// Re-queues jobs left in `running` by a crash or restart. Called once at
    /// startup: without it, an analysis interrupted by a redeploy would sit
    /// in `running` forever and the UI would poll it until the heat death of
    /// the universe.
    pub async fn requeue_orphaned_jobs(&self) -> Result<u64, ReachError> {
        let result = sqlx::query(
            "UPDATE analyses SET status = 'queued', started_at = NULL WHERE status = 'running'",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Counters, EVIDENCE_DISCLAIMER, REPORT_SCHEMA_VERSION};

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let db = Db::connect(path.to_str().unwrap()).await.unwrap();
        (db, dir)
    }

    fn request() -> CreateAnalysis {
        CreateAnalysis {
            advisory_text: Some("A flaw in lookup().".to_string()),
            osv_id: Some("CVE-2021-1".to_string()),
            package_name: Some("leftpad".to_string()),
            ecosystem: Some("npm".to_string()),
            repo_url: Some("https://h/r".to_string()),
            commit: Some("a".repeat(40)),
            git_ref: None,
            subpath: None,
        }
    }

    fn report_for(id: Uuid) -> Report {
        Report {
            schema_version: REPORT_SCHEMA_VERSION,
            analysis_id: id,
            priority: PriorityLabel::DirectReferences,
            priority_description: "d".to_string(),
            rubric_trace: vec!["R8".to_string()],
            ruleset: None,
            package_present: Some(true),
            package_evidence: vec![],
            sites: vec![],
            stages: vec![],
            counters: Counters::default(),
            disclaimer: EVIDENCE_DISCLAIMER.to_string(),
            test_mode: false,
        }
    }

    #[tokio::test]
    async fn migrations_apply_to_a_fresh_file() {
        let (db, _dir) = test_db().await;
        assert!(db.list_analyses(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn insert_claim_complete_roundtrips() {
        let (db, _dir) = test_db().await;
        let id = db.insert_analysis(&request(), "A flaw in lookup().").await.unwrap();

        let view = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(view.status, AnalysisStatus::Queued);
        assert!(view.report.is_none());

        let job = db.claim_next_job().await.unwrap().unwrap();
        assert_eq!(job.id, id);
        assert_eq!(job.package_name.as_deref(), Some("leftpad"));
        assert_eq!(db.get_analysis(id).await.unwrap().unwrap().status, AnalysisStatus::Running);

        db.complete_analysis(id, &report_for(id)).await.unwrap();
        let done = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(done.status, AnalysisStatus::Completed);
        assert_eq!(done.report.unwrap().priority, PriorityLabel::DirectReferences);
        assert!(done.finished_at.is_some());
    }

    #[tokio::test]
    async fn claiming_a_job_twice_is_impossible() {
        // The bug this guards against would silently double inference spend
        // the day a second worker is added.
        let (db, _dir) = test_db().await;
        db.insert_analysis(&request(), "x").await.unwrap();
        assert!(db.claim_next_job().await.unwrap().is_some());
        assert!(db.claim_next_job().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn jobs_are_claimed_oldest_first() {
        let (db, _dir) = test_db().await;
        let mut first_req = request();
        first_req.osv_id = Some("first".to_string());
        let first = db.insert_analysis(&first_req, "x").await.unwrap();
        // RFC3339 timestamps at second-or-finer resolution: sleep so the
        // ordering is not a coin flip.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        db.insert_analysis(&request(), "x").await.unwrap();

        assert_eq!(db.claim_next_job().await.unwrap().unwrap().id, first);
    }

    #[tokio::test]
    async fn failure_is_recorded_with_its_analyst_facing_message() {
        let (db, _dir) = test_db().await;
        let id = db.insert_analysis(&request(), "x").await.unwrap();
        db.claim_next_job().await.unwrap();
        db.fail_analysis(id, "authentication failed").await.unwrap();

        let view = db.get_analysis(id).await.unwrap().unwrap();
        assert_eq!(view.status, AnalysisStatus::Failed);
        assert_eq!(view.error.as_deref(), Some("authentication failed"));
    }

    #[tokio::test]
    async fn orphaned_running_jobs_are_requeued_at_startup() {
        // Otherwise a redeploy mid-analysis leaves the UI polling forever.
        let (db, _dir) = test_db().await;
        db.insert_analysis(&request(), "x").await.unwrap();
        db.claim_next_job().await.unwrap();

        assert_eq!(db.requeue_orphaned_jobs().await.unwrap(), 1);
        assert!(db.claim_next_job().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_list_endpoint_reads_the_denormalised_priority() {
        let (db, _dir) = test_db().await;
        let id = db.insert_analysis(&request(), "x").await.unwrap();
        db.claim_next_job().await.unwrap();
        db.complete_analysis(id, &report_for(id)).await.unwrap();

        let list = db.list_analyses(10).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].priority, Some(PriorityLabel::DirectReferences));
    }

    #[tokio::test]
    async fn an_unknown_id_is_none_rather_than_an_error() {
        let (db, _dir) = test_db().await;
        assert!(db.get_analysis(Uuid::new_v4()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_list_limit_is_clamped_to_a_sane_range() {
        let (db, _dir) = test_db().await;
        // A negative or absurd limit from a query string must not become a
        // negative LIMIT or an unbounded scan.
        assert!(db.list_analyses(-5).await.is_ok());
        assert!(db.list_analyses(999_999).await.is_ok());
    }
}
