use crate::errors::DtrackError;
use crate::models::{DtrackFinding, RawFinding};
use base64::Engine;
use serde::Deserialize;
use uuid::Uuid;

/// Thin typed wrapper around dtrack's REST API — mirrors the
/// `magnolia-signer`/`magnolia-storage` pattern of one narrow crate per
/// external system. Every endpoint call here is a best-effort sketch
/// against dtrack's documented API, NOT verified against a live running
/// instance in this pass (see `DTRACK_PLAN.md`'s "Confidence check on
/// dtrack's actual API" section) — re-verify request/response shapes
/// against a real instance's `/api/openapi.json` before depending on this
/// in production.
pub struct DtrackClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl DtrackClient {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), api_key: api_key.into(), http: reqwest::Client::new() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// Pushes a BOM to dtrack, auto-creating the project if it doesn't
    /// exist. `PUT /api/v1/bom` — BOM ingestion is asynchronous on dtrack's
    /// side (this call only enqueues processing; findings appear later),
    /// so this deliberately does not attempt to wait for or return the
    /// resulting project UUID — callers resolve that separately via
    /// `lookup_project` once dtrack has finished creating the project.
    pub async fn push_bom(
        &self,
        project_name: &str,
        project_version: &str,
        bom_bytes: &[u8],
    ) -> Result<(), DtrackError> {
        let body = serde_json::json!({
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": true,
            "bom": base64::engine::general_purpose::STANDARD.encode(bom_bytes),
        });
        let resp = self
            .http
            .put(self.url("/api/v1/bom"))
            .header("X-Api-Key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| DtrackError::Request(e.to_string()))?;
        Self::check_status(resp).await.map(|_| ())
    }

    /// `GET /api/v1/project/lookup?name=&version=` — project creation via
    /// `autoCreate` is believed synchronous even though vulnerability
    /// analysis afterward is async, so this should reliably find the
    /// project shortly after a successful `push_bom` call. Returns `None`
    /// (not an error) if the project doesn't exist yet — callers should
    /// retry on a later sync pass rather than treat this as fatal.
    pub async fn lookup_project(
        &self,
        project_name: &str,
        project_version: &str,
    ) -> Result<Option<Uuid>, DtrackError> {
        #[derive(Deserialize)]
        struct ProjectLookup {
            uuid: Uuid,
        }
        let resp = self
            .http
            .get(self.url("/api/v1/project/lookup"))
            .header("X-Api-Key", &self.api_key)
            .query(&[("name", project_name), ("version", project_version)])
            .send()
            .await
            .map_err(|e| DtrackError::Request(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = Self::check_status(resp).await?;
        let parsed: ProjectLookup =
            resp.json().await.map_err(|e| DtrackError::UnexpectedResponse(e.to_string()))?;
        Ok(Some(parsed.uuid))
    }

    /// `GET /api/v1/finding/project/{uuid}` — every entry is best-effort
    /// deserialized; callers should treat a parse failure of the whole
    /// response as one failed sync item (logged, retried next pass), not a
    /// reason to crash the sync loop.
    pub async fn get_findings(&self, project_uuid: Uuid) -> Result<Vec<DtrackFinding>, DtrackError> {
        let resp = self
            .http
            .get(self.url(&format!("/api/v1/finding/project/{project_uuid}")))
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .map_err(|e| DtrackError::Request(e.to_string()))?;
        let resp = Self::check_status(resp).await?;
        let raw: Vec<RawFinding> =
            resp.json().await.map_err(|e| DtrackError::UnexpectedResponse(e.to_string()))?;
        Ok(raw.into_iter().map(DtrackFinding::from).collect())
    }

    async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, DtrackError> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(DtrackError::Status { status, body })
        }
    }
}
