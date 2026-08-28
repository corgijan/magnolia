use crate::errors::DepsDevError;
use crate::models::{ProjectDetail, VersionDetail};

/// Thin typed wrapper around deps.dev's public REST API — mirrors the
/// `magnolia-osv`/`magnolia-dtrack` pattern of one narrow crate per external
/// system. No API key: deps.dev's API is public/free. Base URL and every
/// path/field name here were checked against docs.deps.dev/api/v3 (not
/// exercised against a live response — same caveat `DTRACK_PLAN.md` and
/// `SUPPLY_CHAIN_SIGNALS_PLAN.md` carry for their own unverified-against-live-
/// traffic integrations).
pub struct DepsDevClient {
    base_url: String,
    http: reqwest::Client,
}

impl Default for DepsDevClient {
    fn default() -> Self {
        Self::new("https://api.deps.dev")
    }
}

impl DepsDevClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), http: reqwest::Client::new() }
    }

    /// `GET /v3/systems/{system}/packages/{name}/versions/{version}` — a
    /// 404 (package/version not known to deps.dev) is treated as "no related
    /// projects" rather than an error, same as `get_project`'s 404 handling.
    /// `name`/`version` are pushed as individual path segments (not
    /// string-formatted into the URL) so `url` percent-encodes anything that
    /// would otherwise be read as an extra path separator — e.g. npm scoped
    /// names (`@scope/name`) or Go's full-module-path names, both of which
    /// contain a literal `/`.
    pub async fn get_version(&self, system: &str, name: &str, version: &str) -> Result<VersionDetail, DepsDevError> {
        let url = self.build_url(&["v3", "systems", system, "packages", name, "versions", version])?;
        let resp = self.http.get(url).send().await.map_err(|e| DepsDevError::Request(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(VersionDetail::default());
        }
        let resp = Self::check_status(resp).await?;
        resp.json().await.map_err(|e| DepsDevError::UnexpectedResponse(e.to_string()))
    }

    /// `GET /v3/projects/{project_id}` — `project_id` (e.g.
    /// `github.com/lodash/lodash`) is itself a `/`-containing identifier per
    /// deps.dev's own docs, pushed as one path segment the same way as
    /// `get_version`'s `name`, not split on `/` first. A 404 or a project
    /// with no scorecard both come back as `ProjectDetail { scorecard: None }`
    /// — the caller can't distinguish "unknown project" from "known project,
    /// no scorecard available," which is fine since both mean the same thing
    /// here: nothing to store.
    pub async fn get_project(&self, project_id: &str) -> Result<ProjectDetail, DepsDevError> {
        let url = self.build_url(&["v3", "projects", project_id])?;
        let resp = self.http.get(url).send().await.map_err(|e| DepsDevError::Request(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(ProjectDetail::default());
        }
        let resp = Self::check_status(resp).await?;
        resp.json().await.map_err(|e| DepsDevError::UnexpectedResponse(e.to_string()))
    }

    fn build_url(&self, segments: &[&str]) -> Result<reqwest::Url, DepsDevError> {
        let mut url =
            reqwest::Url::parse(&self.base_url).map_err(|e| DepsDevError::Request(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|_| DepsDevError::Request("base url cannot be a base".to_string()))?
            .extend(segments);
        Ok(url)
    }

    async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, DepsDevError> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(DepsDevError::Status { status, body })
        }
    }
}
