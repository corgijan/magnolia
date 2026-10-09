//! Client for the `reach` CVE-reachability analyser.
//!
//! `reach` is a standalone service (its own Cargo project in `reach/`, its
//! own database, its own image) and the boundary between it and AISE is REST
//! only — this crate is the whole of it. Same shape as `magnolia-osv` and
//! `magnolia-dtrack`: a thin typed client, no business logic, and every
//! response modelled loosely enough that the analyser can add fields without
//! breaking AISE.
//!
//! The report is deliberately carried as [`serde_json::Value`] rather than
//! mirrored as a struct here. The report schema belongs to `reach` and will
//! change as its pipeline grows; duplicating it would mean two definitions
//! that must be kept in step, and a stale copy would silently drop fields
//! from the UI. AISE only routes it.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ReachError {
    #[error("reachability analyser unreachable: {0}")]
    Unavailable(String),
    #[error("reachability analyser returned HTTP {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("reachability analyser returned an unreadable response: {0}")]
    Malformed(String),
    #[error("analysis not found")]
    NotFound,
}

/// `POST /api/v1/analyses` body.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisRequest {
    pub advisory_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osv_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// A branch or tag, sent only when `commit` is unknown. The analyser
    /// resolves it once, at request time, and returns the exact commit in
    /// [`AnalysisCreated::commit`].
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisCreated {
    pub id: Uuid,
    /// The exact commit the analysis will run against. Older analysers do
    /// not return it, hence optional.
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub requested_ref: Option<String>,
}

/// A status poll. Everything past `status` is optional so a schema change on
/// the analyser side degrades to a thinner view rather than an error.
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisView {
    pub id: Uuid,
    pub status: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub report: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct ReachClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl ReachClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::builder()
                // Only ever *queues* or *polls* — the analysis itself runs in
                // the analyser's own worker, so no AISE request ever waits on
                // a model. A short timeout is correct here and keeps a
                // wedged analyser from tying up an AISE request handler.
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Queues an analysis, returning the analyser's id for it and the exact
    /// commit it will analyse.
    pub async fn create_analysis(&self, req: &AnalysisRequest) -> Result<AnalysisCreated, ReachError> {
        let resp = self
            .http
            .post(format!("{}/api/v1/analyses", self.base_url))
            .bearer_auth(&self.token)
            .json(req)
            .send()
            .await
            .map_err(|e| ReachError::Unavailable(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(ReachError::Upstream {
                status: status.as_u16(),
                body: truncate(&resp.text().await.unwrap_or_default(), 400),
            });
        }
        resp.json::<AnalysisCreated>()
            .await
            .map_err(|e| ReachError::Malformed(e.to_string()))
    }

    /// Polls one analysis.
    pub async fn get_analysis(&self, id: Uuid) -> Result<AnalysisView, ReachError> {
        let resp = self
            .http
            .get(format!("{}/api/v1/analyses/{id}", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| ReachError::Unavailable(e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(ReachError::NotFound);
        }
        if !status.is_success() {
            return Err(ReachError::Upstream {
                status: status.as_u16(),
                body: truncate(&resp.text().await.unwrap_or_default(), 400),
            });
        }
        resp.json::<AnalysisView>()
            .await
            .map_err(|e| ReachError::Malformed(e.to_string()))
    }

    /// Liveness probe, used by `GET /api/v1/config` so the UI can explain a
    /// disabled button as "analyser down" rather than leaving it inert.
    pub async fn health(&self) -> Result<serde_json::Value, ReachError> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|e| ReachError::Unavailable(e.to_string()))?;
        resp.json().await.map_err(|e| ReachError::Malformed(e.to_string()))
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn create_analysis_sends_the_token_and_returns_the_id() {
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/api/v1/analyses"))
            .and(header("authorization", "Bearer t0ken"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "id": id,
                "status": "queued",
                "commit": "a".repeat(40),
                "requested_ref": null
            })))
            .mount(&server)
            .await;

        let client = ReachClient::new(server.uri(), "t0ken");
        let got = client
            .create_analysis(&AnalysisRequest {
                advisory_text: "A flaw in lookup().".to_string(),
                osv_id: Some("CVE-2021-1".to_string()),
                package_name: Some("leftpad".to_string()),
                ecosystem: Some("npm".to_string()),
                repo_url: Some("https://h/r".to_string()),
                commit: Some("a".repeat(40)),
                git_ref: None,
                subpath: None,
            })
            .await
            .unwrap();
        assert_eq!(got.id, id);
        assert_eq!(got.commit, Some("a".repeat(40)));
    }

    #[tokio::test]
    async fn a_ref_is_sent_under_its_wire_name_and_the_resolved_commit_read_back() {
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        Mock::given(method("POST"))
            .and(path("/api/v1/analyses"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({ "ref": "main" })))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "id": id,
                "status": "queued",
                "commit": "b".repeat(40),
                "requested_ref": "main"
            })))
            .mount(&server)
            .await;

        let got = ReachClient::new(server.uri(), "t")
            .create_analysis(&AnalysisRequest {
                advisory_text: "x".into(),
                osv_id: None,
                package_name: None,
                ecosystem: None,
                repo_url: Some("https://h/r".into()),
                commit: None,
                git_ref: Some("main".into()),
                subpath: None,
            })
            .await
            .unwrap();
        assert_eq!(got.commit, Some("b".repeat(40)));
        assert_eq!(got.requested_ref.as_deref(), Some("main"));
    }

    #[tokio::test]
    async fn optional_fields_are_omitted_rather_than_sent_as_null() {
        // The analyser distinguishes "no repository" (advisory-only) from a
        // null it would have to interpret; sending explicit nulls would make
        // the two indistinguishable in its logs.
        let req = AnalysisRequest {
            advisory_text: "x".to_string(),
            osv_id: None,
            package_name: None,
            ecosystem: None,
            repo_url: None,
            commit: None,
            git_ref: None,
            subpath: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert!(json.get("repo_url").is_none());
    }

    #[tokio::test]
    async fn a_report_with_unknown_fields_still_deserializes() {
        // The analyser owns the report schema and will grow it; AISE must
        // route new fields through untouched rather than 500.
        let server = MockServer::start().await;
        let id = Uuid::new_v4();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id,
                "status": "completed",
                "some_future_field": 42,
                "report": { "priority": "direct_references", "brand_new_key": ["x"] }
            })))
            .mount(&server)
            .await;

        let view = ReachClient::new(server.uri(), "t").get_analysis(id).await.unwrap();
        assert_eq!(view.status, "completed");
        assert_eq!(view.report.unwrap()["brand_new_key"][0], "x");
    }

    #[tokio::test]
    async fn a_missing_analysis_is_reported_as_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = ReachClient::new(server.uri(), "t").get_analysis(Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ReachError::NotFound));
    }

    #[tokio::test]
    async fn an_error_body_is_truncated_before_it_reaches_a_log_line() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("x".repeat(10_000)))
            .mount(&server)
            .await;

        let err = ReachClient::new(server.uri(), "t")
            .create_analysis(&AnalysisRequest {
                advisory_text: "x".into(),
                osv_id: None,
                package_name: None,
                ecosystem: None,
                repo_url: None,
                commit: None,
                git_ref: None,
                subpath: None,
            })
            .await
            .unwrap_err();
        match err {
            ReachError::Upstream { status, body } => {
                assert_eq!(status, 500);
                assert!(body.len() < 500);
            }
            other => panic!("expected an upstream error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unreachable_analyser_is_a_distinct_error_kind() {
        // Nothing listening: the UI must be able to say "analyser is down"
        // rather than "your analysis failed".
        let err = ReachClient::new("http://127.0.0.1:1", "t")
            .get_analysis(Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(matches!(err, ReachError::Unavailable(_)));
    }

    #[test]
    fn base_url_trailing_slashes_do_not_produce_double_slashes() {
        assert_eq!(ReachClient::new("http://h:3100/", "t").base_url(), "http://h:3100");
    }
}
