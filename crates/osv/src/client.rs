use crate::errors::OsvError;
use crate::models::{PackageQuery, QueryBatchResponse, VulnDetail};

/// Chunk size for `POST /v1/querybatch`. OSV's own API reference
/// (google.github.io/osv.dev/post-v1-querybatch/, checked when this was
/// written) does not state a maximum batch size — this is a defensive cap
/// chosen to keep request bodies small, not a documented limit.
const QUERY_BATCH_CHUNK_SIZE: usize = 200;

/// Thin typed wrapper around OSV's public REST API — mirrors the
/// `magnolia-dtrack`/`magnolia-signer`/`magnolia-storage` pattern of one
/// narrow crate per external system. No API key: OSV's API is public/free.
pub struct OsvClient {
    base_url: String,
    http: reqwest::Client,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new("https://api.osv.dev")
    }
}

impl OsvClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), http: reqwest::Client::new() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// `POST /v1/querybatch` — returns one `Vec<String>` of matched
    /// vulnerability IDs per input query, in the same order (OSV guarantees
    /// response ordering matches input order). Chunks the input into
    /// `QUERY_BATCH_CHUNK_SIZE`-sized requests since there's no documented
    /// max batch size to rely on. Pagination (`next_page_token`, triggered
    /// past 1000 vulns for one query or 3000 total per OSV's docs) is
    /// deliberately not followed — irrelevant for this crate's only caller,
    /// which filters for the rare `MAL-` prefix and would never need more
    /// than a handful of IDs per query in practice.
    pub async fn query_batch(&self, queries: &[PackageQuery]) -> Result<Vec<Vec<String>>, OsvError> {
        let mut all_results = Vec::with_capacity(queries.len());
        for chunk in queries.chunks(QUERY_BATCH_CHUNK_SIZE) {
            let body = serde_json::json!({ "queries": chunk });
            let resp = self
                .http
                .post(self.url("/v1/querybatch"))
                .json(&body)
                .send()
                .await
                .map_err(|e| OsvError::Request(e.to_string()))?;
            let resp = Self::check_status(resp).await?;
            let parsed: QueryBatchResponse =
                resp.json().await.map_err(|e| OsvError::UnexpectedResponse(e.to_string()))?;
            all_results.extend(parsed.results.into_iter().map(|r| r.vulns.into_iter().map(|v| v.id).collect()));
        }
        Ok(all_results)
    }

    /// `GET /v1/vulns/{id}` — fetches one vulnerability's record. Only ever
    /// called on the small subset of `MAL-`-prefixed hits from
    /// `query_batch`, never per-component.
    pub async fn get_vuln(&self, id: &str) -> Result<VulnDetail, OsvError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/vulns/{id}")))
            .send()
            .await
            .map_err(|e| OsvError::Request(e.to_string()))?;
        let resp = Self::check_status(resp).await?;
        resp.json().await.map_err(|e| OsvError::UnexpectedResponse(e.to_string()))
    }

    async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, OsvError> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(OsvError::Status { status, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn query_batch_returns_vuln_ids_in_request_order() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    { "vulns": [{ "id": "MAL-2024-0001" }] },
                    { "vulns": [] },
                ]
            })))
            .mount(&server)
            .await;
        let client = OsvClient::new(server.uri());

        let queries = vec![
            PackageQuery::by_purl("pkg:npm/left-pad@1.0.0"),
            PackageQuery::by_purl("pkg:npm/clean-pkg@1.0.0"),
        ];
        let results = client.query_batch(&queries).await.unwrap();

        assert_eq!(results, vec![vec!["MAL-2024-0001".to_string()], vec![]]);
    }

    #[tokio::test]
    async fn query_batch_chunks_large_batches_into_multiple_requests() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(move |req: &wiremock::Request| {
                let body: serde_json::Value = req.body_json().unwrap();
                let n = body["queries"].as_array().unwrap().len();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": vec![serde_json::json!({ "vulns": [] }); n]
                }))
            })
            .expect(2)
            .mount(&server)
            .await;
        let client = OsvClient::new(server.uri());

        let queries: Vec<PackageQuery> = (0..(QUERY_BATCH_CHUNK_SIZE + 10))
            .map(|i| PackageQuery::by_purl(format!("pkg:npm/pkg-{i}@1.0.0")))
            .collect();
        let results = client.query_batch(&queries).await.unwrap();

        assert_eq!(results.len(), QUERY_BATCH_CHUNK_SIZE + 10);
        server.verify().await;
    }

    #[tokio::test]
    async fn query_batch_maps_non_success_status_to_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;
        let client = OsvClient::new(server.uri());

        let err = client.query_batch(&[PackageQuery::by_purl("pkg:npm/left-pad@1.0.0")]).await.unwrap_err();

        match err {
            OsvError::Status { status, body } => {
                assert_eq!(status, 500);
                assert_eq!(body, "internal error");
            }
            other => panic!("expected OsvError::Status, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_vuln_parses_id_and_summary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/MAL-2024-0001"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "MAL-2024-0001",
                "summary": "known malicious package"
            })))
            .mount(&server)
            .await;
        let client = OsvClient::new(server.uri());

        let detail = client.get_vuln("MAL-2024-0001").await.unwrap();

        assert_eq!(detail.id, "MAL-2024-0001");
        assert_eq!(detail.summary.as_deref(), Some("known malicious package"));
    }

    #[tokio::test]
    async fn get_vuln_maps_not_found_to_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/MAL-does-not-exist"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        let client = OsvClient::new(server.uri());

        let err = client.get_vuln("MAL-does-not-exist").await.unwrap_err();

        assert!(matches!(err, OsvError::Status { status: 404, .. }));
    }
}
