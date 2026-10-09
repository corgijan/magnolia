//! OpenAI-compatible inference client.
//!
//! Course constraint: every LLM call in this project goes out as
//! `POST {base_url}/v1/chat/completions` with the OpenAI request shape. No
//! provider SDK is linked and no provider-specific endpoint appears here, so
//! pointing [`crate::config::AiConfig::base_url`] at Ollama, llama.cpp,
//! vLLM, or a hosted gateway is purely an env-var change.
//!
//! # The four graded failure modes
//!
//! 1. **Server unavailable** — connection refused / DNS failure ->
//!    [`AiError::Unavailable`].
//! 2. **Timeout** — the request exceeds `REACH_AI_TIMEOUT_SECS` ->
//!    [`AiError::Timeout`].
//! 3. **Invalid or unparseable output** — the model returns prose, truncated
//!    JSON, or JSON that does not fit the target type. Handled by
//!    [`ChatClient::complete_json`]: validate app-side, **retry exactly
//!    once** with a repair instruction, then give up with
//!    [`AiError::InvalidOutput`] so the caller can degrade.
//! 4. **Processing failure** — anything else (5xx, malformed envelope,
//!    empty choices) -> [`AiError::Upstream`] / [`AiError::EmptyResponse`].
//!
//! None of these is ever propagated as a 500 by the pipeline. Each stage
//! catches its own inference error, records a [`crate::models::StageOutcome`],
//! and continues with whatever deterministic evidence it already has —
//! exactly how AISE's disabled-tenant-signal paths degrade.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::AiConfig;

pub mod prompts;

#[derive(Debug, thiserror::Error)]
pub enum AiError {
    /// Failure mode 1.
    #[error("inference server unavailable at {base_url}: {source}")]
    Unavailable {
        base_url: String,
        #[source]
        source: reqwest::Error,
    },
    /// Failure mode 2.
    #[error("inference timed out after {0:?}")]
    Timeout(Duration),
    /// Failure mode 4 (upstream said no).
    #[error("inference server returned HTTP {status}: {body}")]
    Upstream { status: u16, body: String },
    /// Failure mode 4 (envelope was not what the API contract promises).
    #[error("inference server returned no usable choice")]
    EmptyResponse,
    /// A specific, more actionable shape of failure mode 4: the response had
    /// a `choices[].message.reasoning` (or `reasoning_content`) field with
    /// text in it, but `content` was empty or missing — the model's token
    /// budget was spent entirely on chain-of-thought before it reached an
    /// answer. Distinct from `EmptyResponse` so the fix (raise
    /// `REACH_AI_MAX_TOKENS`) is stated, not just implied. Carries a bounded
    /// snippet of the captured reasoning as evidence of what happened.
    #[error(
        "the model's token budget was exhausted during reasoning, before it wrote an answer \
         (raise REACH_AI_MAX_TOKENS) — captured reasoning: {0}"
    )]
    TruncatedDuringReasoning(String),
    /// Failure mode 3, after the single retry.
    #[error("model output was not valid for the requested schema after one retry: {0}")]
    InvalidOutput(String),
}

impl AiError {
    /// Short, stable tag for report/eval aggregation — the human message
    /// varies, this does not.
    pub fn kind(&self) -> &'static str {
        match self {
            AiError::Unavailable { .. } => "unavailable",
            AiError::Timeout(_) => "timeout",
            AiError::Upstream { .. } => "upstream_error",
            AiError::EmptyResponse => "empty_response",
            AiError::TruncatedDuringReasoning(_) => "truncated_during_reasoning",
            AiError::InvalidOutput(_) => "invalid_output",
        }
    }
}

/// Outcome of [`ChatClient::probe`]. Serializable so it can be surfaced
/// verbatim on `/health` as well as logged.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// A real test completion succeeded: the server accepted the request and
    /// answered with usable JSON content. This is the strongest signal
    /// available — it is the exact request shape a real analysis makes.
    Reachable {
        /// `Some(true/false)` when `/v1/models` could be checked against the
        /// configured model; `None` when the server does not support
        /// listing, or returned something unparseable — neither is a
        /// problem on its own, since this outcome already proves
        /// `/v1/chat/completions` works.
        model_listed: Option<bool>,
    },
    /// A connection was made and an HTTP response came back, but it was not
    /// 2xx. The server exists; something about the request or its
    /// configuration is wrong — a stale `REACH_AI_API_KEY` is the common
    /// case (401). `detail` carries a bounded snippet of the response body.
    RespondedWithError { status: u16, detail: String },
    /// A 2xx response came back, but it could not be turned into a usable
    /// answer — an envelope that does not match the OpenAI shape, an empty
    /// `choices` array, or content that is not valid JSON despite
    /// `response_format: json_object` being requested. This is exactly the
    /// failure a `/v1/models`-only check cannot see: the server is up, and
    /// may even list the right model, while the endpoint every real
    /// analysis depends on returns something unusable.
    RespondedButUnusable { detail: String },
    /// No response at all: DNS failure, connection refused, or the
    /// configured `REACH_AI_TIMEOUT_SECS` elapsing. The likely cause is a
    /// wrong `REACH_AI_BASE_URL`, or the server (e.g. Ollama) not running
    /// yet.
    Unreachable { detail: String },
}

/// The schema [`ChatClient::probe`] asks for — a real target type, not a
/// generic `serde_json::Value`, so the probe validates the model can
/// actually follow a field-name-and-type schema (what every real stage B/D
/// prompt asks for), not merely produce *some* valid JSON.
#[derive(Debug, Deserialize)]
struct ProbeAck {
    #[allow(dead_code)]
    ready: bool,
}

impl ProbeOutcome {
    /// True only for a fully successful test completion — the useful sense
    /// of "reachable" for this probe, since the whole point of testing a
    /// real completion instead of just `/v1/models` is to catch the case
    /// where the server responds but the endpoint real analyses use does
    /// not actually work.
    pub fn is_reachable(&self) -> bool {
        matches!(self, ProbeOutcome::Reachable { .. })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: &'static str,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: "system", content: content.into() }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: "user", content: content.into() }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: "assistant", content: content.into() }
    }
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    max_tokens: u32,
    temperature: f32,
    /// Servers that support it (OpenAI, vLLM, recent Ollama) will hard-
    /// constrain output to JSON. Servers that don't simply ignore an unknown
    /// field, which is why this is sent unconditionally rather than gated on
    /// a capability flag we would have to configure per backend — and why
    /// [`ChatClient::complete_json`] still validates and repairs regardless.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    #[serde(default)]
    message: Option<ResponseMessage>,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    #[serde(default)]
    content: Option<String>,
    /// Some reasoning-capable backends (vLLM-served Qwen3, observed live
    /// against Hetzner's Inference API among others) put chain-of-thought
    /// here and leave `content: null` until the model finishes "thinking" —
    /// if `max_tokens` runs out first, `content` never arrives at all. Two
    /// field names accepted since backends disagree on which one to use.
    #[serde(default, alias = "reasoning_content")]
    reasoning: Option<String>,
}

/// One inference call's observability record — what the eval harness
/// aggregates into latency and retry-rate metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallStats {
    pub attempts: u32,
    pub latency_ms: u64,
    pub repaired: bool,
}

#[derive(Clone)]
pub struct ChatClient {
    http: reqwest::Client,
    config: AiConfig,
}

impl ChatClient {
    pub fn new(config: AiConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            // A hung TCP connect must hit the same deadline as a slow
            // generation, otherwise "server unavailable" can take longer to
            // surface than "server is thinking".
            .connect_timeout(config.timeout.min(Duration::from_secs(10)))
            .build()
            .unwrap_or_default();
        Self { http, config }
    }

    pub fn model(&self) -> &str {
        &self.config.model
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    fn endpoint(&self) -> String {
        format!("{}/v1/chat/completions", self.config.base_url.trim_end_matches('/'))
    }

    /// One raw completion. Maps transport failures onto the failure-mode
    /// taxonomy above; does not interpret the content.
    pub async fn complete(&self, messages: &[ChatMessage], json_mode: bool) -> Result<String, AiError> {
        let body = ChatRequest {
            model: &self.config.model,
            messages,
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
            response_format: json_mode.then_some(ResponseFormat { kind: "json_object" }),
        };

        let mut req = self.http.post(self.endpoint()).json(&body);
        if let Some(key) = &self.config.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                AiError::Timeout(self.config.timeout)
            } else {
                AiError::Unavailable { base_url: self.config.base_url.clone(), source: e }
            }
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AiError::Upstream {
                status: status.as_u16(),
                // Bounded: an upstream error page must not end up as a
                // multi-megabyte string in a log line or a database row.
                body: truncate(&body, 500),
            });
        }

        // Buffered as text first, not `.json()` directly: a `Response` is
        // consumed by a failed `.json()` call, so the raw bytes would be
        // gone by the time we know parsing failed — leaving an operator
        // debugging their own endpoint with nothing but "error decoding
        // response body" and no idea what was actually sent back (an SSE
        // stream when a plain response was requested, an HTML error page
        // from a gateway in front of the model, a differently-shaped
        // envelope). Captured here, a snippet of it becomes the error the
        // caller can actually act on.
        let raw = resp.text().await.map_err(|e| {
            if e.is_timeout() {
                AiError::Timeout(self.config.timeout)
            } else {
                AiError::Upstream { status: status.as_u16(), body: format!("could not read response body: {e}") }
            }
        })?;
        let parsed: ChatResponse = serde_json::from_str(&raw).map_err(|e| AiError::Upstream {
            status: status.as_u16(),
            body: format!("HTTP {} but the body did not match the expected envelope ({e}): {}", status.as_u16(), truncate(raw.trim(), 300)),
        })?;

        // Two passes, not one `find_map`: `content` beats `reasoning` from
        // *any* choice, so a first choice with only reasoning must not shadow
        // a second choice that actually has content. Separately tracking
        // whether reasoning was seen at all is what turns a bare
        // "no usable choice" into the specific, actionable diagnosis below.
        let mut reasoning_snippet: Option<String> = None;
        for choice in &parsed.choices {
            let Some(message) = &choice.message else { continue };
            if let Some(content) = message.content.as_deref() {
                if !content.trim().is_empty() {
                    return Ok(content.to_string());
                }
            }
            if reasoning_snippet.is_none() {
                if let Some(r) = message.reasoning.as_deref() {
                    if !r.trim().is_empty() {
                        reasoning_snippet = Some(truncate(r.trim(), 200));
                    }
                }
            }
        }

        match reasoning_snippet {
            Some(snippet) => Err(AiError::TruncatedDuringReasoning(snippet)),
            None => Err(AiError::EmptyResponse),
        }
    }

    /// A real `/v1/chat/completions` round trip, used as a startup check.
    ///
    /// Never called from a request path — the pipeline's own per-stage
    /// degradation (unaffected by anything in this function) is what
    /// protects an in-flight analysis if the server goes down *after* the
    /// process is already up. This function itself does not gate anything;
    /// whether its result gates startup is the caller's decision.
    /// `main.rs` treats anything but `Reachable` as fatal and refuses to
    /// bind the listener at all — "the container is running" is meant to
    /// imply "the AI feature is usable", not "usable once you fix the
    /// endpoint and restart".
    ///
    /// Deliberately a **completion**, not just `GET /v1/models`: listing is
    /// a side endpoint some minimal servers don't implement at all, and its
    /// success proves nothing about the endpoint every real analysis
    /// actually depends on. A server can list itself as reachable, even list
    /// the right model, and still return something `/v1/chat/completions`
    /// cannot use — envelope shape mismatches, `response_format` handled
    /// oddly, and similar are all real, observed failure modes that a
    /// listing-only check cannot see. This runs through [`Self::complete`]
    /// with `json_mode: true`, the exact call shape stage B and stage D
    /// make, using the exact configured timeout and token budget — so a
    /// `REACH_AI_MAX_TOKENS` too small for the configured model shows up
    /// here too, not just mid-analysis.
    pub async fn probe(&self) -> ProbeOutcome {
        // Describes a schema (field name + type), the same shape every real
        // stage B/D prompt uses — deliberately not "reply with exactly this
        // literal JSON", which is a different, unusual task (verbatim
        // reproduction of an embedded example) that a constrained-decoding
        // backend can handle worse than a normal schema-completion request.
        // Observed live: a real hosted model produced malformed, doubled
        // braces for the old literal-echo prompt on two consecutive
        // attempts, yet answered a schema-shaped prompt like this normally.
        let messages = [
            ChatMessage::system(
                "You are answering a one-time startup health check for an OpenAI-compatible \
                 inference endpoint. Reply with a single JSON object and nothing else.",
            ),
            ChatMessage::user(
                "Respond with a JSON object that has exactly one field: \"ready\", a boolean, \
                 set to true. Do not include any other fields or text.",
            ),
        ];

        // `complete_json`, not raw `complete` + a manual parse check: this
        // gives the probe the exact same one-repair-retry tolerance every
        // real analysis gets from stage B/D. Observed live against a real
        // hosted model that a single malformed-JSON response is sometimes
        // just noise, not a real problem with the endpoint — a startup
        // check with *zero* retry tolerance was stricter than the pipeline
        // it exists to protect, and could refuse to start over a flake that
        // would have silently self-corrected mid-analysis.
        let (result, _stats) = self.complete_json::<ProbeAck>(&messages).await;
        match result {
            Err(AiError::Unavailable { source, .. }) => {
                ProbeOutcome::Unreachable { detail: source.to_string() }
            }
            Err(AiError::Timeout(d)) => {
                ProbeOutcome::Unreachable { detail: format!("timed out after {d:?}") }
            }
            Err(AiError::Upstream { status, body }) => {
                // Reached two different ways: a real non-2xx HTTP response,
                // or a 2xx whose body did not match the expected envelope.
                // The status tells them apart -- the second is a "responded,
                // but not usably" case (this is exactly the Hetzner-endpoint
                // shape that motivated this probe existing at all), not an
                // HTTP error.
                if (200..300).contains(&status) {
                    ProbeOutcome::RespondedButUnusable { detail: body }
                } else {
                    ProbeOutcome::RespondedWithError { status, detail: body }
                }
            }
            Err(AiError::EmptyResponse) => ProbeOutcome::RespondedButUnusable {
                detail: "the server returned 200 with no completion content".to_string(),
            },
            Err(e @ AiError::TruncatedDuringReasoning(_)) => {
                ProbeOutcome::RespondedButUnusable { detail: e.to_string() }
            }
            // The retry itself was attempted and still failed -- two
            // consecutive malformed answers, not one flake.
            Err(AiError::InvalidOutput(detail)) => {
                ProbeOutcome::RespondedButUnusable { detail }
            }
            Ok(_) => ProbeOutcome::Reachable { model_listed: self.model_listing().await },
        }
    }

    /// Best-effort, informational only: does `GET /v1/models` (when the
    /// server implements it) list the configured model by name. `None` when
    /// listing isn't supported, the request fails, or the body can't be
    /// read as the expected shape — none of which is itself a problem, since
    /// only `/v1/chat/completions` is required and [`Self::probe`] has
    /// already exercised that directly by the time this runs. Bounded by a
    /// short timeout independent of `REACH_AI_TIMEOUT_SECS`: listing should
    /// be near-instant on any real server, regardless of how long that
    /// setting allows a generation to take.
    async fn model_listing(&self) -> Option<bool> {
        const LISTING_TIMEOUT: Duration = Duration::from_secs(5);

        let url = format!("{}/v1/models", self.config.base_url.trim_end_matches('/'));
        let mut req = self.http.get(&url);
        if let Some(key) = &self.config.api_key {
            req = req.bearer_auth(key);
        }

        let resp = tokio::time::timeout(LISTING_TIMEOUT, req.send()).await.ok()?.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let value: serde_json::Value = resp.json().await.ok()?;
        let arr = value.get("data")?.as_array()?;
        Some(arr.iter().any(|m| m.get("id").and_then(|i| i.as_str()) == Some(self.config.model.as_str())))
    }

    /// A completion that must deserialize into `T`.
    ///
    /// This is failure mode 3's handler: parse app-side, and on failure send
    /// **one** repair turn that shows the model its own output and the
    /// parser's complaint. A second failure returns [`AiError::InvalidOutput`]
    /// — the caller degrades from there rather than retrying forever, which
    /// is the difference between a slow analysis and an unbounded spend
    /// against a local model that simply cannot produce the shape.
    pub async fn complete_json<T: DeserializeOwned>(
        &self,
        messages: &[ChatMessage],
    ) -> (Result<T, AiError>, CallStats) {
        let started = std::time::Instant::now();
        let mut stats = CallStats { attempts: 1, ..Default::default() };

        let first = self.complete(messages, true).await;
        let first_raw = match first {
            Ok(raw) => raw,
            // Transport-level failure: retrying here would just repeat the
            // same outage. Only *content* failures get the repair turn.
            Err(e) => {
                stats.latency_ms = started.elapsed().as_millis() as u64;
                return (Err(e), stats);
            }
        };

        let first_err = match parse_lenient::<T>(&first_raw) {
            Ok(v) => {
                stats.latency_ms = started.elapsed().as_millis() as u64;
                return (Ok(v), stats);
            }
            Err(e) => e,
        };

        tracing::warn!(error = %first_err, "model output failed validation; retrying once");
        stats.attempts = 2;
        stats.repaired = true;

        let mut repair: Vec<ChatMessage> = messages.to_vec();
        repair.push(ChatMessage::assistant(truncate(&first_raw, 2000)));
        repair.push(ChatMessage::user(format!(
            "That response could not be parsed: {first_err}. Reply again with ONLY the JSON \
             object, no prose, no markdown fence, no trailing commentary. Every required field \
             must be present."
        )));

        let result = match self.complete(&repair, true).await {
            Ok(raw) => parse_lenient::<T>(&raw).map_err(AiError::InvalidOutput),
            Err(e) => Err(e),
        };
        stats.latency_ms = started.elapsed().as_millis() as u64;
        (result, stats)
    }
}

/// Parses model output into `T`, tolerating the two things small models do
/// even when told not to: wrapping the object in a ```json fence, and
/// prefixing it with a sentence of prose. Anything beyond that is a genuine
/// validation failure and gets the repair turn.
pub fn parse_lenient<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    let mut first_error: Option<String> = None;

    // Every balanced object in the output, in order, is a candidate. One
    // pass would be enough for an instruction-tuned model, but a reasoning
    // model emits its <think> prose first, and that prose routinely contains
    // a brace-delimited example that parses as JSON or fails to parse at
    // all. Trying each candidate in turn finds the real answer in both
    // cases; stopping at the first would spend a whole repair round trip
    // rediscovering it.
    for candidate in json_object_candidates(raw) {
        match serde_json::from_str::<T>(&candidate) {
            Ok(v) => return Ok(v),
            Err(e) => {
                first_error.get_or_insert_with(|| e.to_string());
            }
        }
    }

    Err(first_error.unwrap_or_else(|| {
        format!("no JSON object found in output (started with: {})", truncate(raw.trim(), 120))
    }))
}

/// Every balanced `{...}` span in `raw`, outermost-first.
fn json_object_candidates(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    // Bounded: a pathological output must not turn into a quadratic scan.
    const MAX_CANDIDATES: usize = 8;

    while offset < raw.len() && out.len() < MAX_CANDIDATES {
        let Some((start, found)) = extract_json_object(&raw[offset..]) else { break };
        offset += start + found.len();
        out.push(found);
    }
    out
}

/// Finds the outermost balanced `{...}` in a string, ignoring braces that
/// appear inside JSON string literals (a code snippet quoted back at us
/// routinely contains unbalanced braces, and a naive `rfind('}')` would cut
/// the object in the wrong place). Returns the byte offset the match starts
/// at (relative to `raw`) alongside the matched text.
///
/// Retries from each subsequent `{` if an earlier one fails to balance.
/// Observed live: some models emit a stray leading `{"` before the real
/// object (`{"{"ready":true}`) — the first `{` reads the rest as opening a
/// one-character string `"{"`, and the string never finds its matching
/// closing quote, which desyncs quote-tracking for the remainder and makes
/// the whole span look unbalanced even though a real object follows.
/// Starting over at the next `{` recovers it.
pub fn extract_json_object(raw: &str) -> Option<(usize, String)> {
    let bytes = raw.as_bytes();
    // Bounded for the same reason candidate extraction is: a pathological
    // output (lots of stray `{`) must not turn into a quadratic scan.
    const MAX_START_ATTEMPTS: usize = 8;
    let mut search_from = 0usize;

    for _ in 0..MAX_START_ATTEMPTS {
        let start = search_from + raw[search_from..].find('{')?;
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;

        for (i, &b) in bytes.iter().enumerate().skip(start) {
            if in_string {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_string = false;
                }
                continue;
            }
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((start, raw[start..=i].to_string()));
                    }
                }
                _ => {}
            }
        }
        search_from = start + 1;
    }
    None
}

/// Byte-bounded truncation that never splits a UTF-8 character.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Sample {
        name: String,
        #[serde(default)]
        count: u32,
    }

    mod complete_tests {
        use super::super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn client_for(base_url: &str) -> ChatClient {
            ChatClient::new(AiConfig {
                base_url: base_url.to_string(),
                model: "m".to_string(),
                api_key: None,
                timeout: Duration::from_secs(10),
                max_tokens: 128,
                temperature: 0.0,
            })
        }

        #[tokio::test]
        async fn a_200_with_a_body_that_does_not_match_the_envelope_reports_a_snippet_of_it() {
            // This is the exact shape of failure a misbehaving or
            // differently-configured OpenAI-compatible endpoint produces: an
            // HTTP 200, but a body that is not the expected envelope (an SSE
            // stream, a gateway's HTML error page, a provider-specific
            // wrapper). The error must carry enough of the real body for an
            // operator to diagnose it -- not just "error decoding response
            // body", which says nothing about what was actually returned.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string("data: {\"delta\":\"hello\"}\n\n")
                        .insert_header("content-type", "text/event-stream"),
                )
                .mount(&server)
                .await;

            let err = client_for(&server.uri())
                .complete(&[ChatMessage::user("hi")], false)
                .await
                .unwrap_err();

            match err {
                AiError::Upstream { status, body } => {
                    assert_eq!(status, 200);
                    assert!(body.contains("delta"), "error should quote the real body, got: {body}");
                }
                other => panic!("expected Upstream, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_well_formed_envelope_still_parses_normally() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": "hello"}}]
                })))
                .mount(&server)
                .await;

            let out = client_for(&server.uri()).complete(&[ChatMessage::user("hi")], false).await.unwrap();
            assert_eq!(out, "hello");
        }

        #[tokio::test]
        async fn null_content_with_a_reasoning_field_is_reported_as_a_specific_truncation() {
            // The real shape observed live against Hetzner's Inference API
            // (a vLLM-served Qwen3 reasoning model): content is null while
            // the model is still "thinking", and if max_tokens runs out
            // before it starts the answer, content never arrives at all.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "reasoning": "Here's a thinking process:\n\n1. "
                        }
                    }]
                })))
                .mount(&server)
                .await;

            let err = client_for(&server.uri())
                .complete(&[ChatMessage::user("hi")], false)
                .await
                .unwrap_err();
            match err {
                AiError::TruncatedDuringReasoning(snippet) => {
                    assert!(snippet.contains("thinking process"));
                }
                other => panic!("expected TruncatedDuringReasoning, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn the_alternate_reasoning_content_field_name_is_also_accepted() {
            // Different OpenAI-compatible backends disagree on the field
            // name for this.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": null, "reasoning_content": "pondering..."}}]
                })))
                .mount(&server)
                .await;

            let err = client_for(&server.uri())
                .complete(&[ChatMessage::user("hi")], false)
                .await
                .unwrap_err();
            assert!(matches!(err, AiError::TruncatedDuringReasoning(s) if s.contains("pondering")));
        }

        #[tokio::test]
        async fn content_from_a_later_choice_is_not_shadowed_by_an_earlier_reasoning_only_one() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [
                        {"message": {"content": null, "reasoning": "thinking..."}},
                        {"message": {"content": "the real answer"}}
                    ]
                })))
                .mount(&server)
                .await;

            let out = client_for(&server.uri()).complete(&[ChatMessage::user("hi")], false).await.unwrap();
            assert_eq!(out, "the real answer");
        }

        #[tokio::test]
        async fn truly_empty_content_with_no_reasoning_at_all_is_still_the_generic_error() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "choices": [{"message": {"content": null}}]
                })))
                .mount(&server)
                .await;

            let err = client_for(&server.uri())
                .complete(&[ChatMessage::user("hi")], false)
                .await
                .unwrap_err();
            assert!(matches!(err, AiError::EmptyResponse));
        }
    }

    mod probe_tests {
        use super::super::*;
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn client_for(base_url: &str, api_key: Option<&str>) -> ChatClient {
            ChatClient::new(AiConfig {
                base_url: base_url.to_string(),
                model: "configured-model".to_string(),
                api_key: api_key.map(str::to_string),
                timeout: Duration::from_secs(5),
                max_tokens: 128,
                temperature: 0.0,
            })
        }

        fn ok_completion(body: &str) -> ResponseTemplate {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": body}}]
            }))
        }

        async fn mount_completions(server: &MockServer, response: ResponseTemplate) {
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(response)
                .mount(server)
                .await;
        }

        async fn mount_models_listing(server: &MockServer, ids: &[&str]) {
            let data: Vec<_> = ids.iter().map(|id| serde_json::json!({"id": id})).collect();
            Mock::given(method("GET"))
                .and(path("/v1/models"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": data})))
                .mount(server)
                .await;
        }

        #[tokio::test]
        async fn a_working_completion_and_a_matching_listing_is_reachable() {
            let server = MockServer::start().await;
            mount_completions(&server, ok_completion(r#"{"ready": true}"#)).await;
            mount_models_listing(&server, &["configured-model"]).await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::Reachable { model_listed } => assert_eq!(model_listed, Some(true)),
                other => panic!("expected Reachable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn reachable_but_flags_when_the_configured_model_is_not_in_the_listing() {
            let server = MockServer::start().await;
            mount_completions(&server, ok_completion(r#"{"ready": true}"#)).await;
            mount_models_listing(&server, &["some-other-model"]).await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::Reachable { model_listed } => assert_eq!(model_listed, Some(false)),
                other => panic!("expected Reachable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_completion_works_even_when_the_server_does_not_support_listing() {
            // Some minimal OpenAI-compatible servers only ever implement
            // /v1/chat/completions -- not supporting /v1/models must not
            // block the primary, more meaningful signal.
            let server = MockServer::start().await;
            mount_completions(&server, ok_completion(r#"{"ready": true}"#)).await;
            Mock::given(method("GET"))
                .and(path("/v1/models"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::Reachable { model_listed } => assert_eq!(model_listed, None),
                other => panic!("expected Reachable with an unknown listing, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_non_2xx_completion_response_is_reported_with_its_status() {
            let server = MockServer::start().await;
            mount_completions(&server, ResponseTemplate::new(401)).await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::RespondedWithError { status, .. } => assert_eq!(status, 401),
                other => panic!("expected RespondedWithError, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_2xx_response_that_does_not_match_the_envelope_is_unusable_not_an_http_error() {
            // The exact shape of failure that motivated testing a real
            // completion instead of only GET /v1/models: an endpoint that
            // answers 200 with something this client cannot parse as the
            // OpenAI envelope (an SSE stream, in this case).
            let server = MockServer::start().await;
            mount_completions(
                &server,
                ResponseTemplate::new(200)
                    .set_body_string("data: {\"delta\":\"hi\"}\n\n")
                    .insert_header("content-type", "text/event-stream"),
            )
            .await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::RespondedButUnusable { detail } => {
                    assert!(detail.contains("delta"), "should quote the real body, got: {detail}")
                }
                other => panic!("expected RespondedButUnusable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_2xx_completion_whose_content_is_not_json_is_unusable() {
            // json_mode was requested; content that is not JSON means the
            // server did not honour response_format, which every real
            // analysis (stage B, stage D) depends on.
            let server = MockServer::start().await;
            mount_completions(&server, ok_completion("Sure, everything looks fine!")).await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::RespondedButUnusable { detail } => {
                    assert!(detail.contains("everything looks fine"))
                }
                other => panic!("expected RespondedButUnusable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_malformed_first_answer_is_tolerated_if_the_repair_retry_succeeds() {
            // The exact real-world case this was rewritten for: a hosted
            // model that occasionally mangles its first JSON-mode answer.
            // `complete_json`'s own one-repair-retry logic must apply here
            // exactly as it does for a real stage B/D call, so a single
            // flake doesn't block startup over something a live analysis
            // would have silently recovered from.
            let server = MockServer::start().await;
            // The first attempt: malformed (matches everything that is NOT
            // the repair follow-up).
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(ok_completion(r#"{"{"ok": true}"#))
                .mount(&server)
                .await;
            // The repair retry's request body contains the parser's
            // complaint; route it to a valid answer instead. Higher
            // priority than the generic mock above (both default to 5,
            // which falls back to mount order -- the generic one was
            // mounted first and would otherwise win every match, repair
            // request included).
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(body_string_contains("could not be parsed"))
                .respond_with(ok_completion(r#"{"ready": true}"#))
                .with_priority(1)
                .mount(&server)
                .await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::Reachable { .. } => {}
                other => panic!("expected Reachable after the repair retry, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn two_consecutive_malformed_answers_still_fail_the_probe() {
            // The retry tolerance has a limit -- a genuinely broken
            // endpoint (not just one flake) must still refuse to start.
            let server = MockServer::start().await;
            mount_completions(&server, ok_completion(r#"{"{"ok": true}"#)).await;

            match client_for(&server.uri(), None).probe().await {
                ProbeOutcome::RespondedButUnusable { .. } => {}
                other => panic!("expected RespondedButUnusable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn nothing_listening_is_reported_unreachable() {
            match client_for("http://127.0.0.1:1", None).probe().await {
                ProbeOutcome::Unreachable { .. } => {}
                other => panic!("expected Unreachable, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn the_api_key_is_sent_on_the_completion_request() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(header("authorization", "Bearer sk-probe"))
                .respond_with(ok_completion(r#"{"ready": true}"#))
                .mount(&server)
                .await;
            mount_models_listing(&server, &[]).await;

            let outcome = client_for(&server.uri(), Some("sk-probe")).probe().await;
            assert!(outcome.is_reachable());
        }

        #[test]
        fn is_reachable_is_true_only_for_the_reachable_variant() {
            assert!(ProbeOutcome::Reachable { model_listed: None }.is_reachable());
            assert!(!ProbeOutcome::RespondedWithError { status: 500, detail: String::new() }.is_reachable());
            assert!(!ProbeOutcome::RespondedButUnusable { detail: "x".into() }.is_reachable());
            assert!(!ProbeOutcome::Unreachable { detail: "x".into() }.is_reachable());
        }
    }

    #[test]
    fn parses_a_bare_json_object() {
        let v: Sample = parse_lenient(r#"{"name":"a","count":2}"#).unwrap();
        assert_eq!(v, Sample { name: "a".into(), count: 2 });
    }

    #[test]
    fn parses_through_a_markdown_fence_and_leading_prose() {
        // Exactly what a 4B model does on its first attempt roughly half the
        // time; repairing this with a whole extra inference call would
        // double latency for no reason.
        let raw = "Sure! Here is the JSON:\n```json\n{\"name\":\"a\"}\n```\nHope that helps.";
        let v: Sample = parse_lenient(raw).unwrap();
        assert_eq!(v.name, "a");
    }

    #[test]
    fn braces_inside_string_literals_do_not_end_the_object() {
        // The stage D prompt quotes a source snippet back to the model, so
        // the answer routinely contains `{` and `}` inside a string value.
        let raw = r#"{"name":"fn main() { let x = 1; }","count":1}"#;
        let v: Sample = parse_lenient(raw).unwrap();
        assert_eq!(v.name, "fn main() { let x = 1; }");
    }

    #[test]
    fn escaped_quote_inside_a_string_does_not_end_the_string() {
        let raw = r#"{"name":"he said \"hi\" }","count":0}"#;
        let v: Sample = parse_lenient(raw).unwrap();
        assert_eq!(v.name, r#"he said "hi" }"#);
    }

    #[test]
    fn recovers_from_a_stray_leading_brace_quote_pair() {
        // Observed live against a real hosted model (Qwen3.8-27B via a
        // Hetzner endpoint), deterministically, on both the original and the
        // repair-retry attempt: the object arrives prefixed with a stray
        // `{"`, e.g. `{"{"ready":true}`. The first `{` reads the rest as a
        // one-character string `"{"` that never finds its closing quote,
        // which used to make the whole span look unbalanced and fail
        // extraction outright. The real object starts at the second `{`.
        #[derive(Debug, Deserialize, PartialEq)]
        struct Ack {
            ready: bool,
        }
        let v: Ack = parse_lenient(r#"{"{"ready":true}"#).unwrap();
        assert_eq!(v, Ack { ready: true });
    }

    #[test]
    fn finds_the_answer_after_a_reasoning_models_think_block() {
        // deepseek-r1 and friends emit their reasoning first; it commonly
        // contains braces, and the real answer is the last object.
        let raw = "<think>Maybe the shape is {\"x\": 1}? Let me reconsider.</think>\n\
                   {\"name\":\"real\",\"count\":5}";
        let v: Sample = parse_lenient(raw).unwrap();
        assert_eq!(v.name, "real");
        assert_eq!(v.count, 5);
    }

    #[test]
    fn candidate_scanning_is_bounded_and_terminates() {
        let raw = "{}".repeat(50);
        // No panic, no hang; simply no candidate that fits `Sample`.
        assert!(parse_lenient::<Sample>(&raw).is_err());
    }

    #[test]
    fn unbalanced_output_is_a_validation_failure_not_a_panic() {
        // Truncation at max_tokens is the single most common small-model
        // failure; it must surface as an error the caller can degrade on.
        assert!(parse_lenient::<Sample>(r#"{"name":"a","cou"#).is_err());
        assert!(parse_lenient::<Sample>("I don't know.").is_err());
    }

    #[test]
    fn wrong_shape_is_reported_rather_than_silently_defaulted() {
        // `name` is required; a model that omits it must trigger the repair
        // turn, not yield an empty-named ruleset.
        assert!(parse_lenient::<Sample>(r#"{"count":3}"#).is_err());
    }

    #[test]
    fn truncate_never_splits_a_utf8_character() {
        let s = "ααααα";
        let out = truncate(s, 5);
        assert!(out.starts_with("αα"));
        assert!(out.ends_with("…[truncated]"));
    }

    #[test]
    fn error_kinds_are_stable_tags() {
        assert_eq!(AiError::Timeout(Duration::from_secs(1)).kind(), "timeout");
        assert_eq!(AiError::EmptyResponse.kind(), "empty_response");
        assert_eq!(AiError::InvalidOutput("x".into()).kind(), "invalid_output");
    }
}
