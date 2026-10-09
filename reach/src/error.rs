//! Error types.
//!
//! Two layers, deliberately separate: [`ReachError`] is what the pipeline
//! and its I/O produce, [`ApiError`] is what a client sees. The conversion
//! between them is where internal detail stops — a git stderr blob or a
//! database error string never reaches an HTTP response body verbatim.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
pub enum ReachError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("fetch failed: {0}")]
    Fetch(#[from] crate::fetcher::FetchError),
    #[error("inference failed: {0}")]
    Ai(#[from] crate::ai::AiError),
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    BadRequest(String),
    NotFound,
    Internal(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized => write!(f, "Unauthorized"),
            ApiError::BadRequest(m) => write!(f, "Bad request: {m}"),
            ApiError::NotFound => write!(f, "Not found"),
            ApiError::Internal(m) => write!(f, "Internal error: {m}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<ReachError> for ApiError {
    fn from(e: ReachError) -> Self {
        // Logged in full, returned as a generic message: the detail is for
        // the operator's log, not for whoever called the API.
        tracing::error!(error = %e, "request failed");
        ApiError::Internal("internal error".to_string())
    }
}
