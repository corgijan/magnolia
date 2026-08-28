#[derive(Debug, thiserror::Error)]
pub enum DepsDevError {
    #[error("request error: {0}")]
    Request(String),
    #[error("deps.dev returned status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("unexpected response shape: {0}")]
    UnexpectedResponse(String),
}
