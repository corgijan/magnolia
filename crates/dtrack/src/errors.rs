#[derive(Debug, thiserror::Error)]
pub enum DtrackError {
    #[error("request error: {0}")]
    Request(String),
    #[error("dtrack returned status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("unexpected response shape: {0}")]
    UnexpectedResponse(String),
}
