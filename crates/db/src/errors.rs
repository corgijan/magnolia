#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Query error: {0}")]
    QueryError(String),
    #[error("Migration error: {0}")]
    MigrationError(String),
    #[error("Conflict: {0}")]
    Conflict(String),
}

pub(crate) fn map_query_error(e: sqlx::Error) -> DbError {
    if let sqlx::Error::Database(ref db_err) = e {
        if db_err.is_unique_violation() {
            return DbError::Conflict(db_err.message().to_string());
        }
    }
    DbError::QueryError(e.to_string())
}
