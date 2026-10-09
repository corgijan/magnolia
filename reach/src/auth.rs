//! Bearer-token authentication.
//!
//! One static token for the whole service (`REACH_API_TOKEN`). Deliberately
//! not a tenant/RBAC system: `reach` holds no per-tenant data and answers
//! only to AISE, so a second copy of AISE's key infrastructure would be
//! surface area with nothing behind it. Multi-tenancy stays where the data
//! is.

use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

/// Compares in constant time. A byte-by-byte `==` on a secret leaks its
/// prefix through timing, which is enough to recover a token given enough
/// requests — the same reasoning behind AISE's `subtle`-based key check.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    // Length is not secret (and comparing different-length slices would
    // panic), but the contents are.
    a.len() == b.len() && a.ct_eq(b).into()
}

/// Extracts the token from an `Authorization: Bearer <token>` header.
pub fn bearer_token(header: &str) -> Option<&str> {
    let rest = header.strip_prefix("Bearer ").or_else(|| header.strip_prefix("bearer "))?;
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// Guards every route except `/health` and the OpenAPI document (see
/// [`crate::api`], which applies this layer only to the API router).
///
/// `expected_token = None` means authentication is disabled — a local dev
/// convenience that startup logs loudly, never a silent default.
pub async fn require_token(
    axum::extract::State(expected): axum::extract::State<Option<std::sync::Arc<String>>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(expected) = expected else {
        return next.run(req).await;
    };

    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);

    match presented {
        Some(token) if token_matches(&expected, token) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({ "error": "Unauthorized" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_tokens_are_accepted_and_others_are_not() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-token", "secret-tokeN"));
        assert!(!token_matches("secret-token", "wrong"));
        assert!(!token_matches("secret-token", ""));
    }

    #[test]
    fn a_prefix_of_the_real_token_is_rejected() {
        // The length check must not be a shortcut that accepts a prefix.
        assert!(!token_matches("secret-token", "secret"));
        assert!(!token_matches("secret", "secret-token"));
    }

    #[test]
    fn bearer_parsing_accepts_both_capitalisations_and_rejects_junk() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), Some("abc"));
        assert_eq!(bearer_token("Bearer   abc  "), Some("abc"));
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("abc"), None);
    }
}
