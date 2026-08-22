use std::str::FromStr;

use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use sbomstash_auth::{ApiKeyVerifier, Grant, Role};
use uuid::Uuid;

use crate::errors::ApiError;
use crate::state::AppState;

/// Authenticated API key grant, extracted from the `Authorization` header.
///
/// Key format: `Bearer <key_id>:<secret>` where `key_id` is a public UUID
/// used to look up the Argon2 hash and `secret` is verified against it.
pub struct AuthGrant {
    pub key_id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: Role,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    /// Whether this key's own tenant is the platform/bootstrap tenant. Only
    /// super_admin keys in that specific tenant may act across other
    /// tenants — a super_admin key self-minted by some other tenant's
    /// domain_admin does NOT get that reach.
    pub is_platform_tenant: bool,
}

impl AuthGrant {
    pub fn to_grant(&self) -> Grant {
        Grant {
            tenant_id: self.tenant_id,
            domain: self.domain.clone(),
            namespace_scope: self.namespace_scope.clone(),
            role: self.role,
            expires_at: self.expires_at,
            revoked: self.revoked,
        }
    }

    /// Stable principal identifier for audit logs.
    pub fn principal(&self) -> String {
        format!("apikey:{}", self.key_id)
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthGrant {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        let (key_id_str, secret) = token
            .split_once(':')
            .ok_or_else(|| ApiError::BadRequest("API key must be <key_id>:<secret>".to_string()))?;

        let key_id = Uuid::from_str(key_id_str).map_err(|_| ApiError::Unauthorized)?;
        let row = state
            .db
            .lookup_api_key(key_id)
            .await
            .map_err(|e| ApiError::InternalError(e.to_string()))?
            .ok_or(ApiError::Unauthorized)?;

        let valid = ApiKeyVerifier::verify(secret, &row.key_hash)
            .map_err(|e| ApiError::InternalError(e.to_string()))?;
        if !valid {
            return Err(ApiError::Unauthorized);
        }

        let role = Role::from_str(&row.role)
            .map_err(|_| ApiError::InternalError(format!("unknown role in database: {}", row.role)))?;

        // A revoked or expired key must never authenticate successfully,
        // for any endpoint (not just RBAC-gated ones).
        if row.revoked {
            return Err(ApiError::Unauthorized);
        }
        if let Some(expires_at) = row.expires_at {
            if expires_at < Utc::now() {
                return Err(ApiError::Unauthorized);
            }
        }

        // Only matters (and is only worth the extra lookup) for super_admin.
        let is_platform_tenant = if role == Role::SuperAdmin {
            state
                .db
                .get_tenant(row.tenant_id)
                .await
                .map_err(|e| ApiError::InternalError(e.to_string()))?
                .map(|t| t.is_platform)
                .unwrap_or(false)
        } else {
            false
        };

        Ok(AuthGrant {
            key_id: row.id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            namespace_scope: row.namespace_scope,
            role,
            expires_at: row.expires_at,
            revoked: row.revoked,
            is_platform_tenant,
        })
    }
}

/// Enforces the RBAC matrix for an action on a resource.
pub fn require(
    grant: &AuthGrant,
    action: sbomstash_auth::Action,
    namespace: &str,
) -> Result<(), ApiError> {
    sbomstash_auth::RbacEngine::require_role(&grant.to_grant(), &grant.domain, namespace, action)
        .map_err(|e| ApiError::Forbidden(e.to_string()))
}