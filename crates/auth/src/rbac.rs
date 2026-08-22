use crate::AuthError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    #[serde(rename = "super_admin")]
    SuperAdmin,
    #[serde(rename = "domain_admin")]
    DomainAdmin,
    #[serde(rename = "uploader")]
    Uploader,
    #[serde(rename = "auditor")]
    Auditor,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::SuperAdmin => write!(f, "super_admin"),
            Role::DomainAdmin => write!(f, "domain_admin"),
            Role::Uploader => write!(f, "uploader"),
            Role::Auditor => write!(f, "auditor"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "super_admin" => Ok(Role::SuperAdmin),
            "domain_admin" => Ok(Role::DomainAdmin),
            "uploader" => Ok(Role::Uploader),
            "auditor" => Ok(Role::Auditor),
            _ => Err(AuthError::AccessDenied(format!("unknown role: {}", s))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub tenant_id: uuid::Uuid,
    pub domain: String,
    pub namespace_scope: String,
    pub role: Role,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked: bool,
}

/// Segment-aware prefix match: scope "/p1" covers "/p1" and "/p1/sub" but
/// NOT "/p10". Used both by RBAC enforcement and, standalone, to filter
/// listings/lookups down to a key's own namespace scope.
pub fn namespace_in_scope(namespace: &str, scope: &str) -> bool {
    if scope == "/" {
        // Root scope covers every namespace. Without this, the general
        // prefix rule below breaks for the root case: "/" + "/" = "//",
        // which no normalized namespace ever starts with, so a "/"-scoped
        // key would be denied access to anything but the literal root.
        return true;
    }
    namespace == scope || namespace.starts_with(&format!("{}/", scope))
}

pub struct RbacEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Upload,
    Read,
    Annotate,
    ManageKeys,
    ManageAcls,
    /// Platform-level: create/list tenants. Not scoped to the grant's own
    /// domain, since a tenant doesn't yet exist to scope it to.
    ManageTenants,
}

impl RbacEngine {
    pub fn require_role(
        grant: &Grant,
        domain: &str,
        namespace: &str,
        action: Action,
    ) -> Result<(), AuthError> {
        // Check revocation
        if grant.revoked {
            return Err(AuthError::AccessDenied("Grant is revoked".to_string()));
        }

        // Check expiration
        if let Some(expires_at) = grant.expires_at {
            if expires_at < chrono::Utc::now() {
                return Err(AuthError::ExpiredCredentials);
            }
        }

        // ManageTenants is platform-level (create/list tenants), not scoped
        // to the grant's own domain: skip the domain/namespace checks below.
        if action == Action::ManageTenants {
            return match grant.role {
                Role::SuperAdmin => Ok(()),
                _ => Err(AuthError::AccessDenied(
                    "Only super_admin can manage tenants".to_string(),
                )),
            };
        }

        // Check domain match
        if grant.domain != domain {
            return Err(AuthError::AccessDenied(
                "Domain mismatch".to_string(),
            ));
        }

        // Check namespace scope (prefix matching with a segment boundary,
        // so scope "/p1" covers "/p1" and "/p1/sub" but NOT "/p10").
        if !namespace_in_scope(namespace, &grant.namespace_scope) {
            return Err(AuthError::AccessDenied(
                "Namespace out of scope".to_string(),
            ));
        }

        // RBAC matrix
        match (grant.role, action) {
            // SuperAdmin: all actions within its own tenant, plus
            // platform-level ManageTenants (handled above, before this
            // match is ever reached).
            (Role::SuperAdmin, _) => Ok(()),

            // DomainAdmin: full self-service over its own tenant's
            // resources — upload, read/download, manage its own keys and
            // ACLs. The only thing it can't do is create other tenants
            // (ManageTenants, also handled above).
            (
                Role::DomainAdmin,
                Action::Upload | Action::Read | Action::Annotate | Action::ManageKeys | Action::ManageAcls,
            ) => Ok(()),

            // Uploader: upload only (e.g. a CI pipeline that should only
            // push, never browse or manage the tenant).
            (Role::Uploader, Action::Upload) => Ok(()),

            // Auditor: read and annotate only, scoped to its own tenant —
            // it cannot see or infer anything about other tenants.
            (Role::Auditor, Action::Read | Action::Annotate) => Ok(()),

            _ => Err(AuthError::AccessDenied(
                format!("Role {} cannot perform action {:?}", grant.role, action),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn grant(role: Role) -> Grant {
        Grant {
            tenant_id: uuid::Uuid::new_v4(),
            domain: "acme.example".to_string(),
            namespace_scope: "/".to_string(),
            role,
            expires_at: None,
            revoked: false,
        }
    }

    fn assert_allows(grant: &Grant, action: Action) {
        assert!(
            RbacEngine::require_role(grant, "acme.example", "/", action).is_ok(),
            "role {:?} should allow {:?}",
            grant.role,
            action
        );
    }

    fn assert_denies(grant: &Grant, action: Action) {
        assert!(
            RbacEngine::require_role(grant, "acme.example", "/", action).is_err(),
            "role {:?} should deny {:?}",
            grant.role,
            action
        );
    }

    #[test]
    fn rbac_matrix_matches_spec() {
        let super_admin = grant(Role::SuperAdmin);
        let domain_admin = grant(Role::DomainAdmin);
        let uploader = grant(Role::Uploader);
        let auditor = grant(Role::Auditor);

        for action in [
            Action::Upload,
            Action::Read,
            Action::Annotate,
            Action::ManageKeys,
            Action::ManageAcls,
        ] {
            assert_allows(&super_admin, action);
        }

        // domain_admin: full self-service over its own tenant (upload,
        // read/annotate, manage keys/ACLs) — everything except creating
        // other tenants.
        assert_allows(&domain_admin, Action::Upload);
        assert_allows(&domain_admin, Action::Read);
        assert_allows(&domain_admin, Action::Annotate);
        assert_allows(&domain_admin, Action::ManageKeys);
        assert_allows(&domain_admin, Action::ManageAcls);
        assert_denies(&domain_admin, Action::ManageTenants);

        assert_allows(&uploader, Action::Upload);
        assert_denies(&uploader, Action::Read);
        assert_denies(&uploader, Action::Annotate);
        assert_denies(&uploader, Action::ManageKeys);
        assert_denies(&uploader, Action::ManageAcls);

        assert_allows(&auditor, Action::Read);
        assert_allows(&auditor, Action::Annotate);
        assert_denies(&auditor, Action::Upload);
        assert_denies(&auditor, Action::ManageKeys);
        assert_denies(&auditor, Action::ManageAcls);
    }

    #[test]
    fn revoked_grant_is_denied() {
        let mut g = grant(Role::SuperAdmin);
        g.revoked = true;
        assert_denies(&g, Action::Upload);
    }

    #[test]
    fn expired_grant_is_denied() {
        let mut g = grant(Role::SuperAdmin);
        g.expires_at = Some(chrono::Utc::now() - Duration::hours(1));
        assert!(matches!(
            RbacEngine::require_role(&g, "acme.example", "/", Action::Upload),
            Err(AuthError::ExpiredCredentials)
        ));
    }

    #[test]
    fn unexpired_grant_is_allowed() {
        let mut g = grant(Role::Auditor);
        g.expires_at = Some(chrono::Utc::now() + Duration::hours(1));
        assert_allows(&g, Action::Read);
    }

    #[test]
    fn cross_domain_access_is_denied() {
        let g = grant(Role::SuperAdmin);
        assert!(
            RbacEngine::require_role(&g, "other.example", "/", Action::Read).is_err()
        );
    }

    #[test]
    fn namespace_scope_prefix_rules() {
        let mut g = grant(Role::Uploader);
        g.namespace_scope = "/p1".to_string();

        // Same namespace and sub-namespaces are in scope...
        assert!(RbacEngine::require_role(&g, "acme.example", "/p1", Action::Upload).is_ok());
        assert!(
            RbacEngine::require_role(&g, "acme.example", "/p1/sub", Action::Upload).is_ok()
        );
        assert!(
            RbacEngine::require_role(&g, "acme.example", "/p1/sub/deep", Action::Upload)
                .is_ok()
        );
        // ...but sibling namespaces are not.
        assert!(
            RbacEngine::require_role(&g, "acme.example", "/p2", Action::Upload).is_err()
        );
        // Prefix-escape: "/p10" is NOT under "/p1".
        assert!(
            RbacEngine::require_role(&g, "acme.example", "/p10", Action::Upload).is_err()
        );
    }

    #[test]
    fn only_super_admin_can_manage_tenants() {
        assert_allows(&grant(Role::SuperAdmin), Action::ManageTenants);
        assert_denies(&grant(Role::DomainAdmin), Action::ManageTenants);
        assert_denies(&grant(Role::Uploader), Action::ManageTenants);
        assert_denies(&grant(Role::Auditor), Action::ManageTenants);
    }

    #[test]
    fn manage_tenants_ignores_domain_scope() {
        // ManageTenants is platform-level: it must not be gated by the
        // grant's own domain (there's no existing domain to scope it to).
        let g = grant(Role::SuperAdmin);
        assert!(
            RbacEngine::require_role(&g, "some-other-domain", "/", Action::ManageTenants)
                .is_ok()
        );
    }

    #[test]
    fn root_scope_covers_every_namespace() {
        // A "/"-scoped (full access) key must be able to act on namespaces
        // other than the literal root — this was previously broken.
        let g = grant(Role::Uploader);
        assert!(
            RbacEngine::require_role(&g, "acme.example", "/products/v1", Action::Upload)
                .is_ok()
        );
    }

    #[test]
    fn namespace_in_scope_matches_prefix_rules() {
        assert!(namespace_in_scope("/p1", "/p1"));
        assert!(namespace_in_scope("/p1/sub", "/p1"));
        assert!(namespace_in_scope("/p1/sub/deep", "/p1"));
        assert!(!namespace_in_scope("/p2", "/p1"));
        assert!(!namespace_in_scope("/p10", "/p1"));
        assert!(namespace_in_scope("/anything", "/"));
    }

    #[test]
    fn role_from_str_roundtrips() {
        for role in [
            Role::SuperAdmin,
            Role::DomainAdmin,
            Role::Uploader,
            Role::Auditor,
        ] {
            let parsed = role.to_string().parse::<Role>().unwrap();
            assert_eq!(role, parsed);
        }
        assert!("nobody".parse::<Role>().is_err());
    }
}
