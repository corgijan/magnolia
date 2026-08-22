-- Marks exactly the platform/bootstrap tenant, whose super_admin keys are
-- allowed to act across all other tenants. NEVER set via the public
-- POST /api/v1/tenants API (always FALSE there) — only via the
-- BOOTSTRAP_SUPER_ADMIN_KEY startup path or direct SQL. Without this flag,
-- any tenant's self-service domain_admin could mint itself a
-- "super_admin"-labeled key and thereby gain reach into every other
-- tenant's data — this closes that privilege-escalation path.
ALTER TABLE tenants ADD COLUMN is_platform BOOLEAN NOT NULL DEFAULT FALSE;
