-- Lets "deleting" a tenant outside DEV_MODE hide it instead of destroying
-- its data. A compliance archive shouldn't let a single admin action
-- permanently erase years of SBOM history with no retention floor — hiding
-- removes it from listings/selectors while leaving every row, key, and the
-- Merkle tree/signed-tree-head chain fully intact and still queryable
-- directly (e.g. via ?tenant_id= override).
ALTER TABLE tenants ADD COLUMN hidden BOOLEAN NOT NULL DEFAULT FALSE;
