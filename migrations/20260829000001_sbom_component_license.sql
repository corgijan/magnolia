-- Raw (un-normalized) license expression/identifier extracted from each
-- component at index time, mirroring how `ecosystem`/`registry_name` were
-- added to this table for reputation -- stored so license-policy evaluation
-- and the component-search "license" column can both read it directly
-- rather than re-parsing the SBOM on every request. NULL when the
-- component carries no usable license info (see
-- `magnolia_core::extract_components`'s `license` field doc comment).
ALTER TABLE sbom_components ADD COLUMN license_expr TEXT;
