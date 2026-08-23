-- NULL = existing SBOM upload, unchanged behavior. Non-null = a general
-- technical-documentation upload (risk assessment, test report, CVD
-- policy, etc.) reusing the same tamper-evident pipeline — Merkle
-- inclusion, DSSE signing, revocation — under a distinct predicate type
-- and excluded from the "currently running" (deployable) view.
ALTER TABLE manifests ADD COLUMN document_type VARCHAR(100);
