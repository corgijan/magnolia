-- Testing override for CVE reachability: analyse the namespace's configured
-- `revision` even when a manifest recorded its own `source_commit`.
--
-- Normally the recorded commit always wins — it is the code the SBOM was
-- built from. This exists for the case where that commit is not in the
-- mapped repository at all (an SBOM uploaded from a different checkout, a
-- demo fixture, a repository that moved), so the analysis can still be
-- exercised against a known branch. Off by default; the UI labels every
-- analysis it affects as an override (`commit_source = 'revision_override'`),
-- since the scanned code is then not the SBOM's own.
ALTER TABLE namespace_repos
    ADD COLUMN ignore_source_commit BOOLEAN NOT NULL DEFAULT FALSE;
