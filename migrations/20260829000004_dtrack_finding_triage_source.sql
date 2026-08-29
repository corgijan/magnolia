-- Tracks whether a finding's current triage came from a human
-- (`triage_finding`) or from an imported VEX document
-- (`POST /manifest/{hash}/vex/import`). NULL for any triage set before this
-- column existed -- treated the same as 'manual' by the VEX-import
-- overwrite guard (never silently replaced without `overwrite=true`), so
-- old data doesn't need a backfill to stay protected.
--
-- Lets an import tell three cases apart: never triaged (vex_status IS
-- NULL, always safe to apply), triaged by a human or before this column
-- existed (only overwritten if the caller explicitly asks), and triaged by
-- a *previous* VEX import (safe to refresh from a newer document without
-- `overwrite`, since nothing human would be lost either way).
ALTER TABLE dtrack_findings ADD COLUMN triage_source VARCHAR(20);
ALTER TABLE dtrack_findings ADD CONSTRAINT dtrack_findings_triage_source_check
    CHECK (triage_source IS NULL OR triage_source IN ('manual', 'vex_import'));
