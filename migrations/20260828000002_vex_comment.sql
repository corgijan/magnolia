-- Optional human-readable note accompanying a finding's VEX triage,
-- separate from `vex_justification` -- which is now constrained to the
-- fixed OpenVEX justification vocabulary (validated in `triage_finding`)
-- rather than free text. This is for context a fixed code can't capture
-- (e.g. "confirmed with vendor advisory, see JIRA-1234"). Maps to OpenVEX's
-- own `status_notes` field on export.
ALTER TABLE dtrack_findings ADD COLUMN vex_comment TEXT;
