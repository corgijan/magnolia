# VEX hardening — what's left

## Context

Magnolia's `triage_finding` (`crates/api/src/handlers.rs`) already implements real
VEX semantics on top of cached Dependency-Track findings: a `vex_status` of
`affected`/`not_affected`/`fixed`/`under_investigation`, distinct from dtrack's own
`analysis_state`, audit-logged, filterable in the Findings tab. Three gaps identified
against a "real" VEX/supply-chain-monitoring feature set:

## 1. Constrained justification codes + optional human comment — DONE

Today `justification` is a free-text string, required only when `vex_status ==
not_affected`. Real VEX (OpenVEX/CSAF) constrains this to a fixed vocabulary so
downstream consumers can machine-parse *why* something isn't affected, instead of
matching against arbitrary prose.

- Constrain `justification` to OpenVEX's 5 canonical codes (`component_not_present`,
  `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
  `vulnerable_code_cannot_be_controlled_by_adversary`,
  `inline_mitigations_already_exist`), validated server-side, only accepted/required
  for `not_affected`.
- Add a separate, always-optional `comment` field (new `vex_comment` column) for the
  free-text context a fixed code can't capture — maps to OpenVEX's `status_notes`.
- Update the Findings-tab triage control: justification becomes a `<select>` of the 5
  codes (shown only for `not_affected`), comment becomes its own textarea.

## 2. VEX document export endpoint — DONE

No standard, machine-readable VEX artifact exists today — triage is only readable
through Magnolia's own API/UI shape.

- `GET /api/v1/manifest/:manifest_hash/vex` — same auth/tenant-ownership gate as
  `manifest()`/`triage_finding` (`Action::Read`).
- One [OpenVEX](https://github.com/openvex/spec) statement per cached finding.
  Untriaged findings (`vex_status IS NULL`) are exported as `under_investigation`
  (OpenVEX's own "not yet reviewed" convention) rather than omitted, so the document
  accounts for every finding dtrack knows about.
- Regenerated fresh from `dtrack_findings` on every request — no persisted document
  revision history, so `version` is always `1`.

## 3. Feed triage back into Dependency-Track (two-way sync) — DONE

Decision (per direct instruction): push synchronously, on every `triage_finding`
call, not batched into the periodic sync loop.

- `crates/dtrack/src/client.rs`: new `DtrackClient::set_analysis()` — `PUT
  /api/v1/analysis`.
- `crates/dtrack/src/models.rs`: `DtrackFinding` now carries dtrack's own
  `component_uuid`/`vulnerability_uuid` (previously parsed off the raw response only
  to build `finding_key`, then discarded) — needed since dtrack addresses an analysis
  by project+component+vulnerability UUID, not by Magnolia's `finding_key`.
- New `dtrack_findings.component_uuid`/`vulnerability_uuid` columns
  (`20260828000003_dtrack_finding_uuids.sql`), nullable — pre-migration rows get them
  on their next sync refresh; a triage push simply skips a finding that doesn't have
  them yet rather than erroring.
- `crates/api/src/dtrack_sync.rs`: `push_triage_to_dtrack()` (looks up the manifest's
  dtrack project, calls `set_analysis`, logs-and-swallows any failure — never blocks
  or fails the triage write) and `map_vex_to_dtrack_analysis()`, translating
  Magnolia's VEX vocabulary to dtrack's own `AnalysisState`/`AnalysisJustification`
  enums (CycloneDX's impact-analysis vocabulary, not OpenVEX's — there's no official
  1:1 mapping between the two specs, so a couple of OpenVEX codes collapse onto the
  same dtrack code; flagged in the function's doc comment).
- `triage_finding` calls this after its own DB write and audit log, skipped (not
  failed) when dtrack isn't configured, the tenant has `dtrack_sync_disabled`, or the
  finding has no cached component/vulnerability UUID yet.
- This is a deliberate, narrow exception to `dtrack_sync.rs`'s documented "no
  synchronous dtrack call from inside an HTTP handler" rule — updated that comment to
  say so, since a stale invariant is worse than no invariant.

**Not verified against a live dtrack instance** — `PUT /api/v1/analysis`'s request
shape and both enums are best-effort from dtrack's public API docs, same caveat
`DTRACK_PLAN.md` already carries for the rest of this integration. Re-check against a
real instance's `/api/openapi.json` (or just try a triage against one) before
depending on this in production.
