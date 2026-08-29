# Roadmap: Enforcement & Signals

Six features, ordered by dependency (not priority): **4 → 5 → 1 → 2 → 3 → 6**.
Blast radius is a pure read on existing data and ships first. License extraction
must land before the CI gate so `/verify` covers it. Webhooks are infrastructure
that later features emit into. VEX import and EOL are independent.

Milestones:

- **M1** — Features 4 + 5: data & policy groundwork
- **M2** — Features 1 + 2: enforcement & push (the product step)
- **M3** — Features 3 + 6: triage automation & freshness

Cross-cutting: every feature follows three patterns the codebase already has —
**tenant toggle** (migration + `set_tenant_*` + settings endpoints + frontend
switch), **sync loop** (`run_sync_loop` shape in `dtrack_sync.rs`), and
**pure-check-in-core** (compliance-profile trait style). Nothing introduces a
new architecture.

Housekeeping: two pre-existing eslint errors in `frontend/src/App.tsx` (unused
imports `NamespaceRegistrationSetting` / `ReputationTenantSetting`) fail
`CI=true` builds — delete in the first PR.

---

## Feature 4: Vulnerability blast radius *(small — 1 session)*

**Goal:** answer "which namespaces/manifests contain component X" and "which
are affected by CVE-Y" tenant-wide.

- **DB** (`crates/db/src/lib.rs`): two new queries, no migration needed.
  - `list_manifests_containing_component(tenant_id, namespace_scope, purl | name+version)`
    — join `sbom_components` → `manifests`, with a `current_only` flag reusing
    the same "latest per namespace" logic as `latest_manifests_by_namespace`.
  - `list_manifests_affected_by_vulnerability(tenant_id, namespace_scope, vuln_id)`
    — `dtrack_findings` filtered by vuln id, joined to manifests; also match
    `malicious_component_findings` advisory ids so OSV malicious matches are
    covered too.
- **API** (`handlers.rs`): `GET /components/affected?purl=…` and
  `GET /vulnerabilities/{id}/affected`, both honoring `AuthGrant` namespace
  scope like `search_components` does.
- **Frontend:** in component search results, a "used in N manifests" expansion;
  on finding rows, link the vuln id to an affected-manifests view.
- **Tests:** DB-level tests around current-vs-historical manifests and revoked
  manifests. Decision: revoked manifests still appear, flagged — that is the
  point of incident response.

## Feature 5: License compliance *(medium — 2 sessions)*

**Goal:** extract licenses from SBOMs, per-tenant license policy, violations as
a security signal, optionally blocking uploads.

- **Extraction** (`crates/core/src/component_index.rs`): add
  `license: Option<String>` to `ExtractedComponent` — CycloneDX `licenses[]`
  (`license.id` / `license.name` / `expression`), SPDX `licenseConcluded`
  falling back to `licenseDeclared` (`NOASSERTION` = absent, same convention as
  the NTIA checks). Use the `spdx` crate to parse/normalize expressions.
- **DB:** migration adds `license_expr` to `sbom_components`; second migration
  adds `tenant_license_policies` (tenant_id, denied_licenses text[],
  flag_unknown bool, enforce_level warn|block) modeled on
  `compliance_profile_settings`. Existing `reindex_components` backfills old
  manifests.
- **Evaluation:** pure function in `core`:
  `evaluate_license_policy(components, policy) -> Vec<LicenseViolation>`.
  Called in `upload_sbom` after `index_manifest_components` (block when
  `enforce_level = block`), later also by `/verify`.
- **API:** get/set policy endpoints following the `reputation_tenant_setting`
  pattern; violations included in the manifest JSON.
- **Frontend:** fourth row in the "Security signals" section of
  `SbomDetailPanel`; policy editor in settings; license column in component
  search.

## Feature 1: CI policy gate *(medium — 2 sessions)*

**Goal:** `POST /verify` — same checks as upload, but dry-run: no storage, no
Merkle leaf, machine-readable pass/fail for CI.

- **Refactor first:** `enforce_compliance` returns `Err` on failure today;
  change it to return a structured per-profile report and let `upload_sbom`
  decide to reject. Same for `validate_sbom_content`.
- **Endpoint** (`handlers.rs`): multipart like `upload_sbom`; runs schema
  validation → compliance profiles → license policy (feature 5) → synchronous
  malicious check (extract components, call the same OSV batch query the
  malicious sync loop uses — pull that client call into a shared function).
  Reputation/dtrack are async-by-nature: report `not_evaluated` rather than
  blocking CI on external latency.
- **Response:** `{ verdict: "pass"|"fail", checks: [{ id, status, enforce_level, details[] }] }`
  — a `warn`-level failure yields `verdict: pass` with warnings so CI chooses
  strictness.
- **Auth:** reuse upload permission (strictly weaker — no write); add `verify`
  to audit log actions.
- **CLI:** extend the `install_script` shell client with a `verify` subcommand
  mapping verdict → exit code. That is the whole CI integration story.
- **Frontend:** optional "Check an SBOM" drag-and-drop page reusing the
  `check_compliance` UI, showing the full gate result.

## Feature 2: Webhooks *(medium-large — 2–3 sessions)*

**Goal:** push events out instead of making teams poll.

- **DB:** migration adds `webhook_endpoints` (tenant_id, url, secret,
  event_types text[], enabled, created_by) and `webhook_deliveries` as an
  **outbox** (endpoint_id, event_type, payload jsonb, status
  pending|delivered|failed, attempts, next_attempt_at, last_error). Outbox rows
  written in the same transaction as the triggering change where possible.
- **Events v1:** `manifest.uploaded`, `manifest.revoked`,
  `finding.new_critical` (delta detection in `replace_dtrack_findings`),
  `malicious.match_found`, `dtrack.push_failed`.
- **Emitter:** `emit_event(&db, tenant_id, event_type, payload)` in a new
  `crates/api/src/webhooks.rs`; call sites are the places that already call
  `record_audit`.
- **Delivery worker:** tokio loop modeled on `run_sync_loop`: poll due outbox
  rows, POST with `X-Aise-Signature: hmac-sha256(secret, body)` + timestamp
  header, exponential backoff (1m → 5m → 30m → 2h), failed after ~8 attempts.
  SSRF guard: reject non-http(s) and RFC-1918/loopback targets unless a dev-mode
  env flag allows them.
- **API:** CRUD for endpoints (admin role), `POST /webhooks/{id}/test`,
  `GET /webhooks/{id}/deliveries`.
- **Frontend:** settings section — endpoint list, event-type checkboxes, recent
  deliveries with status/error. Slack/email later as delivery adapters.

## Feature 3: VEX import *(medium — 2 sessions)*

**Goal:** accept a supplier VEX document and auto-apply its statements to
findings.

- **Format:** OpenVEX first; CSAF 2.0 as follow-up. Parse in `core` (new
  `vex_import.rs`) into normalized
  `Vec<VexStatement { vuln_id, purls, status, justification }>`.
- **Endpoint:** `POST /manifests/{hash}/vex/import?overwrite=false` — match
  statements to findings: purl → `sbom_components`, vuln id →
  `dtrack_findings.vuln_id` (exact id match only in v1; CVE↔GHSA alias
  resolution is a documented gap).
- **Apply:** existing `set_finding_triage`, then `push_triage_to_dtrack`
  (`map_vex_to_dtrack_analysis` already exists). Migration adds
  `triage_source` (`manual` | `vex_import`) so imports never silently
  overwrite manual triage unless `overwrite=true`; auto-add a finding comment
  citing the document.
- **Provenance:** store the raw imported document in object storage next to the
  SBOM; audit-log the import.
- **Response:** `{ applied, skipped_manual, unmatched: [...] }`.
- **Frontend:** "Import VEX…" button on the manifest detail panel with a result
  summary modal.

## Feature 6: EOL / staleness signal *(medium — 2 sessions)*

**Goal:** fifth security signal — "N of M components are outdated."

- **Source:** deps.dev API for per-package latest-version (same ecosystems the
  reputation loop resolves via `list_sbom_components_missing_ecosystem`).
  endoflife.date only covers runtimes/products — skip in v1 or use only for
  primary components.
- **DB:** migration adds `component_freshness` (ecosystem, name,
  latest_version, checked_at) — keyed like `component_reputation`, deliberately
  not per-version; plus `tenant_freshness_disabled` toggle.
- **Sync loop:** clone the reputation loop shape:
  `list_components_needing_freshness(stale_before, limit)`, batch-query
  deps.dev, `upsert_component_freshness`, plus `force_freshness_sync` /
  `freshness_status` endpoints.
- **Evaluation:** staleness computed at read time (semver compare against
  latest; `require_semver` means versions are mostly parseable); classify
  `current / behind / major-behind / unknown`.
- **Frontend:** fifth signal row + modal listing outdated components sorted by
  how far behind (reputation-modal pattern). Optionally feed `major-behind`
  into `/verify` as warn-only.

---

## Status log

- 2026-08-29 — Roadmap created.
- 2026-08-29 — **All six features implemented** (commit `3d11f6b`): `/verify`
  CI gate + `magnolia-upload.sh` verify support, webhooks
  (`webhooks.rs` + outbox migration + test/deliveries endpoints), VEX import
  (`core/vex_import.rs`, `triage_source` migration), blast radius
  (`/components/affected`, `/vulnerabilities/:id/affected`), license
  compliance (`core/license.rs`, `license_expr` + `tenant_license_policies`
  migrations), freshness/EOL (`core/freshness.rs`, `freshness_sync.rs`,
  `component_freshness` migration). 144 unit tests green, `tsc` clean,
  eslint-breaking unused imports removed.
- Open verification gaps: no DB-level tests (sqlx queries in the five new
  migrations/queries only fail at runtime — needs a live-stack smoke test);
  new endpoints and frontend panels not yet exercised against a running
  deployment; webhook delivery never tested against a real receiver; no
  security review of the new surface (webhook SSRF guard, HMAC signing,
  `/verify` auth, VEX overwrite semantics) yet.
