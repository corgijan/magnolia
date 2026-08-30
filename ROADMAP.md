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
- 2026-08-30 — **Most of those gaps now closed.** Everything below was
  exercised against the live Docker stack (api + postgres + Dependency-Track),
  not just compiled: new endpoints, migrations, and frontend panels were
  driven end-to-end with `curl`/`psql`/the real CLI. Webhook delivery against
  a real external receiver is still untested. Details:
  - **`/verify` is now the single policy gate.** Added `vulnerabilities`
    (non-`MAL-` OSV IDs, from the querybatch response that was already being
    fetched and discarded) and `package-reputation` (cache read, no live
    deps.dev call in the request path). Folded in the Tools tab's separate
    `POST /tools/compliance-check`, which is **removed**: compliance profiles
    and license policy are now always previewed, even at `enforce_level=off`.
    Response gained a richer `compliance[]` array so minimum-vs-full is
    legible instead of collapsed into one status string.
  - **License policy**: `flag_unknown: bool` → `UnknownLicenseHandling
    {ignore,warn,flag}` (migration `20260830000001`). New pure
    `license_policy_status()` is the single source of truth for pass/warn/fail,
    shared by the upload gate and `/verify` so they cannot drift. SPDX
    identifiers are now validated on save (`is_valid_spdx_license_id`).
  - **Namespace registration**: added `DELETE /api/v1/namespaces/registered`
    + Settings "Remove" button — previously a mis-typed namespace could never
    be un-registered. Rejection message now lists what *is* registered.
  - **Cache management**: `POST /api/v1/tenants/cache/clear` (component index,
    malicious findings, dtrack findings/projects), audit-logged.
  - **Freshness/reputation on upload**: `upload_sbom` now nudges an immediate
    sync pass (spawned, never awaited) instead of waiting up to an hour;
    verified a never-before-seen package scored in <1s. UI shows a
    "Scanning…" state rather than hiding the row.
  - **Deployment**: `db`/`dtrack-db`/`dependency-track` no longer publish host
    ports at all; secrets parameterised via `.env` (+ tracked `.env.example`);
    frontend behind a compose profile; `API_PORT`/`FRONTEND_PORT`/
    `FRONTEND_INSTANCE_NAME` added; UI can be pointed at a remote API.
  - **CLI**: stdlib-only Python port (`scripts/magnolia-upload.py`, served at
    `/install.py`) is now the documented default; bash version retained.
  - **Testing**: `test-sboms/` — four real `syft`-generated SBOMs spanning
    CycloneDX 1.5/1.6 + SPDX 2.2/2.3 — plus `tests/test_real_sboms.py`, which
    drives the real CLI against a live server. Rust suite 144 → 165.
  - **Security review + auth overhaul.** Audit findings in
    `docs/AI_DEVLOG.md` episode 8. Fixed the top one: Argon2-per-request
    (~19 MB, ~12 ms) replaced with constant-time SHA-256 behind a
    scheme-prefixed hash, keeping legacy keys working — measured
    **333 → 4,335 req/s** (`ab -n 300 -c 20`). Key format changed to
    `mag_<43 base64url>` (row located by hash; migration `20260830000002`
    adds the unique index). The publicly-known `deadbeef-…` bootstrap key is
    **revoked**, and `docker-compose.yml` now has *no* bootstrap default —
    unset creates no key (fail closed).
- Remaining known gaps (2026-08-30): **no CI** (`.github/workflows` absent —
  nothing runs the 165 tests automatically); no DB-level integration tests;
  webhook delivery untested against a real receiver; app connects to Postgres
  as superuser and `audit_logs` has no DB-level immutability; signing key and
  dtrack key are written `0644`; webhook SSRF guard checks only literal IPs
  (no DNS-resolution or redirect check); no rate limiting / request timeout.
  Course deliverables still missing: **OpenAPI document**, `crates/ai` + the
  AI feature (decided later the same day — see the next entry), and the
  evaluation suite (`eval/`).
- 2026-08-30 — **AI feature decided and submitted** (course project
  description): **CVE reachability evidence**. Primary goal is AI-assisted
  scanning of the codebase to establish whether a reported CVE actually
  affects it — whether the vulnerable code is present and reachable — so a
  team acts on real exposure rather than raw finding counts. Declared
  fallback, also submitted: AI-assisted extraction and grounded summarisation
  of CVE advisories. In both cases the model surfaces **evidence for an
  analyst, never an automated verdict** (see `CLAUDE.md` for why that line
  matters and where it must show up in the UI). Project framing was also
  corrected in `CLAUDE.md`: this is a **supply-chain observability and
  transparency** service, with CRA compliance one application of it rather
  than the whole purpose.
  - *Suggested build order:* the fallback first. It shares advisory
    ingestion (`malicious_check.rs` already pulls OSV advisory text via
    `get_vuln`; `dtrack_findings` carries descriptions) and the eval harness
    with the reachability version, so it de-risks the deliverable while
    remaining useful if reachability doesn't land.
  - *Not started:* `crates/ai` does not exist. Still required alongside it:
    the OpenAI-compatible client (env-configured base URL/model/key), the
    four mandatory failure modes (server unavailable, timeout, invalid
    output → validate + retry once + degrade, processing failure), and the
    `eval/` suite (≥10 cases incl. ambiguous / prompt-injection via advisory
    text / malformed / out-of-scope, plus one baseline comparison).
