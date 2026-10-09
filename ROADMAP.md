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
- 2026-08-30 — **AI feature built: `reach/`, a standalone CVE-reachability
  evidence analyser**, plus its AISE-side integration. The largest missing
  course deliverable, and it closes several others with it.
  - **Own project, in-tree.** `reach/` is a separate Cargo project (own
    `Cargo.lock`, own `[workspace]`, `exclude = ["reach"]` in the root
    manifest), own SQLite database, own Dockerfile, own compose service.
    One repository and one history for the submission; the boundary to AISE
    is REST and nothing else. Build/test it from inside `reach/` with plain
    `cargo test` — **138 tests**, separate from AISE's own suite.
  - **Pipeline** (`reach/src/pipeline/`): A presence check (deterministic,
    manifests + a language-agnostic identifier index, and a zero-evidence
    short circuit that costs no inference call) → B advisory-to-ruleset
    (LLM) → C occurrence search (deterministic, ranked, capped) → D
    per-occurrence labelling (LLM) → E rubric (pure function, unit-tested).
    Every stage degrades rather than aborting and records a `StageOutcome`;
    only "could not fetch the source you asked about" fails an analysis.
  - **All four graded failure modes handled** in `reach/src/ai/`: server
    unavailable, timeout, invalid output (validate app-side → one repair
    retry → degrade), and processing failure. Verified live: with the
    inference endpoint pointed at a closed port, an analysis still completed
    through the full Docker stack and returned real stage-A evidence with
    the failure named in the report.
  - **Two mechanical anti-hallucination checks**, both surfacing a count in
    every report: extracted symbols must appear in the advisory text
    (grounding), and every model claim must cite a `file:line` that exists
    in the checkout *and* was inside the snippet the model was shown
    (citation verification). Unverifiable claims are dropped, not displayed.
  - **`eval/` suite** — 12 cases covering nominal, ambiguous, malformed,
    out-of-scope, prompt injection via advisory text *and* via a source
    comment, advisory-only, monorepo subpath, hallucination bait, and the
    package-absent short circuit. Fixtures are plain directories made into
    throwaway git repos at run time, so runs need no network. Metrics:
    extraction P/R/F1 against a gold set, the same for a **non-AI heuristic
    baseline** on identical inputs, priority accuracy, citation pass rate,
    structured-output first-try rate, per-label precision, injection
    resistance, latency percentiles. `--baseline-only` runs the whole suite
    against a closed port, which doubles as a test of the degradation
    contract (12/12 still produce reports).
  - **Run against a real local model** (deepseek-r1:8b via Ollama — the
    submission-target size class, not a hosted frontier model). A single-case
    run completed and is captured in `eval/results/`: extraction P=1.00
    R=1.00 against the heuristic baseline's P=0.50 on the nominal case. Two
    genuine small-model failures were observed and handled rather than
    papered over — output truncated mid-JSON at `max_tokens` (a reasoning
    model spends most of the budget on `<think>` before the JSON starts) and
    one empty completion. Both degraded correctly.
    **A full 12-case run has not completed yet.** One was started and stopped
    after 9 cases (~9 minutes each on this hardware), so no full results file
    exists. Of the 9 it reached, 7 passed; the 2 failures were both the eval
    harness's own forbidden-substring bug (see `AI_DEVLOG.md` ep. 9, item 2),
    fixed afterwards but **not yet re-verified against the model**. Treat
    real-model numbers as provisional until a full run lands; the
    `--baseline-only` run is complete and green at 12/12.
  - **OpenAPI deliverable satisfied** on this surface: `utoipa`-generated
    `/openapi.json` (3 paths, 13 schemas) plus `/docs`. AISE's own OpenAPI
    document is still missing.
  - **AISE side** (migration `20260830000003_reachability.sql`):
    `namespace_repos` (settings pattern — where a namespace's *own* source
    lives, never inferred from SBOM metadata, which points at the
    dependency's repository), `manifests.source_commit` (sent by
    `scripts/magnolia-upload.py`, which refuses to record one from a dirty
    tree), and `finding_reachability` linking findings to analyses. New
    `crates/reachability` client, two endpoints, audit-logged, presence-gated
    on `AISE_REACH_BASE_URL`/`AISE_REACH_TOKEN` exactly like dtrack. UI is
    v1 scope on purpose: an "Analyze reachability" button on a finding that
    explains itself when disabled, a minimal report rendering with the
    no-verdict disclaimer, a "How was this determined?" expander showing the
    rubric trace and per-stage outcomes, and a Source-repositories settings
    card.
  - *Verified:* `cargo test --workspace` = 174 (was 165); `cd reach && cargo
    test` = 138; `npx tsc --noEmit` and `CI=true npx react-scripts build`
    clean; full path exercised against the live Docker stack (upload with
    `source_commit` → repo mapping → queue → poll → degraded report), with
    the audit rows checked in Postgres.
  - *Deliberate deviations from the plan, both documented in code:* the
    stage-A index is a hand-written language-agnostic scanner rather than
    tree-sitter (per-language grammars would have made "language-agnostic"
    mean "the eight languages we vendored"), and the fetcher uses a plain
    `--depth 1` fetch rather than `--filter=blob:limit=1m` (a blob filter
    only defers work that `git checkout` immediately undoes, one request per
    blob).
  - *Still open:* AISE's own OpenAPI document; CI (`.github/workflows` still
    absent); the dismissal queue and richer report UI; per-label precision
    is measured over 12 synthetic fixtures and is a sanity check, not a
    calibrated number.
- 2026-08-31 — **`reach` probes its inference endpoint on startup.**
  `GET {REACH_AI_BASE_URL}/v1/models`, spawned as a background task so it
  never delays the port bind (verified live: the "listening" log line lands
  before the probe's own result, both inside the container and natively) and
  never gates startup or any request — an unreachable endpoint is still a
  per-analysis degradation, not a failure to boot. Logged once, and kept at
  `GET /health` under `ai_probe` so an operator has ongoing visibility, not
  just a line in a log they may not be watching: `reachable` (with
  `model_listed: true/false/null`, `null` meaning the server doesn't support
  listing at all — not itself a problem, since only
  `/v1/chat/completions` is required), `responded_with_error` (server up,
  request rejected — usually a stale `REACH_AI_API_KEY`), or `unreachable`.
  8 new tests against a mocked endpoint (wiremock) plus live verification
  against a real Ollama server in all three states (unreachable, matching
  model, mismatched model name).
  - **Revised the same day, against real production traffic.** The first
    live run — against a real hosted endpoint the user configured — hit
    exactly the gap a `/v1/models`-only check cannot see: the probe reported
    `reachable`, and the very next real analysis failed at stage B with an
    opaque "unreadable body" error. The probe now sends an actual
    `POST /v1/chat/completions` test prompt with `json_mode: true` — the
    exact call shape stage B/D make — and only falls back to `GET /v1/models`
    as a secondary, informational check once the completion itself succeeds.
    New outcome `responded_but_unusable` (2xx, but not something this service
    can use) is distinguished from `responded_with_error` (a real non-2xx).
    Also fixed in the same pass: `ChatClient::complete()` consumed the HTTP
    response via `.json()` before capturing its raw bytes, so an envelope
    mismatch produced only "error decoding response body" with no way to see
    what was actually returned — now buffered as text first, with a bounded
    snippet of the real body carried in the error. Verified live against
    deepseek-r1:8b in both directions: `REACH_AI_MAX_TOKENS=200` correctly
    surfaced `responded_but_unusable` ("200 with no completion content" — the
    reasoning model's whole budget went to its `<think>` block), and
    `REACH_AI_MAX_TOKENS=2000` correctly surfaced `reachable`.
  - **Separately, the same live run panicked the background worker.**
    `lexer.rs` indexed a `&str` at a raw byte offset (`text[i..]`) while
    scanning a real repository containing an em dash in a comment — a
    perfectly ordinary character that happens to be 3 bytes wide in UTF-8.
    Reproduced exactly (same file, same line, same byte offset) in a unit
    test before fixing. Worse than the crash itself: `run_worker`'s loop
    calls the pipeline inline in one long-lived task with no panic boundary,
    so the panic didn't just fail that job — it silently ended background
    processing for the rest of the container's life, leaving the triggering
    job stuck at `running` forever and every later job unclaimed. Fixed in
    two parts: `lexer.rs`'s three `text[i..]` call sites now go through a
    `starts_with_at` helper built on `str::get` (returns `None` instead of
    panicking on a non-boundary index — std, no new dependency), and
    `worker.rs` now runs `pipeline::run` in its own `tokio::spawn`ed task so
    the runtime's own per-task panic boundary catches an unanticipated panic
    anywhere in the pipeline, marking just that one job failed (with a
    generic message — never the raw panic payload, which for an indexing bug
    routinely quotes a chunk of the scanned repository) while the loop
    keeps serving every job after it. `cargo test` = 154 + 5 (was 138 + 5).
- 2026-08-31 — **`reach` now refuses to start if the inference endpoint
  doesn't work**, per explicit user request. The startup probe (added
  earlier the same day) is no longer spawned in the background — `main.rs`
  now `.await`s it before the listener ever binds, and treats anything but
  `Reachable` as fatal: logs why, exits `1`, opens no port. Verified live in
  both directions, natively and in the actual `aise-reach` Docker image: a
  dead endpoint produces `Exited (1)` with no port ever bound; a working one
  logs "startup check passed" then "listening", in that order, and serves
  normally.
  - *Explicitly a startup-time gate only*, kept separate from the
    per-request degradation the course grades (an analysis started after the
    process is up must still degrade gracefully if the endpoint later goes
    down — untouched by this change, still covered by the existing worker
    and pipeline tests). The two don't conflict: one is "can the process
    come up at all", the other is "does a request-time AI failure break
    anything once it's running".
  - Docker `HEALTHCHECK`'s `--start-period` raised 10s → 180s to match: the
    gate can now legitimately take most of `REACH_AI_TIMEOUT_SECS` (120s
    default) on a slow/cold local model, and the old short window would have
    reported "unhealthy" on a container that was correctly waiting, not
    failing.
- 2026-08-31 — **Incident: a real Hetzner inference API key was committed
  to `reach/.env.example`** (should only ever live in the git-ignored
  `reach/.env`), in commit `6f3f6be` on `AI-checkouter`. Caught while
  debugging why the endpoint wasn't working. Contained: never pushed
  (`origin` only carries `development`; the branch has no upstream and the
  commit was absent from every `refs/remotes/*` and from `git ls-remote
  origin`), and `reach/.env` itself was confirmed never tracked. Remediated
  by amending the commit (it was the branch tip, so this rewrote nothing
  before it) — `6f3f6be` → `ab8c3f6`, key absent from the new commit,
  verified by grepping its full diff. User's explicit call: keep the key
  rather than rotate it, given the exposure was local-only plus this chat
  transcript. Recorded here per CLAUDE.md's "never write secrets into the
  repo" rule, and as the reason `reach/.env.example` must stay placeholder-
  only — a real value belongs in `reach/.env` and nowhere else.
- 2026-08-31 — **Root-caused the real Hetzner endpoint failure, live, end to
  end.** Two independent, unrelated misconfigurations, found in sequence by
  testing the exact request `reach` makes against the exact endpoint, both
  with and without auth, and comparing to the provider's own docs:
  1. `REACH_AI_BASE_URL` was `https://inference.hetzner.com`; the provider's
     documented base is `https://inference.hetzner.com/api` (reach appends
     `/v1/...`). The wrong base silently hit an unrelated catch-all route on
     the same host — every path (`/`, `/v1/models`, `/v1/chat/completions`)
     returned an identical static 9-byte `"inference"` body with HTTP 200,
     regardless of method, payload, or auth, which is what made this so hard
     to place: it looked like a broken server, not a wrong path. User-fixed
     once identified; `.env.example` now calls this class of mistake out
     explicitly.
  2. Once pointed at the right path, a **third** genuinely new failure mode
     surfaced: Hetzner's Qwen3.6-35B-A3B (served via vLLM) is a reasoning
     model that returns chain-of-thought in a separate `reasoning` /
     `reasoning_content` field and leaves `content: null` until it finishes
     "thinking" — with `REACH_AI_MAX_TOKENS=1024`, the whole budget went to
     reasoning and `content` never arrived, which `complete()` reported as a
     bare `empty_response` with no way to tell "truly empty" apart from
     "spent the whole budget thinking". Fixed: `ResponseMessage` now parses
     `reasoning`/`reasoning_content` (both field names seen in the wild
     accepted), and a genuine content-empty-but-reasoning-present response is
     reported as the new, specific `AiError::TruncatedDuringReasoning`,
     carrying a snippet of the captured reasoning and naming the fix
     (`REACH_AI_MAX_TOKENS`) directly in the message — surfaces through
     `probe()`'s `responded_but_unusable` outcome and through every stage's
     `StageOutcome` detail the same way every other `AiError` already does.
     6 new tests, including the literal response shape captured live from
     Hetzner. `.env`/`.env.example` bumped to `REACH_AI_TIMEOUT_SECS=180`,
     `REACH_AI_MAX_TOKENS=8000` accordingly (both were already env-
     configurable — this was a defaults problem, not a missing-config one).
  - **Startup gate change from the same session, reinforced by this:** the
     "refuse to start unless the endpoint works" gate added earlier the same
     day caught misconfiguration (1) immediately and clearly on every
     restart, rather than it surfacing as a silent per-analysis degradation
     an operator might not notice for a while.
  - `cargo test` = 158 + 5 (was 154 + 5).
- 2026-08-31 — **Added `--experimental-verdict` to `reach-check.py`, on
  explicit user request, against the concern I raised first.** Prints an
  applicability judgement ("is this CVE applicable?") and a bare confidence
  percentage — exactly what CLAUDE.md's "evidence, not verdict" / "label,
  not probability" rules say the project must not do, and says so must
  "survive into the UI copy". Flagged the conflict, offered a compliant
  alternative, and the user chose to have it built anyway as explicitly
  non-compliant/experimental.
  - **Isolation, by design:** lives entirely in the CLI script, behind an
    opt-in flag, as a second, separate call straight to the raw inference
    endpoint. Nothing in `reach`'s own service, prompts, report schema, or
    API changed — the actual submitted deliverable stays compliant. A large
    warning banner (naming CLAUDE.md, stating "DO NOT USE THIS OUTPUT IN THE
    GRADED SUBMISSION") brackets the output every time the flag is used.
  - **Caught its own version of the same reasoning-model bug** while
    testing: the ad-hoc call defaulted to `max_tokens: 300`, exhausted
    entirely on Qwen3.6's hidden reasoning, so it initially got back an
    empty string with no diagnosis at all (no `AiError`-style categorisation
    exists client-side in Python). Fixed with a `--verdict-max-tokens`
    default of 4000 and a reasoning-field check mirroring the Rust fix, so
    an insufficient budget here is at least named rather than silently
    returning nothing.
  - Verified live end-to-end against the real Hetzner endpoint and the real
    `lispr` repository.
- 2026-08-31 — **`--experimental-verdict` flipped to on-by-default**, on
  request, with `--no-experimental-verdict` to opt out. Same isolation and
  warning banner as before (see the previous entry) — this only changes
  which side is the default. Alongside it, the script now reads
  `reach/.env` itself for `REACH_AI_BASE_URL`/`MODEL`/`API_KEY` (mirroring
  the server's own dotenvy loading, real env vars still winning), since
  making the verdict call the default meant a plain
  `python3 ./scripts/reach-check.py --repo ... --advisory ...` needed
  those three values without the caller exporting anything by hand.
  Verified live with zero `REACH_AI_*` variables exported in the shell.
- 2026-08-31 — **Added stage-by-stage logging through the pipeline**, on
  request. Previously the only visibility during a run was one "starting
  analysis" line and one "analysis completed" line from `worker.rs` — a
  slow LLM call (which this session repeatedly showed can take a couple of
  minutes against a real hosted model) produced total silence in between.
  Now every stage logs when it starts and, via a shared `log_stage` helper,
  when it finishes — severity follows the stage's own status
  (`Ok`/`Skipped` → info, `Degraded` → warn, `Failed` → error), reusing the
  exact same detail text that ends up in the report's `StageOutcome`, so the
  log and the API can never drift apart. Stage D (per-occurrence LLM
  scoring, one call per site, the actual long-wait point) additionally logs
  before and after **each individual site**, not just once for the whole
  stage — `score_sites` gained a `job_id` parameter for this. `cargo test`
  = 158 + 5, unchanged (purely additive logging, no behaviour change);
  verified live end-to-end against the real Hetzner endpoint with the full
  stage-by-stage log captured.
- 2026-08-31 — **Tree-sitter structural refinement built: function/class
  boundaries for snippets, and structural nested-call search.** New
  `src/treesitter.rs` module (Rust crate, not Python — chosen specifically
  so it stays an in-process, compiler-typed Cargo dependency rather than a
  subprocess or sidecar), vendoring Rust/JavaScript/Python/Go grammars.
  Strictly additive on top of the lexer, which stays the universal,
  zero-config baseline for every other language and for stage A/C's core
  identifier search.
  - **Snippet boundaries.** `stage_c::snippet_for` now widens a snippet to
    the real enclosing function/class (capped at 60 lines) when a grammar is
    vendored for the file, falling back to the fixed ±4-line window
    otherwise. Directly fixed a real case found live: an advisory
    describing `(print (test 5))` originally surfaced an unrelated, wrongly
    "most relevant" line because the fixed window was too narrow for the
    model to see the actual construction; with the whole function visible,
    the model correctly identified it.
  - **Structural nested-call search.** New `Ruleset.nested_calls:
    Vec<NestedCallPattern>` — deliberately just two already-grounded symbol
    names (`outer`, `inner`), never raw query syntax from the model; the
    actual tree-sitter query is built by Rust code from a fixed per-language
    template, so it stays guaranteed-valid regardless of what the model
    says. Pre-filtered against the lexical index (only parses a file where
    both names already appear lexically) before ever invoking tree-sitter.
    Ranked well above ordinary hits when it fires.
  - **Honest finding from live testing, not swept under anything:** for the
    motivating `lispr` case, the structural query did *not* fire — the
    Lisp code lives inside a Rust macro invocation (`lsp_main![...]`), and
    tree-sitter's Rust grammar treats macro-invocation contents as an opaque
    token tree, not parsed `call_expression` nodes. The boundary-widening
    half of this feature is what actually fixed the case; the structural
    half works correctly (12 new tests across 4 languages, verified
    including the exact false-positive it exists to avoid: independent
    unnested calls to both names), but has a real, documented blind spot
    for code embedded in a macro/DSL.
  - **A second real bug found live, same session, root-caused and fixed
    with a regression test that reproduces the exact scenario:** two
    independently-scored occurrences of `test` (the `defun` at line 10 and
    the call at line 11) both cited line 11 after being shown the newly
    widened snippet — a legitimate, even insightful model judgement, but it
    produced two redundant report entries for the same location with two
    different LLM calls burned on them. Root-caused by writing an isolated
    test against the real lexer first (which proved the lexer itself is
    correct — line 10 and line 11 are two genuine, separate occurrences) to
    rule that out before looking downstream. Fixed with
    `stage_d::collapse_citation_collisions`, deduping by
    `(path, final_cited_line, term)` and keeping the strongest label;
    surfaced as a new `Counters::collapsed_duplicate_citations` field, and
    the stage D detail text. 4 new tests, including the exact collision
    shape observed live and a check that same-line-different-term hits
    (e.g. `print` and `test` on the same physical line — legitimately
    different evidence) are never wrongly merged.
  - `--experimental-verdict` (see previous entries) reworked at the same
    time: instead of a Python heuristic pre-picking one site, it now shows
    the model every occurrence found — "no matter how it was found" — and
    the model itself names which one it considers most relevant. Verified
    this actually mattered: the model's picked location matched the real
    construction correctly once shown the full evidence set.
  - `cargo test` = 194 + 5 (was 158 + 5). Every finding in this entry was
    confirmed against the real Hetzner endpoint and the real `lispr`
    repository, not just unit tests.
- 2026-08-31 — **Fixed a real "silent report" bug in `reach-check.py`, and
  surfaced a genuine non-determinism finding in the same exchange.** A
  re-run of the identical `(print (test 5))` advisory against the identical
  repo/commit produced a completely different result — stage B extracted
  zero symbols this time, versus `print, test` the run before — despite
  `REACH_AI_TEMPERATURE=0`. That is outside anything fixable in `reach`'s
  own code: temperature=0 is sent correctly, but the hosted Qwen3.6-35B-A3B
  endpoint evidently does not decode perfectly deterministically regardless
  (plausible for a batched MoE model served at scale). Worth remembering
  when reading eval numbers from a hosted, non-local endpoint.
  - **The actual bug:** an empty ruleset is explicitly a *correct* answer in
    this pipeline's design ("do not guess symbol names the advisory does
    not mention"), but `print_human_report` only printed the ruleset/
    occurrences sections when they were non-empty, and only printed a
    stage's detail line when its status was degraded/failed — so a
    legitimately-empty, `Ok`-status extraction rendered as a blank gap with
    zero explanation, indistinguishable from a rendering bug. Fixed:
    ruleset summary/searched-terms/notes are now always printed (with an
    explicit "(none given)"/"(no symbols extracted)" rather than nothing),
    the occurrence count is always stated even at zero, and every pipeline
    stage's detail line is now shown, not just degraded/failed ones -- an
    `Ok` stage B that found nothing is exactly the stage whose detail line
    most needs to be visible. Verified against both a synthetic empty
    report and a synthetic populated one (no regression).
- 2026-08-31 — **Startup probe given the same retry tolerance as the rest
  of the pipeline.** Found by switching `REACH_AI_MODEL` to a second real
  model on the same Hetzner endpoint (`Qwen3.8-27B`, a dense reasoning
  model) and hitting a startup refusal on a malformed JSON reply. Reproduced
  the exact request directly: the model, key, and endpoint all check out —
  a follow-up identical call succeeded cleanly — so the failure was a
  one-off malformed answer, not a real problem with the endpoint. The
  startup probe (`ChatClient::probe`) called raw `complete()` with **zero**
  retry tolerance, while every real analysis (stage B, stage D) already
  gets **one** repair retry via `complete_json` for exactly this failure
  shape — the gate was stricter than the pipeline it exists to protect, and
  could refuse to start over a flake a live analysis would have silently
  recovered from. `probe()` now calls `complete_json` directly instead of
  hand-rolling its own parse check, so it gets identical retry semantics
  for free — also net-simpler, one call site instead of two. 2 new tests:
  a malformed-then-repaired-success case (proves the tolerance), and a
  twice-malformed case (proves the gate still refuses a genuinely broken
  endpoint, not just any single-request hiccup). `cargo test` = 196 + 5.
- 2026-08-31 — **Real root cause of the `Qwen3.8-27B` malformed-JSON
  failure found and fixed — it wasn't the probe's prompt wording.** The
  same startup instance kept failing deterministically, on both the
  original and the repair-retry attempt, with the exact same malformed
  text: `{"{"ready":true}`. That it repeated identically through a retry
  ruled out a prompt-framing theory (a schema-description prompt was tried
  first and made no difference — same artifact, unit-tested but not yet
  live-verified when that change landed). Root cause was in `reach`'s own
  parser, not the model: `extract_json_object` starts scanning for a
  balanced `{...}` at the *first* `{` only; here that first `{` opens what
  the matcher reads as a one-character string `"{"`, whose closing quote
  never arrives, permanently desyncing quote-tracking for the rest of the
  output — so a real, valid object one character later (`{"ready":true}`)
  was never found and the whole reply was reported as unparseable. Fixed
  by retrying the balanced-brace scan from each subsequent `{` (bounded to
  8 attempts) instead of giving up after the first fails to balance;
  `extract_json_object` now also returns the match's start offset so the
  candidate-scanning loop advances correctly past whichever `{` actually
  matched. New regression test reproduces the exact live-observed byte
  sequence. Live-verified after rebuilding: a fresh instance against the
  real Hetzner endpoint with `REACH_AI_MODEL=Qwen3.8-27B` now logs
  `startup check passed`. Also fixed one unrelated pre-existing clippy
  warning (`treesitter.rs`, `usize::MAX.min(1 << 20)` → `1 << 20`) found
  while re-running the zero-warnings check. `cargo test` = 197 + 5,
  `cargo clippy --all-targets` = 0 warnings.
- 2026-09-17 — **Reachability, step two: namespace revision, background
  analysis, review help.** Namespace mappings gain an optional `revision`
  (branch/tag/commit) and an `auto_analyze` toggle (migration
  `20260917000001`). A manifest's own `source_commit` still wins; without
  one, the revision is sent to `reach` as the new `ref` field and resolved
  **once, at request time** (`reach/src/fetcher/resolve.rs`: `git ls-remote`
  / `git rev-parse` in the hardened git env) to an exact commit that the
  analysis is pinned to — `finding_reachability.commit_source` records which
  happened and the UI says so. New `crates/api/src/reachability.rs` holds the
  logic shared by the button and a new background loop that queues analyses
  for opted-in namespaces' current untriaged findings (most severe first,
  `REACHABILITY_AUTO_MAX_IN_FLIGHT`, per-finding backoff, audited as
  `system:reachability-auto`) and keeps a status cache that drives an
  `evidence: …` badge in the Findings list. The finding view's report became
  a "review help": advisory summary, things to confirm (advisory
  preconditions + fixed lexical-search caveats per priority label), call
  sites ordered relevant-first with forge deep links at the analysed commit,
  false matches collapsed. Verified: `cargo test --workspace` = 182,
  `reach` = 208 + 5, clippy clean, `tsc` + `CI=true` build clean, and an
  end-to-end run against a throwaway Postgres + native `reach` (stub
  OpenAI-compatible model) + local git fixture: the loop queued the finding
  on its own, `main` resolved to the fixture HEAD, a later re-run after a new
  commit resolved to the new commit while the old row stayed pinned, a bad
  ref was a 400 before queueing, and the list badge/audit rows were correct.
  **Not verified:** the UI visually (not opened in a browser), and any run
  against a real model or a real https forge (`ls-remote` path covered by a
  pure parser test only).

- **2026-09-29 — review of `reach` + its AISE integration, and nine fixes.**
  Reviewed the analyser and the Magnolia-side integration, then fixed
  everything found. See `docs/AI_DEVLOG.md` ep. 11 for the reasoning; the
  changes:

  *Analyser / deployment.* `docker-compose.yml`: `reach` gets `restart:
  unless-stopped` and `depends_on: {ollama: {condition: service_healthy,
  required: false}}`, and `ollama` gets a healthcheck. Before this, a plain
  `docker compose up` (no `--profile ollama`, no `REACH_AI_*` in the root
  `.env`) left a **permanently dead** analyser: the startup probe fails, the
  process `exit(1)`s before binding, and the Dockerfile's `HEALTHCHECK
  --start-period` therefore never applies. New `scripts/stack-up.sh` is the
  supported way up — it checks the root `.env` for `REACH_AI_BASE_URL` *before*
  a five-minute build (compose never reads `reach/.env`), waits for the
  startup gate, detects a restart loop, and `--dtrack` additionally brings up
  Dependency-Track and mints its key, since dtrack is what produces the
  findings the reachability button attaches to.

  *Analyser / correctness.* The `/openapi.json` document was **not spec-valid**:
  all three authenticated paths declared a `bearer` security requirement that
  nothing defined (`utoipa` does not infer it). Added a `Modify` impl plus a
  test that walks every operation and asserts each named scheme exists.
  Stage D's prompt was interpolating four attacker-influenceable values
  *outside* the data fence its own module docs promise — `ruleset.summary`,
  `preconditions`, the term, and the **file path** (a newline is legal in a
  POSIX filename). The summary is a genuine second-order injection channel:
  one crafted advisory steers one stage B answer, replayed into every stage D
  call. Now fenced, with `prompts::sanitize_inline` for the two values that
  must stay inline. `USELESS_SYMBOLS` no longer drops a generic name the
  advisory *qualifies* (`yaml.load`, `Marshal::load`) — dropping `load`
  unconditionally turned CVE-2017-18342 into "no searchable symbols" and a
  `package_present_only` report, a false negative indistinguishable from a
  clean result; the rule biases toward recall on purpose and the residual gap
  is in the README. New `Counters::dropped_invalid_answers` stops an invented
  label being reported as an unverifiable citation, the report's headline
  trust signal. The `PANIC_DURING_ANALYSIS` string had whitespace runs and a
  duplicated word.

  *Eval.* New case 13 (qualified generic symbol, CVE-2017-18342 shape) with a
  `yaml-app` fixture; 13 cases now. Also fixed a real reproducibility bug
  found by *running* the suite: the throwaway fixture repos inherited the
  developer's global `commit.gpgsign`, so `git commit` prompted for an SSH
  passphrase and the whole suite was unrunnable on such a machine.

  *AISE integration.* `POST …/reachability` now returns **409** while an
  analysis for the same finding is `queued`/`running` (`?force=true` to
  override) — the analyser runs one job at a time and the only previous guard
  was the disabled button in the UI. Migration `20260929000001` adds
  `finding_reachability.report_json`/`report_stored_at`: AISE previously kept
  only an `analysis_id` and re-fetched the report on every render, so
  resetting the analyser's volume destroyed the evidence an analyst had
  triaged against. The archive is written on the first terminal poll, the
  write coalesces so a later failed poll cannot erase it, and both degraded
  branches now serve it and say so in the UI. New `get_dtrack_finding`
  replaces a `list_dtrack_findings` + `.find()` on the 3-second poll path.
  The background loop now logs its interval and in-flight budget at startup.

  **Verified:** `reach` 223 tests + clippy clean; workspace 185 tests, no new
  clippy warnings; `tsc` + `CI=true` build clean. New SQL exercised verbatim
  against the live dev Postgres in a rolled-back transaction, including that a
  report-less poll does not erase an archived report. Full stack up against
  the user's real Hetzner endpoint (`Qwen/Qwen3.6-35B-A3B-FP8`): startup gate
  passed in 22 s, `reachability_enabled: true`, the new auto-loop log line
  present, and `/openapi.json` fetched from inside the compose network to
  confirm the security scheme. Eval 13/13 baseline-only; case 13 against the
  real model passes with extraction P=1.00 R=1.00 while the non-AI baseline
  scores 0.00 on it.

  **Not verified:** the UI still has not been opened in a browser. The stage D
  prompt changed, and only case 13 was re-run against a real model — the other
  twelve are deterministically green but their model-dependent metrics predate
  the prompt change. Eval cases 06 and 08 remain unrun against a real model.
