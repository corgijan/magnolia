# AISE — supply-chain observability & transparency (university course project)

Multi-tenant service for **software supply-chain observability and
transparency**; EU CRA compliance is one concrete application of it, not the
whole purpose. Signed Merkle transparency log: SBOM upload (CycloneDX/SPDX),
DSSE signing, inclusion/consistency proofs, vulnerability findings via
Dependency-Track, OSV malicious-package checks, OpenSSF Scorecard reputation,
freshness/EOL, license policy, compliance profiles (NTIA, TR-03183), VEX
export/import + triage, webhooks, CI policy gate (`/verify`).
Rust workspace (`crates/`) + React frontend (`frontend/`) + Postgres.
Roadmap and status log: `ROADMAP.md`.

This repo is the deliverable for the AISE course module (6 CP). Course rules
below are HARD CONSTRAINTS — they override convenience.

## Course constraints (non-negotiable)

**AI component:**
- All LLM calls go through an **OpenAI-compatible API** (`POST
  {base_url}/v1/chat/completions`). Never call a provider-specific SDK or
  endpoint from core logic.
- Base URL, model name, API key, and inference settings (timeout, max tokens,
  temperature) come **only from env vars** (`AISE_AI_BASE_URL`,
  `AISE_AI_MODEL`, `AISE_AI_API_KEY`, `AISE_AI_TIMEOUT_SECS`, ...). Swapping
  the server/model must require zero code changes.
- During development the endpoint may point at Claude's OpenAI-compatible
  endpoint. **The assessed functionality must run on a locally hosted model
  (Ollama / llama.cpp, e.g. a Gemma-class 4–8B model) at submission** — treat
  the hosted endpoint as a stand-in. Prompts tuned on a frontier model behave
  differently on a 4B model: run evals against the local model early and
  regularly, not at the end.
- Mandatory failure handling (graded): inference server unavailable, timeout,
  invalid/unparseable model output (validate JSON app-side, retry once, then
  degrade), and processing failures. An inference failure must never break a
  core (non-AI) flow — degrade the way disabled tenant signals already do.
- Any confidence value shown in the UI or API is a **label, not a
  probability** — never present it as one unless it has been calibrated.

**Chosen AI feature (decided 2026-08-30, submitted in the course project
description):** **CVE reachability evidence.**

- *Primary goal:* AI-assisted scanning of the codebase to establish whether a
  reported CVE actually affects it — whether the vulnerable code is present
  and reachable at all — so a team acts on real exposure instead of raw
  finding counts. Input is the advisory plus the relevant code context;
  output is structured, cited evidence.
- *Declared fallback (also submitted):* if reachability proves too ambitious
  for the timeframe — a real risk on a 4–8B local model — fall back to
  AI-assisted **extraction and grounded summarisation of CVE advisories**
  (the former candidate (a)). Building the fallback first is the safer order:
  it shares the advisory-ingestion path and the eval harness.
- *Hard line, unchanged:* the model surfaces **evidence for an analyst, never
  an automated verdict.** "Vulnerable symbol X is/isn't referenced at
  path Y" is evidence; "this CVE is not exploitable" is a verdict and is out
  of scope. This is what keeps the reachability framing compatible with the
  no-verdict-suggesting-triage rule, and it must survive into the UI copy —
  see also the "confidence is a label, not a probability" rule above.
- *Data already in place:* `malicious_check.rs` already fetches OSV advisory
  text via `get_vuln`, and `dtrack_findings` carries per-finding
  descriptions — the ingestion side of both the primary and fallback feature
  largely exists.
- *Current state (2026-08-30):* **built.** The analyser is `reach/` — a
  standalone Cargo project in this repo, excluded from the root workspace,
  with its own SQLite database, Dockerfile and compose service; AISE talks to
  it over REST through `crates/reachability`. There is deliberately no
  `crates/ai`: all LLM work lives in `reach/src/ai/` (OpenAI-compatible
  client, all four graded failure modes) because the AI feature is that
  service. Pipeline, eval suite and limitations: `reach/README.md`. AISE-side
  UI is v1 scope — a button on a finding plus a minimal report view.

## Course deliverables to maintain continuously (not at the end)

- **AI development log** (`docs/AI_DEVLOG.md`): after each substantial
  agent-assisted task, append an episode: task given, proposed contribution,
  permissions/tools used, verification performed, accepted/modified/rejected,
  observed benefits/failures/risks. 5–8 representative episodes are required —
  when finishing a significant piece of work in a session, write the episode
  in the same session.
- **AI evaluation suite**: ≥10 representative cases with aggregated metrics
  (extraction precision/recall, groundedness, structured-output validity,
  latency). Must include ambiguous, unsafe (prompt-injection via advisory
  text), malformed, and out-of-scope inputs; uncertainty handling; failure-case
  analysis; and one baseline comparison (e.g. regex/keyword extraction, or
  local model vs. hosted model on identical cases). Keep cases + results in
  `eval/` as reproducible artifacts (script, not manual runs).
- **Docs**: README (setup, architecture, configuration, limitations),
  architecture/data-flow overview, **OpenAPI spec** for the REST API (currently
  missing — must exist at submission), Dockerfile, automated tests,
  presentation-ready example data.

## Compliance status (update when it changes)

Already satisfied by the codebase: domain responsibility, application logic
beyond LLM calls, Postgres persistence, React UI, REST API, Docker /
docker-compose, env-based config, `/health`, unit tests (`cargo test
--workspace` — 192 as of 2026-10-03; plus 227 in `reach/`), audit logging,
**automated tests over real data** (`test-sboms/` + `tests/test_real_sboms.py`),
**AI dev log** (`docs/AI_DEVLOG.md`, 14 episodes as of 2026-10-04), **the AI
feature** (`reach/` — CVE reachability evidence, with all four mandatory
failure modes), **the eval suite** (`reach/eval/` — 13 cases with aggregated
metrics and a non-AI baseline), and **an OpenAPI document for the analyser**
(`utoipa`-generated at `/openapi.json`, with Swagger UI at `/docs`, and a
test asserting every declared security requirement names a defined scheme).
Missing: **AISE's own OpenAPI document** (the analyser has one; the main API
does not). CI exists since 2026-10-09 (`.github/workflows/ci.yml`: both test
suites, baseline eval, frontend build, real-SBOM tests against a live
server). Licence: GPL-3.0-or-later (`LICENSE`). Course deliverables index:
`DELIVERABLES.md`. The architecture/data-flow doc (`ARCHITECTURE.md`) was
rewritten against the code on 2026-09-17 and now covers `reach/`.

## Repo conventions

- Established patterns — follow them, don't invent parallel ones:
  **tenant toggle** (migration + `set_tenant_*` in `crates/db` + settings
  endpoints + frontend switch), **sync loop** (`crates/api/src/*_sync.rs`
  shape), **pure check in core** (compliance-profile trait style: logic in
  `crates/core`, unit-tested, no I/O).
- Migrations: `migrations/YYYYMMDD00000N_name.sql`, append-only.
- DB queries live in `crates/db/src/lib.rs` (runtime-checked sqlx — SQL errors
  surface only at runtime, so smoke-test new queries against a live DB).
- Frontend is one large `frontend/src/App.tsx`; match its existing component
  and CSS patterns.
- Verification before calling work done: `cargo test --workspace`,
  `cd frontend && npx tsc --noEmit`, and `CI=true npx react-scripts build`
  (eslint warnings fail CI builds). If `reach/` was touched, also
  `cd reach && cargo test` — it is a separate Cargo project and the root
  workspace does not build it.
- Track progress in `ROADMAP.md`'s status log; leave an aidex session note
  before ending a session.

## Sandbox & hygiene (course requirement)

- The agent harness runs workspace-restricted; keep it that way. Never read or
  write secrets into the repo — inference keys and DB credentials come from
  env / `.env` (gitignored) only.
- Destructive or security-relevant operations (migrations against non-dev DBs,
  force-pushes, deletions) require explicit confirmation.
- Prefer meaningful commit messages over "fixes" — version history is part of
  the graded submission.
