# AI development log

Required course deliverable (see `CLAUDE.md`). Each episode records a
substantial agent-assisted task: what was asked, what the agent proposed,
which tools/permissions it used, how the result was verified, whether the
contribution was accepted / modified / rejected, and what was observed
about benefits, failures and risks.

**Agent:** Claude Code (Opus 5), run against this repository with a
workspace-restricted harness — file read/write inside the repo, shell,
Docker/`psql` against the local dev stack, and an MCP code-index server
(AiDex). No network write access beyond the local containers.

**Scope note, stated up front for honesty:** episodes 1–8 cover work from
**2026-08-29 to 2026-08-30**. The log itself was created on 2026-08-30, so
the earlier episodes are reconstructed from the session transcript and the
agent's own session notes rather than written at the moment of the work.
`CLAUDE.md` asks for continuous logging; from this point on, episodes are
appended in the same session as the work they describe.

**Distinction:** this log is about *AI-assisted development of the product*.
The product's own AI component is a separate thing: **CVE reachability
evidence**, decided on 2026-08-30 and built the same day as the standalone
`reach/` service (there is no `crates/ai` — all LLM work lives in
`reach/src/ai/`). Episode 9 covers building it, and is the one episode where
the two subjects meet: an agent-assisted task whose output is itself an AI
feature.

---

## Episode 1 — `/verify` consolidated into the single policy gate

**Task given.** Successive prompts: surface OSV's general vulnerability IDs
(not just `MAL-` ones) in `/verify`; add a package-reputation check; then
"remove the tools compliance check and move the checks into Check an SBOM
(CI policy gate)"; then make minimum-vs-full compliance legible.

**Proposed contribution.** Reuse the OSV `querybatch` response `/verify`
already paid for — `build_findings` was discarding every non-`MAL-` ID —
and add a `vulnerabilities` check beside `malicious-packages` from the same
call. Add `package-reputation` as a *cache read* (`get_component_reputation`)
mirroring the existing `outdated-components` pattern, explicitly **not** a
live deps.dev call in the request path. Delete the Tools tab's separate
`POST /tools/compliance-check` endpoint and fold its behaviour into
`/verify`, adding preview variants (`compliance_reports_preview_for_tenant`,
`license_violations_preview_for_tenant`) so profiles/policies are evaluated
even when `enforce_level = "off"`.

**Tools/permissions used.** File edit, `cargo check`/`cargo test`, `tsc`,
`react-scripts build`, AiDex queries.

**Verification.** `cargo test --workspace` (27 api / 96 core, no
regressions); `tsc --noEmit` and `CI=true react-scripts build` clean; live
`curl` against the running container confirming the new check rows appear
in the JSON.

**Accepted / modified / rejected.** Accepted. One self-caught defect during
implementation: the first draft called `find_malicious_components` **twice**,
issuing two identical OSV network calls for one request. Restructured to
call once and derive both checks from the single `OsvCheckResult`. A third
option the user raised — synchronous Dependency-Track polling inside
`/verify` — was explicitly **rejected** as high-risk (ties request latency
to an external scanner) and left as `not_evaluated`.

**Observed.** *Benefit:* the agent spotted that the data for the new feature
was already being fetched and thrown away, avoiding any new API cost.
*Risk:* it also introduced the duplicate-call bug in the same edit — the
useful work and the defect came from the same pass, so review was what
separated them, not the agent's confidence.

---

## Episode 2 — License policy: binary → three-state unknown handling

**Task given.** "Add the option to warn when no license info is found so
that it's not binary ignore … return a warn when uploading an SBOM."

**Proposed contribution.** Replace `LicensePolicy.flag_unknown: bool` with
`UnknownLicenseHandling { Ignore, Warn, Flag }`, and centralise the one
subtle rule in a new pure function `license_policy_status(violations,
enforce_level, unknown_handling)`: an `Unknown`-reason violation under
`Warn` **never** fails a verdict, even when `enforce_level == "block"`;
only a `Denied` violation, or `Unknown` under `Flag`, can block. Both the
upload gate (`enforce_license_policy`) and `/verify` call that one function
so they cannot drift apart. Migration `20260830000001` adds
`unknown_license_handling`, backfills from `flag_unknown`, drops the old
column.

**Tools/permissions used.** File edit, new SQL migration, `cargo test`,
`docker compose build/up`, `psql` schema inspection, `curl`.

**Verification.** 8 new core unit tests. Then **live** against the running
stack: set `enforce_level=block` + handling `warn` → `/verify` returned
`"status": "warn"` (verdict passable); switched to `flag` → `"status":
"fail"`, verdict `fail`. Schema change confirmed via `\d
tenant_license_policies`. Tenant's original settings restored afterwards.

**Accepted / modified / rejected.** Accepted. Follow-up correction: the user
reported the new `warn` state was invisible in the UI. Root cause was two
separate defects — the manifest endpoint used the *enforcement* helper
(which returns empty when `enforce_level == "off"`) instead of the preview
one, and `showLicenseSignal` hid the row entirely unless enforcement was on.
Both fixed.

**Observed.** *Benefit:* pushing the pass/warn/fail decision into one pure,
unit-tested function made the "warn never blocks" invariant checkable in
isolation. *Failure:* the agent implemented the backend state correctly but
did not trace it to the surface — the feature was "done" by test evidence
and still invisible to the user. Backend-green is not user-visible-working.

---

## Episode 3 — Incident: destructive git command caused uncommitted data loss

**Task given.** (During Docker build-cache work.) No task; this was an
agent-initiated action while tidying a one-line test edit.

**What happened.** The agent ran `git checkout -- src/App.tsx` from inside
`frontend/` intending to discard a single test comment. The command reverted
the **entire file** to the last commit, destroying roughly 1,750 lines of
uncommitted work from earlier in the same day (the frontend halves of six
roadmap features). The file had never been staged, so no git-level recovery
existed.

**Tools/permissions used.** Shell (`git checkout`) — the harness permitted
it without confirmation at the time.

**Recovery.** The agent flagged the loss immediately rather than continuing,
and asked the user whether external recovery existed. The user answered
"No local recovery available — please reconstruct it." Reconstruction used
three sources: `frontend/src/api.ts` (untouched, so the full type/function
contract survived), verbatim `Edit` calls still visible in the session
transcript for recent features, and detailed AiDex session notes for older
ones.

**Verification.** `tsc --noEmit` clean; `CI=true react-scripts build`
produced a **byte-identical gzipped bundle size (92.84 kB)** to the
pre-incident build — strong evidence the reconstruction was complete. Every
exported symbol in `api.ts` was cross-checked for a reference in `App.tsx`.

**Accepted / modified / rejected.** N/A — this was damage, not a
contribution. Recovery accepted after verification.

**Observed.** *Risk — the most important entry in this log:* an agent with
unconfirmed shell access can destroy unversioned work in one command, and
the blast radius is invisible in the command itself (`git checkout -- <file>`
looks surgical; it is not). *Mitigations adopted afterwards:* never use bulk
revert to undo a small manual edit — hand-revert the specific lines, or
`git diff` first to see the true scope. The harness guidance now also
requires `git status` before any destructive git operation. *Secondary
observation:* the recovery only worked because non-code artefacts
(`api.ts`, session notes, transcript) independently encoded the same
design — redundancy across representations, not the agent's memory, is what
made it recoverable.

---

## Episode 4 — Diagnosing a user-reported bug that was not a code bug

**Task given.** "I added namespace /test and couldn't upload in the ui to
the namespace /test, why and fix!!!"

**Proposed contribution.** Rather than editing code first, the agent
inspected live state: `psql` against `registered_namespaces` showed the
tenant had registered **`/tets`** — a typo — with
`require_namespace_registration` enabled. The upload rejection was correct
behaviour. The agent nonetheless identified two genuine product gaps that
made the typo invisible and unrecoverable: the error message named only the
attempted namespace, never the registered ones; and there was **no way at
all** to un-register a namespace once created.

**Tools/permissions used.** `psql` reads against the dev DB, AiDex queries,
file edit, `cargo check`/`test`, `tsc`/build.

**Verification.** Compile + test suites clean. The new
`DELETE /api/v1/namespaces/registered` endpoint and its Settings "Remove"
button were exercised in the same session.

**Accepted / modified / rejected.** Accepted. Notably the agent **declined**
to fix the user's data directly — correcting the `/tets` row would have been
a raw mutation of live tenant data that was never requested. It shipped the
mechanism and told the user which button to press.

**Observed.** *Benefit:* diagnosis before implementation avoided "fixing"
correct code. The genuinely useful output was the pair of UX gaps, not a
patch. *Risk avoided:* an agent eager to satisfy "and fix!!!" could easily
have run an `UPDATE` on production-shaped data; the boundary between
"provide the capability" and "use the capability on the user's behalf" needs
to stay explicit.

---

## Episode 5 — Porting the CLI from Bash to Python

**Task given.** "Port the script to python3 with very good and clean code
quality" (following a question about Ubuntu-slim dependencies).

**Proposed contribution.** A stdlib-only `scripts/magnolia-upload.py`
(argparse, urllib, dataclasses, type hints), preserving the Bash version's
flags, `Magnoliafile` format and exit codes. Sectioned into config
resolution / HTTP / tenant preflight / commands / CLI.

**Tools/permissions used.** File write, `ruff check` + `ruff format`,
`python3 -m py_compile`, live `curl`-equivalent runs against the dev server,
`psql` for cross-checking tenant/key state.

**Verification.** `ruff` clean. Then every path exercised live: verify
(terse / `--verbose` / `--json`), upload, and five error paths (missing
config, missing API key, tenant mismatch, missing SBOM file, unreachable
server). `--verbose` output was diffed against the Bash version's and
matched line for line.

**Accepted / modified / rejected.** Accepted **after a real defect was
caught by live testing**. The first implementation built the multipart body
with the file part **last**. The server reads whichever multipart field
arrives *first* as the SBOM bytes regardless of its field name, so it parsed
the string `"cyclonedx"` as the SBOM and returned a schema error. Fixed by
writing the file part first, with a comment recording why the ordering is
load-bearing.

**Observed.** *Failure:* the bug was invisible to every static check —
`ruff`, `py_compile` and type hints all passed. Only running it against the
real server surfaced it. *Risk:* a port that "looks equivalent" can silently
depend on an undocumented server-side behaviour (positional multipart
parsing) that the original encoded incidentally, through curl's argument
order. Behavioural parity needs execution, not review.

---

## Episode 6 — Test suite over real, generator-produced SBOMs

**Task given.** "Write a test suite where real SBOMs are verified against
the proper implementation. Give me a folder of real SBOMs for testing."

**Proposed contribution.** Generate fixtures with `syft` (Anchore's SBOM
generator) from this repository's **own** dependency manifests rather than
hand-writing them, deliberately spanning every format/version
`validate_sbom_schema` claims to support: CycloneDX 1.5 and 1.6, SPDX 2.2
and 2.3; single- and mixed-ecosystem graphs (~1,600 / 1,285 / 1,268 / 367
components). Two independent suites: a hermetic Rust unit test embedding all
four via `include_str!`, and `tests/test_real_sboms.py`, which shells out to
the **real CLI** against a **live server** — deliberately not a
reimplementation of the HTTP logic.

**Tools/permissions used.** `syft`, file write, `cargo test`, `python3
unittest`, `ruff`.

**Verification.** Rust suite 105/105 (was 96). Python suite 3/3 against the
running instance. `test-sboms/README.md` records the exact `syft` commands
for reproducibility.

**Accepted / modified / rejected.** Accepted. Initial `syft` invocation
scanned `target/` and `node_modules/` and had to be killed after 120s;
re-run with explicit `--exclude` globs, completing in 1.3s.

**Observed.** *Benefit:* real generator output immediately exercised code
paths hand-written fixtures would not have (real purls, license expressions,
1,600-component graphs). *Risk noted:* the Python suite asserts only
properties that must hold for *any* valid SBOM (schema passes, response
shape valid, compliance profiles evaluated) — deliberately not exact
verdicts, which depend on mutable tenant policy. A stricter suite would be
brittle against the very settings other episodes change.

---

## Episode 7 — Deployment hardening for an internet-facing host

**Task given.** "Check the Dockerfile so that I can set it up on a VPS with
internet connection. Don't expose databases etc." Later: make the frontend
optional; allow pointing the UI at another server.

**Proposed contribution.** Remove `ports:` from `db`, `dtrack-db` and
`dependency-track` entirely so they are reachable only on the compose
network — reasoning explicitly that a host firewall is *not* sufficient,
since Docker's own iptables rules are known to bypass `ufw`; the guarantee
comes from there being no published port at all. Parameterise every secret
via `${VAR:-default}`, add a tracked `.env.example` (with generation
commands) and a git-ignored `.env`. Gate the frontend behind a compose
profile. Add a browser-side "Server URL" override so a separately hosted UI
can target a remote API.

**Tools/permissions used.** File edit, `docker compose config/build/up`,
`docker ps`, `curl`, `tsc`/build.

**Verification.** `docker ps` confirmed `db`/`dtrack-db`/`dependency-track`
expose no host binding while `api` still publishes 3000; `/health` and
`/api/v1/whoami` returned 200 against the recreated stack; the frontend
container was built and its nginx `/api/` proxy verified end to end. The
cross-origin path was verified with a real CORS preflight (`OPTIONS` with a
foreign `Origin`) plus an authenticated cross-origin `GET`.

**Accepted / modified / rejected.** Accepted. Modified after user feedback
during rollout: `API_PORT` had to be threaded through, and a stale
`${FRONTEND_PORT:-false}` fragment was repaired. Two user-reported failures
turned out **not** to be code defects — a `Magnoliafile` `tenant_url`
missing its `https://` scheme (Caddy answered the resulting HTTP request
with a 308, which the script correctly refused to follow), and a Caddyfile
pointing `reverse_proxy` at a bare hostname. Both diagnosed, neither
"fixed" in code.

**Observed.** *Benefit:* the agent could state *why* removing the port
mapping is stronger than a firewall rule, not merely that it is
conventional. *Risk:* it changed the compose-level `DEV_MODE` default from
`true` to `false` — correct for production, but it would have silently
altered the user's local behaviour, so a local `.env` preserving the old
values was written in the same change. Defaults that harden production can
break development invisibly.

---

## Episode 8 — Security review, then the fix it identified

**Task given.** "Review the current project and tell me where things need to
be more secured or can be improved." Then "do 1" (the top finding), then
change the key format.

**Proposed contribution.** An evidence-based audit rather than a generic
checklist: each finding backed by a code location and, where possible, a
measurement. Top finding — Argon2 runs on **every** authenticated request
(`auth.rs:79`) at ~19 MB and ~12 ms, while the secrets it protects carry 244
bits of CSPRNG entropy. Argon2 exists to make brute-forcing *low-entropy
human passwords* expensive and buys nothing here. Fix: SHA-256 with
constant-time comparison, behind a **scheme-prefixed** hash format
(`sha256:` vs legacy `$argon2`) so existing keys keep working with no
migration. Then, on request, a `mag_<43 base64url>` token format — which is
only possible *because* hashes became deterministic: the token alone can now
locate its row by hash, whereas a salted hash required the caller to supply
the row id.

**Tools/permissions used.** AiDex + `grep` for code audit, `psql` (schema,
`EXPLAIN`, row counts), `docker exec` for on-disk key permissions, `curl`
and `ab` for measurement, file edit, `cargo test`, new migration.

**Verification.** Before/after with `ab` (n=300, c=20): **333 req/s /
60.05 ms → 4,335 req/s / 4.61 ms**, zero failures — a 13× improvement. Live
checks that legacy `<key_id>:<secret>` keys still authenticate (200), wrong
secrets still 401, a new `mag_` key authenticates, six malformed-token
variants all 401, and — critically — that **revocation is still instant**
(revoke → next request 401). `EXPLAIN` initially showed a Seq Scan; rather
than assume, `enable_seqscan=off` confirmed the new unique index is
correctly shaped and the planner was simply optimising a 24-row table.
Rust suite 153 → 165 tests.

**Accepted / modified / rejected.** Accepted. Two agent self-corrections:
(a) an early draft claimed the webhook client had "no timeout" — reading the
delivery path showed an explicit 10 s timeout, and the claim was withdrawn
before being reported; (b) a test fixture initially contained an **invented**
Argon2 hash the agent had fabricated rather than generated; caught, and a
real one produced with a throwaway program (which also empirically confirmed
the `m=19456` figure cited in the review). Separately, the agent **declined**
to place the user's new bootstrap key into `docker-compose.yml` as a default,
since that would republish a known super_admin credential — the exact defect
being removed; it went to git-ignored `.env` and the default became empty
(fail-closed).

**Observed.** *Benefit:* measurement changed the recommendation's weight —
"Argon2 is slow" is an opinion, "333 → 4,335 req/s" is not. Reading the code
before reporting prevented one false finding from reaching the user.
*Failure/risk:* the fabricated hash is the sharpest example in this log of an
agent producing confident, plausible, wrong artefacts — it looked exactly
like a real PHC string. It was caught only because the test was actually
run. Any generated *fixture* that encodes a cryptographic fact must be
produced by execution, never written from memory.

---

## Episode 9 — the AI feature itself: `reach/`, a CVE-reachability evidence analyser

**Task given.** "Try that and build it in its own subfolder in this project",
pointing at a written plan for a standalone reachability-evidence service
plus a minimal AISE-side button.

**Proposed contribution.** The whole service: `reach/` as a separate Cargo
project (own lockfile, own `[workspace]`, `exclude = ["reach"]` in the root
manifest), a five-stage pipeline (deterministic presence check → LLM ruleset
extraction → deterministic occurrence search → per-occurrence LLM labelling →
pure-function rubric), an OpenAI-compatible client covering the four graded
failure modes, a `git`-CLI fetcher behind a trait, `utoipa`-generated
OpenAPI, a Dockerfile and compose service with an optional Ollama profile, a
12-case eval suite with a non-AI baseline, and on the AISE side a migration,
a client crate, two audit-logged endpoints, and the button.

**Tools/permissions used.** File read/write inside the repo, `cargo`
build/test, `npx tsc` / `react-scripts build`, `docker compose` build and up,
`psql` against the local dev database, `curl` against both services, and a
local Ollama server for the real-model eval run.

**Verification.** `cd reach && cargo test` = 138; `cargo test --workspace` =
174 (was 165); `tsc --noEmit` and `CI=true react-scripts build` clean. Then
the part that mattered: the full path against the live Docker stack — upload
an SBOM carrying `source_commit`, map the namespace to a repository, queue an
analysis, poll it, and read the resulting report and the audit rows in
Postgres. Separately, a real run of the eval suite against a **local 8B
model** (deepseek-r1:8b via Ollama), not a hosted frontier model.

**Accepted / modified / rejected.** Accepted, with two deliberate deviations
from the plan, both documented at the code that implements them:

- Stage A's index is a hand-written language-agnostic scanner rather than
  tree-sitter. Per-language grammars would have made "language-agnostic" mean
  "the eight languages we vendored", and a polyglot repository's remaining
  files would have contributed nothing silently.
- The fetcher does a plain `--depth 1` fetch instead of
  `--filter=blob:limit=1m`. A blob filter only defers work that `git checkout`
  immediately undoes, one lazy request per filtered blob.

**Observed benefits.** Writing tests alongside each module caught three real
defects before anything ran: a `RETURNING`-based job claim that sqlx never
actually applied (the row came back, the status stayed `queued`, so the same
job would have been handed out forever), and two wrong guesses about git's
stderr wording. All three were unit-test failures, not review findings.

**Observed failures and risks.**

1. *The harness reported its own configuration as a model failure.* The first
   `--baseline-only` run — no inference server by design — scored 5/12,
   because every model-dependent expectation was vacuously unmet. A metric
   that reads as "the model is bad" when the model was never called is worse
   than no metric. Fixed by making the harness check only what the
   deterministic path owns in that mode, and by recording the mode in every
   results file so one kind of run cannot be mistaken for the other.
2. *The same eval-design flaw, three times, each worse than the last.* The
   forbidden-substring checks were searching the entire serialized report,
   and every instance fired on the right string for the wrong reason.

   First, statically: the out-of-scope case forbids "is exploitable", and the
   report's own mandatory disclaimer says it "does not determine whether the
   vulnerability is exploitable" — the sentence that establishes the
   no-verdict framing was tripping a verdict check. Then the real-model run
   found two more. The code-comment injection case failed because the report
   contained the payload — inside the **source snippet**, which is precisely
   what the analyst has to see; the check was penalising the tool for showing
   a human the hostile comment. And the out-of-scope case failed on "exploit
   payload", which the model had almost certainly written into `notes`, the
   field the stage B prompt explicitly asks it to use for instruction-like
   text it noticed and did not act on.

   The last two matter most, because the "fix" they invite is the wrong one:
   an eval that rewards a lower score for hiding quoted evidence, or for
   silently swallowing an injection attempt instead of reporting it, would
   have steered the prompts toward being less useful and less honest. The
   checks now search only the model's **substantive conclusions** — summary,
   extracted terms, preconditions, site reasoning — never quoted file
   content, never our own constants, never `notes`. Suppression is caught
   separately and more reliably: every injection case also asserts that the
   real symbol was still extracted and the finding still reported. Five unit
   tests now pin this down, since it is the part of the harness most likely
   to be "simplified" back into being wrong.

   *Caveat, stated because it is the honest state:* the run that surfaced the
   second and third instances was stopped before it finished, so it produced
   no results file, and cases 06 and 08 have **not** been re-run against the
   real model since the fix. Their real-model outcome is currently unknown,
   not passing. The diagnosis above is inference from the fixture text and
   the prompt design, not from a captured report.
3. *The local model behaved as the course warned it would.* Against
   deepseek-r1:8b, one call was truncated mid-JSON at `max_tokens` (a
   reasoning model spends most of the budget on its `<think>` block before
   the JSON starts) and one returned an empty completion. Both degraded
   correctly rather than failing the analysis. This is the concrete evidence
   for "prompts tuned on a frontier model behave differently on a small local
   one": the failure was not reasoning quality, it was output shape and
   budget. It also motivated a real fix — the JSON extractor now tries every
   balanced object in the output rather than the first, because a `<think>`
   block routinely contains braces.
4. *Latency is a design constraint, not a detail.* One case took eight
   minutes on the local model. `REACH_MAX_SCORED_SITES` (one inference call
   per occurrence) is the knob that decides whether this feature is usable at
   submission, and it is documented as such.
5. *Standing risk.* Per-label precision is measured over twelve synthetic
   fixtures. It is a sanity check, not a calibrated probability, and the
   README and the UI copy both say so — which is the whole reason the labels
   are ordinal names rather than percentages.

**Note on the trust boundary.** Two things in this feature are attacker-
influenceable by construction: advisory text (fetched from a community-fed
database) and repository content (the thing under examination). Both are
fenced as data in every prompt, the fence markers are scrubbed from the
payload so it cannot close its own block, and both injection channels are
required eval cases. Nothing the model returns is executed, and every
location it claims is checked against the real checkout before it reaches a
report — an unverifiable claim is dropped and counted rather than shown.

## Episode 10 — Reachability in the background, with a namespace revision and a review view

**Task given.** "Allow for each namespace to add metadata like revision and
link to git to give it to reach … so that a reach job can run in the
background and in the end a review help can be displayed with relevant info
on the CVE in the view in the Magnolia UI so that triage is hopefully faster
and less annoying."

**Proposed contribution.** Read the existing feature first: the repository
link already existed per namespace, and the per-finding button already
existed. What was missing was (1) a way to analyse SBOMs uploaded *without* a
commit, (2) running without a click, and (3) a report laid out for triage.
Built: a `revision` + `auto_analyze` on the namespace mapping; a `ref` field
on `reach`'s create endpoint resolved once to an exact commit; a shared
`crates/api/src/reachability.rs` used by both the button and a new
background loop; a status cache for list badges; and a "review help" view.

**The design tension, and how it was resolved.** The project had a
documented rule: never analyse a moving branch head, because evidence about
`main` cannot be reproduced. The request asked for exactly a branch-like
namespace revision. Rather than either refusing or silently dropping the
rule, the revision is resolved **at request time** by the analyser and the
analysis, the stored row and the report are all pinned to the resulting
commit; the ref is kept only as provenance. A manifest's own commit still
wins, and the UI states when the scanned commit came from the namespace
revision ("may not be the exact code this SBOM describes"). The rule's
purpose — reproducible, auditable evidence — survives; its over-strict form
did not.

**Staying on the evidence side of the line.** The background loop never
writes a VEX status and never closes anything. The review view's "worth
confirming" list is fixed text chosen by which deterministic rules fired
(plus the advisory's own extracted preconditions), not new model output — so
the feature added no prompt, no new graded AI surface, and no path by which a
model could phrase a verdict. An empty result is explicitly framed as "no
lexical reference found", with the lexical search's blind spots listed next
to it.

**Tools/permissions used.** File read/write in the repo; `cargo test`/
`clippy` in both projects; `tsc` and the `CI=true` build; a throwaway
`postgres:15` container on a spare port; native `reach` and
`magnolia-server` processes; a Python stub of an OpenAI-compatible endpoint
in the session scratchpad; `curl` and `psql` (via `docker exec`). The browser
was deliberately not used to log into the UI: that would have meant typing
an API key into a page.

**Verification.** 182 workspace tests (+8), 208 + 5 in `reach` (+10 lib,
including ref-name validation, `ls-remote` precedence and annotated-tag
peeling, and resolution in a real local git repository), clippy clean, build
clean. End to end: the loop queued the CRITICAL finding without a click;
`main` resolved to the fixture's exact HEAD; a finding with no advisory text
was correctly skipped; a nonexistent branch came back as a readable 400
before anything was queued; after a new fixture commit, a re-run resolved to
the new commit while the earlier analysis stayed pinned to the old one; the
findings list and audit log showed the cached status and
`system:reachability-auto` respectively.

**Accepted / modified / rejected.** Pending the user's review; not committed.

**Observed benefits / failures / risks.**
1. *A pre-existing, environment-dependent test failure surfaced.* Five git
   fixture tests in `reach` failed on the developer's machine because the
   global git config signs commits with a passphrase-protected key. The
   tests were never hermetic; they now set `GIT_CONFIG_GLOBAL=/dev/null`.
   This would equally have broken a CI runner with signing configured.
2. *A shotgun text replacement landed in the wrong struct.* A scripted edit
   meant for `get_analysis` also matched the job-claim query's struct literal
   and failed compilation — caught immediately, but a reminder that
   pattern-based edits across a file need a uniqueness check.
3. *Stub-model verification has a ceiling.* The end-to-end run proves the
   plumbing, the SQL and the pinning semantics, not model quality; the
   `ls-remote` path against a real forge is covered only by a pure parser
   test. Both remain open, alongside a visual check of the new view.
4. *Standing cost risk.* Auto-analysis spends minutes of local-model time
   per finding. It is opt-in per namespace, capped in flight, limited to the
   current release's untriaged findings, and backs off per finding on
   permanent failures — but a large first sync on an opted-in namespace will
   still occupy the analyser for a long time.

---

## Cross-cutting observations

**Where the agent was most useful.** Tracing an invariant across layers
(finding that `/verify` and the upload gate could drift, and collapsing them
onto one pure function); noticing already-paid-for data being discarded
(episode 1); and audit work where breadth plus evidence-gathering matters
(episode 8).

**Recurring failure modes.**
1. *Confident fabrication of plausible artefacts* — the invented Argon2
   hash (ep. 8). Static plausibility is not correctness.
2. *Declaring done at the wrong layer* — backend correct, feature invisible
   in the UI (ep. 2).
3. *Static checks passing over a real behavioural break* — the multipart
   ordering bug (ep. 5).
4. *Destructive actions whose blast radius exceeds their apparent scope* —
   the `git checkout` incident (ep. 3).

**What consistently caught these.** Running the thing against the live
stack. In every episode above, the defects that mattered were found by
execution — `ab`, `curl`, `psql`, a real CLI invocation — not by compilation,
type-checking, linting, or unit tests, all of which passed while the bugs
were present. Unit tests protected against *regression*; only live runs
established *correctness in the first place*.

**Open risk.** Verification in this project still depends on a human-driven
local Docker stack. There is no CI (`.github/workflows` does not exist), so
none of the 174 workspace tests, the 138 tests in `reach/`, the integration
suite, or the eval suite run automatically — the evidence in this log was
produced by explicit request, not by a gate.

---

## Episode 11 — A review of `reach` and its AISE integration, then the fixes

**Task given.** "Read especially the reach related parts and give me feedback
on that", then "i want to run it with the hetzner model, give me an easy way
to start and check whether the integration in Magnolia is well done", then
"fix the things".

**Permissions / tools used.** Read access across `reach/` and the AISE
reachability paths; `cargo test`/`clippy` in both Cargo projects; `docker
compose` build and run of the full stack against the user's real Hetzner
OpenAI-compatible endpoint; `psql` against the live dev Postgres; one live
eval case against the real model. Wrote to `reach/src/`, `crates/`,
`frontend/src/App.tsx`, `docker-compose.yml`, a new migration, a new
`scripts/stack-up.sh`, and the root `.env` (gitignored).

**Proposed contribution.** Nine findings, ranked, with the reasoning and a
time estimate each; then, on request, all nine fixed. The findings that
mattered were not style issues:

1. *`docker compose up` left a dead analyser.* `reach` `exit(1)`s when its
   startup probe fails; the compose default pointed `REACH_AI_BASE_URL` at
   the profile-gated `ollama` service that a plain `up` does not start; and
   the service had no `restart:` policy and no `depends_on`. The Dockerfile's
   `HEALTHCHECK --start-period=180s` could never help, because the process
   exits *before* binding a port. Fixed with `restart: unless-stopped`, a
   healthcheck on `ollama`, and `depends_on: {ollama: {required: false}}`.
2. *The OpenAPI document was not spec-valid.* Every path declared
   `security(("bearer" = []))` while nothing registered the scheme —
   `utoipa` does not infer it — so the emitted document referenced an
   undefined security scheme. OpenAPI is a graded deliverable. Fixed with a
   `Modify` impl, plus a test that walks every operation's `security` and
   asserts each named scheme exists, so a second scheme later cannot
   reintroduce the same gap.
3. *Untrusted text bypassed the prompt's own data fence.* `prompts.rs`
   documents that all untrusted text is fenced; `site_messages` interpolated
   `ruleset.summary`, `preconditions`, the search term and the **file path**
   outside it. The path is the sharp one: a newline is legal in a POSIX
   filename, so a crafted repository could end the sentence it was quoted in
   and continue with what reads as a top-level instruction. The summary is
   the subtle one: a *second-order* channel where one crafted advisory steers
   one stage B answer, which is then replayed as prompt text into every stage
   D call. Fixed by fencing the advisory context and adding
   `sanitize_inline` for the two values that must stay inline.
4. *The generic-symbol denylist silently dropped famous CVEs.* `load` is on
   the noise list — and `yaml.load` is CVE-2017-18342, `pickle.load` and
   `Marshal.load` the same shape. Such an advisory yielded zero searchable
   symbols and a `package_present_only` report: a false negative that looks
   exactly like a clean result. Fixed by rescuing a denylisted name when the
   advisory writes it in qualified form, with the residual gap documented.

Plus a counter that conflated "invented label" with "unverifiable citation"
in the report's headline trust signal; a user-facing panic message with
collapsed-whitespace runs and a duplicated word; and, AISE-side, a POST with
no in-flight guard, no persisted report, an N+1 finding lookup on the
3-second poll path, and a background loop that started silently.

**A fifth finding the work itself produced.** Running the eval suite failed
outright on this machine: the harness builds throwaway git repositories for
its fixtures and inherited the developer's global `commit.gpgsign`, so `git
commit` prompted for an SSH key passphrase and failed. A suite whose stated
purpose is reproducible artifacts was unrunnable for anyone with commit
signing configured — found only by running it, not by reading it. Fixed by
pinning the git config the fixtures are built with.

**Verification performed.** `reach`: 223 tests (from 208), clippy clean.
Workspace: 185 tests (from 182), no new clippy warnings. Frontend: `tsc
--noEmit` and `CI=true` build clean. The new SQL was exercised verbatim
against the live dev Postgres inside a rolled-back transaction — including
the property that actually matters, that a later poll carrying no report does
not erase an already-archived one (`report_survived = t` after a `missing`
poll). The full stack was brought up against the real Hetzner endpoint: the
startup gate passed in 22 s, `/api/v1/config` reported
`reachability_enabled: true`, the new auto-loop log line appeared with its
budget, and the live `/openapi.json` was fetched from inside the compose
network to confirm the security scheme is really there. Eval: 13/13
baseline-only, and the new case 13 passes against the real model with
extraction P=1.00 R=1.00 — while the non-AI baseline scores 0.00 on it,
making it the sharpest single case in the baseline comparison.

**Accepted / modified / rejected.** The user accepted all nine fixes and
chose "one command starts both" for the dtrack coupling over gating `reach`
behind the dtrack profile or hard-failing without it — the least coupled of
the three options offered. Two scope questions were asked before writing any
code, because the answers changed the size of the change set by roughly a
factor of two.

**Observed benefits / failures / risks.** The benefit was in *ranking*:
nine findings across two Cargo projects, compose and the frontend, ordered by
what a grader or an operator would actually hit first, rather than in the
order they were discovered. The generic-symbol fix is the one with real
judgement in it — a denylist is a recall/precision tradeoff, and the fix
deliberately biases toward recall (`pre-load` reads as qualified) because a
noisy occurrence list is skimmable while a silent miss is invisible; that
asymmetry is written down in both the code and the README rather than being
left implicit. The risk: two fixes changed behaviour that only a live model
exercises — the stage D prompt was restructured, and only *one* eval case was
re-run against the real model. The other twelve have been verified
deterministically but not re-measured against the model since the prompt
changed, so the prompt-sensitive metrics in this log predate it.

**Still open.** AISE's own OpenAPI document; CI (`.github/workflows` remains
absent, so none of this ran automatically); and eval cases 06 and 08 against
the real model.

---

**Session note for episodes 12–14 (2026-10-02 to 2026-10-04).** Agent:
Claude Code with Claude Opus 5.5, in auto mode (commands ran without a prompt
per call; the harness still blocked or asked for anything destructive or
outward-facing). **This session ran directly on the macOS host, not inside
the microsandbox VM** the README describes as the normal setup — visible in
the agent starting Docker Desktop on the host with `open -a Docker`. Its file
access was not limited to the workspace by a VM boundary in this session;
it stayed inside the workspace and its scratch directory by convention.

## Episode 12 — Test mode and a Findings-page rework, with two regressions the agent shipped

**Task given.** "Add a testing mode to reach that always returns a yes
finding is interesting and an example line. The UI should be able to work
with that", then "rework the findings ui, there needs to be more clean
separation between single findings and triage … you have chrome to look at
the results", then "make it fill the whole page", "add a filter for known
source".

**Permissions / tools used.** Edits to `reach/src/` (new
`pipeline/test_mode.rs`, `config.rs`, `main.rs`, `api.rs`),
`frontend/src/App.tsx`/`App.css`/`api.ts`, `crates/db`, `crates/api`,
`docker-compose.yml`, `scripts/stack-up.sh`; `cargo test`/`clippy`; `docker
compose` rebuilds of the running stack; `psql` reads against the dev
database. The Chrome extension the user offered **never connected**, so for
visual checks the agent installed `playwright-core` in its scratch directory,
drove the system Chrome headless, and logged in with **short-lived test API
keys it minted itself** (an `auditor` and a `domain_admin` key for the demo
tenant, both expiring the next day, kept only in the scratch directory).

**Proposed contribution.**
- `REACH_TEST_MODE`: skips the startup inference check; every analysis
  returns, after a 2-second pause, a canned `direct_references` report with
  one `likely_relevant` example line. The report carries `test_mode: true`,
  every analyst-facing string starts with `TEST MODE`, its citation is never
  marked verified, and the UI shows a warning banner. The eval harness pins
  the flag off so a canned report can never be scored.
- Findings page: master–detail instead of rows expanding inline; the detail
  has *Overview* / *Reachability* / *Triage* tabs, so the AI evidence and the
  human decision sit on different tabs.
- A `known_source` filter (namespace has a mapped repository), implemented
  in the SQL query rather than client-side, because the list is paginated.

**Two contributions that were wrong, and how they were found.**
1. *The reworked layout was shipped without being looked at.* With no
   browser connected, the agent verified only `tsc` and the production build,
   said so, and moved on. The user reported "the evidence is not shown
   properly anymore". Headless screenshots then showed what static checks
   could not: the detail pane was ~640 px wide so evidence wrapped and code
   snippets were cut off, list badges broke across two lines, the report was
   a box inside a box, and the page had two scrollbars. Fixed and re-checked
   by screenshot at 1440×900 and 1280×760; the user then asked for a
   viewport-filling layout, also checked by screenshot.
2. *The rework introduced a stale-state bug.* The user reported "the left
   side … says analysis failed even if its not failed". The agent checked the
   database first (`completed` — correct) and found the cause in its own
   design: the list loaded statuses once while the Reachability tab polled on
   its own, and nothing connected them. Fixed by having the panel report
   status changes upward and patching that one row; verified live by
   re-running an analysis in headless Chrome and printing the row's text
   each second (`analysis failed` → `analysing…` → `No trace of the package`
   within 4 s).

**Verification performed.** `reach`: 227 tests (4 new for test mode),
clippy clean; a native run in test mode queued and completed an analysis
via `curl`. Workspace 185 → 192 tests across this and episode 13.
`known_source`: 212 findings → 0 for a tenant with no mappings, 10 → 10 for
the mapped one, against the live API. Every UI change: `tsc`, `CI=true`
build, container rebuild, headless screenshot.

**Accepted / modified / rejected.** Accepted, after the two corrections
above. The agent's first test-mode design also skipped repository-ref
resolution; it kept real resolution instead, so test mode exercises the same
request path as production.

**Observed benefits / failures / risks.** The benefit was a workaround for a
broken tool: when the offered browser integration failed, the agent built
its own screenshot loop rather than stopping. The failure is the recurring
one from the cross-cutting observations — *declaring done at the wrong
layer*: a compiling, type-checked UI is not a working UI, and both
regressions were found by the user, not by the agent. Minting credentials
for its own verification is a real risk surface; it was limited to the
local dev stack, read-mostly roles, a one-day expiry, and files outside the
repository, and it is recorded here so it is visible.

## Episode 13 — Source repositories from the Magnoliafile, and a testing override for the recorded commit

**Task given.** "Move Source repositories into its own settings tab AND
allow for it to be set in the Magnoliafile, but make it not mandatory", then,
after an analysis failed with "commit cd7ed71… is not available from the
remote": "where does the commit id come from?", then "in the settings allow
for testing to overwrite the commit id".

**Permissions / tools used.** Edits to `crates/api` (upload handler,
settings handler, revision choice), `crates/db` (queries, model), a new
migration `20261002000001`, `scripts/magnolia-upload.py`, `Magnoliafile`,
the frontend, README. `cargo test`; SQL run against the live dev database
inside **rolled-back transactions**; one settings change made through the
API with a test key and then reverted.

**Proposed contribution.**
- Optional Magnoliafile keys `source_repo` / `source_subpath` /
  `source_revision`, sent as upload fields. Two decisions the user did not
  specify, made explicit: **an admin-set mapping always wins** (an upload
  only creates or refreshes a mapping whose `created_by` carries a
  `magnoliafile:` prefix, enforced in one upsert with a `WHERE` on the
  conflict branch), and **uploads accept `https://` only** — the Settings
  form also allows an absolute local path for the offline demo, and an
  upload key should not be able to point the analyser at files inside its
  container.
- Diagnosis of the failed analysis: the commit came from the SBOM upload,
  not the mapping. `/demo/api` had been uploaded on 2026-08-30 with the
  commit of a 6-file local demo fixture, and the precedence rule ("a
  manifest's recorded commit always wins") sent that commit to a GitHub
  repository that never contained it. The agent also pointed out that the
  SBOM's packages (JavaScript) did not fit the newly mapped repository (Nix
  packaging), so correct evidence would still be "no trace".
- `ignore_source_commit`: a per-namespace testing override that analyses
  the namespace revision instead, recorded as `commit_source =
  revision_override` and shown as a warning on every affected report, so an
  override can never be mistaken for the SBOM's own code.

**Verification performed.** 5 unit tests for the upload rules, 2 for the
override rule. The upsert was run verbatim against the live database in a
rolled-back transaction: a new mapping is inserted, a Magnoliafile mapping
refreshed, an admin mapping left untouched (`INSERT 0 0`). The override was
checked end to end: the planned revision for a real finding flipped from
the recorded commit to `revision_override`/`main` and back. Turning it on
without a revision returns `400`. No real upload was made, because every
upload appends a permanent leaf to the transparency log.

**Accepted / modified / rejected.** Accepted. Side effect, reported to the
user: restoring the setting after the live check left the test key as the
mapping's "Set by".

**Observed benefits / failures / risks.** The useful part was answering
the *question* behind the request: the user asked to override the commit,
but the root cause was mismatched demo data, and the agent said so before
building the override. The risk the override adds — evidence about code
that is not the SBOM's — is contained by labelling, not by prevention.

## Episode 14 — Course-spec gap analysis and a documentation audit against the code

**Task given.** The user pasted the course specification: "what needs to be
done to fulfil this spec?", then "check that all diagrams and their data are
correct and that all endpoints are documented correctly", "convert to
mermaid + sandbox diagram", "rework the readme according to spec", "check for
all deliverables".

**Permissions / tools used.** Read access across the repository; small
Python scripts that parse `crates/api/src/lib.rs` and `handlers.rs`; `grep`
over migrations; Mermaid rendering in headless Chrome; writes to
`README.md`, `ARCHITECTURE.md`, new `docs/API.md` and `docs/OPERATIONS.md`.

**Proposed contribution.**
- *Gap analysis* against the 20 minimum criteria, with two flagged as risks
  to passing: the AI ran only on a hosted endpoint, and `reach` exits at
  startup when the model is unreachable. When the user wanted to treat the
  hosted Hetzner endpoint as equivalent to a local model, the agent pointed
  out that the spec allows "infrastructure operated by the student" but
  excludes "a paid external AI API", and that which one applies depends on
  who runs the server; the user chose to leave the local-model section open,
  and the README now says so explicitly.
- *API reference generated from code, not memory.* The README listed 15 of
  78 routes. `docs/API.md` was built from the router (78 method/path pairs),
  the exact `require(&grant, Action::…)` call in each handler (comments
  stripped first, because a naive search counted permissions mentioned in
  doc comments), the request/response structs, and the error type's
  status-code mapping.
- *Diagrams and claims checked against the code.* The reachability data-flow
  diagram still said analyses are refused without a recorded commit and that
  no report is stored, both outdated. The README claimed S3/WORM storage
  (it is a file volume), 244-bit keys (256), missing schema validation (it
  exists), and that upload ignores `?tenant_id=` (the CLI depends on it). All
  23 documented tables matched the migrations. The three ASCII diagrams
  became Mermaid, plus a sandbox diagram; all four were validated by
  rendering, which caught a syntax error (a `;` in a sequence-diagram note).
- *README rebuilt in the spec's order*, with a table for the five required
  failure conditions and an evaluation section that reports what the result
  files actually contain.

**Verification performed.** Each documented fact was traced to a line of
code or a file (route table, `require` calls, structs, `ApiError` mapping,
compose file, migrations, eval result JSON). A script checked every
relative link and heading anchor across the documents. Every Mermaid block
was re-extracted from the finished files and rendered.

**What the agent got wrong, and caught.** Its own README draft contained
three claims that verification overturned before they were written: that
triage can be cleared back to "untriaged" (the API rejects that), that the
archive explorer is a tab of that name (it is labelled *Dashboard*), and
that a truncated advisory is reported (it is cut silently). Earlier in the
same session it had written two sandbox details the user had not given
("workspace only", the `.env` rule) and asked for confirmation instead of
publishing them as fact; the user confirmed the mount and added that network
access is not restricted, which is now documented as a trade-off.

**Accepted / modified / rejected.** Accepted. Operational detail moved
verbatim to `docs/OPERATIONS.md` rather than being deleted; two passages
with no new home (the install one-liner, proof verification) were restored.

**Observed benefits / failures / risks.** The main finding of the audit is
uncomfortable and is now stated in the README: **no full AI evaluation run
over all 13 cases exists** — the full runs on record cover one case each,
and the 13-case run had inference switched off. The documentation had not
claimed otherwise, but nothing had made the gap visible either. The general
lesson matches episode 12: documentation drifts like code, and only
checking it against the source catches it.
