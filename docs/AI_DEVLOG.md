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
It is not about the product's own AI component (`crates/ai`), which is not
built yet. That feature was decided on 2026-08-30 — **CVE reachability
evidence**, with grounded advisory summarisation as the declared fallback;
see `CLAUDE.md` and `ROADMAP.md`. Episodes covering its implementation will
be appended here as it is built.

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
none of the 165 tests or the integration suite run automatically — the
evidence in this log was produced by explicit request, not by a gate.
