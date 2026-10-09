# reach — CVE reachability evidence

A standalone service that answers one question, for one finding at a time:

> The advisory says `unsafeLoad` is vulnerable. **Where in my code is it
> referenced?**

Given an advisory and an exact source revision, `reach` returns every place
that revision references the symbols the advisory names, ranked, with a short
explanation of each, and with every `file:line` verified against the real
checkout.

## The hard line: evidence, never a verdict

This service does **not** decide whether a vulnerability is exploitable, does
not triage, and does not close findings. "`unsafeLoad` is called at
`src/importer.js:6`" is evidence a human acts on. "This CVE does not affect
you" is a verdict, and nothing here emits one — not the API, not the report,
not the UI copy in AISE.

The priority label is an **ordinal name for which deterministic rules fired**
(see `src/pipeline/rubric.rs`), not a probability and not a score. The only
number that may legitimately appear next to it is the per-label precision
measured by the eval suite over the fixture corpus — never a percentage
invented by the model or by this code.

## How it works

| Stage | Who | What |
|---|---|---|
| A | deterministic | Is the affected package present at all? Reads dependency manifests and lock files, plus a language-agnostic identifier index. **Zero evidence short-circuits the whole analysis with no LLM call.** |
| B | LLM #1 | Advisory → ruleset: vulnerable symbols, search patterns, preconditions. JSON-schema-validated, one repair retry, and every extracted symbol must actually appear in the advisory text. |
| C | deterministic | Every occurrence of those terms, ranked (production code over tests over comments), capped, with numbered context snippets. |
| D | LLM #2, per occurrence | Ordinal label (`likely_relevant` / `unclear` / `likely_irrelevant`) plus a cited line. The citation is checked against the checkout; unverifiable claims are dropped and counted. |
| E | pure function | Rubric: fired rules → priority label + trace. Unit-tested, no I/O, deterministic. |

Two mechanical anti-hallucination checks, both of which produce a visible
count in every report rather than failing quietly:

- **Grounding (stage B).** A symbol the advisory never mentions is dropped.
  An invented symbol is worse than a missing one — it sends an analyst
  hunting through their code for something that was never at issue.
- **Citation verification (stage D).** The model must cite a line from the
  snippet it was shown; the line must exist in the file *and* fall inside
  that window. A real line the model was never shown is rejected too — it
  cannot have had grounds to reason about it.

### Structural refinement (`src/treesitter.rs`)

Additive on top of the lexer, for a small, deliberately limited set of
vendored grammars (Rust, JavaScript, Python, Go):

- **Real function/class boundaries for snippets**, instead of a fixed
  ±4-line window — falls back to the fixed window for an unvendored
  language, a parse failure, or a boundary wider than 60 lines.
- **Structural nested-call search**, for advisories that describe a
  *composition* rather than a single symbol (`"the construction of
  outer(inner(x)) is exploitable"`). Stage B can extract a
  `NestedCallPattern { outer, inner }` — both names go through the same
  grounding as any other extracted symbol, but the actual tree-sitter query
  is always built by Rust code from a fixed template, never emitted by the
  model directly. A composition match ranks above every ordinary hit.

Both degrade to the ordinary lexical/fixed-window behaviour whenever a
grammar isn't vendored, can't parse the file, or the composition doesn't
occur in real syntax (a Lisp-style DSL embedded in a Rust macro invocation
is a real, observed case where the structural half finds nothing even
though the boundary half still works — see Known limitations).

## Degradation

Every stage degrades rather than aborting. The only thing that fails an
analysis outright is being unable to fetch the source that was asked for —
the caller asked about *their* code, and answering about nothing would be
worse than saying so.

| What breaks | What the analyst still gets |
|---|---|
| Inference server down or timing out | Deterministic occurrences, unlabelled, capped at `references_unclear` |
| Model returns unparseable JSON twice | Same, with the failure named in the stage record |
| Advisory names no symbols | Package-presence evidence, `package_present_only` |
| Model cites a line it was not shown | That claim dropped and counted; the others stand |
| Repository over the size cap | Truncation stated in the report; partial index used |

No inference failure ever returns a 5xx.

## Running it

**Recommended: Docker Compose from the repository root**, which starts
`reach` together with Magnolia and Dependency-Track; see the root README,
"Build, test and start", and [In Docker](#in-docker) below. To run only
`reach` natively, for development:

```sh
cp .env.example .env      # then edit
cargo run                 # http://127.0.0.1:3100
```

`/docs` serves Swagger UI (from a CDN); `/openapi.json` is generated offline
from the same types the handlers use and needs nothing external.

On startup, before the listener ever binds, the service sends a real test
completion through `REACH_AI_BASE_URL` and **refuses to start** unless it
succeeds — this is deliberately a full `/v1/chat/completions` round trip
with `json_mode: true` (the exact call shape stage B and stage D make),
rather than just `GET /v1/models`: a listing check cannot see a server that
is up, even lists the right model, and still returns something the
completions endpoint cannot use (wrong envelope shape, `response_format`
not honoured, a reasoning model's token budget entirely consumed by its
`<think>` block before it reaches an answer). On failure the process logs
why and exits `1` without ever opening a port — "the container is running"
is meant to imply "the AI feature is usable", not "usable once you notice
every analysis is failing at stage B and go fix the endpoint."

This is a **startup**-time gate only, separate from the pipeline's own
per-request degradation: once the process is up, the AI endpoint going down
later is still just a degraded report (see "Degradation" above), never a
broken flow — this check only stops a misconfigured deployment from coming
up in the first place. Can take a while for a slow or cold local model
(logged up front so a long pause reads as "waiting", not "stuck"); the
Docker `HEALTHCHECK`'s `--start-period` is sized to match.

The result is logged and kept at `GET /health` under `ai_probe` as one of:

- `reachable` — a test completion succeeded (the only outcome the process
  is still running to report). `model_listed` is `true`/`false` when
  `GET /v1/models` could be cross-checked, or `null` when the server doesn't
  support listing (not a problem on its own, since this outcome already
  proves the endpoint that matters works).
- `responded_with_error` — a real non-2xx HTTP response; check
  `REACH_AI_API_KEY` and `REACH_AI_MODEL`. (Fatal at startup.)
- `responded_but_unusable` — a 2xx came back, but it wasn't something this
  service can use (bad envelope, empty content, non-JSON content). (Fatal at
  startup.)
- `unreachable` — no response at all; check `REACH_AI_BASE_URL` and that the
  server is actually running. (Fatal at startup.)

```sh
# Queue an analysis
curl -X POST http://127.0.0.1:3100/api/v1/analyses \
  -H "Authorization: Bearer $REACH_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "advisory_text": "fastyaml 2.x: the `unsafeLoad` function instantiates arbitrary constructors named in the document.",
        "osv_id": "GHSA-TEST-0001",
        "package_name": "fastyaml",
        "ecosystem": "npm",
        "repo_url": "https://github.com/acme/app",
        "commit": "<full 40-char sha>"
      }'

# Poll it
curl http://127.0.0.1:3100/api/v1/analyses/<id> \
  -H "Authorization: Bearer $REACH_API_TOKEN"
```

Only know the branch? Send `"ref": "main"` (a branch, tag or `HEAD`)
instead of `commit`. It is resolved **once, when the request is accepted** —
`git ls-remote` for a remote, `git rev-parse` for a local path, with the same
hardened git environment as a fetch — and the analysis, the stored row and
the report are pinned to the resulting commit. The response returns it as
`commit` alongside `requested_ref`; re-reading the analysis later never
re-resolves the ref. An exact `commit` always wins when both are sent, and a
ref that does not exist is a `400` before anything is queued.

Omitting `repo_url` runs stage B alone and returns the structured advisory
extraction — useful on its own, and the project's declared fallback feature.

### A working session on `reach`

`reach` is its own Cargo project, so a session on it starts from inside this
directory and never from the workspace root:

```sh
cd reach
cp .env.example .env              # once; put REACH_AI_* in it
cargo test                        # the root `cargo test --workspace` does NOT build this
cargo clippy --all-targets
cargo run                         # serves on REACH_SERVER_ADDR, default 127.0.0.1:3100
```

`cargo run` refuses to start if the configured inference endpoint cannot
answer a real completion, so a successful `reach listening` line means the AI
path is genuinely usable — see the startup gate above. From there:

```sh
# is it up, and against what
curl -s localhost:3100/health | python3 -m json.tool

# drive one analysis end to end (resolves the branch for you)
./scripts/reach-check.py --repo https://github.com/acme/app \
  --advisory "The \`unsafeLoad\` function instantiates arbitrary constructors."

# the eval suite — the deterministic half needs no inference server at all
cargo run --bin eval -- --baseline-only
cargo run --bin eval -- --case 13
```

Inside the AISE stack instead of natively, `reach` publishes no host port; it
is reachable as `http://reach:3100` on the compose network. Bring the whole
thing up with `../scripts/stack-up.sh --frontend`, which checks the
root `.env` for `REACH_AI_BASE_URL` before building (compose never reads
`reach/.env`) and waits for the startup gate to pass. Watch a running
analysis with `docker compose logs -f reach` — every stage logs its own
outcome as it finishes, so a slow analysis is legible rather than silent.

### One-shot CLI

`scripts/reach-check.py` wraps the two calls above into one command,
resolving a branch/tag to an exact commit id via `git ls-remote` (no clone)
so you can point it at a public repo URL directly instead of hunting down a
SHA first:

```sh
./scripts/reach-check.py --repo https://github.com/acme/app \
  --advisory "The \`unsafeLoad\` function instantiates arbitrary \
constructors named in the document, allowing remote code execution."
```

Reads `$REACH_URL` (default `http://127.0.0.1:3100`) and `$REACH_API_TOKEN`;
override with `--url`/`--token`. Advisory text can also come from
`--advisory-file` or stdin. `--json` prints the raw result instead of a
summary. Python 3 stdlib only — no dependencies to install.

**Verdict + confidence output — on by default, not part of `reach`, not
compliant, do not use in the submission** (`--no-experimental-verdict` to
turn it off). Prints an additional applicability judgement and an
uncalibrated confidence percentage, by making a second, separate call
straight to the raw inference endpoint — bypassing `reach` entirely (reads
`REACH_AI_BASE_URL`/`MODEL`/`API_KEY` from `reach/.env` automatically). This
exists only because it was explicitly requested after the tradeoff below
was raised; `reach` itself never does this, by design:

> "Vulnerable symbol X is/isn't referenced at path Y" is evidence;
> "this CVE is not exploitable" is a verdict and is out of scope... this
> must survive into the UI copy. Any confidence value shown in the UI or
> API is a label, not a probability — never present it as one unless it
> has been calibrated. — CLAUDE.md

Every use of this flag prints a large warning naming that requirement. See
the script's own module docstring for the full rationale before using it.

### In Docker

The root `docker-compose.yml` starts `reach` alongside AISE. A local model
is one profile away:

```sh
docker compose --profile ollama up -d ollama
docker compose exec ollama ollama pull gemma3:4b
docker compose up -d reach
```

## Configuration

Env vars only — see `.env.example`. Swapping the inference server or model is
an env change and a restart; no code in this crate knows which backend is
answering, because every call is a plain OpenAI-compatible
`POST {base_url}/v1/chat/completions`.

Two settings worth knowing about up front:

- `REACH_AI_MAX_TOKENS` — reasoning models (deepseek-r1 and friends) spend
  most of the budget on their `<think>` block before the JSON starts. 1024 is
  fine for an instruction-tuned model and produces nothing but truncation
  errors on a reasoning one; use 6000+ there.
- `REACH_MAX_SCORED_SITES` — each scored occurrence is one inference call, so
  this is the main latency knob. Five sites against a local 8B model is
  minutes, not seconds.

### Test mode

`REACH_TEST_MODE=true` (or `./scripts/stack-up.sh --frontend --test-mode`)
skips the startup inference check and answers **every** analysis, after a
2-second pause, with the same canned report: `direct_references`, one
`likely_relevant` occurrence at `reach-test-mode/example.py:42`. No advisory
is read, no repository is fetched, and no model is called. The point is to
exercise the AISE button → poll → report view without a model.

The report is marked `"test_mode": true`, every analyst-facing string in it
starts with `TEST MODE`, its citation is never `verified`, and AISE's report
view shows a banner for it. `/health` reports `"test_mode": true` and
`"ai_probe": "skipped"`. AISE **archives** reports, so canned ones stay in its
database after the mode is switched off. They stay labelled, but use a
throwaway dev database for this. The eval harness ignores the flag.

## Security

`repo_url` arrives from an API request and is treated as hostile throughout:

- **Scheme allowlist** — `https://` and local paths only, enforced both by
  `validate_repo_url` and by git itself via `GIT_ALLOW_PROTOCOL`. `ext::` is
  rejected specifically: it makes git run an arbitrary command.
- **No argv injection** — a value starting with `-` is rejected outright
  (`--upload-pack=…` is remote code execution).
- **No credentials in URLs** — userinfo is rejected; a token goes through
  `GIT_CONFIG_*` env vars, never argv (visible in `ps`) and never the URL
  (which git echoes back in errors).
- **No symlinks** — `core.symlinks=false` at checkout, and the indexer
  refuses to follow links.
- **Exact revisions only** — a 40/64-hex object id, never a ref. Evidence
  pinned to a moving `HEAD` could not be reproduced or audited.
- **Repository content is never executed** — no build, no install, no hooks.
  The container runs as a non-root user.

Advisory text and repository content are both attacker-influenceable, so both
are delimited as data in every prompt, with the fence markers scrubbed from
the payload so it cannot close its own block. Prompt injection through each
channel is a required case in the eval suite.

## Evaluation

```sh
cargo run --bin eval                     # full run against $REACH_AI_BASE_URL
cargo run --bin eval -- --baseline-only  # deterministic path only, no server
cargo run --bin eval -- --case 05        # one case
```

Thirteen cases in `eval/cases/`, covering nominal, ambiguous, malformed,
out-of-scope, prompt-injection (via advisory *and* via a code comment),
advisory-only, monorepo-subpath, hallucination-bait, the
package-genuinely-absent short circuit, and an advisory whose only symbol is
a generic name in qualified form (case 13 — the CVE-2017-18342 shape; the
non-AI baseline scores 0.00 on it, which is the sharpest single case in the
baseline comparison). Fixtures in `eval/fixtures/` are
plain directories turned into throwaway git repositories at run time, so
runs need no network and no vendored `.git`. Those repositories are built
with the developer's own git configuration pinned off (`commit.gpgsign`,
templates, hooks): inheriting a global signing key made `git commit` prompt
for a passphrase and fail, which left the whole suite unrunnable on that
machine.

Reported metrics: extraction precision/recall/F1 against a gold symbol set,
the same scores for a **non-AI heuristic baseline** on identical inputs,
priority accuracy, citation pass rate, structured-output first-try rate,
per-label precision, injection resistance, and latency percentiles. Results
land in `eval/results/`.

`--baseline-only` points the client at a closed port, so it doubles as a live
test of the degradation contract: all thirteen cases must still produce
reports.

## Why this lives in the AISE repo but not in its workspace

One repository, one history, one submission — but the service boundary is
REST and nothing else. `reach/` is its own Cargo project (its own
`Cargo.lock`, its own `[workspace]`, excluded from the root workspace), its
own SQLite database, its own image. AISE talks to it through
`crates/reachability`, a thin typed client, and holds only analysis ids.

Build and test from inside this directory:

```sh
cd reach && cargo test
```

## Known limitations

Stated here because they bound what the reports mean:

- **The index is lexical, not semantic.** It cannot resolve imports, aliases,
  re-exports, or dynamic dispatch. `import { unsafeLoad as load }` then
  `load(x)` is not found. This is the ceiling on recall, and the reason
  stages D and E exist rather than the tool reporting matches directly.
- **A very generic symbol name is only searched when the advisory qualifies
  it.** Names like `load`, `parse`, `get` and `open` appear in almost every
  file ever written, so stage B drops them as noise — *unless* the advisory
  writes them in a member-access form (`yaml.load`, `Marshal::load`,
  `obj->load`). That rescue exists because several of them are the genuine and
  only symbol a famous advisory names: `yaml.load` is CVE-2017-18342, and
  dropping it unconditionally turned that advisory into "no searchable
  symbols" and a `package_present_only` report — a false negative that looked
  exactly like a clean result. The residual gap: an advisory that names such a
  symbol *only* as a bare word in prose is still dropped, and the rule is
  deliberately generous in the other direction (`pre-load` reads as qualified),
  because a noisier occurrence list is much cheaper than a silent miss. Eval
  case 13 pins this down.
- **Vendored dependency trees are not indexed** (`node_modules`, `vendor`,
  `target`). Package presence is established from manifests and lock files
  instead, which is cheaper and more reliable, but a vendored copy with no
  manifest entry is only found if its name appears as an identifier.
- **"No package evidence" is not "not affected."** A dependency pulled in by
  a lock-file format this scanner does not read would look identical.
- **Per-label precision comes from twelve synthetic fixtures.** It is a
  sanity check on a small corpus, not a calibrated probability, and must
  never be presented as one.
- **Structural (nested-call) search cannot see inside a macro or DSL body.**
  `src/treesitter.rs` vendors real grammars for Rust, JavaScript, Python,
  and Go, and can find "call to A containing a call to B" precisely when
  the composition is genuine source syntax. Found live in a real repository
  whose Lisp-style code lives inside a Rust macro invocation: tree-sitter's
  Rust grammar treats macro-invocation arguments as an opaque token
  stream, not parsed `call_expression` nodes, so the structural query finds
  nothing there even when the composition is textually present. The
  function/class boundary-widening half of the same feature has no such
  gap — it only needs the *enclosing* function to be real syntax, which it
  is even when the macro body inside isn't parsed as expressions.
