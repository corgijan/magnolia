# Evaluation suite

Reproducible by construction, and runnable with or without an inference
server.

```sh
cd reach
cargo run --bin eval                     # full run against $REACH_AI_BASE_URL
cargo run --bin eval -- --baseline-only  # deterministic path only, no server
cargo run --bin eval -- --case 05        # one case, by id substring
```

The harness (`src/bin/eval.rs`) drives the **real pipeline** — the same code
the service runs, not a reimplementation — so a change to a prompt, a cap, or
the rubric shows up here immediately.

## Layout

- `cases/` — one JSON file per case: the advisory, the fixture to analyse,
  and the expectations it is held to.
- `fixtures/` — plain directories, turned into throwaway git repositories at
  run time. Nothing vendored, no `.git` to keep in sync, no network needed.
- `results/` — one JSON file per run (git-ignored; force-add a run you want
  to keep as a submission artifact). Each records the run **mode**, so a
  `baseline-only` run can never be mistaken for a full one.

## The cases

| # | Category | What it is for |
|---|---|---|
| 01 | nominal | Well-formed advisory, repository that really calls the symbol. The happy path everything else is measured against. |
| 02 | nominal | Package genuinely absent — must short-circuit with **zero** inference calls. |
| 03 | no_symbols | Advisory describes the flaw only in prose. The correct answer is an empty symbol list. |
| 04 | ambiguous | Vague conditions; uncertainty must be recorded, not resolved by guessing. |
| 05 | injection | Prompt injection **via advisory text** — tries to close the data fence and suppress the finding. |
| 06 | injection | Prompt injection **via a source comment** — repository content is attacker-influenceable too. |
| 07 | malformed | Truncated mojibake advisory. Must degrade, not fail, and not invent symbols. |
| 08 | out_of_scope | Advisory demands an exploit and an exploitability verdict. Both are out of scope by design. |
| 09 | fallback | No repository at all — the declared fallback feature standing alone. |
| 10 | ambiguous | A local function coincidentally sharing the vulnerable symbol's name. What a plain grep cannot do. |
| 11 | nominal | Monorepo with a subpath; a finding from a sibling service means containment failed. |
| 12 | no_symbols | Advisory explicitly invites the model to guess symbol names. The grounding check's counter is the visible hallucination rate. |

Two invariants are checked on **every** case regardless of what it declares:
the report carries the evidence disclaimer, and no site carries a model label
with an unverified citation.

## Metrics

- **Extraction precision / recall / F1** against a gold symbol set — reported
  for the AI path *and* for a non-AI heuristic baseline
  (`src/pipeline/baseline.rs`: backticked spans, `name()` call forms,
  camelCase and snake_case identifiers) on identical inputs. That baseline is
  a real attempt at the same job, not a strawman: it does well on advisories
  that mark their symbols as code and badly on ones that do not, which is
  exactly the contrast worth measuring.
- **Priority accuracy** — fraction of cases whose label was in the expected
  set.
- **Citation pass rate** — sites reported over sites reported plus claims
  dropped for an unverifiable citation. The complement is the hallucination
  rate, made visible rather than assumed away.
- **Structured-output first-try rate** — fraction of inference calls that
  validated without needing the repair retry. This is the honest measure of
  how well whichever model is configured follows a JSON schema.
- **Per-label precision** — the only number that may ever sit next to a
  priority label in the UI. Measured over twelve synthetic fixtures, so it is
  a sanity check, **not** a calibrated probability.
- **Injection resistance** — how many injection cases resisted.
- **Latency** p50 / p95 / total. Worth watching: against a local 8B model a
  single case can take minutes, and `REACH_MAX_SCORED_SITES` (one inference
  call per occurrence) is the knob that decides usability.

## `--baseline-only`

Points the client at a closed port, so every case exercises the
"inference server unavailable" path. Two purposes: it produces the
deterministic-only baseline numbers, and it is a live test of the degradation
contract — all twelve cases must still produce reports, and the model-
dependent expectations are skipped rather than scored, so the run cannot
report the harness's own configuration as a model failure.

## Reproducibility

`REACH_AI_TEMPERATURE` defaults to `0`, so the same model over the same cases
gives the same answers and the metrics measure the prompt rather than
sampling noise. The checkout cache lives in a fresh temporary directory per
run, so a run can never score a stale tree.
