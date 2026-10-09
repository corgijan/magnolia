---
marp: true
paginate: true
header: '◆ Magnolia'
footer: 'AISE 2026 × Jan Vaorin'
---

<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Space+Grotesk:wght@500;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* Magnolia's own UI palette (frontend/src/App.css) */
:root {
  --bg:      #0d1117;
  --panel:   #161b22;
  --panel-2: #1c2330;
  --border:  #2d3748;
  --text:    #e6edf3;
  --muted:   #8b98a9;
  --accent:  #4f8cff;
  --ok:      #3fb950;
  --err:     #ff7b72;
  --warn:    #e3b341;
  --font-body:    'Inter', 'Helvetica Neue', Arial, sans-serif;
  --font-display: 'Space Grotesk', 'Inter', sans-serif;
  --font-mono:    'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
}

section {
  --color-background: var(--bg);
  --color-foreground: var(--text);
  --color-highlight: var(--accent);
  --color-dimmed: var(--muted);
  background: var(--bg);
  color: var(--text);
  font-family: var(--font-body);
  font-size: 30px;
  line-height: 1.5;
  letter-spacing: -0.005em;
  font-feature-settings: 'kern' 1, 'liga' 1, 'tnum' 1;
}

/* per-slide density: <!-- _class: compact --> or dense */
section.compact { font-size: 25px; line-height: 1.4; }
section.dense   { font-size: 21px; line-height: 1.35; }
section.compact h2, section.dense h2 { margin-bottom: .45em; }
section.compact ul > li { margin-bottom: .32em; }
section.dense   ul > li { margin-bottom: .22em; }

ul ul { font-size: .85em; margin-top: .2em; opacity: .8; }
ul ul > li { margin-bottom: .15em; }
ul > li { margin-bottom: .5em; }

h1, h2, h3 {
  font-family: var(--font-display);
  font-weight: 700;
  line-height: 1.15;
  letter-spacing: -0.02em;
  text-wrap: balance;
  color: var(--text);
}
h1 { font-size: 1.9em; }
h2 { font-size: 1.35em; }
h3 { font-weight: 500; letter-spacing: 0; color: var(--muted); }
section.lead h1 { font-size: 2.4em; }

strong { font-weight: 600; color: #fff; }
a { color: var(--accent); }
code, pre, kbd { font-family: var(--font-mono); font-size: .85em; }
code {
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: .05em .35em;
  color: var(--text);
}
pre { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }
pre code { border: none; background: none; }

/* running head, footer, page number */
header, footer, section::after {
  font-family: var(--font-mono);
  font-size: 15px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--muted);
  opacity: .8;
}
header { color: var(--accent); }

/* tables look like Magnolia's data tables */
table { font-size: 22px; line-height: 1.35; border-collapse: collapse; }
th, td { background: transparent !important; border: none; border-bottom: 1px solid var(--border); padding: .35em .7em; }
th {
  font-family: var(--font-mono);
  font-size: 15px;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
}
td:first-child { font-weight: 600; white-space: nowrap; }

section table th, section table td {
  border: none !important;
  border-bottom: 1px solid var(--border) !important;
  background: transparent !important;
}
section table th { color: var(--muted) !important; border-bottom: 1px solid var(--muted) !important; }
section table td { color: var(--text) !important; }
section table tr { background: transparent !important; }

blockquote::before, blockquote::after { content: none !important; }
blockquote {
  border-left: 4px solid var(--accent);
  color: var(--text);
  font-family: var(--font-display);
  font-weight: 500;
}

/* the ◆ wordmark */
.mark { color: var(--accent); }
.wordmark { font-family: var(--font-display); font-weight: 700; font-size: 2.6em; letter-spacing: -0.03em; }

/* cards: Magnolia's .card, laid out in a row */
.cards { display: grid; gap: 22px; margin-top: .5em; }
.cards.c2 { grid-template-columns: repeat(2, 1fr); }
.cards.c3 { grid-template-columns: repeat(3, 1fr); }
.cards.c5 { grid-template-columns: repeat(5, 1fr); gap: 14px; }
.cards > div {
  background: var(--panel);
  border: 1px solid var(--border);
  border-top: 4px solid var(--border);
  border-radius: 10px;
  padding: .55em .7em .6em;
}
.cards > div.ai  { border-top-color: var(--accent); background: #14233d; }
.cards > div.det { border-top-color: var(--muted); }
.cards h3 { font-weight: 700; font-size: .95em; color: var(--text); margin: 0 0 .25em; }
.cards p  { margin: 0 0 .4em; font-weight: 600; font-size: .78em; color: var(--muted); }
.cards ul { font-size: .72em; padding-left: 1em; margin: 0; }
.cards li { margin-bottom: .2em; }

/* status badges, as in the findings list */
.badge {
  display: inline-block;
  padding: .05em .55em;
  border-radius: 999px;
  font-size: .62em;
  font-weight: 600;
  vertical-align: middle;
  font-family: var(--font-body);
}
.b-ok   { background: rgba(46,160,67,.15);  color: var(--ok);   border: 1px solid rgba(46,160,67,.4); }
.b-err  { background: rgba(248,81,73,.15);  color: var(--err);  border: 1px solid rgba(248,81,73,.4); }
.b-warn { background: rgba(210,153,34,.15); color: var(--warn); border: 1px solid rgba(210,153,34,.4); }
.b-ai   { background: rgba(79,140,255,.15); color: var(--accent); border: 1px solid rgba(79,140,255,.45); }

.muted { color: var(--muted); }
.takeaway { margin-top: 1em; font-family: var(--font-display); font-weight: 500; }
.small { font-size: .7em; }

/* screenshot slides */
section.shot { padding-top: 60px; padding-bottom: 50px; }
section.shot h2 { font-size: 1.05em; margin: 0 0 .35em; }
section.shot h2 .step { color: var(--accent); font-family: var(--font-mono); font-weight: 500; margin-right: .4em; }
.screen {
  display: block;
  margin: 0 auto;
  max-width: 100%;
  max-height: 500px;
  border: 1px solid var(--border);
  border-radius: 10px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, .45);
}
.side { display: grid; grid-template-columns: auto 1fr; gap: 34px; align-items: start; }
.side .screen { max-height: 520px; margin: 0; }
.side ul { font-size: .68em; margin-top: 0; }
.side li { margin-bottom: .45em; }
.caption { margin-top: .5em; text-align: center; font-size: 18px; color: var(--muted); }

/* a code-review-like evidence card */
.evidence {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: .5em .8em;
  font-size: .7em;
}
.evidence pre { margin: .3em 0 0; font-size: .9em; padding: .4em .6em; }
</style>

<!-- theme: gaia -->
<!-- _class: lead -->
<!-- _paginate: false -->
<!-- _header: '' -->

<div class="wordmark"><span class="mark">◆</span> Magnolia</div>

### Supply-chain transparency with CVE reachability evidence

<p class="muted" style="font-size: 18px">AISE course project </p>

<!--
One sentence: Magnolia keeps a signed, tamper-evident archive of a team's SBOMs and helps
analysts triage the vulnerability findings on them, using an LLM to show where in their
own code an advisory's vulnerable symbols are referenced.
-->

---
<center>

## The problem
### Do we know what we are running ? 

</center>

---

## The problem

<div class="cards c2">
  <div>
    <h3>Trust in the record</h3>
    <p>"What exactly did you ship in 1.4.2, and when did you know?"</p>
    <ul>
      <li>customers and regulators (EU Cyber Resilience Act) ask</li>
      <li>tamper proof</li>
    </ul>
  </div>
  <div class="ai">
    <h3>Too many findings</h3>
    <p>A finding says a dependency is vulnerable, not that <em>our</em> code uses the vulnerable part</p>
    <ul>
      <li>dozens of findings per release</li>
      <li>checking them is time consuming</li>
    </ul>
  </div>
</div>

<p class="takeaway">Magnolia answers both: a signed log, and <strong>cited evidence</strong> for each finding.</p>

<!--
The left problem is the transparency log; the right one is where the AI component lives.
-->

---

<!-- _class: compact -->

## Responsibility and core scenarios

> The service keeps a **signed, tamper-evident archive** of SBOMs and helps analysts **triage the findings** on them — Supported by an LLM

1. **CI publishes a release** — upload, policy checks, signed into the log with its commit
2. **An analyst triages a finding with evidence** <span class="badge b-ai">core AI scenario</span>
   - start an analysis → read the cited `file:line` evidence → record a VEX decision
3. **An auditor checks the record** — inclusion and consistency proofs in the browser, OpenVEX export

<!--
Scenario 2 is the vertical slice I demo. Scenarios 1 and 3 are the non-AI substance around it.
-->

---

<!-- _class: compact -->

## Architecture

<center><img src="./architecture.svg" style="height: 500px"></center>

<!--
Two services. api (Magnolia) owns the log, findings, triage, settings and the UI's API.
reach owns analyses and reports, with its own SQLite. They talk only over REST — no shared
database, no shared code; reach is even a separate Cargo project. Magnolia works fully
without reach; reach starts and is usable on its own through its API and Swagger UI.
The LLM is reached only by reach, through the OpenAI-compatible endpoint.
-->

---

<!-- _class: compact -->

## Design decisions

<div class="cards c3">
  <div>
    <h3>Evidence, never a verdict</h3>
    <p>The analyst decides</p>
    <ul>
      <li>"<code>yaml.load</code> at <code>src/config.py:12</code>" is evidence</li>
    </ul>
  </div>
  <div>
    <h3>Pinned to a commit</h3>
    <p>Reproducible evidence</p>
    <ul>
      <li>the SBOM's recorded commit is scanned</li>
      <li>a branch is resolved once; overrides are labelled</li>
    </ul>
  </div>
</div>

<div class="cards c3" style="margin-top: 22px">
  <div>
    <h3>Signed, append-only log</h3>
    <p>Tamper-evident by construction</p>
    <ul><li>Merkle Mountain Range, Ed25519, DSSE/in-toto</li></ul>
  </div>
  <div>
    <h3>Degrade, don't break</h3>
    <p>Every integration is optional</p>
  </div>
</div>

---

<!-- _class: dense -->

## Persistence, UI and API

| | Magnolia (`api`) | `reach` (AI) |
|---|---|---|
| **Persistence** | PostgreSQL, 23 tables: log, manifests, findings + triage, settings, audit, archived reports · SBOM files · signing key | SQLite: analyses with input, status and full report · git cache |
| **API** | REST, 78 endpoints, documented in `docs/API.md`; role- and namespace-scoped API keys | REST, generated OpenAPI + Swagger UI |
| **UI** | React: **Findings** (list · Overview · Reachability · Triage), archive explorer, proofs, search, settings | — (used through Magnolia's UI) |
| **Integration** | Dependency-Track, OSV, deps.dev, webhooks, upload CLI + `Magnoliafile` | OpenAI-compatible LLM server |

<p class="muted small">AI results are persisted twice: in reach's database, and as an archived copy on the finding — evidence survives an analyser reset.</p>

---

<!-- _class: lead -->
<!-- _paginate: false -->

# Demo

### CI upload → finding → reachability evidence → triage


<!--
Live demo, scenario 2:
1. stack is up: ./scripts/stack-up.sh --frontend
2. Findings → "Known source only" → pick a critical finding → Overview (advisory)
3. Reachability → Analyze reachability → badge in the list turns to "analysing…"
4. Report: priority label, extracted symbols, preconditions to confirm, Where to look
   with file:line links, "How was this determined?"
5. Triage tab: set VEX status + justification + comment → audit log
Fallback if the model is slow: REACH_TEST_MODE (labelled canned report) or a recorded run.
-->

---

<!-- _class: shot -->

## <span class="step">1</span>CI upload → a signed, browsable SBOM

<img class="screen" src="./img/archive.png">
<p class="caption">Archive explorer: the uploaded CycloneDX SBOM of <code>/demo/api</code> 9.9.1 with its component tree; signals and the signature further down</p>

<!--
Scenario 1. The CLI uploaded this SBOM; it is stored, appended to the Merkle log and signed (DSSE). Revocation is a flag, never a delete.
-->

---

<!-- _class: shot -->

## <span class="step">2</span>Tell Magnolia where the code lives

<img class="screen" src="./img/settings-sources.png">
<p class="caption">Settings → Source repositories: one repository per namespace, set here or by an upload's <code>Magnoliafile</code>; the testing override is badged</p>

<!--
Without a mapping there is nothing to scan; the finding explains why the button is disabled.
-->

---

<!-- _class: shot -->

## <span class="step">3</span>Pick a finding

<img class="screen" src="./img/findings-overview.png">
<p class="caption">Findings: list beside the selected finding; evidence badges per row; <em>Overview</em> shows the advisory</p>

<!--
Filters: severity, triage status, currently running, known source only. The list is server-paginated.
-->

---

<!-- _class: shot -->

## <span class="step">4</span>Read the evidence

<div class="side">
<img class="screen" src="./img/reach-testmode.png">
<div>

- **Priority label** — names the rules that fired, not a probability
- **Disclaimer** on every report: evidence, not a verdict
- **What the advisory says** and the symbols searched for
- **Worth confirming** before triaging
- **Where to look**: `file:line` · symbol · label · citation status, reason, snippet
- <span class="badge b-warn">test mode</span> this report is canned — the banner says so; a real report has the same layout

</div>
</div>

<!--
Honest note: the demo data has no repository that uses a vulnerable function, so the only 'direct references' report on file is a test-mode one, and the banner says so. The layout is identical for a real report.
-->

---

<!-- _class: shot -->

## <span class="step">5</span>A real analysis on the demo data

<div class="side">
<img class="screen" src="./img/reach-real.png">
<div>

- **Stage A** found no trace of `uuid` in the scanned revision
- so **B–D are skipped** — no model call is spent
- **Package evidence** says what was searched and where
- **Worth confirming**: a lock file the scanner can't read would look the same
- **How was this determined?** — every rule that fired, every stage with its outcome and duration

</div>
</div>

<!--
This is the honest result for the current demo data: the namespace is mapped to a repository that does not contain the package. No model call was spent.
-->

---

<!-- _class: shot -->

## <span class="step">6</span>Decide and record

<img class="screen" src="./img/triage.png">
<p class="caption">Triage tab: the VEX decision and the discussion live apart from the AI evidence, which is linked but never pre-fills the decision</p>

<!--
not_affected requires an OpenVEX justification. Every change is audit-logged and pushed to Dependency-Track.
-->

---

<!-- _class: shot -->

## <span class="step">7</span>The auditor's check

<img class="screen" src="./img/proofs.png">
<p class="caption">Proofs: an inclusion proof fetched from the API and verified in the browser ("proof verifies against root"); the consistency proof below it verifies the same way</p>

<!--
Scenario 3. The verification runs client-side (frontend/src/merkle.ts), so it doesn't trust the server's own check.
-->

---

<!-- _class: compact -->

## The AI component: a five-stage pipeline

<div class="cards c5">
  <div class="det"><h3>A</h3><p>Package present?</p><ul><li>manifests, lock files, identifier index</li><li>absent → stop, <strong>no LLM call</strong></li></ul></div>
  <div class="ai"><h3>B · LLM</h3><p>Advisory → ruleset</p><ul><li>vulnerable symbols, patterns, preconditions</li><li>JSON-validated</li></ul></div>
  <div class="det"><h3>C</h3><p>Find occurrences</p><ul><li>lexical + tree-sitter for 4 languages</li><li>ranked, capped</li></ul></div>
  <div class="ai"><h3>D · LLM</h3><p>Label each site</p><ul><li><code>likely_relevant</code> · <code>unclear</code> · <code>likely_irrelevant</code></li><li>must cite a line</li></ul></div>
  <div class="det"><h3>E</h3><p>Rubric</p><ul><li>pure function: fired rules → priority label + trace</li></ul></div>
</div>

<p class="takeaway">The model does two <strong>narrow, validated</strong> jobs. Remove it and you're left with a keyword search — the evaluation measures that difference.</p>

<!--
Blue = LLM, grey = deterministic. Model: any OpenAI-compatible server, configured by REACH_AI_*.
-->

---

<!-- _class: compact -->

## Uncertainty: labels, not probabilities

- **Grounding** — an extracted symbol that isn't in the advisory text is **dropped**
- **Citation check** — a claim must cite a line that exists *and* was in the snippet the model saw, or it's **dropped**
- **Invalid answers** — an invented label is dropped; the occurrence stays, unlabelled
- **`unclear`** is a first-class answer, not an error
- The priority label names **which rubric rules fired** — no confidence number, because none is calibrated
- Every report **counts what it dropped** and carries its own disclaimer

<div class="evidence">
  <span class="muted">illustration ·</span> <span class="badge b-err">Direct references found</span> <span class="muted">src/config.py:12 · <code>yaml.load</code> · likely relevant · citation verified</span>
<pre>cfg = yaml.load(request.data)</pre>
</div>

---

<!-- _class: dense -->

## Failure handling

| Condition | What happens |
|---|---|
| **Inference server unavailable** | Stages B/D record the failure; report keeps the deterministic occurrences, unlabelled — never a 5xx. Magnolia keeps working and serves the archived report |
| **Timeout** | `REACH_AI_TIMEOUT_SECS` bounds every call; handled as a stage failure |
| **Malformed model output** | Validated app-side; **one repair retry**, then the stage degrades; ungrounded / uncited / invalid answers dropped and counted |
| **Input cannot be processed** | Bad advisory, commit or URL → `400` before queueing; unfetchable repo → `failed` with a reason; a crash fails only that job |
| **Storage read/write fails** | Logged, generic JSON `500`, never a partial result; worker retries next pass |

<p class="muted small">Known gap: <code>reach</code> refuses to start when the model is unreachable at startup — visible, but not a degraded start.</p>

---

<!-- _class: compact -->

## Evaluation

**13 cases**, one script (`cargo run --bin eval`), results as JSON

- nominal · package absent · no symbols · **ambiguous** · **prompt injection** (advisory and code comment) · **malformed** · **out of scope** · advisory-only · lexical false positive · monorepo · **hallucination bait** · qualified generic symbol
- metrics: extraction P/R/F1, **non-AI keyword baseline** on the same inputs, priority accuracy, citation pass rate, structured-output first try, injection resistance, latency

| Run | Cases | Result |
|---|---|---|
| Deterministic path only | 13 | 13/13 pass · 2/2 injections resisted · baseline F1 0.73 |
| Hosted Qwen 3.6 35B | 1 | AI P/R **1.00** vs. baseline **0.00** · 165 s |
| Local deepseek-r1:8b | 1 | AI F1 1.00 vs. 0.67 · one repair retry · 479 s |

<p class="muted small">Open: a full AI run over all 13 cases after the last prompt change, and the written failure analysis.</p>

<!--
Case 13 is the sharpest baseline comparison: an advisory naming yaml.load — the keyword
baseline drops "load" as too generic and reports nothing; the model keeps the qualified form.
-->

---

<!-- _class: compact -->

## Agent harness and sandbox

<div style="display: grid; grid-template-columns: 1.25fr 1fr; gap: 28px; align-items: center">
<img src="./sandbox.svg" style="width: 100%">
<div>

- **Claude Code**, Sonnet 5 for routine, Opus 5.5 for hard tasks
- **microsandbox** Linux VM on the macOS hypervisor
- only the **workspace** is mounted
- network **not restricted** — documented trade-off
- destructive / outward actions need **confirmation**

</div>
</div>

<!--
Honest note from the dev log: the last session ran on the host, not in the VM — it's recorded
in episode 12's session note.
-->

---

<!-- _class: compact -->

## What the agent got wrong — and what caught it

<div class="cards c2">
  <div><h3>Destructive git command</h3><p>Episode 3</p><ul><li>a checkout wiped uncommitted work beyond its apparent scope</li></ul></div>
  <div><h3>A fabricated artefact</h3><p>Episode 8</p><ul><li>a plausible but invented Argon2 hash</li></ul></div>
  <div><h3>Done at the wrong layer</h3><p>Episodes 2, 12</p><ul><li>backend right, UI wrong; a rework shipped without being looked at</li></ul></div>
  <div><h3>Docs drift like code</h3><p>Episode 14</p><ul><li>diagrams and README claims contradicted the code</li></ul></div>
</div>


---

<!-- _class: lead -->
<!-- _paginate: false -->
<!-- _header: '' -->

<div class="wordmark"><span class="mark">◆</span> Questions</div>

<p class="muted" style="font-size: 20px">README · ARCHITECTURE.md · docs/API.md · reach/README.md · docs/AI_DEVLOG.md</p>
