# Malicious/typosquat detection + package reputation scoring

## Context

Two of the remaining items from `SUPPLY_CHAIN_TODO.md`. Both differ from the
existing dtrack integration in one useful way: vulnerability matching genuinely
needs dtrack to analyze *the exact BOM graph of one manifest* (a component's
transitive position can matter), so `dtrack_findings` has to be a per-manifest,
per-tenant, synced-and-pushed record. Malicious-package status and reputation
scores depend only on **(ecosystem, name[, version])** — an identity, not a BOM
graph — so neither needs anything pushed anywhere. Both become: mirror a public
dataset into a small local table, then join it against the `sbom_components`
index Magnolia already builds at upload time (`index_manifest_components` in
`crates/api/src/handlers.rs`). No per-manifest sync state, no per-tenant table —
one shared cache for the whole deployment, refreshed on its own schedule,
queried live at read time.

Both need a **purl → ecosystem** mapping (`pkg:npm/...` → `npm`, `pkg:pypi/...` →
`PyPI`, `pkg:cargo/...` → `crates.io`, `pkg:golang/...` → `Go`, `pkg:maven/...` →
`Maven`, `pkg:nuget/...` → `NuGet`, `pkg:gem/...` → `RubyGems` — exact spelling
depends on the target API's own vocabulary, OSV's and deps.dev's differ
slightly, so this needs two small mapping tables, not one shared enum). This is
pure domain logic with no I/O — belongs in `crates/core` next to
`component_index.rs`, not duplicated per feature.

---

## 1. Malicious/typosquat package detection

### Data source

[OSV](https://osv.dev) carries confirmed-malicious package advisories with IDs
prefixed `MAL-` (e.g. `MAL-2024-1234`), same schema as its regular
vulnerability data, sourced from `ossf/malicious-packages`. Two ways to consume
it:

- **Bulk mirror (recommended):** `ossf/malicious-packages` publishes a zipped
  OSV export of every entry. Download and re-parse periodically — this is a
  background job, not a per-upload call, so a daily/weekly cadence is plenty
  (this list doesn't change minute-to-minute the way vulnerability data does).
- **Live query (rejected for the default path):** `api.osv.dev` supports
  per-(ecosystem, name, version) queries and would return `MAL-` entries
  alongside real vulns. Rejected as the primary path because it means one
  external call per component per upload (SBOMs can have hundreds) against a
  rate-limited free API — the bulk mirror avoids that entirely. Could still be
  offered later as an optional "check this one package live" action.

### Schema

```sql
CREATE TABLE known_malicious_packages (
    id BIGSERIAL PRIMARY KEY,
    ecosystem TEXT NOT NULL,      -- OSV's ecosystem string: "npm", "PyPI", "crates.io", "Go", ...
    name TEXT NOT NULL,
    -- NULL = every version is malicious (common: a pure typosquat/impersonation
    -- package has no "safe" version). Non-null = a specific affected version.
    version TEXT,
    source_id TEXT NOT NULL,      -- upstream advisory id, e.g. "MAL-2024-1234"
    summary TEXT,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ecosystem, name, version, source_id)
);
CREATE INDEX known_malicious_packages_lookup_idx ON known_malicious_packages (ecosystem, lower(name));
```

Deployment-global, not per-tenant — same table serves every tenant's lookups.

### Sync job

New narrow crate (`magnolia-malwatch`, mirroring the `magnolia-dtrack` pattern)
or a module reusing `dtrack_sync.rs`'s shape: download the bulk export, parse
each OSV record's `ecosystem`/`package.name`/`affected[].versions`/`id`/
`summary`, and **replace** the table's contents (full mirror each pull, not an
upsert-and-never-delete like `dtrack_findings` — a package pulled from the feed
because it was misclassified should actually disappear locally too).

### Surfacing

A **live SQL join** at read time — `manifest()` gains a
`malicious_components: Vec<MaliciousComponentJson>` field, computed by joining
that manifest's `sbom_components` rows against `known_malicious_packages` on
(ecosystem-from-purl, name, version-or-NULL-wildcard). No precomputation, no
per-manifest cache row, no staleness window: a manifest uploaded five minutes
before the mirror last refreshed shows accurate results the instant the mirror
catches up, without needing to touch that manifest's row.

### Open decisions (need your call before implementing)

- **Block or just flag?** Vulnerabilities never block an upload (that's
  compliance's job); a *confirmed malicious package* is arguably worse.
  Options: (a) always informational, same tier as vuln findings; (b) a new
  tenant setting (`block_known_malicious_packages`, same shape as
  `require_semver_version`) that rejects the upload outright when set.
- **Typosquat heuristics (phase 2, not phase 1):** edit-distance against a
  "top N packages per ecosystem" list to catch things the OSV feed hasn't
  cataloged yet. Real value, but heuristic and noisy (needs a curated
  popular-package reference list, a distance threshold, and would want its own
  opt-in/enforcement setting) — worth scoping separately once the OSV-backed
  version is live and its false-positive rate (should be ~zero) is confirmed.
- **Dependency confusion (deferred, not in this plan):** requires the tenant
  to declare their internal package namespace, then a live registry call to
  check if that name also exists publicly. Different shape from the other two
  (needs tenant config + live external calls), so it's its own future plan.

---

## 2. Package reputation scoring

### Data source

[deps.dev](https://deps.dev)'s public API already serves pre-computed OpenSSF
Scorecard results plus project/licensing metadata, keyed by
(system, package, version) and by project (source repo). Running Scorecard
ourselves is rejected — it needs a GitHub token, cloning, and static analysis
per project, real infra for something deps.dev already computes and serves
free. `system` values: `NPM`, `PYPI`, `CARGO`, `GO`, `MAVEN`, `NUGET`,
`RUBYGEMS` (deps.dev's own vocabulary, distinct from OSV's).

### Schema

```sql
-- Scorecard is a per-*project* (source repo) signal, not per-version — a
-- package's score doesn't change between two patch releases of the same
-- project, so this is keyed by package identity, not package+version like
-- known_malicious_packages.
CREATE TABLE component_reputation (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    scorecard_score REAL,          -- 0.0-10.0; NULL if deps.dev has no data for it
    project_repo TEXT,             -- e.g. "github.com/lodash/lodash"
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    fetch_error TEXT,              -- last fetch failure, if any; cleared on success
    PRIMARY KEY (ecosystem, name)
);
```

Also deployment-global — lodash's score doesn't depend on which tenant
uploaded it.

### Enrichment job

Same two-phase shape as `dtrack_sync.rs`'s push/refresh, but simpler since
there's no "project" to create first: each tick, pick `N` distinct
(ecosystem, name) pairs from `sbom_components` that are either missing from
`component_reputation` or older than a TTL (reputation moves slowly — 30 days
is plenty, vs. dtrack's much shorter vuln-refresh cadence), call deps.dev per
pair, upsert the result (or `fetch_error` on failure, matching
`dtrack_push_failures`' pattern of recording *why* something is stale rather
than silently retrying forever).

### Surfacing

Same live-join approach as malicious-package detection —
`GET /api/v1/manifest/:manifest_hash/reputation` (or folded into `manifest()`
directly, undecided, see below) returning each component's cached score. A
component with no `component_reputation` row yet (enrichment hasn't reached it)
should read as "not checked yet," same language already used for
`dtrack_synced_at: null` — not an error, not a zero score.

### Open decisions (need your call before implementing)

- **Fold into `manifest()` or a separate endpoint?** `manifest_vex` and
  `manifest_diff` were both added as separate endpoints rather than growing
  `ManifestJson` further — probably the same call here, but worth confirming
  since reputation is arguably core-enough to want inline.
- **Threshold/enforcement:** show the raw score only, or add a
  compliance-profile-style "flag anything below score X" setting? The
  compliance-profile `enabled`/`enforce_level` shape is the closest existing
  precedent if you want enforcement rather than just display.
- **Per-version vs per-project granularity:** deps.dev can return per-version
  detail too (not just per-project Scorecard) — worth deciding whether
  anything version-specific (e.g. deprecation, yanked status) is worth a
  second column now or a later addition.

---

## Suggested order

1. `purl_ecosystem`-style mapping helpers in `crates/core` (shared, no I/O,
   easy to unit test against real purl examples already in
   `component_index.rs`'s test suite).
2. Malicious-package detection end-to-end (smaller: one bulk file, one table,
   one join, no rate-limited per-item API calls) — validates the "mirror +
   join" pattern cheaply before repeating it for reputation.
3. Package reputation scoring, reusing the same job shape against deps.dev.

Neither is started — this is a plan only, pending the open decisions above.
