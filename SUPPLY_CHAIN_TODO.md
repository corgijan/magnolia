# Supply-chain-monitoring gaps — what's left

## Done this round

- VEX hardening (constrained justification codes + comment, OpenVEX export endpoint,
  two-way dtrack analysis sync) — see `VEX_TODO.md`.
- SBOM diffing between manifest versions — `GET /api/v1/manifest/:manifest_hash/diff`
  (optional `?against=<hash>`, defaults to the previous manifest in the same
  namespace). Reuses the `sbom_components` index built at upload time; identity for
  matching across versions is `purl` (version stripped) or component name. Surfaced
  in the SBOM detail view as a collapsible "Component changes" panel.
- Malicious/typosquat package detection — one batched `POST /v1/querybatch` call to
  OSV's public API per upload (purl-based, components without a purl are skipped),
  filtered for `MAL-`-prefixed advisories, stored in `malicious_component_findings`
  and surfaced in `manifest()`'s response. Informational only (never blocks an
  upload). A periodic background job (`malicious_sync.rs`, default hourly)
  now also rescans the existing archive daily-per-manifest, catching a
  package that gets flagged `MAL-` after it was already uploaded — plus a
  "Force malicious sync" button and status counts in Settings, same shape
  as the reputation background job's. See `SUPPLY_CHAIN_SIGNALS_PLAN.md`
  for the corrected design (the original bulk-mirror plan turned out wrong
  once checked against OSV's real docs) and the open items (typosquat
  heuristics, dependency confusion) it explicitly deferred.
- Package reputation scoring — OpenSSF Scorecard scores via deps.dev's public API
  (verified against docs.deps.dev/api/v3 first). New `magnolia-depsdev` crate +
  `crates/api/src/reputation_sync.rs` background job (hourly by default, deps.dev has
  no batched-query endpoint like OSV so this can't be a single call at upload time
  the way malicious-check is), `sbom_components` gained `ecosystem`/`registry_name`
  columns, new `component_reputation` table (deployment-global, not per-tenant).
  Surfaced in `manifest()`'s response and the SBOM detail view. Caveat: the
  purl→deps.dev-name mapping (`crates/core/src/purl.rs`) is unit-tested but not
  verified against real deps.dev responses — no live traffic exercised it. See
  `SUPPLY_CHAIN_SIGNALS_PLAN.md` for details.

## Left to do, in no particular order

- **Continuous vuln/CVE monitoring & alerting** — findings only update when the sync
  loop runs or someone opens the SBOM/Findings tab; no push notification when a *new*
  CVE lands against something already archived.
- **Build provenance / SLSA attestations** — verifying *how* an artifact was built
  (source repo, builder identity, reproducibility), not just that its SBOM was signed
  after upload. The right primitives already exist (DSSE envelopes, in-toto statement
  types in `magnolia-core`) — not yet wired to ingest/verify provenance attestations
  themselves.
- **Remediation workflows** — auto-opening a PR/ticket for a vulnerable dependency
  instead of only surfacing the finding for a human to act on.
- **Notification integrations** — Slack/email/webhook on new findings or failed
  compliance checks, instead of pull-only via the UI/API.
