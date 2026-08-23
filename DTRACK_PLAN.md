# Optional self-hosted Dependency-Track integration

## Context

Magnolia archives SBOMs with tamper-evidence and (as of this session) checks them against BSI TR-03183-2's data-field requirements, but it has no idea whether any of the components in an archived SBOM actually have known vulnerabilities — that's explicitly out of scope for an SBOM by design (TR-03183-2 §3.1: an SBOM MUST NOT contain vulnerability info, since vuln data is dynamic and SBOM data is static). OWASP Dependency-Track (dtrack) is the standard open-source tool for the other half of that: it ingests a BOM, continuously matches its components against NVD/OSS-Index/etc., and produces findings. The user wants Magnolia to optionally run a dtrack instance, push uploads to it, and show the resulting findings directly in Magnolia's own SBOM detail view — not just link out to a separate dtrack UI.

Key design call, made explicit because it differs from the compliance-profile feature built earlier this session: this is **deployment-wide and env-var-gated, not a per-tenant setting**. Dependency-Track is real infrastructure (its own Postgres, a slow first vulnerability-database sync) — an operator either runs one or doesn't, mirroring how `STORAGE_PATH`/`SIGNING_KEY_PATH` already select backends by env-var presence in `crates/api/src/main.rs`, not a per-tenant toggle table like `compliance_profile_settings`.

**Multi-tenancy caveat (real limitation, not solved here, must be documented):** a single shared dtrack instance has no concept of Magnolia's tenant boundaries — all tenants' BOMs land in the same dtrack project list, visible to anyone holding the shared `DTRACK_API_KEY` or dtrack admin login. Magnolia's own API stays correctly tenant-scoped (findings are looked up by `manifest_hash` *after* the existing tenant-ownership check in the `manifest()` handler), so there's no cross-tenant leak through Magnolia itself — but dtrack's own admin surface is a shared resource across the whole deployment. Call this out in docs.

## Confidence check on dtrack's actual API (do this before writing code)

I'm reasonably but not fully confident on dtrack's REST API shape from training knowledge. Before implementing `crates/dtrack`, hit a real running instance's OpenAPI spec (`docker compose --profile dtrack up -d dtrack-db dependency-track`, then `curl localhost:8080/api/openapi.json`) and confirm:
- `PUT /api/v1/bom` request/response shape (JSON `{projectName, projectVersion, autoCreate, bom: <base64>}`, header `X-Api-Key`, returns a processing token — **not** the project UUID, since BOM ingestion itself is async).
- `GET /api/v1/project/lookup?name=&version=` returns the project incl. UUID (project creation via `autoCreate` is believed synchronous even though vuln analysis afterward is async).
- `GET /api/v1/finding/project/{uuid}` response shape, and what field is a stable per-finding key.
- The exact permission name(s) an API key needs for BOM upload + findings read (default "Automation" team may already have BOM-upload permissions; findings-read may need adding).
- External-Postgres env var names for `dependencytrack/apiserver` (believed to be `ALPINE_DATABASE_MODE=external`, `ALPINE_DATABASE_URL`, `ALPINE_DATABASE_DRIVER=org.postgresql.Driver`, `ALPINE_DATABASE_USERNAME`, `ALPINE_DATABASE_PASSWORD` — verify against the pinned image version's actual docs).

None of this blocks writing the plan/scaffolding below, but treat the `crates/dtrack/src/client.rs` endpoint calls as a sketch to verify, not final code.

## Design

### Docker Compose — opt-in via `profiles:`

Two new services (`dtrack-db`: postgres:15, its own volume; `dependency-track`: official `dependencytrack/apiserver` image pinned to a real version tag, not `:latest`), both under `profiles: ["dtrack"]` so plain `docker compose up` is completely unaffected — dtrack only starts with `docker compose --profile dtrack up`. A persistent volume for dtrack's own data dir (the NVD/OSS-Index mirror is slow to rebuild from scratch). `dependencytrack/frontend` is deliberately **not** added — Magnolia's own UI is the intended findings surface; dtrack's web UI is only useful for the one-time manual bootstrap and advanced manual triage, both out of scope for v1. `api`'s environment gets `DTRACK_URL: http://dependency-track:8080` and an empty `DTRACK_API_KEY` placeholder the operator fills in after bootstrap, plus optional `DTRACK_SYNC_INTERVAL_SECS` (defaults to 600 in code if unset).

**One-time manual bootstrap (cannot be automated, document in README):** dtrack's apiserver creates a default `admin`/`admin` account on first boot with a forced password change; the operator logs in (via curl against the REST API, or briefly enabling the frontend image) to locate/create an API key with BOM-upload + findings-read permissions, then sets `DTRACK_API_KEY` for the `api` service and restarts it. Unavoidable — dtrack has no way to pre-provision a key via env vars alone.

### New crate `crates/dtrack` (`magnolia-dtrack`)

Mirrors the existing `magnolia-signer`/`magnolia-storage` pattern: a narrow crate wrapping one external system behind a small typed client. Uses `reqwest` (`default-features = false, features = ["json", "rustls-tls"]` — rustls, not native-tls/OpenSSL, so the `rust:1-slim-bookworm` Dockerfile builder stage doesn't need `libssl-dev` added, a real gotcha it currently avoids entirely). This is the **first direct `reqwest` dependency** in the workspace (currently only pulled in transitively via `jsonschema`) and the **first background/periodic task** anywhere in the codebase (confirmed via `grep -rn "tokio::spawn\|spawn_blocking\|interval" crates/*/src/*.rs` — nothing exists today) — both need to be built defensively since there's no established precedent to lean on.

`DtrackClient` (`crates/dtrack/src/client.rs`): `push_bom(project_name, project_version, bom_bytes) -> Result<(), DtrackError>`, `lookup_project(project_name, project_version) -> Result<Option<Uuid>, DtrackError>`, `get_findings(project_uuid) -> Result<Vec<DtrackFinding>, DtrackError>`. `DtrackFinding` (`crates/dtrack/src/models.rs`): `component_name`, `component_version`, `vulnerability_id`, `severity`, `description`, `analysis_state`, `finding_key` (stable per-finding identity — verify against real response shape).

**Project naming**: one dtrack project **per manifest** (not per namespace), since Magnolia's manifests are immutable while dtrack's usual model is one project with many BOM versions — `project_name = "{tenant_domain}{namespace}"`, `project_version = "{version}-{manifest_hash[..12]}"`. The hash suffix guarantees uniqueness across tenants/re-uploads sharing a namespace+version, since dtrack has no notion of Magnolia's tenant boundary.

### DB layer — cache-only read path

New migration `migrations/20260823000004_dtrack_integration.sql`:
```sql
-- One dtrack project per manifest (see naming rule above).
CREATE TABLE dtrack_projects (
    manifest_hash TEXT PRIMARY KEY REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    dtrack_project_uuid UUID NOT NULL,
    pushed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at TIMESTAMPTZ
);
CREATE INDEX dtrack_projects_uuid_idx ON dtrack_projects (dtrack_project_uuid);

-- Cached copy of dtrack's findings, refreshed by the background sync loop.
-- Magnolia's own read path (GET /api/v1/manifest/:hash) only ever reads
-- this table — never calls dtrack live — so normal browsing stays
-- available independent of dtrack's uptime.
CREATE TABLE dtrack_findings (
    manifest_hash TEXT NOT NULL REFERENCES manifests(manifest_hash) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    component_name TEXT NOT NULL,
    component_version TEXT,
    vulnerability_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    analysis_state TEXT,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (manifest_hash, finding_key)
);
```
Applies automatically via the existing `sqlx::migrate!("../../migrations")` call in `main.rs` — no manual step.

`crates/db/src/models.rs`: `DtrackProjectRecord`, `DtrackFindingRecord` (both `FromRow`, mirroring `ComplianceSettingRecord`'s style).

`crates/db/src/lib.rs` new methods (mirroring `list_compliance_settings`/`set_compliance_setting`'s query style):
- `list_manifests_without_dtrack_project(limit) -> Vec<ManifestRecord>` — `WHERE sbom_format = 'cyclonedx' AND NOT revoked AND manifest_hash NOT IN (SELECT manifest_hash FROM dtrack_projects) ORDER BY created_at LIMIT $1`. **CycloneDX only for v1** — dtrack's SPDX BOM support is unverified; don't imply it works.
- `insert_dtrack_project(manifest_hash, project_uuid)` — insert, `ON CONFLICT DO NOTHING`.
- `list_dtrack_projects(limit) -> Vec<DtrackProjectRecord>` — `ORDER BY last_synced_at ASC NULLS FIRST` so never-synced/stalest projects get priority each pass.
- `replace_dtrack_findings(manifest_hash, findings)` — transaction: `DELETE ... WHERE manifest_hash = $1` then bulk-insert; delete-then-insert is simpler and more correct than diffing, since findings can legitimately disappear (remediated, reanalyzed).
- `touch_dtrack_project_synced(manifest_hash)` — `UPDATE ... SET last_synced_at = now()`.
- `list_dtrack_findings(manifest_hash) -> Vec<DtrackFindingRecord>` — used by the `manifest()` read path.

### Background sync loop — new file `crates/api/src/dtrack_sync.rs`

`run_sync_loop(db: Arc<Database>, storage: Arc<dyn ObjectStore>, client: Arc<DtrackClient>, interval: Duration)` — a `tokio::spawn`ed loop, only started in `main.rs` when both `DTRACK_URL` and `DTRACK_API_KEY` are set (same presence-gated pattern as storage/signer backend selection). Each tick:
1. **Push phase**: `list_manifests_without_dtrack_project(50)`, fetch each one's bytes from `storage`, push via `client.push_bom(...)`, resolve the project UUID via `lookup_project(...)`, `insert_dtrack_project(...)`.
2. **Refresh phase**: `list_dtrack_projects(100)`, for each fetch `client.get_findings(uuid)`, `replace_dtrack_findings(...)`, `touch_dtrack_project_synced(...)`.

Every per-item failure is caught and logged (`tracing::warn!`) and the loop continues — one bad SBOM or a transient dtrack outage must never kill the loop or affect Magnolia's own request handling. This mirrors the existing "secondary concern can't block/fail the primary flow" idiom already in `upload_sbom` (`let _ = record_audit(...)`). No synchronous dtrack call is ever made from inside an HTTP handler — this is genuinely fire-and-forget background work, decoupled from the upload request/response cycle.

### API layer

`crates/api/src/state.rs`: `AppState` gains `pub dtrack: Option<Arc<DtrackClient>>` — `None` means the integration is off for this deployment. **The manual `Clone` impl must be updated to include it** (easy to forget, called out explicitly since this struct doesn't derive `Clone`).

`crates/api/src/main.rs`: after building `AppState`, gate client construction on both env vars being present and non-empty; if present, `tokio::spawn(run_sync_loop(...))` with `Arc::clone`s of `state.db`/`state.storage`. Log clearly whether the integration is enabled or disabled at startup.

`crates/api/src/handlers.rs`:
- `ConfigJson` gains `pub dtrack_enabled: bool` (populated as `state.dtrack.is_some()`), surfaced via `GET /api/v1/config` — mirrors `storage_backend`'s existing role of letting the UI reflect deployment-time choices.
- New `DtrackFindingJson` DTO + `From<DtrackFindingRecord>` impl, alongside the existing `ComplianceReportJson`.
- `ManifestJson` gains `pub vulnerability_findings: Vec<DtrackFindingJson>`, placed right after `compliance`.
- `manifest()` handler: right after the existing compliance-report computation, add a `state.db.list_dtrack_findings(&record.manifest_hash).await` call, map to `DtrackFindingJson`, include in the response. **DB read only — never a live dtrack call in the request path.**

No manual "sync now" endpoint for v1 — periodic sync is enough; easy to add later (`POST /api/v1/manifest/:hash/dtrack-sync`) if wanted.

### Frontend

`frontend/src/api.ts`: `VulnerabilityFinding` interface (component name/version, vulnerability id, severity, description, analysis state), `Manifest.vulnerability_findings: VulnerabilityFinding[]`, `BackendConfig.dtrack_enabled: boolean`.

`Dashboard`'s existing "Backend Configuration" card gets one more `kv-row`: a `Badge` showing whether Dependency-Track is enabled.

`SbomDetailPanel`: a new block immediately after the existing Compliance block, reusing its exact `.compliance-block`/`.kv-row`/`Badge`/nested-`<ul>` CSS and conditional-render convention (`manifest.vulnerability_findings.length > 0`) — severity-count badges (critical/high/medium/low) followed by a list of individual findings, each showing component@version, severity, a short description, and a link out to the CVE/NVD record when the vulnerability id looks like a CVE. No new CSS classes required; the existing `.compliance-block` styling already fits.

## Ordered implementation

1. `Cargo.toml` (workspace) — add `crates/dtrack` to `members`.
2. `crates/dtrack/{Cargo.toml,src/{lib,client,models,errors}.rs}` — new crate; verify real dtrack endpoint shapes first (see confidence-check section); `cargo check -p magnolia-dtrack` on its own before wiring it in.
3. `migrations/20260823000004_dtrack_integration.sql`.
4. `crates/db/src/models.rs` + `crates/db/src/lib.rs` — records + six methods.
5. `crates/api/Cargo.toml` — add `magnolia-dtrack` path dependency.
6. `crates/api/src/state.rs` — `dtrack` field + updated `Clone` impl.
7. `crates/api/src/dtrack_sync.rs` (new) + export from `crates/api/src/lib.rs`.
8. `crates/api/src/main.rs` — env-gated client construction + `tokio::spawn`.
9. `crates/api/src/handlers.rs` — DTOs, `ManifestJson`/`ConfigJson` fields, `manifest()`/`config()` updates.
10. `docker-compose.yml` — `dtrack-db` + `dependency-track` services under `profiles: ["dtrack"]`, volumes, `api` env additions.
11. `frontend/src/api.ts` — new types.
12. `frontend/src/App.tsx` — Dashboard config row + `SbomDetailPanel` findings block.
13. `README.md` — document the `--profile dtrack` invocation and the one-time bootstrap step.

Steps 1–2 are independent and can be built/tested first. Steps 3–4 depend only on migration numbering. Steps 5–9 depend on 1–4. Steps 10–13 depend on 5–9's shapes being final.

## Verification

1. `cargo check -p magnolia-dtrack`, then `cargo check --workspace` (catches the `AppState::Clone` trap and any DTO mismatches), then `cargo test --workspace` (confirms nothing existing regressed).
2. `docker compose up -d` (no profile) — confirm Magnolia behaves exactly as before: `dtrack_enabled: false` in `GET /api/v1/config`, logs show the integration is disabled, no sync loop running.
3. `docker compose --profile dtrack up -d` — confirm `dtrack-db`/`dependency-track` come up and dtrack finishes its first-boot sync (can take a while — don't time out the check prematurely).
4. Complete the one-time bootstrap, set a real `DTRACK_API_KEY`, restart `api`. Confirm the startup log shows the integration enabled.
5. Live smoke test: upload a real CycloneDX SBOM containing a known-vulnerable component (e.g. an old `lodash`/`log4j` entry) via curl with the bootstrap super_admin key. Temporarily lower `DTRACK_SYNC_INTERVAL_SECS` for the test, wait one interval, then `GET /api/v1/manifest/:hash` and confirm `vulnerability_findings` is populated with plausible CVEs/severities — cross-check the count against dtrack's own `GET /api/v1/finding/project/{uuid}` using the same API key.
6. Stop the `dependency-track` container mid-run and confirm `GET /api/v1/manifest/:hash` still returns 200 with the last-cached findings, and `docker compose logs api` shows repeated sync-failure warnings without the process crashing.
7. Frontend: `npx tsc --noEmit`, `CI=true npm run build` (clean up `build/` after), then manually open a manifest with findings in a browser and confirm the new block renders with severity badges and CVE links.

---

# Appendix: what else Magnolia needs to be a genuinely useful CRA compliance tool

The dtrack integration above closes one concrete gap. Zooming out to the Cyber Resilience Act (EU 2024/2847) itself — not just BSI TR-03183 — here's what else matters, roughly in priority order for a product whose job is "help a manufacturer actually comply," not just "archive files."

## 1. Vulnerability findings (this plan)
CRA Annex I Part II(2): manufacturers must identify and remediate vulnerabilities without undue delay. Magnolia currently has no way to know if anything it's archived is actually vulnerable — the dtrack integration above is the direct fix. Highest leverage, already scoped.

## 2. CSAF/VEX export — the natural next step after dtrack lands
TR-03183-3 and CRA Annex I Part II(4) both want vulnerability information published in a structured, machine-readable form (CSAF, with VEX as a profile) — not a raw findings dump. Once dtrack findings are cached in Magnolia (§ above), the next step is letting an analyst triage them (mark "affected" / "not affected" / "fixed", per VEX status vocabulary) and export a signed CSAF/VEX document per product/version — reusing the exact DSSE signing infrastructure already built for manifests. Without this, findings sit in Magnolia's UI but there's no artifact a downstream consumer or auditor can actually consume.

## 3. CVD (Coordinated Vulnerability Disclosure) policy + security.txt as first-class data
CRA Annex I Part II(5) requires manufacturers to have and publish a CVD policy. Today Magnolia can only hold this as a generic `document` upload (free-form, no structure, no dedicated surface) — same treatment as any other file. A small, high-signal upgrade: a dedicated `document_type` with required fields (a public contact channel, disclosure timeline commitment, PGP key or security.txt reference) and a way to serve/link it per tenant, rather than it being indistinguishable from a risk-assessment PDF in the archive tree.

## 4. Support-period / EOL tracking per namespace
CRA Annex I Part II(6): manufacturers must provide security updates for a defined support period and state it. Magnolia's "currently running" view already tracks *what's* deployed per namespace, but has no concept of *until when* that's still supported — no expiry date, no warning when a product's support window is closing or has lapsed. A `support_until` field per namespace (surfaced as a warning badge in the Explorer, similar to the revoked/compliance badges already built) would close this cheaply, reusing the same per-namespace settings infrastructure already built for "currently running" visibility and compliance profiles.

## 5. Article 14 incident/vulnerability reporting timeline tracker — highest stakes, currently fully missing
This is the one CRA obligation with a hard clock attached, and Magnolia has zero support for it today. CRA Article 14 requires manufacturers to notify ENISA/their national CSIRT of:
- **Any actively exploited vulnerability**: early warning within **24 hours** of becoming aware, a follow-up notification within **72 hours**, and a final report within **14 days** of a fix becoming available.
- **Any severe incident** affecting the product's security: the same 24h/72h pattern, with a final report within **1 month**.

Missing these deadlines isn't a quality gap the way an incomplete SBOM is — it's a direct regulatory violation. Nothing in Magnolia today models "an incident/vulnerability report exists, has a clock running against it, and needs a 24h/72h/14-day trail of notifications." Realistic first version: an internal deadline-tracking entity (not automated submission to ENISA's platform, which likely isn't stably API-accessible yet) — create a report tied to a namespace/manifest, log the "became aware at" timestamp, get automatic deadline markers and status (on track / due soon / overdue) for each of the three stages, and an audit trail of what was reported when. This is the single highest-leverage feature from a strict "don't get fined" perspective, but also the largest lift — it's its own data model and UI, not a small addition like the others above.

## 6. Annex VII "technical documentation" bundle export
Annex VII requires a defined documentation package (product description, essential-requirements mapping, SBOM, vulnerability-handling process description, conformity route). Magnolia already stores the SBOM plus arbitrary supporting documents (CVD policy, risk assessments, etc.) as generic uploads, but has no single "assemble and export the current compliance package for product X, version Y" action — no bundling, no manifest-of-manifests, nothing a manufacturer could hand directly to an auditor or notified body today. A natural, lower-urgency follow-up once 1–5 above exist to bundle.

**Recommended order if pursued sequentially**: 1 (this plan) → 5 (highest regulatory stakes, worth starting early even though it's the biggest lift, since it's pure gap right now) → 2 (natural continuation of 1) → 3 and 4 (small, cheap, reuse existing per-namespace settings infra) → 6 (ties everything together once the pieces exist).
