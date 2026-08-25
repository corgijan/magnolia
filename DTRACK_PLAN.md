# Optional self-hosted Dependency-Track integration

## Context

Magnolia archives SBOMs with tamper-evidence and (as of this session) checks them against BSI TR-03183-2's data-field requirements, but it has no idea whether any of the components in an archived SBOM actually have known vulnerabilities — that's explicitly out of scope for an SBOM by design (TR-03183-2 §3.1: an SBOM MUST NOT contain vulnerability info, since vuln data is dynamic and SBOM data is static). OWASP Dependency-Track (dtrack) is the standard open-source tool for the other half of that: it ingests a BOM, continuously matches its components against NVD/OSS-Index/etc., and produces findings. The user wants Magnolia to optionally run a dtrack instance, push uploads to it, and show the resulting findings directly in Magnolia's own SBOM detail view — not just link out to a separate dtrack UI.

Key design call, made explicit because it differs from the compliance-profile feature built earlier this session: this is **deployment-wide and env-var-gated, not a per-tenant setting**. Dependency-Track is real infrastructure (its own Postgres, a slow first vulnerability-database sync) — an operator either runs one or doesn't, mirroring how `STORAGE_PATH`/`SIGNING_KEY_PATH` already select backends by env-var presence in `crates/api/src/main.rs`, not a per-tenant toggle table like `compliance_profile_settings`.

**Multi-tenancy caveat (real limitation, not solved here, must be documented):** a single shared dtrack instance has no concept of Magnolia's tenant boundaries — all tenants' BOMs land in the same dtrack project list, visible to anyone holding the shared `DTRACK_API_KEY` or dtrack admin login. Magnolia's own API stays correctly tenant-scoped (findings are looked up by `manifest_hash` *after* the existing tenant-ownership check in the `manifest()` handler), so there's no cross-tenant leak through Magnolia itself — but dtrack's own admin surface is a shared resource across the whole deployment. Call this out in docs.

## Confidence check on dtrack's actual API — DONE, verified against a real running instance (2026-08-25)

Implemented, then verified end-to-end against `dependencytrack/apiserver:4.13.0` (`docker compose --profile dtrack up`) — the plan's original guesses turned out mostly right, with one real gap found and fixed:

- `PUT /api/v1/bom` request shape confirmed exactly via `/api/openapi.json`'s `BomSubmitRequest` schema: `{projectName, projectVersion, autoCreate, bom: <base64>}`, header `X-Api-Key`. Response is a processing token, not the project UUID — confirmed, matches `push_bom`'s design (never parsed, resolved separately via `lookup_project`).
- `GET /api/v1/project/lookup?name=&version=` confirmed — returns a `Project` object with a `uuid` field. Project creation via `autoCreate` is synchronous (a `lookup_project` call right after a successful `push_bom` reliably found the project in live testing).
- `GET /api/v1/finding/project/{uuid}` confirmed to return an array with a top-level `matrix` string field (used as `finding_key`) plus nested `component`/`vulnerability`/`analysis` objects — **the OpenAPI spec leaves those nested objects untyped** (`additionalProperties: object`), so the exact nested field names in `crates/dtrack/src/models.rs`'s `RawComponent`/`RawVulnerability`/`RawAnalysis` (`component.uuid/name/version`, `vulnerability.uuid/vulnId/severity/description`, `analysis.state`) are still best-effort from training knowledge, not confirmed against a real finding — this sandbox had no outbound network access to NVD, so dtrack's vulnerability-database mirror never synced and no real finding was ever produced to inspect. If findings come back empty/malformed in a real deployment, re-check these nested field names first.
- **Real gap found**: the default "Automation" team's `BOM_UPLOAD` permission is **not** sufficient for `autoCreate: true` to actually create a new project — that requires `PROJECT_CREATION_UPLOAD` too (confirmed via a live 401 "The principal does not have permission to create project" that only cleared up after granting it). `VIEW_VULNERABILITY` was also needed for findings-read, as originally guessed. Updated the README's bootstrap instructions to call out `PROJECT_CREATION_UPLOAD` explicitly, not just "BOM-upload permissions."
- External-Postgres env var names for `dependencytrack/apiserver` confirmed exactly as guessed **for the 4.x line**: `ALPINE_DATABASE_MODE=external`, `ALPINE_DATABASE_URL` (JDBC form), `ALPINE_DATABASE_DRIVER=org.postgresql.Driver`, `ALPINE_DATABASE_USERNAME`, `ALPINE_DATABASE_PASSWORD` — the container connected to `dtrack-db` on first boot with no errors. **dtrack 5.x renamed these** — confirmed live against `5.0.5` after it hard-failed at startup with `Legacy Dependency-Track v4 configuration properties are no longer supported`. Per the official upgrade guide (dependencytrack.github.io, "v0.7.0-alpha.3" upgrade notes, since the v5.0.0-rc.2 notes just point back to it): `ALPINE_DATABASE_URL` → `DT_DATASOURCE_URL`, `ALPINE_DATABASE_USERNAME` → `DT_DATASOURCE_USERNAME`, `ALPINE_DATABASE_PASSWORD` → `DT_DATASOURCE_PASSWORD`; `ALPINE_DATABASE_MODE`/`ALPINE_DATABASE_DRIVER` are dropped entirely (driver inferred from the JDBC URL scheme, no more embedded-vs-external mode to pick). **Also confirmed live: 4.x and 5.x do not share a schema** — 4.x used DataNucleus-managed tables, 5.x uses Flyway migrations expecting its own baseline; pointing a fresh 5.x container at a Postgres volume still holding 4.x's schema fails with `relation "PACKAGE_METADATA" does not exist` partway through Flyway's first migration. There's no in-place upgrade path exercised here — the fix that worked was wiping `dtrack-db`'s volume and letting 5.x initialize fresh. `docker-compose.yml` is now pinned to `dependencytrack/apiserver:5.0.5` with the `DT_DATASOURCE_*` names, verified end-to-end on a wiped volume: booted healthy, `dtrack-bootstrap` completed successfully, `api` came up with `dtrack_enabled: true` and began pushing BOMs immediately.
- Full pipeline verified live: 14 real manifests successfully pushed and auto-created as dtrack projects; the background sync loop's push/refresh phases both ran without crashing across multiple ticks; two manifests with a schema-invalid `metadata.manufacturer.contact[].email` correctly failed with a logged warning and no loop interruption; triage (`not_affected` without justification → 400, with justification → 200 with `triaged_by`/`triaged_at`) verified via the real HTTP endpoint; the triage-survives-a-real-still-present-finding path was verified by direct SQL against `replace_dtrack_findings`'s exact query (couldn't be exercised through a real dtrack finding, for the same NVD-network-access reason above) — confirmed `vex_status`/`vex_justification`/`triaged_by`/`triaged_at` are untouched by the `ON CONFLICT DO UPDATE` while `severity`/`description`/`analysis_state`/`synced_at` do get refreshed; `finding_triage` audit-log entries confirmed in `GET /api/v1/audit-logs` with the justification riding in `reason`.

## Design

### Docker Compose — opt-in via `profiles:`

Two new services (`dtrack-db`: postgres:15, its own volume; `dependency-track`: official `dependencytrack/apiserver` image pinned to a real version tag, not `:latest`), both under `profiles: ["dtrack"]` so plain `docker compose up` is completely unaffected — dtrack only starts with `docker compose --profile dtrack up`. A persistent volume for dtrack's own data dir (the NVD/OSS-Index mirror is slow to rebuild from scratch). `dependencytrack/frontend` is deliberately **not** added — Magnolia's own UI is the intended findings surface; dtrack's web UI is only useful for the one-time manual bootstrap and advanced manual triage, both out of scope for v1. `api`'s environment gets `DTRACK_URL: http://dependency-track:8080` and an empty `DTRACK_API_KEY` placeholder the operator fills in after bootstrap, plus optional `DTRACK_SYNC_INTERVAL_SECS` (defaults to 600 in code if unset).

**One-time bootstrap — dtrack itself requires this, cannot be skipped via config:** dtrack's apiserver creates a default `admin`/`admin` account on first boot with a forced password change, and an API key can only be minted through its own REST API/UI. Confirmed by extracting and grepping the real image's `application.properties` — no property exists to pre-seed the admin password, a team, or an API key. `scripts/bootstrap-dtrack.sh` automates the sequence (password change → login → grant `BOM_UPLOAD`/`PROJECT_CREATION_UPLOAD`/`VIEW_VULNERABILITY` to the `Automation` team → mint a key), used two ways:
- **Manual**: `docker compose --profile dtrack up -d`, then the script by hand — it writes the key to a git-ignored `.env` file that `docker-compose.yml` reads via `${DTRACK_API_KEY:-}`, so the only genuinely manual step is running that one script once (or re-running it, safely — it's idempotent) rather than hand-editing any tracked file.
- **Fully automatic**: `docker-compose.dtrack.yml` (verified end-to-end, including the failure path) — un-gates `dtrack-db`/`dependency-track` via the compose-spec `!override` merge tag on `profiles` (a plain list-override in the override file does NOT work — compose merges/unions `profiles` lists across files rather than replacing them, confirmed by hitting "depends on undefined service" until switching to `!override`), adds a one-shot `dtrack-bootstrap` init container that runs the same script with `DTRACK_BOOTSTRAP_KEY_FILE` set (writes the raw key to a shared volume instead of `.env`), and `api` depends on that container's `service_completed_successfully` with a new `DTRACK_API_KEY_FILE` env var (added to `main.rs`, read at startup, only used when the plain `DTRACK_API_KEY` is empty) pointed at the same volume. The bootstrap container's entrypoint always exits 0 even when the script itself fails internally (network hiccup, dtrack slow to boot) — confirmed live by pointing it at a wrong port — specifically so a dtrack-side failure can never block `api`'s own startup, only leave the integration disabled. One command, idempotent, works on a completely fresh volume — confirmed by wiping all dtrack volumes and running it cold.

### New crate `crates/dtrack` (`magnolia-dtrack`)

Mirrors the existing `magnolia-signer`/`magnolia-storage` pattern: a narrow crate wrapping one external system behind a small typed client. Uses `reqwest` (`default-features = false, features = ["json", "rustls-tls"]` — rustls, not native-tls/OpenSSL, so the `rust:1-slim-bookworm` Dockerfile builder stage doesn't need `libssl-dev` added, a real gotcha it currently avoids entirely). This is the **first direct `reqwest` dependency** in the workspace (currently only pulled in transitively via `jsonschema`) and the **first background/periodic task** anywhere in the codebase (confirmed via `grep -rn "tokio::spawn\|spawn_blocking\|interval" crates/*/src/*.rs` — nothing exists today) — both need to be built defensively since there's no established precedent to lean on.

`DtrackClient` (`crates/dtrack/src/client.rs`): `push_bom(project_name, project_version, bom_bytes) -> Result<(), DtrackError>`, `lookup_project(project_name, project_version) -> Result<Option<Uuid>, DtrackError>`, `get_findings(project_uuid) -> Result<Vec<DtrackFinding>, DtrackError>`. `DtrackFinding` (`crates/dtrack/src/models.rs`): `component_name`, `component_version`, `vulnerability_id`, `severity`, `description`, `analysis_state`, `finding_key` (stable per-finding identity — verify against real response shape).

**Project naming**: one dtrack project **per manifest** (not per namespace), since Magnolia's manifests are immutable while dtrack's usual model is one project with many BOM versions — `project_name = "{tenant_domain}{namespace}"`, `project_version = "{version}-{manifest_hash[..12]}"`. The hash suffix guarantees uniqueness across tenants/re-uploads sharing a namespace+version, since dtrack has no notion of Magnolia's tenant boundary.

### DB layer — cache-only read path

New migration `migrations/20260825000002_dtrack_integration.sql`:
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
    analysis_state TEXT,          -- dtrack's own generic analysis state, synced verbatim
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Magnolia's own VEX-style triage, independent of dtrack's analysis_state
    -- above (see "VEX-style triage on findings" below) — the two can
    -- legitimately disagree, since dtrack has no notion of Magnolia's
    -- product/manifest context.
    vex_status TEXT,              -- 'affected' | 'not_affected' | 'fixed' | 'under_investigation' | NULL (untriaged)
    vex_justification TEXT,       -- required by the API layer when vex_status = 'not_affected', not DB-enforced
    triaged_by TEXT,
    triaged_at TIMESTAMPTZ,
    PRIMARY KEY (manifest_hash, finding_key)
);
```
Applies automatically via the existing `sqlx::migrate!("../../migrations")` call in `main.rs` — no manual step.

`crates/db/src/models.rs`: `DtrackProjectRecord`, `DtrackFindingRecord` (both `FromRow`, mirroring `ComplianceSettingRecord`'s style; `DtrackFindingRecord` includes the four `vex_*`/`triaged_*` columns).

`crates/db/src/lib.rs` new methods (mirroring `list_compliance_settings`/`set_compliance_setting`'s query style):
- `list_manifests_without_dtrack_project(limit) -> Vec<ManifestRecord>` — `WHERE sbom_format = 'cyclonedx' AND NOT revoked AND manifest_hash NOT IN (SELECT manifest_hash FROM dtrack_projects) ORDER BY created_at LIMIT $1`. **CycloneDX only for v1** — dtrack's SPDX BOM support is unverified; don't imply it works.
- `insert_dtrack_project(manifest_hash, project_uuid)` — insert, `ON CONFLICT DO NOTHING`.
- `list_dtrack_projects(limit) -> Vec<DtrackProjectRecord>` — `ORDER BY last_synced_at ASC NULLS FIRST` so never-synced/stalest projects get priority each pass.
- `replace_dtrack_findings(manifest_hash, findings)` — transaction: `DELETE ... WHERE manifest_hash = $1` then bulk-insert; delete-then-insert is simpler and more correct than diffing, since findings can legitimately disappear (remediated, reanalyzed). **Must preserve existing triage on a finding that's still present after a re-sync** — e.g. `INSERT ... ON CONFLICT (manifest_hash, finding_key) DO UPDATE SET <non-triage columns> = excluded.<...>` instead of a blind delete-then-insert of triaged rows, or a two-step "delete only rows not in the new finding_key set, then upsert" — don't let a routine sync pass silently wipe an analyst's triage decision.
- `touch_dtrack_project_synced(manifest_hash)` — `UPDATE ... SET last_synced_at = now()`.
- `list_dtrack_findings(manifest_hash) -> Vec<DtrackFindingRecord>` — used by the `manifest()` read path.
- `set_finding_triage(manifest_hash, finding_key, vex_status, justification, triaged_by) -> Option<DtrackFindingRecord>` — `UPDATE dtrack_findings SET vex_status = $1, vex_justification = $2, triaged_by = $3, triaged_at = now() WHERE manifest_hash = $4 AND finding_key = $5 RETURNING *`; `None` if the finding no longer exists (e.g. resolved by a later sync) — resolved to `ApiError::NotFound` at the handler layer.

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
- New `DtrackFindingJson` DTO + `From<DtrackFindingRecord>` impl, alongside the existing `ComplianceReportJson`. Includes `vex_status: Option<String>`, `vex_justification: Option<String>`, `triaged_by: Option<String>`, `triaged_at: Option<String>` alongside the base dtrack-sourced fields.
- `ManifestJson` gains `pub vulnerability_findings: Vec<DtrackFindingJson>`, placed right after `compliance`.
- `manifest()` handler: right after the existing compliance-report computation, add a `state.db.list_dtrack_findings(&record.manifest_hash).await` call, map to `DtrackFindingJson`, include in the response. **DB read only — never a live dtrack call in the request path.**

No manual "sync now" endpoint for v1 — periodic sync is enough; easy to add later (`POST /api/v1/manifest/:hash/dtrack-sync`) if wanted.

### VEX-style triage on findings

An analyst-settable VEX status (`affected` / `not_affected` / `fixed` / `under_investigation` — the CSAF/VEX vocabulary) per finding, with a justification, tracked to who/when — this is Magnolia's own product-specific exploitability judgment, not something dtrack can supply (it has no notion of Magnolia's manifests). Built directly on the `dtrack_findings` row (see the `vex_*`/`triaged_*` columns above), not a separate table — there's exactly one current triage state per finding, and `audit_logs` already captures triage *history* (actor, timestamp, justification) via its existing `reason` field, so a second table for history isn't needed yet.

New endpoint, `POST /api/v1/manifest/:manifest_hash/findings/:finding_key/triage`, following `revoke_manifest`'s (`crates/api/src/handlers.rs`) exact existing pattern rather than inventing a new one:
```rust
pub struct TriageFindingRequest {
    pub vex_status: String,               // validated against the 4-value enum
    pub justification: Option<String>,     // required (400) when vex_status == "not_affected"
}

pub async fn triage_finding(
    State(state): State<AppState>,
    grant: AuthGrant,
    Path((manifest_hash, finding_key)): Path<(String, String)>,
    Query(q): Query<TenantOverrideQuery>,
    Json(body): Json<TriageFindingRequest>,
) -> Result<Json<DtrackFindingJson>, ApiError> {
    require(&grant, Action::Annotate, &grant.namespace_scope)?;   // same action as revoke_manifest
    let (tenant_id, cross_tenant) = effective_tenant(&grant, q.tenant_id)?;
    let record = state.db.get_manifest(&manifest_hash).await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    if record.tenant_id != tenant_id
        || (!cross_tenant && !magnolia_auth::namespace_in_scope(&record.namespace, &grant.namespace_scope))
    { return Err(ApiError::NotFound); }

    if !["affected", "not_affected", "fixed", "under_investigation"].contains(&body.vex_status.as_str()) {
        return Err(ApiError::BadRequest("invalid vex_status".to_string()));
    }
    if body.vex_status == "not_affected" && body.justification.as_deref().unwrap_or("").is_empty() {
        return Err(ApiError::BadRequest("justification is required when vex_status is not_affected".to_string()));
    }

    let updated = state.db.set_finding_triage(&manifest_hash, &finding_key, &body.vex_status, body.justification.as_deref(), &grant.principal())
        .await.map_err(db_err)?.ok_or(ApiError::NotFound)?;
    let _ = record_audit(&state, &grant, "finding_triage", &format!("{manifest_hash}:{finding_key}"), true, body.justification.clone()).await;
    Ok(Json(updated.into()))
}
```
Registered in `crates/api/src/lib.rs` alongside the other manifest-scoped routes (`/api/v1/manifest/:manifest_hash/...`). Audit trail needs no schema change — `record_audit`'s existing `reason: Option<String>` parameter carries the justification, and `"finding_triage"` entries appear in the existing `GET /api/v1/audit-logs` feed automatically since `action`/`resource`/`reason` are already unstructured text columns.

Deliberately out of scope for this pass: signing triage decisions into a DSSE-signed, exportable CSAF/VEX document. No generic "sign an arbitrary JSON payload" helper exists today — every DSSE call site (`upload_sbom`, `snapshot.rs`) hand-rolls its own `Predicate`/`Statement<P>` → `pae()` → `signer.sign()` → `build_envelope()` sequence. A future `VexPredicate`/`VexStatement` would follow that same four-step pattern once triage data exists to export (this is the Appendix's "§2 CSAF/VEX export" item, still a good next step after this one, not built here).

### Frontend

`frontend/src/api.ts`: `VulnerabilityFinding` interface (component name/version, vulnerability id, severity, description, analysis state, plus `vex_status`/`vex_justification`/`triaged_by`/`triaged_at`), `Manifest.vulnerability_findings: VulnerabilityFinding[]`, `BackendConfig.dtrack_enabled: boolean`. New `api.triageFinding(manifestHash, findingKey, vexStatus, justification, tenantId?)` following the exact `request(...)`/`tenantQs(...)` shape every other method in that file uses — same shape as `api.revokeManifest`.

`Dashboard`'s existing "Backend Configuration" card gets one more `kv-row`: a `Badge` showing whether Dependency-Track is enabled.

`SbomDetailPanel`: a new block immediately after the existing Compliance block, reusing its exact `.compliance-block`/`.kv-row`/`Badge`/nested-`<ul>` CSS and conditional-render convention (`manifest.vulnerability_findings.length > 0`) — severity-count badges (critical/high/medium/low) followed by a list of individual findings, each showing component@version, severity, a short description, and a link out to the CVE/NVD record when the vulnerability id looks like a CVE. No new CSS classes required; the existing `.compliance-block` styling already fits.

Each finding also gets a triage control: a VEX-status `<select>` (untriaged / affected / not_affected / fixed / under_investigation) plus a justification `<textarea>` (shown/required when "not_affected" is selected) and a Save button. Mirrors `revoke`'s existing state pattern exactly (`frontend/src/App.tsx`'s `SbomDetailPanel.revoke` function) — per-finding `busy`/`error` state, disabled-while-in-flight, and a post-success `load()` re-fetch so the saved `triaged_by`/`triaged_at` show immediately. Unlike revoke, no `window.confirm` — triage is correctable, not "final and cannot be undone" — a "triaged by X on Y" line after saving is feedback enough.

## Ordered implementation

1. `Cargo.toml` (workspace) — add `crates/dtrack` to `members`.
2. `crates/dtrack/{Cargo.toml,src/{lib,client,models,errors}.rs}` — new crate; verify real dtrack endpoint shapes first (see confidence-check section); `cargo check -p magnolia-dtrack` on its own before wiring it in.
3. `migrations/20260825000002_dtrack_integration.sql` — includes the `vex_*`/`triaged_*` columns on `dtrack_findings` from the start (see DB layer section above).
4. `crates/db/src/models.rs` + `crates/db/src/lib.rs` — records + seven methods (the base six plus `set_finding_triage`).
5. `crates/api/Cargo.toml` — add `magnolia-dtrack` path dependency.
6. `crates/api/src/state.rs` — `dtrack` field + updated `Clone` impl.
7. `crates/api/src/dtrack_sync.rs` (new) + export from `crates/api/src/lib.rs`.
8. `crates/api/src/main.rs` — env-gated client construction + `tokio::spawn`.
9. `crates/api/src/handlers.rs` — DTOs (including the triage fields on `DtrackFindingJson`), `ManifestJson`/`ConfigJson` fields, `manifest()`/`config()` updates, and the new `triage_finding` handler.
10. `crates/api/src/lib.rs` — register the `POST /api/v1/manifest/:manifest_hash/findings/:finding_key/triage` route alongside `docker-compose.yml`'s `dtrack-db` + `dependency-track` services under `profiles: ["dtrack"]`, volumes, `api` env additions.
11. `frontend/src/api.ts` — new types, including the triage fields, plus `api.triageFinding(...)`.
12. `frontend/src/App.tsx` — Dashboard config row, `SbomDetailPanel` findings block, and the per-finding triage controls (select + justification + save).
13. `README.md` — document the `--profile dtrack` invocation, the one-time bootstrap step, and the VEX status vocabulary (including that `not_affected` requires a justification).

Steps 1–2 are independent and can be built/tested first. Steps 3–4 depend only on migration numbering. Steps 5–9 depend on 1–4. Steps 10–13 depend on 5–9's shapes being final.

## Verification

1. `cargo check -p magnolia-dtrack`, then `cargo check --workspace` (catches the `AppState::Clone` trap and any DTO mismatches), then `cargo test --workspace` (confirms nothing existing regressed).
2. `docker compose up -d` (no profile) — confirm Magnolia behaves exactly as before: `dtrack_enabled: false` in `GET /api/v1/config`, logs show the integration is disabled, no sync loop running.
3. `docker compose --profile dtrack up -d` — confirm `dtrack-db`/`dependency-track` come up and dtrack finishes its first-boot sync (can take a while — don't time out the check prematurely).
4. Complete the one-time bootstrap, set a real `DTRACK_API_KEY`, restart `api`. Confirm the startup log shows the integration enabled.
5. Live smoke test: upload a real CycloneDX SBOM containing a known-vulnerable component (e.g. an old `lodash`/`log4j` entry) via curl with the bootstrap super_admin key. Temporarily lower `DTRACK_SYNC_INTERVAL_SECS` for the test, wait one interval, then `GET /api/v1/manifest/:hash` and confirm `vulnerability_findings` is populated with plausible CVEs/severities — cross-check the count against dtrack's own `GET /api/v1/finding/project/{uuid}` using the same API key.
6. Stop the `dependency-track` container mid-run and confirm `GET /api/v1/manifest/:hash` still returns 200 with the last-cached findings, and `docker compose logs api` shows repeated sync-failure warnings without the process crashing.
7. Frontend: `npx tsc --noEmit`, `CI=true npm run build` (clean up `build/` after), then manually open a manifest with findings in a browser and confirm the new block renders with severity badges and CVE links.
8. `POST .../findings/:finding_key/triage` with `vex_status: "not_affected"` and no justification → confirm 400. Retry with a justification → confirm 200 and the response includes `triaged_by`/`triaged_at`.
9. `GET /api/v1/manifest/:hash` → confirm the triaged finding carries the VEX fields. Then trigger a fresh dtrack sync pass (wait one interval or lower `DTRACK_SYNC_INTERVAL_SECS`) and confirm the triage survives — this specifically exercises `replace_dtrack_findings`'s upsert-not-blind-delete behavior; don't assume it "just works" without checking.
10. `GET /api/v1/audit-logs` → confirm a `"finding_triage"` entry appears with the justification as `reason`.
11. Frontend: manually triage a finding in the browser, reload the page, confirm the saved state comes back from the API (not just local state).

---

# Appendix: what else Magnolia needs to be a genuinely useful CRA compliance tool

The dtrack integration above closes one concrete gap. Zooming out to the Cyber Resilience Act (EU 2024/2847) itself — not just BSI TR-03183 — here's what else matters, roughly in priority order for a product whose job is "help a manufacturer actually comply," not just "archive files."

## 1. Vulnerability findings (this plan)
CRA Annex I Part II(2): manufacturers must identify and remediate vulnerabilities without undue delay. Magnolia currently has no way to know if anything it's archived is actually vulnerable — the dtrack integration above is the direct fix. Highest leverage, already scoped.

## 2. CSAF/VEX export — the natural next step after dtrack + triage land
TR-03183-3 and CRA Annex I Part II(4) both want vulnerability information published in a structured, machine-readable form (CSAF, with VEX as a profile) — not a raw findings dump. The dtrack integration above now includes VEX-status triage (an analyst marking each finding "affected" / "not_affected" / "fixed" / "under_investigation", with a justification — see "VEX-style triage on findings"), so the remaining gap is exporting that triaged data as a **signed** CSAF/VEX document per product/version — reusing the exact DSSE signing infrastructure already built for manifests (a `VexPredicate`/`VexStatement` following the same `Statement<P>` → `pae()` → `signer.sign()` → `build_envelope()` pattern every other DSSE call site already uses). Without this, triaged findings sit in Magnolia's UI but there's no artifact a downstream consumer or auditor can actually consume.

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
