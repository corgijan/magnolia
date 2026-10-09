# Magnolia (AISE) REST API reference

Every route of the AISE API server (`magnolia-server`, `crates/api`), checked
against `create_router` in `crates/api/src/lib.rs` and the handlers in
`crates/api/src/handlers.rs`. 78 method/path pairs.

The CVE-reachability analyser `reach` is a separate service with its own API
and a generated OpenAPI document (`/openapi.json`, Swagger UI at `/docs`); see
[`reach/README.md`](../reach/README.md). It is not repeated here.

> **No OpenAPI document exists for this API yet** (the analyser has one). This
> file is the reference until it does.

## Accessing the API locally

| How it runs | Base URL |
|---|---|
| `docker compose up` | `http://127.0.0.1:3000` (`API_PORT`, default 3000) |
| `cargo run --bin magnolia-server` | `http://127.0.0.1:3000` (`SERVER_ADDR`) |
| Web UI dev server / compose frontend | `http://localhost:4000` proxies `/api` and `/health` to the API |

```bash
export MAG=http://127.0.0.1:3000
export KEY='mag_<secret>'          # BOOTSTRAP_SUPER_ADMIN_KEY, or a key from POST /api/v1/keys
curl -s $MAG/health -o /dev/null -w '%{http_code}\n'      # 200, no auth
curl -s -H "Authorization: Bearer $KEY" $MAG/api/v1/whoami
```

## Authentication and permissions

All `/api/v1/*` routes require `Authorization: Bearer mag_<secret>` (legacy
`<key_id>:<secret>` keys still work). `/health`, `/install.sh` and
`/install.py` need no key.

Each endpoint below lists the **permission** its handler checks. The role
matrix (`crates/auth/src/rbac.rs`):

| Permission | super_admin | domain_admin | uploader | auditor |
|---|---|---|---|---|
| `Read` | ✓ | ✓ | – | ✓ |
| `Annotate` | ✓ | ✓ | – | ✓ |
| `Upload` | ✓ | ✓ | ✓ | – |
| `ManageKeys` | ✓ | ✓ | – | – |
| `ManageSettings` | ✓ | ✓ | – | – |
| `ManageTenantData` | ✓ | – | – | – |
| `ManageTenants` | ✓ | – | – | – |
| *key only* | any valid, unrevoked, unexpired key; no permission check |

Besides the role, every check also requires the target namespace to be inside
the key's `namespace_scope` (whole-segment prefix: `/p1` covers `/p1/sub`, not
`/p10`).

**Acting on another tenant.** Every endpoint that takes the `tenant_id` query
parameter below (including upload) accepts `?tenant_id=<uuid>` to act on that
tenant instead of the key's own. It is honoured **only** for a `super_admin`
key of the platform tenant (`is_platform`); anyone else gets `403`.
`POST /api/v1/keys` takes `tenant_id` in the JSON body instead.

## Errors

Every error is JSON: `{"error": "<message>"}`.

| Status | When |
|---|---|
| `400` | Invalid input; the message names the field (e.g. `version is required`, `invalid vex_status filter`) |
| `401` | Missing, unknown, revoked or expired key |
| `403` | Role lacks the permission, namespace outside the key's scope, or a cross-tenant `tenant_id` from a non-platform key |
| `404` | Resource does not exist **or** belongs to another tenant/namespace (existence is not confirmed across tenants) |
| `409` | Conflicts with current state (e.g. a reachability analysis for this finding is already queued/running) |
| `413` | Request body over the size limit (multipart endpoints: 10 MiB SBOM + 64 KiB overhead) |
| `500` | Database, storage or signing failure |

Endpoints marked **204** return no body on success.

## Meta

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness; always `200`, empty body |
| GET | `/install.sh` | none | The bash upload CLI (`scripts/magnolia-upload.sh`), served from the instance |
| GET | `/install.py` | none | The Python upload CLI (`scripts/magnolia-upload.py`) |
| GET | `/api/v1/whoami` | key only | `{key_id, tenant_id, domain, namespace_scope, role, is_platform_tenant}` |
| GET | `/api/v1/config` | key only | Deployment flags: `{storage_backend, signer_backend, dev_mode, dtrack_enabled, dtrack_sync_interval_secs, reputation_enabled, freshness_enabled, malicious_check_enabled, reachability_enabled}` |
| GET | `/api/v1/signing-key` | key only | `{algorithm, keyid, public_key_base64, public_key_pem}`: the Ed25519 key that signs tree heads and DSSE manifests |

## Transparency log

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| POST | `/api/v1/upload` | `Upload` | query `tenant_id`; multipart, see below | `UploadResponse` |
| POST | `/api/v1/verify` | `Upload` | query `tenant_id`; multipart: `sbom_file` (first part), `format` | `{verdict: "pass"\|"fail", checks: [{id, status, enforce_level, details[]}], compliance: [{profile_id, profile_name, enforce_level, meets_minimum, minimum_issues[], fully_compliant, missing_fields[]}]}`; nothing is stored |
| GET | `/api/v1/tree-head/latest` | `Read` | `tenant_id` | `TreeHead` |
| GET | `/api/v1/tree-head/:tree_size` | `Read` | `tenant_id` | `TreeHead` at that size; `404` if none |
| GET | `/api/v1/proof/inclusion/:leaf_index` | `Read` | `tenant_id` | `{leaf_index, tree_size, peak_index, peaks: [hex], sibling_path: [{hash: hex, sibling_is_left}]}` |
| GET | `/api/v1/proof/consistency/:old_tree_size/:new_tree_size` | `Read` | `tenant_id` | `{old_tree_size, new_tree_size, peaks: [hex], peak_proofs: [{leaf_start, level, peak_hash: hex, new_peak_index, steps: [{hash, sibling_is_left}]}]}`; `new_tree_size` must be the current size |
| GET | `/api/v1/leaves` | `Read` | `limit` (default 50), `offset`, `tenant_id` | `[{seq_id, leaf_index, tenant_id, namespace, sbom_s3_key, leaf_hash, status, created_at, manifest_hash, revoked, domain, version, document_type}]`, newest first, filtered to the key's scope |
| POST | `/api/v1/snapshot` | `Read` | `tenant_id`; JSON `{namespace?, version?}` | `application/x-tar` download: a signed archive of every manifest in scope |

`TreeHead` = `{tree_size, root_hash, signature, frontier: [hex], created_at, signature_verified}`.

Verifying an inclusion proof: hash the leaf up `sibling_path` (the result must
equal `peaks[peak_index]`), then fold `peaks` left to right to obtain the tree
root and compare it with the signed tree head's `root_hash`. Leaves are
`H(0x00 ‖ sbom_bytes)`, inner nodes `H(0x01 ‖ left ‖ right)`, SHA-256.

**Upload multipart fields.** `sbom_file` must be the **first** part (the
server reads the first part as the file regardless of its name).

| Field | Required | Notes |
|---|---|---|
| `sbom_file` | yes | ≤ 10 MiB |
| `format` | no (default `cyclonedx`) | `cyclonedx`, `spdx` or `document` |
| `namespace` | no (default `/`) | must be inside the key's scope; must be registered if the tenant requires it |
| `version` | yes | free-text release label; must be SemVer 2.0.0 if the tenant requires it |
| `document_type` | when `format=document` | e.g. `vex`, `license` |
| `source_commit` | no | full 40/64-hex git object id; anything else is a `400` |
| `source_repo` | no | `https://` only; recorded as the namespace's source repository (see below) |
| `source_subpath` | no | needs `source_repo`; relative, no `..` |
| `source_revision` | no | needs `source_repo`; branch/tag/commit |

Checks, in order: field validation → schema validation → `Upload` permission →
compliance profiles and license policy → SemVer and namespace registration →
platform-tenant refusal. Then the SBOM is stored, appended to the tenant's
Merkle tree, the tree head and DSSE manifest are signed and persisted.

`UploadResponse` = `{sbom_hash, manifest_hash, version, namespace, domain,
tree_size, leaf_index, leaf_seq_id, signed_tree_head: TreeHead, source_repo?}`.
`source_repo` is present only when one was declared: `recorded` (it is now
the namespace's mapping), `kept_existing` (an admin-set mapping takes
precedence and was not changed) or `not_recorded` (saving it failed; the
upload itself succeeded).

```bash
curl -X POST "$MAG/api/v1/upload" -H "Authorization: Bearer $KEY" \
  -F "sbom_file=@sbom.json" -F format=cyclonedx -F namespace=/product/api -F version=1.2.3 \
  -F source_commit=$(git rev-parse HEAD) -F source_repo=https://github.com/acme/api
```

## Manifests

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/manifest/:manifest_hash` | `Read` | `tenant_id` | `Manifest` (below) |
| GET | `/api/v1/manifest/:manifest_hash/vex` | `Read` | `tenant_id` | OpenVEX document `{@context, @id, author, timestamp, version, statements: [{vulnerability: {name}, timestamp, products: [{@id}], status, justification?, status_notes?}]}`; untriaged findings are exported as `under_investigation` |
| POST | `/api/v1/manifest/:manifest_hash/vex/import` | `Annotate` | `overwrite` (bool), `tenant_id`; multipart with the OpenVEX file | `{applied, skipped_manual, unmatched: [{vuln_id, reason}]}`. Triage set by a person is kept (`skipped_manual`) unless `overwrite=true`; matching is by exact vulnerability id, no CVE↔GHSA aliasing |
| GET | `/api/v1/manifest/:manifest_hash/diff` | `Read` | `against` (manifest hash; default: previous in namespace), `tenant_id` | `{from_manifest_hash, from_version, to_manifest_hash, to_version, added: [Component], removed: [Component], changed: [{name, purl, from_version, to_version}], unchanged_count}` |
| POST | `/api/v1/manifest/:manifest_hash/revoke` | `Annotate` (also `uploader` when `DEV_MODE=true`) | `tenant_id` | **204**; `400` if already revoked. A status flag; nothing leaves the log |
| GET | `/api/v1/manifests/current` | `Read` | `tenant_id` | `[{namespace, domain, version, manifest_hash, sbom_hash, sbom_format, created_at}]`: latest non-revoked manifest per namespace |
| GET | `/api/v1/namespaces/manifests` | `Read` | `namespace` (required), `tenant_id` | `[{manifest_hash, version, created_at, revoked}]`, newest first |

`Manifest` = `{manifest_hash, leaf_seq_id, tenant_id, domain, version,
sbom_hash, sbom_format, sbom_s3_key, namespace, previous_manifest_hash,
signature, dsse_envelope, document_type, created_by, created_at, sbom_hex,
revoked, revoked_at, revoked_by, compliance: [ComplianceReport],
vulnerability_findings: [Finding], dtrack_synced_at, dtrack_push_error,
malicious_components: [...], component_reputation: [...],
license_violations: [...], component_freshness: [...]}`. `Component` =
`{name, version, purl}`.

## Findings, triage and reachability

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/findings` | `Read` | see below | `[FindingWithContext]` |
| POST | `/api/v1/manifest/:manifest_hash/findings/:finding_key/triage` | `Annotate` | `tenant_id`; JSON `{vex_status, justification?, comment?}` | the updated `Finding`. `vex_status` ∈ `affected`, `not_affected`, `fixed`, `under_investigation`; `not_affected` requires an OpenVEX `justification`. Also pushed to Dependency-Track when configured |
| GET | `/api/v1/manifest/:manifest_hash/findings/:finding_key/comments` | `Read` | `tenant_id` | `[{id, author, body, created_at}]` |
| POST | `/api/v1/manifest/:manifest_hash/findings/:finding_key/comments` | `Annotate` | `tenant_id`; JSON `{body}` | the new comment |
| GET | `/api/v1/manifest/:manifest_hash/findings/:finding_key/reachability` | `Read` | `tenant_id` | `Reachability` |
| POST | `/api/v1/manifest/:manifest_hash/findings/:finding_key/reachability` | `Annotate` | `force` (bool), `tenant_id` | `Reachability` (status `queued`); `409` while one is queued/running unless `force=true`; `400` with a reason when blocked, no analyser is configured, or the analyser rejects the request (e.g. a branch that does not exist); `500` when the analyser is unreachable |

**`GET /api/v1/findings` query parameters**

| Parameter | Notes |
|---|---|
| `severity` | one value or comma-separated, case-insensitive (`CRITICAL,HIGH`) |
| `vex_status` | `untriaged`, `affected`, `not_affected`, `fixed`, `under_investigation`; anything else is a `400` |
| `namespace` | exact or segment prefix |
| `release_version` | exact manifest version |
| `manifest_hash` | one manifest |
| `current_only` | latest non-revoked manifest per namespace, honouring the "currently running" visibility setting |
| `hide_stale` | latest non-revoked manifest per namespace, unconditionally |
| `known_source` | only namespaces with a source repository mapped (the ones reachability can run on) |
| `limit` / `offset` | default 50, clamped to 1–500 |
| `tenant_id` | cross-tenant override |

`Finding` = `{finding_key, component_name, component_version,
vulnerability_id, severity, description, analysis_state, vex_status,
vex_justification, vex_comment, triaged_by, triaged_at, triage_source}`.
`FindingWithContext` = `Finding` + `{manifest_hash, domain, namespace,
release_version, revoked, comment_count, reachability_status,
reachability_priority}`, sorted by severity, then vulnerability id.

`Reachability` = `{enabled, blocked_reason, repo_url, subpath, commit,
commit_source, revision, requested_automatically, analysis_id, status,
requested_by, requested_at, report, error}`:

- `enabled` is `false` when no analyser is configured
  (`AISE_REACH_BASE_URL`/`AISE_REACH_TOKEN`).
- `blocked_reason` explains why nothing can run: no repository mapped, no
  commit or revision, or no advisory text yet.
- `commit_source` says which code is scanned:
  - `manifest`: the SBOM's recorded commit
  - `namespace_revision`: the namespace's revision, because the SBOM has no
    commit
  - `revision_override`: the namespace's revision instead of a recorded
    commit (testing override)
- `status` is `queued`, `running`, `completed`, `failed`, `missing` (the
  analyser no longer knows the analysis) or `unavailable` (the analyser is
  unreachable).
- `report` is the analyser's report, passed through unchanged. When the
  analyser is unreachable or has lost the analysis, AISE serves its archived
  copy and says so in `error`.

## Source repositories (reachability configuration)

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/settings/namespace-repos` | `Read` | `tenant_id` | `[NamespaceRepo]`, filtered to the key's scope |
| POST | `/api/v1/settings/namespace-repos` | `ManageSettings` | `tenant_id`; JSON `{namespace, repo_url, subpath?, revision?, auto_analyze?, ignore_source_commit?}` | `NamespaceRepo` (upsert) |
| DELETE | `/api/v1/settings/namespace-repos` | `ManageSettings` | `namespace` (required), `tenant_id` | **204**; `404` if not mapped |

`NamespaceRepo` = `{namespace, repo_url, subpath, revision, auto_analyze,
ignore_source_commit, created_by, updated_at}`. Field rules:

- `repo_url` is `https://` without credentials, or an absolute local path
  (offline demo only).
- `subpath` must be relative, with no `..`.
- `ignore_source_commit` requires `revision`, otherwise the request is a
  `400`.
- `created_by` starting with `magnoliafile:` means the mapping came from an
  upload; a later upload may refresh it. One saved here is never overwritten
  by an upload.

## Search and blast radius

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/search/components` | `Read` | `name` and/or `purl` (one required), `version`, `namespace`, `current_only`, `limit`, `offset`, `tenant_id` | `[{name, version, purl, cpe, is_primary, manifest_hash, domain, namespace, release_version, revoked, document_type, license_expr}]` |
| POST | `/api/v1/search/reindex` | `ManageSettings` | `tenant_id` | `{manifests_indexed, components_indexed}`: backfills the component index |
| GET | `/api/v1/components/affected` | `Read` | `purl` and/or `name` (one required), `version`, `current_only`, `tenant_id` | `[{manifest_hash, domain, namespace, release_version, revoked}]` |
| GET | `/api/v1/vulnerabilities/:vuln_id/affected` | `Read` | `current_only`, `tenant_id` | same shape; matches Dependency-Track findings and OSV `MAL-` ids |

## Background signals

| Method | Path | Permission | Response |
|---|---|---|---|
| POST | `/api/v1/dtrack/sync` | `ManageSettings` (query `tenant_id`) | `{manifests_pushed, projects_refreshed}`: one push + refresh pass for the resolved tenant |
| POST | `/api/v1/reputation/sync` | `ManageSettings` | `{components_processed}`; deployment-wide |
| GET | `/api/v1/reputation/status` | `Read` | `{pending, checked, failed}` |
| GET | `/api/v1/reputation/components` | `ManageTenantData` (query `tenant_id`) | `[{ecosystem, name, scorecard_score, bucket, project_repo, checked_at}]`, ascending score |
| POST | `/api/v1/freshness/sync` | `ManageSettings` | `{components_processed}`; `400` if deps.dev is disabled |
| GET | `/api/v1/freshness/status` | `Read` | `{pending, checked, failed}` |
| POST | `/api/v1/malicious/sync` | `ManageSettings` | `{manifests_processed}` |
| GET | `/api/v1/malicious/status` | `Read` | `{pending, checked}` |
| POST | `/api/v1/tenants/cache/clear` | `ManageTenantData` (query `tenant_id`) | `{component_index_rows, malicious_findings_rows, dtrack_findings_rows, dtrack_projects_rows}`: deletes derived caches only, never manifests or the log |

## Tenant settings

All take query `tenant_id`. Reads need `Read`; writes need `ManageSettings`
and return **204**.

| Path | GET returns | POST body |
|---|---|---|
| `/api/v1/settings/dtrack-sync` | `{disabled}` | `{disabled}` |
| `/api/v1/settings/semver-version` | `{required}` | `{required}` |
| `/api/v1/settings/reputation-sync` | `{disabled}` | `{disabled}` |
| `/api/v1/settings/freshness` | `{disabled}` | `{disabled}` |
| `/api/v1/settings/malicious-check` | `{disabled}` | `{disabled}` |
| `/api/v1/settings/namespace-registration` | `{required}` | `{required}` |
| `/api/v1/settings/license-policy` | `{denied_licenses[], unknown_license_handling, enforce_level}` | same shape; `enforce_level` ∈ `off`, `warn`, `block` |
| `/api/v1/compliance/settings` | `[{profile_id, profile_name, description, enabled, enforce_level}]` | `{profile_id, enabled, enforce_level}` |
| `/api/v1/namespaces/hidden` | `[namespace]` | `{namespace, hidden}` |

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/compliance/profiles` | `Read` | – | `[{id, name, description}]` (NTIA, BSI TR-03183-2) |
| GET | `/api/v1/namespaces/registered` | `Read` | `tenant_id` | `[{namespace, created_by, created_at}]` |
| POST | `/api/v1/namespaces/registered` | `ManageSettings` | `tenant_id`; JSON `{namespace}` | **204**, idempotent |
| DELETE | `/api/v1/namespaces/registered` | `ManageSettings` | `namespace` (required), `tenant_id` | **204**, idempotent |

## Keys, tenants, audit

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/keys` | `ManageKeys` | `tenant_id` | `[{id, tenant_id, domain, namespace_scope, role, expires_at, revoked, created_at}]` |
| POST | `/api/v1/keys` | `ManageKeys` | JSON `{role, namespace_scope? (default "/"), expires_at? (RFC 3339), tenant_id?}` | `{key, key_id, tenant_id, domain, namespace_scope, role, expires_at}`; **`key` is shown only here** |
| POST | `/api/v1/keys/:key_id/revoke` | `ManageKeys` | `tenant_id` | **204**, irreversible |
| GET | `/api/v1/tenants` | `ManageTenants` | – | `[{id, domain, name, created_by, created_at, is_platform}]` |
| POST | `/api/v1/tenants` | `ManageTenants` (platform tenant) | JSON `{domain, name}` | `{tenant, initial_key}`: the tenant plus its first `domain_admin` key |
| DELETE | `/api/v1/tenants/:tenant_id` | super_admin of the platform tenant | – | **204**. Hides the tenant; a hard, cascading delete only with `DEV_MODE=true`. The platform tenant cannot be deleted |
| GET | `/api/v1/audit-logs` | `Read` | `limit` (default 50), `tenant_id` | `[{id, tenant_id, principal, action, resource, result, reason, created_at}]` |

## Webhooks

| Method | Path | Permission | Parameters | Response |
|---|---|---|---|---|
| GET | `/api/v1/webhooks` | `Read` | `tenant_id` | `[{id, url, event_types[], enabled, created_by, created_at}]` |
| POST | `/api/v1/webhooks` | `ManageSettings` | `tenant_id`; JSON `{url, event_types[]}` | `{id, url, event_types, secret}`; **`secret` is shown only here** |
| PATCH | `/api/v1/webhooks/:id` | `ManageSettings` | `tenant_id`; JSON `{url, event_types[], enabled}` | **204** |
| DELETE | `/api/v1/webhooks/:id` | `ManageSettings` | `tenant_id` | **204** |
| POST | `/api/v1/webhooks/:id/test` | `ManageSettings` | `tenant_id` | `{ok, error}` after sending a `webhook.test` event |
| GET | `/api/v1/webhooks/:id/deliveries` | `Read` | `limit`, `tenant_id` | `[{id, event_type, status, attempts, next_attempt_at, last_error, created_at, delivered_at}]` |

Events: `manifest.uploaded`, `manifest.revoked`, `finding.new_critical`,
`malicious.match_found`, `dtrack.push_failed`. Bodies are signed with
HMAC-SHA256 in `X-Aise-Signature`; private, loopback, link-local and
metadata addresses are refused.
