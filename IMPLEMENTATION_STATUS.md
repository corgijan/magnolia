# sbomStash — Current Status

**Last verified: 2026-08-22 — `cargo test --all` green (33 tests), `cargo check --all --bins` clean, frontend `tsc` + production build passing. Full tenant-isolation flow verified end-to-end against a fresh Postgres via `docker-compose` (create tenant → mint keys → upload → cross-tenant reads correctly blocked → restart → trees rebuild correctly). domain_admin self-service, `BOOTSTRAP_SUPER_ADMIN_KEY` bootstrap, required upload `version`, namespace-scoped key isolation (upload/leaves/manifest), and key revocation all verified live against the running compose stack.**

## What's Built

### Tenants & isolation (new)
- **`tenants` table**: one row per domain (domain is unique — a tenant *is* a domain). `api_keys`, `merkle_leaves`, `manifests`, `audit_logs` all have a real FK into it now (previously `tenant_id` was a free-typed UUID with no registry backing it).
- **Each tenant has its own Merkle tree and signed-tree-head chain.** `AppState.trees` is `HashMap<tenant_id, MerkleTree>` instead of one global tree; `signed_tree_heads`' primary key is now `(tenant_id, tree_size)`. Leaves, tree-head, inclusion/consistency proofs, and manifest/SBOM content are all scoped to the caller's own tenant — nothing is visible or inferable across tenants.
- **`manifest` fetch-by-hash is now ownership-checked** — this closed a real gap: previously any authenticated Read-capable key could fetch *any* tenant's raw SBOM content by guessing/knowing its manifest hash. Now returns 404 (not 403) for another tenant's manifest, so existence isn't leaked either.
- **`POST /api/v1/tenants`** (super_admin only, via a new `Action::ManageTenants` that bypasses domain-scoping since there's no existing domain to scope it to) creates a tenant and mints its first `domain_admin` key in the same call — no more manual SQL to bootstrap a new tenant.

### Cryptographic core (`sbomstash-core`)
- **Merkle Mountain Range** (`crates/core/src/merkle.rs`)
  - O(log N) append, frontier stored compactly, full node sequence kept in memory for proof generation
  - **Inclusion proofs** per leaf (sibling path up to its peak + all peaks); verification is a plain hash fold
  - **Consistency proofs** (old size → current size): every old peak is proven an ancestor of the new tree; rejects leaf rewrites and reordering
  - Peaks are folded left-to-right by leaf range (descending level), domain-separated SHA-256 (`0x00` leaf / `0x01` node prefixes)
  - Server restart rebuilds each tenant's tree by replaying `merkle_leaves.leaf_hash`, grouped by `tenant_id`
- **Signed Tree Head**: canonical payload = `tree_size (8B BE) || root_hash`, signed by the pluggable Signer, per tenant
- **Manifest**: per-tenant hash chain (`previous_manifest_hash`), signed, stored in `manifests`

### Auth & RBAC (`sbomstash-auth`)
- API keys `<key_id>:<secret>`: public UUID for lookup, Argon2 hash of the secret at rest
- RBAC matrix (super_admin / domain_admin / uploader / auditor) with domain + namespace-scope enforcement
- **Fix:** namespace scope matching is segment-aware (`/p1` does NOT cover `/p10`)
- **Fix:** a revoked or expired key is now rejected at auth-extraction time, for every endpoint — previously it only got denied later, per RBAC action
- **New:** `Action::ManageTenants` — checks role only (super_admin), skips domain/namespace scoping since tenant creation is platform-level
- **Changed:** `domain_admin` now has full self-service over its own tenant (Upload, Read, Annotate, ManageKeys, ManageAcls) — previously it could only manage keys, meaning a fresh tenant's own admin key couldn't upload or read anything. The only thing it still can't do is create other tenants.
- **Fix:** `namespace_in_scope("/anything", "/")` used to return `false` — a root-scoped (`"/"`) key could only ever act on the literal namespace `"/"`, not any sub-namespace, because the segment-prefix rule (`scope + "/"`) degenerates to `"//"` when `scope == "/"`, which no normalized namespace starts with. Root scope now explicitly means "everything." This is now a public helper, `sbomstash_auth::namespace_in_scope`, reused by both RBAC enforcement and the namespace-filtered leaf/manifest queries below.
- **New:** key revocation is tenant-scoped at the DB layer (`revoke_api_key(tenant_id, key_id)` — `UPDATE ... WHERE id = $1 AND tenant_id = $2`), so a key can only ever be revoked by (an admin of) its own tenant.

### Namespace scoping now actually restricts reads, not just uploads
Previously a namespace-scoped key (e.g. `namespace_scope: "/product/v1"`) could still see *every* leaf and manifest in its tenant via `GET /api/v1/leaves` and `GET /api/v1/manifest/:hash` — only `Upload` checked the namespace. Now:
- `merkle_leaves` has a `namespace` column (denormalized from its manifest at insert time); `list_merkle_leaves` filters by the caller's `namespace_scope` in SQL (segment-aware, via `starts_with()`, `/` = everything) so pagination stays correct.
- `manifest` fetch-by-hash checks `namespace_in_scope` in addition to the tenant check — 404 (not 403) if the manifest is outside the key's namespace scope, for the same anti-enumeration reason as the tenant check.
- **Deliberately not namespace-scoped:** the Merkle tree/tree-head/inclusion-consistency-proof endpoints. These are structurally per-tenant (one shared MMR per tenant, spanning all its namespaces) — sub-scoping proofs by namespace would require per-namespace trees, a much bigger change. A namespace-scoped key can still see the tenant's overall STH and can still request/verify an inclusion proof for any leaf index in the tenant; it just can't list or fetch the *content* of leaves/manifests outside its scope. This mirrors CT-log transparency semantics (the log structure is visible; the documents behind it are access-controlled).

### SBOM/manifest version
`Manifest.version` existed in the core struct but was hardcoded to `"1.0"` and never persisted. Now it's a required multipart field on upload (`BadRequest` if missing/empty), persisted in a new `manifests.version` column, included in the manifest's signed payload, and returned by both the upload response and manifest lookup.

### Server startup / dev bootstrap
- `BOOTSTRAP_SUPER_ADMIN_KEY=<key_id>:<secret>` env var (optional): on startup, ensures that exact key exists as a super_admin key, creating its tenant from `BOOTSTRAP_TENANT_DOMAIN`/`BOOTSTRAP_TENANT_NAME` if needed. Idempotent (checks `key_id` first, never overwrites). `docker-compose.yml` sets this to a well-known `deadbeef-...` example so `docker compose up` is immediately usable — verified across two consecutive restarts (creates once, skips on the second).

### API (`sbomstash-api`, binary `sbomstash-server`)
| Endpoint | Notes |
|---|---|
| `GET /api/v1/whoami` | authenticated-only (no RBAC action) — role/domain/namespace_scope for the calling key |
| `POST /api/v1/upload` | multipart (sbom_file, format, namespace, **version** — required) → validate → storage → MMR insert → STH sign → leaf/STH/manifest DB rows → audit |
| `GET /api/v1/tree-head/latest` | signature verified server-side before responding |
| `GET /api/v1/tree-head/:tree_size` | historical STH |
| `GET /api/v1/proof/inclusion/:leaf_index` | MMR inclusion proof |
| `GET /api/v1/proof/consistency/:old/:new` | `new` must equal current tree size |
| `GET /api/v1/leaves?limit=&offset=` | newest first, your tenant **and namespace_scope** only |
| `GET /api/v1/manifest/:manifest_hash` | manifest + SBOM content (hex); 404 if another tenant's or outside your namespace_scope |
| `POST /api/v1/keys` | create key for your own tenant (derived from your auth, not request body); full key returned once |
| `GET /api/v1/keys` | list keys for your tenant (no hashes) |
| `POST /api/v1/keys/:key_id/revoke` | revoke a key belonging to your own tenant → 204; 404 if not found/not yours |
| `POST /api/v1/tenants` | super_admin only — create tenant + mint its first domain_admin key |
| `GET /api/v1/tenants` | super_admin only — list all tenants |
| `GET /api/v1/audit-logs?limit=` | per-tenant audit trail |

- CORS enabled for the dev web UI; all actions (success and failure) written to the in-memory logger and `audit_logs`

### Frontend (`frontend/`, React + TypeScript, port 4000, CRA proxy → :3000)
- **Nav only shows tabs the current key's role is actually allowed to use** — a client-side mirror of the backend RBAC matrix (`ROLE_ACTIONS` in `App.tsx`) filters `TABS` and double-guards each tab's rendered content, not just the nav buttons. Falls back to the first allowed tab if the current one becomes disallowed (e.g. after logging in with a different-role key).
- Header shows the current key's tenant domain, role, and namespace scope at all times (`.tenant-badge`), plus a Log out button (clears the key, drops back to the connection-status gate).
- Dashboard: latest STH, signature-verified badge, frontier peaks
- Upload: file + format + namespace + **version** (required), result shows version/domain/namespace plus leaf index/hashes
- Leaves: table of recent leaves (own tenant + namespace scope only), now shows each leaf's namespace
- **Manifest Lookup**: paste a manifest_hash → shows version, domain, namespace, format, previous_manifest_hash, created_by/at
- **Proofs**: inclusion + consistency with in-browser verification (Web Crypto SHA-256 port of the Rust verifier), plus a **Download JSON** button to save the fetched proof locally
- API Keys: create (role + namespace scope + optional expiry) + list, with a persistent copy-to-clipboard reveal for the new key, and a **Revoke** button per key (confirmation prompt, tenant-scoped on the backend)
- Tenants: create (domain + name, super_admin only) + list, reveals the new tenant's first key
- Audit Log: per-tenant trail

## Tests

```bash
cargo test --all    # 33 tests
```
- merkle (17): every-leaf verification for sizes 1..48, tamper detection,
  rewrite/reorder rejection for consistency proofs, JSON roundtrip,
  rebuild-from-leaf-hashes equivalence, invalid-input rejection
- auth (16): RBAC matrix per spec, revocation, expiration, domain mismatch,
  namespace prefix boundary (incl. the root-scope fix), key generation/hash/verify
  roundtrips, ManageTenants requires super_admin and ignores domain scoping

## Remaining (production path)
1. `S3Store` with Object Lock (WORM) to replace `InMemoryStore`
2. `VaultSigner` / `AwsKmsSigner` to replace `LocalFileSigner`
3. Full CycloneDX/SPDX schema validation (currently structural JSON checks)
4. PostgreSQL RLS per tenant, TLS, rate limiting, metrics, graceful shutdown

## Migrations
```bash
psql -h localhost -U postgres -d sbomstash < migrations/20240821000000_initial_schema.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260821000001_manifests.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000001_tenants.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000002_versions_and_namespace_scoping.sql
```
The third migration is schema-breaking (`signed_tree_heads` is rebuilt with a
new per-tenant primary key) — apply it to a fresh database; there's no
migration-rollback tooling yet. The fourth is additive (`ALTER TABLE ... ADD
COLUMN ... DEFAULT ...`) and safe to run against an existing database —
note that Postgres only runs `docker-entrypoint-initdb.d` scripts against a
*fresh* volume, so an already-initialized `docker compose` DB volume needs
this one applied by hand (`docker exec -i <db-container> psql -U postgres -d
sbomstash < migrations/20260822000002_versions_and_namespace_scoping.sql`).