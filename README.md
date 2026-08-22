# Magnolia — Compliance SBOM Archive

A pragmatic, cryptographically-sound SBOM archive for EU Cyber Resilience Act (CRA) compliance. Version-accurate, immutable, append-only.

## Quick Start

### Build
```bash
cargo build --release
```

### Run Server
```bash
# Requires: PostgreSQL running, migrations applied
export DATABASE_URL="postgres://user:pass@localhost/sbomstash"
cargo run --bin magnolia-server
# Server listens on http://127.0.0.1:3000
```

### Health Check
```bash
curl http://127.0.0.1:3000/health
```

## Architecture Overview

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for deep dive.

**Three core systems:**

1. **Cryptographic Core** (`crates/core/`)
   - Merkle Mountain Range (append-only tree)
   - Signed Tree Heads (STH)
   - Hash-chained manifests

2. **Multi-Tenancy & RBAC** (`crates/auth/`)
   - Domain-scoped namespaces, one tenant per domain, full data isolation between tenants
   - API key authentication (Argon2-hashed)
   - RBAC matrix:
     - `super_admin` — everything in its own tenant, plus can create other tenants (`ManageTenants` is platform-level, not domain-scoped)
     - `domain_admin` — full self-service over its own tenant: upload, read/download, manage its own keys/ACLs. Minted automatically as a new tenant's first key. Cannot create other tenants.
     - `uploader` — upload only (e.g. a CI pipeline that should only push, never browse)
     - `auditor` — read/annotate only, scoped strictly to its own tenant — other tenants are invisible, not just inaccessible
   - **The platform tenant**: exactly one tenant is flagged `is_platform` (the `BOOTSTRAP_SUPER_ADMIN_KEY` tenant — never settable via the public API). Only a `super_admin` key belonging to *that* tenant can pass `?tenant_id=<uuid>` to act on another tenant's data/keys (see/manage all tenants). A `super_admin` key self-minted by any other tenant's `domain_admin` is still only as powerful as `domain_admin` within its own tenant — it does **not** gain cross-tenant reach just from the role name, which would otherwise be a privilege-escalation path.

3. **Storage & Signing** (`crates/storage/`, `crates/signer/`)
   - ObjectStore trait (S3 + in-memory test impl)
   - Signer trait (local file MVP, Vault/KMS future)

## Project Structure

```
magnolia/
├── crates/
│   ├── api/           # Axum HTTP layer, auth extractor, handlers, server binary
│   ├── core/          # Merkle Mountain Range, manifests, proofs
│   ├── auth/          # API key, RBAC, multi-tenancy
│   ├── signer/        # Signing trait + local file impl
│   ├── storage/       # ObjectStore trait + in-memory impl
│   ├── db/            # PostgreSQL models, queries
│   └── audit/         # Append-only audit logs
├── frontend/          # React (TypeScript) web UI
├── migrations/        # SQL schema (manual for MVP)
├── ARCHITECTURE.md    # Full architecture doc
└── Features.md, tech.md # Requirements
```

The server binary is `crates/api/src/main.rs` (`cargo run --bin magnolia-server`).

## MVP Status

**Working (tested):**
- ✅ Merkle Mountain Range with correct inclusion + consistency proofs (17 unit tests)
- ✅ API key auth (`<key_id>:<secret>`, Argon2-hashed secrets, timing-safe verify)
- ✅ RBAC matrix enforcement incl. namespace prefix-scope boundary check (14 unit tests)
- ✅ **Tenants are a real entity** (`tenants` table, one row per domain) — `POST /api/v1/tenants` (super_admin only) creates a tenant *and* mints its first `domain_admin` key in one call
- ✅ **Full per-tenant data isolation**: each tenant has its own Merkle tree / signed-tree-head chain; leaves, tree-head, proofs, manifests, keys, and audit log are all scoped to the caller's tenant — nothing is shared or visible across tenants
- ✅ `POST /api/v1/upload` — full ingest: validate → store → MMR insert → STH sign → DB commit → manifest chain → audit
- ✅ Proof endpoints (inclusion, consistency) with client-side verification in the web UI
- ✅ Signed Tree Head history (`/api/v1/tree-head/latest`, `/api/v1/tree-head/:size`), per tenant
- ✅ API key provisioning (`POST /api/v1/keys`) for your own tenant — key shown once, key listing, audit log endpoint
- ✅ React web UI: dashboard, upload (with version), leaves (namespace-filtered), manifest lookup with a real SBOM artifact viewer (pretty-printed, component/package summary, local file download), proof verification + local JSON download, key management (create/revoke), tenant management, audit — nav only ever shows tabs your key's role is actually allowed to use, your tenant/role/namespace scope is shown at the top, and the platform super_admin gets a tenant selector to act on any other tenant
- ✅ Server rebuilds each tenant's in-memory MMR from `merkle_leaves` on startup
- ✅ Trait-based signer (LocalFileSigner) and storage (InMemoryStore)

**Remaining for production:**
1. S3 storage integration — replace InMemoryStore with S3Store (Object Lock WORM)
2. KMS signer — replace LocalFileSigner with VaultSigner or AwsKmsSigner
3. Full SBOM schema validation (CycloneDX/SPDX), currently structural JSON checks
4. PostgreSQL RLS per tenant, TLS, rate limiting, metrics

## API (v1)

All endpoints take `Authorization: Bearer <key_id>:<secret>`.
API keys are created via `POST /api/v1/keys` (the full key is shown once, for
*your own* tenant — you cannot mint a key for anyone else's).

### Upload SBOM
```http
POST /api/v1/upload
Authorization: Bearer <api_key>
Content-Type: multipart/form-data

sbom_file=<binary>  format=cyclonedx|spdx  namespace=/product/v1  version=1.2.3
```
`version` is required — a free-text label for the SBOM/product release it describes (e.g. `1.2.3`), stored on the manifest. `namespace` must fall within the key's own `namespace_scope` (segment-aware prefix match; `/` covers everything).

Response:
```json
{
  "sbom_hash": "sha256 hex of the SBOM bytes",
  "manifest_hash": "sha256 hex of the signed manifest",
  "version": "1.2.3",
  "namespace": "/product/v1",
  "domain": "acme.example",
  "tree_size": 42,
  "leaf_index": 41,
  "leaf_seq_id": 42,
  "signed_tree_head": {
    "tree_size": 42,
    "root_hash": "hex",
    "signature": "hex",
    "frontier": ["hex", "..."],
    "created_at": "2026-08-21T10:00:00Z",
    "signature_verified": true
  }
}
```

### Other endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/v1/whoami` | any valid key | Confirms your key is authenticated (not revoked/expired) and returns its role/domain/namespace_scope — no RBAC action required |
| GET | `/api/v1/tree-head/latest` | auditor, domain_admin, super_admin | Latest Signed Tree Head (signature verified server-side) |
| GET | `/api/v1/tree-head/:tree_size` | auditor, domain_admin, super_admin | Historical STH at a given tree size |
| GET | `/api/v1/proof/inclusion/:leaf_index` | auditor, domain_admin, super_admin | MMR inclusion proof for a leaf |
| GET | `/api/v1/proof/consistency/:old/:new` | auditor, domain_admin, super_admin | MMR consistency proof (`new` must equal current size) |
| GET | `/api/v1/leaves?limit=&offset=` | auditor, domain_admin, super_admin | Recent leaves for your tenant, filtered to your key's `namespace_scope` (newest first) |
| GET | `/api/v1/manifest/:manifest_hash` | auditor, domain_admin, super_admin | Manifest record + SBOM content (hex) — 404 if it belongs to another tenant or is outside your `namespace_scope` |
| POST | `/api/v1/manifest/:manifest_hash/revoke` | auditor, domain_admin, super_admin (+ uploader if `DEV_MODE=true`) | Marks a manifest revoked — a status flag, not a delete; nothing is removed from the log or the Merkle tree. 400 if already revoked. |
| POST | `/api/v1/keys` | domain_admin, super_admin | Create a key for your own tenant (key shown once) |
| GET | `/api/v1/keys` | domain_admin, super_admin | List keys for your tenant |
| POST | `/api/v1/keys/:key_id/revoke` | domain_admin, super_admin | Revoke a key belonging to your own tenant (irreversible) |
| POST | `/api/v1/tenants` | super_admin only | Create a tenant + mint its first `domain_admin` key (key shown once) |
| GET | `/api/v1/tenants` | super_admin only | List all tenants |
| GET | `/api/v1/audit-logs?limit=` | auditor, domain_admin, super_admin | Audit entries for your tenant |

All of the above (except `whoami`, `POST /api/v1/tenants`, `GET /api/v1/tenants`, and upload) accept an optional `?tenant_id=<uuid>` (or `tenant_id` in the JSON body for `POST /api/v1/keys`) to act on another tenant instead of your own — honored **only** for a `super_admin` key belonging to the platform tenant; everyone else gets 403.

Inclusion proof response (hashes are hex strings):
```json
{
  "leaf_index": 41,
  "tree_size": 42,
  "peak_index": 1,
  "peaks": ["hex", "..."],
  "sibling_path": [{"hash": "hex", "sibling_is_left": true}]
}
```
Verification: hash the leaf up `sibling_path` (must match `peaks[peak_index]`),
then fold `peaks` left to right to obtain the tree root.

## Design Philosophy: Pragmatic MVP

**Chosen: Direct WORM (Path B)**
- Upload SBOM directly to S3 with Object Lock
- Commit to DB immediately
- Accept "orphans" (zombie files if DB crashes) as negligible cost
- Justification: SBOMs small; S3 orphan costs (fractions of cents/year) << complexity of 3-phase recovery

**Why not Path A (3-Phase)?**
- More failure modes (staging, pending_lock, finalized states)
- Self-healing background worker adds complexity
- Requires outbox pattern or distributed transactions
- Simpler code > theoretical perfection in MVP

## Security Model

1. **S3 Object Lock (WORM)** — Once locked, files immutable
2. **Merkle-tree tamper-evidence** — Changing any SBOM changes root, signature breaks
3. **API key + Argon2** — Keys hashed at rest, timing-safe comparison
4. **Audit logs (append-only)** — Every action logged immutably
5. **Domain boundaries** — Tenants cannot cross-read data
6. **RBAC matrix** — Principle of least privilege

## Configuration

### Environment Variables
```bash
DATABASE_URL=postgres://user:pass@localhost:5432/sbomstash
RUST_LOG=info
SERVER_ADDR=127.0.0.1:3000

# Optional, dev/test only: ensures this exact <key_id>:<secret> exists as a
# super_admin key on startup (creating its tenant if needed). Idempotent —
# safe to leave set across restarts, never overwrites an existing key.
# Unset (or change to your own value) for anything beyond local testing.
BOOTSTRAP_SUPER_ADMIN_KEY=deadbeef-dead-dead-dead-deadbeefdead:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
BOOTSTRAP_TENANT_DOMAIN=test.example
BOOTSTRAP_TENANT_NAME=Test Tenant

# Optional, dev/test only: relaxes a small number of RBAC checks for local
# testing convenience. Currently the only thing it affects: an uploader-role
# key can revoke its own manifests (normally that needs auditor/domain_admin/
# super_admin). Never set this in production.
DEV_MODE=true
```

### Local Development Setup

**Quickest path:** `docker compose up --build` starts Postgres (with all migrations auto-applied via `docker-entrypoint-initdb.d`) and the API server on `127.0.0.1:3000` — and, out of the box, also **bootstraps a ready-to-use super_admin key** via the `BOOTSTRAP_SUPER_ADMIN_KEY` env var in `docker-compose.yml`:
```
deadbeef-dead-dead-dead-deadbeefdead:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```
That's a tenant on `test.example` (from `BOOTSTRAP_TENANT_DOMAIN`), created idempotently on every startup — safe to leave in place across restarts. Paste that key straight into the UI header and skip the manual-bootstrap step entirely. **Change or remove it before anything beyond local testing** — it's a well-known, publicly documented key.

Then just run the frontend natively (step 5 below) — its dev-server proxy already points at `127.0.0.1:3000`.

**Manual path** (run each piece yourself, or if you'd rather bootstrap your own key/domain instead of the built-in `deadbeef` one):

**Manual path** (run each piece yourself):

1. Start PostgreSQL
```bash
docker run --name magnolia-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=sbomstash \
  -p 5432:5432 \
  -d postgres:15
```

2. Run schema (all six migrations, in order)
```bash
psql -h localhost -U postgres -d sbomstash < migrations/20240821000000_initial_schema.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260821000001_manifests.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000001_tenants.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000002_versions_and_namespace_scoping.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000003_platform_tenant.sql
psql -h localhost -U postgres -d sbomstash < migrations/20260822000004_manifest_revocation.sql
```

3. (Optional) generate a signing key — the server auto-creates one at startup
```bash
openssl rand -hex 32 > .sbomstash_key
chmod 600 .sbomstash_key
```

4. Run server (listens on 127.0.0.1:3000)
```bash
cargo run --bin magnolia-server
```

5. Run the web UI (port 4000, proxies `/api` and `/health` to the server)
```bash
cd frontend && npm install && npm start
# open http://localhost:4000
```

6. Bootstrap your first tenant + super_admin key, then use the key in the
   UI header. There's no admin key yet for the very first tenant, so create
   one directly. Generate a key_id/secret/hash triple:
```bash
cargo run -p magnolia-auth --example bootstrap_key
# prints key_id=..., full_key=..., argon2_hash=...
```
   Then insert the tenant and its key (replace the UUID/domain/hash with
   your generated values):
```sql
INSERT INTO tenants (id, domain, name, created_by, created_at)
VALUES ('22222222-2222-4222-8222-222222222222', 'acme.example', 'Acme Corp', 'bootstrap', NOW());

INSERT INTO api_keys (id, tenant_id, domain, namespace_scope, role, key_hash, revoked)
VALUES (
  '<key_id from bootstrap_key>',
  '22222222-2222-4222-8222-222222222222',  -- must match the tenant row above
  'acme.example',                           -- must match the tenant's domain
  '/',                                      -- namespace scope
  'super_admin',
  '<argon2_hash from bootstrap_key>',
  FALSE
);
-- API key = "<key_id>:<secret>" (the full_key printed by bootstrap_key)
```
   From here on, every *other* tenant is self-service: a super_admin calls
   `POST /api/v1/tenants` (or uses the Tenants tab in the UI), which creates
   the tenant and mints its first `domain_admin` key in one step — no more
   manual SQL. Each tenant only ever sees its own data (leaves, tree head,
   proofs, manifests, keys, audit log); `tenant_id` in `api_keys` is a real
   foreign key into `tenants` now, not a free-typed UUID.

## Testing

```bash
# Unit tests (merkle proofs, RBAC, API keys)
cargo test --all

# Check compilation
cargo check --all --bins

# Frontend
cd frontend && npm test && npm run build
```

The merkle suite verifies that every leaf in trees of size 1..48 produces a
verifiable inclusion proof, that tampered/rewritten/reordered leaves break
existing proofs, and that consistency proofs reject rewrites and reorders.

## Deployments

### Production Readiness

Before production, migrate:

1. **Signer:** LocalFileSigner → VaultSigner (or AwsKmsSigner)
   - Private key never leaves HSM/Vault
   - Audit logging of all sign operations

2. **Storage:** InMemoryStore → S3Store
   - Object Lock (Compliance mode)
   - Lifecycle rules for staging cleanup

3. **Database:** Add row-level security (RLS) for multi-tenancy

4. **Security:** TLS (HTTPS), mutual TLS for integrations, API rate limiting

5. **Observability:** Prometheus metrics, structured JSON logging, trace correlation IDs

See [ARCHITECTURE.md](./ARCHITECTURE.md) for full production checklist.

## Contributing

### Code Style
- Rust 2021 edition, clippy clean
- Trait-based design (pluggable implementations)
- Error types use `thiserror`
- Async/await throughout (tokio)

### Adding a Feature

1. Update ARCHITECTURE.md
2. Write trait interface (if pluggable)
3. Implement in appropriate crate
4. Add tests
5. Update API docs

## License

TBD

## References

- [RFC 6962 — Certificate Transparency Logs](https://tools.ietf.org/html/rfc6962)
- [Merkle Mountain Ranges](https://docs.grin.mw/wiki/chain/merkle_tree/)
- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/library/cyber-resilience-act)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)

---

**Status:** MVP — full ingest pipeline, proofs, web UI (S3 + KMS still ahead)
**Version:** 0.3.0
**Last Updated:** 2026-08-22
