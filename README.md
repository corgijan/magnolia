# Magnolia — Supply-Chain Observability & Transparency

A pragmatic, cryptographically-sound service for software supply-chain observability and transparency, built on a version-accurate, immutable, append-only SBOM archive. EU Cyber Resilience Act (CRA) compliance is one concrete application of it, not the whole purpose.

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
   - API key authentication (SHA-256 hashed at rest)
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
- ✅ API key auth (`mag_<secret>`, SHA-256-hashed secrets, constant-time verify; legacy `<key_id>:<secret>` keys still accepted)
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

All endpoints take `Authorization: Bearer mag_<secret>`. (Keys minted before the format change, of the form `<key_id>:<secret>`, are still accepted — no need to re-issue.)
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

**Basic example** (`sbom.json` is a CycloneDX or SPDX file on disk; the key must belong to a real tenant — the platform/bootstrap tenant is admin-only and rejects uploads):
```bash
curl -X POST http://127.0.0.1:3000/api/v1/upload \
  -H "Authorization: Bearer mag_<secret>" \
  -F "sbom_file=@sbom.json" \
  -F "format=cyclonedx" \
  -F "namespace=/product/v1" \
  -F "version=1.2.3"
```

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
| POST | `/api/v1/manifest/:manifest_hash/findings/:finding_key/triage` | auditor, domain_admin, super_admin | Sets Magnolia's own VEX-status triage (see "Optional: Dependency-Track integration" below) on one cached finding. 400 if `vex_status` isn't one of the four VEX values, or if it's `not_affected` without a `justification`. 404 if the finding no longer exists (e.g. resolved by a later dtrack sync). |
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

### CLI / CI integration

`POST /api/v1/upload` and `POST /api/v1/verify` (the dry-run CI policy gate —
see its own doc comment on `verify_sbom` in handlers.rs) are both wrapped by
a small CLI, served straight from your own Magnolia instance so there's
nothing extra to install or keep in sync — **Python is the default,
recommended way to run it** (stdlib only, nothing to `pip install`; the
original bash version is still served too, for bash-only environments):

```bash
curl -fsSL <tenant_url>/install.py | python3 - --version=2.0.0
curl -fsSL <tenant_url>/install.py | python3 - verify --sbom=out.cdx.json
```

Or save it once and run it locally against a checked-out `Magnoliafile`:

```bash
curl -fsSL <tenant_url>/install.py -o magnolia-upload.py && chmod +x magnolia-upload.py
MAGNOLIA_API_KEY='mag_<secret>' ./magnolia-upload.py verify
```

Same flags, same `Magnoliafile` format, same exit codes as the bash version
below — pick whichever your environment already has:

```bash
curl -fsSL <tenant_url>/install.sh | bash -s -- verify --sbom=out.cdx.json
```

Full flag reference: `./magnolia-upload.py --help` (or `./magnolia-upload.sh
--help`) — both scripts' `--help` is generated from their own source, so
it's always in sync with what they actually do.

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
3. **API key + SHA-256** — Keys hashed at rest, constant-time comparison. Secrets are server-generated with 244 bits of CSPRNG entropy, which is what makes an unsalted fast hash appropriate here (a password KDF defends low-entropy inputs; these cannot be brute-forced at any hash speed). See `ApiKey::hash`
4. **Audit logs (append-only)** — Every action logged immutably
5. **Domain boundaries** — Tenants cannot cross-read data
6. **RBAC matrix** — Principle of least privilege

## Configuration

### Environment Variables

See `.env.example` for the docker-compose-driven equivalent of these (what
to override in a local `.env` file, with generation commands) — this list is
for running `magnolia-server` directly, e.g. via `cargo run`.
```bash
DATABASE_URL=postgres://user:pass@localhost:5432/sbomstash
RUST_LOG=info
SERVER_ADDR=127.0.0.1:3000

# Ensures this exact key exists as a super_admin key on startup (creating
# its tenant if needed). Idempotent — safe to leave set across restarts,
# never overwrites an existing key. This is the only way to get a first key
# into a fresh deployment. Generate one with:
#   cargo run -p magnolia-auth --example bootstrap_key
BOOTSTRAP_SUPER_ADMIN_KEY=mag_<43 base64url chars>
BOOTSTRAP_TENANT_DOMAIN=test.example
BOOTSTRAP_TENANT_NAME=Test Tenant

# Optional, dev/test only: relaxes a small number of RBAC checks for local
# testing convenience. Currently the only thing it affects: an uploader-role
# key can revoke its own manifests (normally that needs auditor/domain_admin/
# super_admin). Never set this in production.
DEV_MODE=true
```

### Local Development Setup

**Quickest path:** generate a bootstrap key, put it in `.env`, then `docker compose up --build`:
```bash
cargo run -p magnolia-auth --example bootstrap_key   # prints a mag_... key
echo 'BOOTSTRAP_SUPER_ADMIN_KEY=mag_...' >> .env     # .env is git-ignored
docker compose up --build
```
The server migrates its own schema on every startup (nobody ever needs to run a `.sql` file by hand — see "Migrations" below) and creates that key as a super_admin on the `BOOTSTRAP_TENANT_DOMAIN` tenant (`test.example` by default), idempotently, on every startup. Paste it into the UI header and skip the manual-bootstrap step entirely.

There is deliberately **no built-in default** — a fallback baked into this repo would be a publicly-known super_admin credential (which is exactly what the old `deadbeef-…` default was). Leaving `BOOTSTRAP_SUPER_ADMIN_KEY` unset simply creates no key at all.

Then just run the frontend natively (step 5 below) — its dev-server proxy already points at `127.0.0.1:3000`.

**Manual path** (run each piece yourself, e.g. with your own Postgres instead of Docker):

1. Start PostgreSQL
```bash
docker run --name magnolia-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=sbomstash \
  -p 5432:5432 \
  -d postgres:15
```

2. (Optional) generate a signing key — the server auto-creates one at startup
```bash
openssl rand -hex 32 > .sbomstash_key
chmod 600 .sbomstash_key
```

3. Run the server, with the same bootstrap env vars the Docker path uses
   (see "Environment Variables" above). This one step replaces the entire
   old manual dance: the server applies every pending migration itself on
   startup (see "Migrations" below — no `.sql` file ever needs to be run by
   hand), then creates `BOOTSTRAP_TENANT_DOMAIN`/`BOOTSTRAP_TENANT_NAME` and
   the `BOOTSTRAP_SUPER_ADMIN_KEY` key if they don't already exist:
```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/sbomstash
export BOOTSTRAP_SUPER_ADMIN_KEY=mag_...   # from `cargo run -p magnolia-auth --example bootstrap_key`
export BOOTSTRAP_TENANT_DOMAIN=acme.example
export BOOTSTRAP_TENANT_NAME="Acme Corp"
cargo run --bin magnolia-server
# listens on 127.0.0.1:3000
```

4. Run the web UI (port 4000, proxies `/api` and `/health` to the server)
```bash
cd frontend && npm install && npm start
# open http://localhost:4000 — paste the BOOTSTRAP_SUPER_ADMIN_KEY value above
```

   From here on, every *other* tenant is self-service: a super_admin calls
   `POST /api/v1/tenants` (or uses the Tenants tab in the UI), which creates
   the tenant and mints its first `domain_admin` key in one step.

### Optional: Dependency-Track integration

Magnolia can optionally push uploaded CycloneDX SBOMs to a self-hosted
[OWASP Dependency-Track](https://dependencytrack.org/) instance and cache its
vulnerability findings, surfaced directly in the SBOM detail view — SBOMs
themselves deliberately carry no vulnerability data (it's dynamic; SBOM
content is static), so this closes that gap. This is **deployment-wide and
env-var-gated, not a per-tenant setting** — an operator either runs a dtrack
instance for the whole deployment or doesn't.

**Not started by a plain `docker compose up`.** Two ways to turn it on:

**Fully automatic (recommended)** — `docker-compose.dtrack.yml` starts
`dtrack-db`/`dependency-track` (no `--profile` flag needed) *and* runs the
one-time bootstrap dtrack itself requires (see below) via a one-shot init
container, writing the resulting API key to a volume `api` reads at its own
startup. Genuinely one command, including on a completely fresh volume,
and safe to re-run (idempotent — reuses an already-bootstrapped password
and an already-minted key rather than redoing either):
```bash
docker compose -f docker-compose.yml -f docker-compose.dtrack.yml up -d
```
If bootstrap ever fails (dtrack slow to start, network hiccup, etc.) it's
logged clearly by the `dtrack-bootstrap` service, but `api` still starts
normally with the integration simply left disabled — dtrack is optional and
must never block Magnolia's own core service from coming up.
`docker-compose.yml` alone (no `-f docker-compose.dtrack.yml`) is completely
unaffected either way — dtrack stays off by default.

**Manual, if you'd rather control it yourself** — start just the containers
via the profile, then run the bootstrap script by hand:
```bash
docker compose --profile dtrack up -d
DTRACK_ADMIN_PASSWORD='pick-one' ./scripts/bootstrap-dtrack.sh
docker compose --profile dtrack up -d api   # pick up the new key
```
Either way, give dtrack a while to finish its first-boot
vulnerability-database sync before expecting real findings.

**What the bootstrap actually does (dtrack itself requires this; verified
there's no env var or config property on dtrack's side to skip it — see
`DTRACK_PLAN.md`'s "Confidence check" section):** dtrack creates a default
`admin`/`admin` account on first boot with a forced password change, and an
API key can only be minted through its own REST API/UI, not pre-provisioned
via env vars. The bootstrap (whether run automatically by
`docker-compose.dtrack.yml` or by hand via the script) changes the
password, grants the `Automation` team the three permissions actually
needed (verified live: `BOM_UPLOAD` alone is **not** enough for
`autoCreate` to work; it also needs `PROJECT_CREATION_UPLOAD`, plus
`VIEW_VULNERABILITY` for findings-read), and generates an API key. In
manual mode the key lands in a local `.env` file (git-ignored) that
`docker-compose.yml` reads via `${DTRACK_API_KEY:-}`; in automatic mode it
lands on a shared volume that `api` reads via `DTRACK_API_KEY_FILE`. Run by
hand, it's safe to re-run with the same `DTRACK_ADMIN_PASSWORD` — it
detects an already-changed password and an already-granted permission and
skips them; pass `--new-key` to mint a fresh API key instead of reusing the
existing one. Until a key is actually wired in, the integration silently
stays disabled (`dtrack_enabled: false` in `GET /api/v1/config`) even with
`dependency-track` running.

**Multi-tenancy caveat:** a single shared dtrack instance has no concept of
Magnolia's tenant boundaries — all tenants' BOMs land in the same dtrack
project list, visible to anyone holding the shared `DTRACK_API_KEY` or
dtrack admin login. Magnolia's own API stays correctly tenant-scoped
(findings are only ever looked up by `manifest_hash`, after the existing
tenant-ownership check), so there's no cross-tenant leak through Magnolia
itself — but dtrack's own admin surface is a shared resource across the
whole deployment.

**VEX-style triage.** Beyond dtrack's own findings, Magnolia lets an
analyst set a VEX status per finding — `affected`, `not_affected`, `fixed`,
or `under_investigation` — with a justification, tracked to who/when. This
is Magnolia's own product-specific exploitability judgment (e.g. "this
vulnerable component isn't reachable in our build"), independent of
dtrack's own generic analysis state — the two can legitimately disagree.
`not_affected` requires a non-empty `justification`; every other status
does not. Every triage action is also recorded in `GET /api/v1/audit-logs`.

```bash
env:
  DTRACK_URL: http://dependency-track:8080   # set automatically in docker-compose.yml
  DTRACK_API_KEY: ""                          # fill in after the bootstrap step above
  DTRACK_SYNC_INTERVAL_SECS: "600"            # optional, defaults to 600
```

### Production / VPS deployment

The compose files ship with insecure defaults so local `docker compose up`
needs zero setup — none of that is safe to leave in place on a host reachable
from the internet.

1. **Set real secrets.** Copy `.env.example` to `.env` and fill in
   `BOOTSTRAP_SUPER_ADMIN_KEY`, `POSTGRES_PASSWORD`, `DEV_MODE=false`, and
   (if you're also enabling Dependency-Track) `DTRACK_DB_PASSWORD` /
   `DTRACK_ADMIN_PASSWORD` — generation commands are in the file itself.
   `.env` is git-ignored; `docker compose` picks it up automatically from
   the same directory as the compose file.

2. **Start everything except the UI** (Magnolia's own frontend, like
   Dependency-Track, is optional and off by default — `profiles:
   ["frontend"]`; not required at all if any other HTTP client, including
   `scripts/magnolia-upload.py` (see "CLI / CI integration" above) or a separately-hosted UI pointed at this
   server via its "Server URL" field, talks to `api` directly):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dtrack.yml up -d --build
   ```
   This brings up `db`, `api`, and the full Dependency-Track stack
   (`dtrack-db`, `dependency-track`, `dtrack-bootstrap`) in one command —
   drop `-f docker-compose.dtrack.yml` if you don't want Dependency-Track at
   all. Either way, only `api` publishes a port (`3000`, or `API_PORT` if
   set in `.env`); `db`, `dtrack-db`, and `dependency-track` are reachable
   solely from other containers on the compose network, never from the host
   or the internet — see the comment at the top of `docker-compose.yml`.

   **To also serve the web UI from this same host**, add `--profile
   frontend` to the command above (nginx, serving the built React app on
   `FRONTEND_PORT`, default `4000` — proxies `/api/` and `/health` to `api`
   internally, no extra config needed):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dtrack.yml --profile frontend up -d --build
   ```

3. **Put a reverse proxy with TLS in front of port 3000.** `api` itself
   serves plain HTTP — API keys go out as bearer tokens, so this matters.
   Any of Caddy, nginx, or Traefik works; Caddy is the least config for a
   single-domain setup (automatic Let's Encrypt, one line: `your-domain.com
   { reverse_proxy localhost:3000 }`). Not included here since the right
   choice depends on what else, if anything, shares this VPS.

4. **Firewall the host** to only 22 (SSH) and 443/80 (your reverse proxy) —
   `ufw allow 22,80,443/tcp` plus a default-deny, or your cloud provider's
   security-group equivalent. Don't rely on the firewall alone to keep `db`
   off the internet, though — Docker's own port-publishing (`ports:` in a
   compose file) creates iptables rules that bypass ufw's rules entirely;
   the actual guarantee here is that `db`/`dtrack-db`/`dependency-track`
   simply have no `ports:` mapping at all, so there's nothing for a firewall
   to need to block in the first place.

5. **Back up `db_data`.** It's a normal named Docker volume — `docker run
   --rm -v aise_db_data:/data -v $PWD:/backup postgres:15 tar czf
   /backup/db_backup.tar.gz -C /data .` (stop `api` first, or use `pg_dump`
   for a live backup instead). `signing_key` (holds the DSSE signing key
   and, if `STORAGE_PATH` stays set, uploaded SBOM bytes) is worth the same
   treatment — losing it doesn't lose the Merkle log's integrity, but it
   does lose the ability to sign new manifests or serve old SBOM content
   until replaced.

### Migrations

The server applies every pending file in `migrations/` itself, on every
startup — via `sqlx::migrate!`, tracked in a `_sqlx_migrations` table so
already-applied ones are never re-run. Nobody should ever need to run
`psql < migrations/....sql` by hand; just start the server. Adding a new
migration is just adding a new `migrations/<timestamp>_<name>.sql` file —
the next server restart picks it up automatically.

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
