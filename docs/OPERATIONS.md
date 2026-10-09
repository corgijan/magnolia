# Operations guide

Setup and operating detail that the [README](../README.md) only summarises.
Moved here unchanged from the README on 2026-10-03, except where noted.

## Contents

- [Manual local setup](#manual-local-setup)
- [Dependency-Track integration](#dependency-track-integration)
- [Production / VPS deployment](#production--vps-deployment)
- [Migrations](#migrations)
- [Production readiness](#production-readiness)
- [Storage design (target)](#storage-design-target)
- [Contributing](#contributing)

## Manual local setup

Run each piece yourself, e.g. with your own Postgres instead of Docker:

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

## Dependency-Track integration

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

**`./scripts/stack-up.sh`** uses the fully automatic path above by default
(pass `--no-dtrack` to leave Dependency-Track out) and reports whether the
integration came up. The manual `bootstrap-dtrack.sh` path needs Dependency-Track
reachable from the host (`DTRACK_URL`, or `--url=`); in the default compose
setup it publishes no host port, so run the script with
`docker-compose.dev.yml`, which maps it to `127.0.0.1:8081`.

## Production / VPS deployment

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

## Migrations

The server applies every pending file in `migrations/` itself, on every
startup — via `sqlx::migrate!`, tracked in a `_sqlx_migrations` table so
already-applied ones are never re-run. Nobody should ever need to run
`psql < migrations/....sql` by hand; just start the server. Adding a new
migration is just adding a new `migrations/<timestamp>_<name>.sql` file —
the next server restart picks it up automatically.

## Production readiness

Before production, migrate:

1. **Signer:** LocalFileSigner → VaultSigner (or AwsKmsSigner)
   - Private key never leaves HSM/Vault
   - Audit logging of all sign operations

2. **Storage:** FileStore → S3Store
   - Object Lock (Compliance mode)
   - Lifecycle rules for staging cleanup

3. **Database:** Add row-level security (RLS) for multi-tenancy

4. **Security:** TLS (HTTPS), mutual TLS for integrations, API rate limiting

5. **Observability:** Prometheus metrics, structured JSON logging, trace correlation IDs

See [ARCHITECTURE.md](../ARCHITECTURE.md) for full production checklist.

## Storage design (target)

The intended storage design. **Not implemented**: SBOM bytes are written to
`FileStore` today; see ARCHITECTURE.md → Object storage.

**Chosen: Direct WORM (Path B)** — the target design. Today the bytes go to
`FileStore` (a plain volume, not WORM); the S3 backend is not implemented yet.
- Upload SBOM directly to S3 with Object Lock
- Commit to DB immediately
- Accept "orphans" (zombie files if DB crashes) as negligible cost
- Justification: SBOMs small; S3 orphan costs (fractions of cents/year) << complexity of 3-phase recovery

**Why not Path A (3-Phase)?**
- More failure modes (staging, pending_lock, finalized states)
- Self-healing background worker adds complexity
- Requires outbox pattern or distributed transactions
- Simpler code > theoretical perfection in MVP

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
