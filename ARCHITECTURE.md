# Magnolia Architecture

## Overview

Magnolia is a compliance-focused SBOM archive implementing a pragmatic approach to immutable, append-only storage with cryptographic tamper-evidence. It bridges operational vulnerability analysis (e.g., Dependency-Track) and legally-required WORM archival under EU Cyber Resilience Act (CRA).

## Design Philosophy

**Pragmatic MVP approach:**
- Direct WORM: Upload SBOM to S3 with Object Lock enabled immediately
- Atomic DB commit follows storage
- Accept "orphans" (zombie files in S3 if DB crashes) as negligible cost vs. complexity
- Justification: SBOMs are small; S3 orphan costs (fractions of cents/year) outweigh simpler, more reliable codebase

## System Architecture

### Core Layers

#### 1. **magnolia-core** — Cryptographic Core
- **Merkle Mountain Range**: Append-only tree structure for tamper-evidence
  - O(1) memory / O(log N) time for insertions
  - Frontier array stored compactly in DB (max 32 entries ≈ 1 KB)
- **Signed Tree Head (STH)**: Timestamped, KMS-signed commitment of tree state
- **Manifest Versioning**: Hash-chained manifests (each refs `previous_manifest_sha256`)
  - Republishing a version creates a new revision; old revisions remain immutable

**Key exports:**
- `MerkleTree` — maintains frontier, root hash; O(log N) append
- `SignedTreeHead` — immutable, signed tree state
- `Manifest` — SBOM metadata with hash chaining
- `InclusionProof`, `ConsistencyProof` — cryptographic audit evidence

#### 2. **magnolia-signer** — Pluggable Signing

**Trait-based design** (swap implementations):
```rust
pub trait Signer: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
}
```

**MVP Implementation: LocalFileSigner**
- Private key stored locally (filesystem)
- HMAC-SHA256 signing via local key
- Used for initial development; upgrade to Vault/KMS before production

**Future implementations (pluggable):**
- `VaultSigner` — HashiCorp Vault Transit
- `AwsKmsSigner` — AWS KMS
- `Pkcs11Signer` — Hardware security modules

#### 3. **magnolia-storage** — Object Store Abstraction

**Trait-based design**:
```rust
pub trait ObjectStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn delete(&self, key: &str) -> Result<()>;
}
```

**MVP Implementation: InMemoryStore**
- Hashmap-backed for testing
- Full transactional semantics

**Future implementations:**
- `S3Store` — AWS S3 with Object Lock (WORM)
- `GcsStore` — Google Cloud Storage
- `AzureStore` — Azure Blob Storage

#### 4. **magnolia-auth** — Multi-Tenancy & RBAC

**Components:**
- **ApiKey**: Generated once, displayed once, never stored in plaintext
- **ApiKeyHash**: SHA-256 hash of the key, stored in DB with a `sha256:` scheme prefix
- **ApiKeyVerifier**: Constant-time comparison; dispatches on the stored prefix, so pre-migration `$argon2` rows still verify
- **Grant**: `(api_key_hash → domain, namespace_scope, role, expires_at, revoked_flag)`
- **RbacEngine**: Central RBAC matrix enforcement

**RBAC Matrix**:
| Role | Upload | Read | Annotate | Manage Keys | Manage ACLs |
|---|---|---|---|---|---|
| `super_admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `domain_admin` | ✗ | ✗ | ✗ | ✓ | ✓ |
| `uploader` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `auditor` | ✗ | ✓ | ✓ | ✗ | ✗ |

**Multi-Tenancy:**
- Domain as tenant boundary (e.g., `acme-corp/...`)
- Hierarchical namespaces (e.g., `/product/v1`, `/product/v1/sub`)
- Prefix-based scope inheritance: `/p1` scope covers `/p1/sub1`, `/p1/sub2`
- Normalized to lowercase, no leading/double slashes, no `..`

#### 5. **magnolia-db** — PostgreSQL Data Layer

**Schema** (append-only, normalized):

**signed_tree_heads** — History of tree states
```sql
tree_size BIGINT PRIMARY KEY,       -- Tree commit number
root_hash BYTEA,                     -- Root of MMR
signature BYTEA,                     -- KMS signature
frontier BYTEA[],                    -- Frontier array (max 32 entries)
created_at TIMESTAMPTZ
```

**merkle_leaves** — Append-only log of SBOMs
```sql
seq_id BIGSERIAL PRIMARY KEY,
tenant_id UUID,
sbom_s3_key VARCHAR(255),
leaf_hash BYTEA,
status VARCHAR(50),                  -- 'pending_lock' | 'locked'
created_at TIMESTAMPTZ
```

**merkle_nodes** — Cache for O(1) proof generation
```sql
level INT, index BIGINT PRIMARY KEY,
hash BYTEA
```

**audit_logs** — Append-only audit trail
```sql
id UUID PRIMARY KEY,
tenant_id UUID,
principal VARCHAR(255),              -- "user@domain" or API key fingerprint
action VARCHAR(255),                 -- 'upload', 'read', 'annotate', etc.
resource VARCHAR(255),               -- SBOM hash or manifest ID
result VARCHAR(50),                  -- 'success' | 'failure'
reason TEXT,                         -- Why (esp. for super_admin actions)
created_at TIMESTAMPTZ
```

**api_keys** — Tenant credentials
```sql
id UUID PRIMARY KEY,
tenant_id UUID,
domain VARCHAR(255),
namespace_scope VARCHAR(255),
role VARCHAR(50),
key_hash VARCHAR(255),               -- 'sha256:<hex>' (legacy rows: Argon2 PHC)
expires_at TIMESTAMPTZ,
revoked BOOLEAN,
created_at TIMESTAMPTZ
```

#### 6. **magnolia-audit** — Append-Only Audit Log

In-memory audit logger; eventually persisted to DB.

```rust
pub struct AuditLogEntry {
    pub id: UUID,
    pub tenant_id: UUID,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub result: AuditResult,  // Success | Failure
    pub reason: Option<String>,
    pub created_at: DateTime,
}
```

**Usage:**
- Log every API action
- Mandatory `reason` for `super_admin` actions (compliance)
- Immutable once written

#### 7. **magnolia-api** — HTTP Layer (Axum)

**Entry point**: Multi-tenancy via domain/namespace routing, Bearer token auth.

**Core endpoints** (v1):

```
POST /api/v1/upload
  Body: multipart/form-data { sbom_file, format: 'cyclonedx'|'spdx' }
  Auth: Bearer <api_key>
  Response: { manifest_hash, tree_size, leaf_index, signature }

GET /api/v1/manifest/:hash
  Auth: Bearer <api_key>
  Response: Manifest + S3 metadata

GET /api/v1/proof/inclusion/:leaf_index
  Auth: Bearer <api_key> (auditor or super_admin)
  Response: InclusionProof (O(log N) path to root)

GET /api/v1/proof/consistency/:old_tree_size/:new_tree_size
  Auth: Bearer <api_key> (auditor or super_admin)
  Response: ConsistencyProof (proves no deletion/reordering)

GET /api/v1/tree-head/latest
  Auth: Bearer <api_key> (auditor or super_admin)
  Response: Latest SignedTreeHead

POST /api/v1/admin/keys/create
  Auth: Bearer <api_key> (domain_admin or super_admin)
  Body: { namespace_scope, role, expires_at }
  Response: { api_key (shown once), created_at }
```

**Middleware:**
- Bearer token extraction & verification
- RBAC enforcement per endpoint
- Audit logging (success/failure)
- Error mapping to HTTP status codes

## Data Flow: Upload Path (Pragmatic MVP)

1. **Client** → `POST /api/v1/upload` with Bearer token + SBOM file
2. **API Middleware**
   - Extract & verify API key
   - Load Grant from DB
   - RBAC check: `RbacEngine::require_role(grant, domain, namespace, Action::Upload)`
3. **Handler**
   - Hash SBOM: `leaf_hash = sha256_leaf(sbom_data)`
   - Compute manifest: `Manifest::new(...).with_signature(...)`
4. **Storage**
   - Direct to S3 with Object Lock (WORM)
   - S3 key format: `{domain}/{namespace}/{manifest_hash}.sbom`
5. **Merkle Tree**
   - Append `leaf_hash` to tree
   - Recalculate frontier & root (O(log N))
6. **Signing**
   - Sign tree state: `signature = signer.sign(root_hash || tree_size)`
   - Create `SignedTreeHead`
7. **Database (atomic transaction)**
   - Insert `signed_tree_heads` record
   - Insert `merkle_leaves` record (status = 'locked')
   - Insert `audit_logs` record
8. **Response**
   - Return `{ manifest_hash, tree_size, leaf_index, signed_tree_head }`

## Pragmatic Resilience Trade-off

**Path A (3-Phase Upload)** — Theoretically safer but complex:
- Phase 1: Staging (S3, no lock)
- Phase 2: DB commit (status = 'pending_lock')
- Phase 3: Finalize (lock in S3)
- Self-healing: Background worker re-locks orphaned files

**Path B (Direct WORM)** — Chosen for MVP:
- Upload directly to S3 with Object Lock
- Commit to DB immediately after
- **Risk**: If DB crashes after S3 write, orphan file (cannot delete)
- **Mitigation**: File is cost-negligible; re-uploading creates new revision
- **Benefit**: Simpler, fewer failure modes, easier to reason about

## Crate Dependencies (Workspace)

```
magnolia-api
├── magnolia-core
├── magnolia-auth
├── magnolia-signer
├── magnolia-storage
├── magnolia-db
└── magnolia-audit

magnolia-core (no internal deps)
magnolia-auth (no internal deps)
magnolia-signer (no internal deps)
magnolia-storage (no internal deps)
magnolia-db (no internal deps)
magnolia-audit (no internal deps)
```

## Key Design Decisions

1. **Trait-based abstraction** for `Signer` and `ObjectStore`
   - Enables testing (mock/in-memory impls)
   - Future: Swap to production signers (Vault) without API changes

2. **Append-only Merkle Mountain Range**
   - Efficient: O(log N) appends, O(1) memory
   - Tamper-evident: Changing past SBOM changes root; signature breaks
   - Auditor-friendly: Proofs are compact, verifiable offline

3. **Atomic DB transactions**
   - All-or-nothing: If any step fails, whole upload fails
   - Audit trail always consistent with storage

4. **Pragmatic acceptance of S3 orphans**
   - Cost << complexity of 3-phase recovery
   - Reliable codebase prioritized

## Testing Strategy

1. **Unit tests** (trait impls)
   - `LocalFileSigner` mock signing
   - `InMemoryStore` CRUD
   - `RbacEngine` matrix enforcement

2. **Integration tests**
   - Full upload flow (in-memory storage)
   - Merkle proof verification
   - API endpoint contracts

3. **Audit trail tests**
   - Every action logged
   - Immutability checks

## Production Readiness Checklist

- [ ] Migrate `LocalFileSigner` → `VaultSigner` (or `AwsKmsSigner`)
- [ ] Migrate `InMemoryStore` → `S3Store` with Object Lock
- [ ] PostgreSQL connection pooling + RLS (row-level security) for multi-tenancy
- [ ] Rate limiting per API key
- [ ] TLS (HTTPS, mutual TLS for integrations)
- [ ] Structured logging (JSON, correlation IDs)
- [ ] Metrics (Prometheus)
- [ ] API versioning strategy (v1 → v2 migration)
- [ ] Retention policy enforcement (delete old SBOMs after legal hold)

## Security Assumptions

1. **S3 Object Lock is reliable**: Once locked, files cannot be deleted/overwritten (compliance mode assumed)
2. **KMS is isolated**: Private key never leaves signer backend
3. **API keys are single-use secret**: Clients must handle secure storage
4. **Audit logs are immutable**: Append-only DB table; never updated/deleted
5. **Domain boundaries are enforced**: Tenants cannot cross-read other tenants' data

---

**Version:** 0.1 (MVP)  
**Last Updated:** 2024-08-21  
**Status:** Skeleton phase complete; next: schema migration + HTTP handlers
