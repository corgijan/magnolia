 sbomStash — FEATURES.md (v1 Scope) Funktionaler Bauplan für die erste Implementierung. Gedacht als Startpunkt für Claude Code: erst Skelett + Traits, dann Ingest-Pfad, dann Verify, dann UI. ## 0. Repo-Layout ``` sbomstash/ ├── crates/ │ ├── api/ # axum HTTP-Layer, DTOs, Routing, Fehler-Mapping │ ├── core/ # Manifest, HashChain, RetentionPolicy, Canonicalization │ ├── auth/ # API-Key-Hashing/-Verifikation, RBAC-Middleware │ ├── signer/ # trait Signer + local_file.rs / vault.rs / kms.rs / pkcs11.rs │ ├── storage/ # trait ObjectStore + s3.rs (+ memory.rs für Tests) │ ├── db/ # sqlx-Modelle, Queries, Migrations │ └── audit/ # append-only Audit-Log-Writer ├── static/ # index.html, app.js, style.css ├── migrations/ └── bin/sbomstash-server.rs ``` ## 1. Feature-Liste ### F1 — Multi-Tenancy & Namespaces - [ ] Domain als Mandantengrenze (`acme-corp/...`) - [ ] Hierarchische Namespaces, `/`-getrennt, freie Strings - [ ] Präfix-Vererbung bei Zugriffsrechten (`/p1` deckt `/p1/sub1` ab) - [ ] Namespace-Validierung: erlaubte Zeichen, lowercase-Normalisierung, Längenlimit, kein `..`, kein führender/doppelter `/` ### F2 — API-Key-Auth - [ ] Key-Erzeugung, Anzeige genau einmal, `argon2`-Hash at rest - [ ] `Authorization: Bearer <key>` auf jedem Request - [ ] Grant-Tupel: `(key) → (domain, namespace_scope, role, expires_at)` - [ ] Revoke-Flag + Ablaufdatum - [ ] Rollen: `super_admin`, `domain_admin`, `uploader`, `auditor` ### F3 — RBAC - [ ] Zentrale `require_role(grant, domain, namespace, action)`-Funktion - [ ] Matrix: uploader darf Upload, nicht annotieren; auditor darf lesen + annotieren, nicht uploaden; domain_admin verwaltet Keys/ACLs seiner Domain; super_admin überall, aber mit Pflicht-`reason` im Audit-Log - [ ] Unit-Tests für jede Zelle der Matrix (das ist der Sicherheitskern) ### F4 — SBOM-Ingest - [ ] Upload (CycloneDX/SPDX JSON), Format-Erkennung + Basisvalidierung - [ ] Kanonisierung (RFC 8785) → SHA-256 über **unkomprimierten** Inhalt - [ ] Revisionsnummer automatisch hochzählen pro (domain, ns, product, version) - [ ] `previous_manifest_sha256` aus letzter Revision der Linie holen - [ ] Retention auflösen (Request-Wunsch vs. Domain-Floor, Maximum gewinnt) - [ ] Manifest bauen → signieren → S3 mit Object Lock schreiben (SBOM + Manifest) → Postgres-Index → Audit-Log - [ ] Idempotenz: identischer Inhalt + identische Version → optional "no-op, gib bestehende Revision zurück" statt neuer Revision ### F5 — Signatur & Signer-Abstraktion - [ ] `trait Signer { sign(), verify(), key_id(), backend_name() }` - [ ] Backend-Auswahl **rein über Konfiguration/ENV**, kein Code-Change nötig - [ ] Signer-Registry: Auflösung pro Domain (`domains.signer_backend/key_id`), Fallback auf global konfiguriertes Default-Backend - [ ] Signaturziel: kanonische Bytes des Manifests **ohne** `signature`-Feld **Backends v1:** | `SBOMSTASH_SIGNER_BACKEND` | Status | Zweck | |---|---|---| | `local_file` | v1 | Ed25519-Key aus Datei — Dev, CI, Air-Gapped-Setups | | `vault_transit` | v1 | Produktionsdefault, Open Source, self-hostbar | | `aws_kms` | v1 | Managed Cloud | | `pkcs11` | Stub | Enterprise-HSM, Interface vorbereiten | **F5a — `local_file`-Signer (Detailanforderungen)** - [ ] Aktivierung ausschließlich über `SBOMSTASH_SIGNER_BACKEND=local_file` - [ ] Privater Key aus Datei: `SBOMSTASH_SIGNER_LOCAL_KEY_PATH=/path/key.pem` - [ ] Format: **Ed25519, PKCS#8 PEM** (`ed25519-dalek` + `pkcs8`-Feature); optional Raw-32-Byte-Fallback, aber PEM als Primärpfad - [ ] Key-ID: `SBOMSTASH_SIGNER_LOCAL_KEY_ID` (Default: `local-<sha256(pubkey)[..8]>`) → landet im Manifest, damit später eindeutig zuordenbar - [ ] Key wird **einmal beim Start** geladen, nicht pro Request (Dateizugriff im Hot Path vermeiden); Fail-Fast beim Start, wenn Datei fehlt/unlesbar/kaputt - [ ] **Permission-Check**: Datei muss `0600`/`0400` sein, sonst Start abbrechen - [ ] Public Key exportierbar über `GET /api/v1/signers/:key_id/pubkey` → nötig für Offline-Verifikation von Exporten (F10) - [ ] **Sicherheitsnetz**: bei `SBOMSTASH_ENV=production` + `local_file` → Start nur mit explizitem `SBOMSTASH_ALLOW_LOCAL_SIGNER_IN_PROD=true`, sonst Abbruch mit klarer Fehlermeldung. Zusätzlich `WARN`-Log bei jedem Start und Kennzeichnung `"signer_backend": "local_file"` im Manifest (bleibt für immer sichtbar). - [ ] Optional: `SBOMSTASH_SIGNER_LOCAL_KEY_GENERATE=true` erzeugt beim ersten Start einen Key, falls die Datei nicht existiert — **nur** außerhalb von `production`, damit `docker compose up` ohne Vorarbeit funktioniert ### F6 — Hash-Kette & Verifikation - [ ] `GET /manifests/:id/verify` prüft: Signatur gültig, Kettenglied korrekt, S3-Objekt-Hash == Manifest-Hash, Annotationsketten intakt - [ ] `GET /.../chain` liefert die vollständige Revisionskette einer Version - [ ] Hintergrund-Job: periodischer Full-Chain-Scan, Ergebnis als Metrik/Alert ### F7 — Immutability & Retention - [ ] Object Lock pro Namespace: `governance` | `compliance` - [ ] `extend_retention()` — Verkürzung wird API-seitig hart abgelehnt - [ ] Konfigurierbarer `min_retention_days` pro Domain (und optional Namespace) - [ ] `post_expiry_action`: `auto_delete` | `manual_review` - [ ] Service-IAM-Rolle ohne Delete-Rechte auf gelockte Objekte (defense in depth) ### F8 — Auditor-Annotationen - [ ] `POST /manifests/:id/annotations` — freies JSON-`content` - [ ] Eigene Hash-Kette pro Manifest-Revision (`previous_annotation_sha256`) - [ ] Eigene Signatur, ebenfalls in S3 unter Object Lock - [ ] Nur `auditor` / `domain_admin` / `super_admin` - [ ] Annotationen sind unlöschbar und unveränderlich **F8a — Retraction (Widerruf statt Löschen)** - [ ] Annotationen haben ein Pflichtfeld `type`: `finding` | `risk_acceptance` | `note` | `retraction` - [ ] Eine `retraction` ist eine **normale, signierte Annotation** in derselben Kette, die per `retracts: <annotation_id>` auf die widerrufene zeigt - [ ] Pflichtfeld `reason` bei `type = retraction` (Freitext, wird mitsigniert) - [ ] Validierung: Ziel muss existieren, zum selben Manifest gehören und darf **selbst keine `retraction`** sein; Doppel-Widerruf → `409 Conflict` - [ ] Die widerrufene Annotation bleibt physisch und in der Kette erhalten — sie wird nur **als widerrufen markiert dargestellt**, nie entfernt - [ ] `GET /manifests/:id/annotations` liefert pro Eintrag zusätzlich `retracted_by` (Annotation-ID oder `null`); Query-Param `?include_retracted=false` blendet sie in der Default-Ansicht aus - [ ] Frontend: widerrufene Annotationen durchgestrichen + ausklappbarer Widerrufsgrund darunter — Historie bleibt für den Auditor sichtbar - [ ] Rolle: nur `auditor` (und `domain_admin`/`super_admin`), sinnvollerweise **nicht zwingend derselbe Auditor** wie der Autor — vier-Augen-fähig Beispiel: ```json { "type": "retraction", "retracts": "b3f1c2a0-...", "reason": "Falsche CVE-Zuordnung, betraf Version 2.3.0 nicht 2.4.1", "reference": "JIRA-4902" } ``` ### F9 — Audit-Log - [ ] Jeder Request: key_id, domain, namespace, action, resource, IP, timestamp, Ergebnis (allow/deny) - [ ] Append-only; kein UPDATE/DELETE in der Anwendung - [ ] Periodischer Export nach S3 (WORM), optional selbst hash-verkettet ### F10 — Backup/Export - [ ] `GET /export?domain=&namespace=` → komprimiertes Archiv (tar.zst) mit SBOMs + Manifesten + Annotationen + Signaturen - [ ] **Public Keys aller verwendeten Signer** mit ins Archiv legen - [ ] Enthält ein `VERIFY.md` / Verify-Skript, damit ein Auditor das Archiv **offline** ohne sbomStash prüfen kann ### F11 — Index-Rebuild (DR) - [ ] `sbomstash-server rebuild-index` scannt S3 und baut Postgres neu auf - [ ] Reconcile-Modus: meldet Diskrepanzen S3 ↔ DB, ohne zu schreiben ### F12 — Minimal-Frontend (Vanilla JS, kein Build) - [ ] `static/index.html` + `app.js` + `style.css`, per `ServeDir` ausgeliefert - [ ] Screens: (1) API-Key eingeben, (2) Domain-/Namespace-Baum, (3) Versionsliste, (4) Manifest-Detail + Annotationen - [ ] Statusbadges für Signatur ✅/❌ und Kette ✅/❌ - [ ] Annotation hinzufügen + widerrufen (POST + Reload) - [ ] Hinweis-Banner, wenn `signer_backend == "local_file"` ("nicht produktionstauglich signiert") - [ ] `escapeHtml()` für alle nutzergelieferten Strings (Stored-XSS!) - [ ] Key im `sessionStorage`, kein Cookie → kein CSRF-Thema ## 2. API-Oberfläche (v1) ``` # Auth / Meta GET /api/v1/whoami GET /api/v1/healthz # Discovery GET /api/v1/domains GET /api/v1/domains/:domain/namespaces GET /api/v1/domains/:domain/namespaces/:ns/products GET /api/v1/domains/:domain/namespaces/:ns/manifests # Ingest POST /api/v1/domains/:domain/namespaces/:ns/products/:product/versions/:version/sboms # Manifest GET /api/v1/manifests/:id GET /api/v1/manifests/:id/verify GET /api/v1/manifests/:id/chain GET /api/v1/manifests/:id/download PATCH /api/v1/manifests/:id/retention # nur Verlängerung # Annotationen GET /api/v1/manifests/:id/annotations?include_retracted=true POST /api/v1/manifests/:id/annotations # inkl. type=retraction # Signer GET /api/v1/signers/:key_id/pubkey # für Offline-Verifikation # Admin POST /api/v1/admin/domains # super_admin POST /api/v1/admin/keys # domain_admin+ DELETE /api/v1/admin/keys/:id # revoke GET /api/v1/admin/audit-log # Export GET /api/v1/export ``` ## 3. Datenbank (Query-Index, nicht Source of Truth) ```sql CREATE TABLE domains ( id UUID PRIMARY KEY, name TEXT UNIQUE NOT NULL, signer_backend TEXT NOT NULL, signer_key_id TEXT NOT NULL, min_retention_days INT NOT NULL DEFAULT 0, default_lock_mode TEXT NOT NULL DEFAULT 'governance' ); CREATE TABLE api_keys ( id UUID PRIMARY KEY, key_hash TEXT NOT NULL, domain_id UUID REFERENCES domains(id), role TEXT NOT NULL, -- super_admin|domain_admin|uploader|auditor namespace_scope TEXT, -- NULL = ganze Domain expires_at TIMESTAMPTZ, revoked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now() ); CREATE TABLE manifests ( id UUID PRIMARY KEY, domain_id UUID REFERENCES domains(id), namespace TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL, revision INT NOT NULL, sbom_sha256 TEXT NOT NULL, -- kanonisch, unkomprimiert sbom_format TEXT NOT NULL, previous_manifest_sha256 TEXT, manifest_sha256 TEXT NOT NULL, s3_key TEXT NOT NULL, retention_mode TEXT NOT NULL, -- governance|compliance retention_until TIMESTAMPTZ NOT NULL, post_expiry_action TEXT NOT NULL, -- auto_delete|manual_review signer_backend TEXT NOT NULL, signer_key_id TEXT NOT NULL, signature BYTEA NOT NULL, uploader_key_id UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (domain_id, namespace, product, version, revision) ); CREATE TABLE annotations ( id UUID PRIMARY KEY, manifest_id UUID REFERENCES manifests(id), domain_id UUID REFERENCES domains(id), author_key_id UUID, ann_type TEXT NOT NULL, -- finding|risk_acceptance|note|retraction retracts UUID REFERENCES annotations(id), -- nur bei ann_type='retraction' content JSONB NOT NULL, content_sha256 TEXT NOT NULL, previous_annotation_sha256 TEXT, signature BYTEA NOT NULL, signer_backend TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now() ); -- eine Annotation darf nur einmal widerrufen werden CREATE UNIQUE INDEX annotations_retracts_uniq ON annotations (retracts) WHERE retracts IS NOT NULL; CREATE TABLE audit_log ( id BIGSERIAL PRIMARY KEY, api_key_id UUID, domain_id UUID, action TEXT NOT NULL, resource TEXT, outcome TEXT NOT NULL, -- allow|deny|error reason TEXT, -- Pflicht bei super_admin-Aktionen source_ip INET, created_at TIMESTAMPTZ NOT NULL DEFAULT now() ); ``` ## 4. S3-Layout ``` {domain}/{namespace}/{product}/{version}/rev-{n}/sbom.json.gz {domain}/{namespace}/{product}/{version}/rev-{n}/manifest.json {domain}/{namespace}/{product}/{version}/rev-{n}/annotations/{annotation_id}.json ``` ## 5. Kern-Traits ```rust #[async_trait] pub trait Signer: Send + Sync { async fn sign(&self, payload: &[u8]) -> Result<Signature, SignerError>; async fn verify(&self, payload: &[u8], sig: &Signature) -> Result<bool, SignerError>; fn key_id(&self) -> &str; fn backend_name(&self) -> &'static str; fn public_key(&self) -> Option<Vec<u8>>; // für Offline-Verify/Export } #[async_trait] pub trait ObjectStore: Send + Sync { async fn put_immutable(&self, key: &str, data: Bytes, retention: RetentionConfig) -> Result<(), StoreError>; async fn get(&self, key: &str) -> Result<Bytes, StoreError>; async fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError>; async fn extend_retention(&self, key: &str, until: DateTime<Utc>) -> Result<(), StoreError>; } ``` Beide als `Arc<dyn ...>` im axum-`AppState` → austauschbar und mockbar. ## 6. Konfiguration (ENV) Alles über Umgebungsvariablen, Prefix `SBOMSTASH_`, geparst mit `figment` oder `envy` in ein typisiertes `Config`-Struct. **Fail-Fast beim Start**, nie lazy. ```bash # Allgemein SBOMSTASH_ENV=development # development|staging|production SBOMSTASH_BIND_ADDR=0.0.0.0:8080 SBOMSTASH_DATABASE_URL=postgres://... # Storage SBOMSTASH_STORAGE_BACKEND=s3 # s3|memory SBOMSTASH_S3_BUCKET=sbomstash SBOMSTASH_S3_ENDPOINT=http://minio:9000 # leer = AWS SBOMSTASH_S3_REGION=eu-central-1 # Signer — Auswahl SBOMSTASH_SIGNER_BACKEND=local_file # local_file|vault_transit|aws_kms|pkcs11 # Signer — local_file SBOMSTASH_SIGNER_LOCAL_KEY_PATH=/etc/sbomstash/signing-key.pem SBOMSTASH_SIGNER_LOCAL_KEY_ID=dev-key-1 # optional, sonst aus Pubkey-Hash SBOMSTASH_SIGNER_LOCAL_KEY_GENERATE=true # nur außerhalb production SBOMSTASH_ALLOW_LOCAL_SIGNER_IN_PROD=false # Notbremse, Default false # Signer — vault_transit SBOMSTASH_VAULT_ADDR=https://vault:8200 SBOMSTASH_VAULT_TRANSIT_KEY=sbomstash-acme SBOMSTASH_VAULT_AUTH_METHOD=kubernetes # keine statischen Tokens in prod # Signer — aws_kms SBOMSTASH_KMS_KEY_ARN=arn:aws:kms:... # Retention-Defaults SBOMSTASH_DEFAULT_MIN_RETENTION_DAYS=1825 # 5 Jahre SBOMSTASH_DEFAULT_LOCK_MODE=governance ``` Startlogik für den Signer: ```rust let signer: Arc<dyn Signer> = match cfg.signer_backend { Backend::LocalFile => { if cfg.env == Env::Production && !cfg.allow_local_signer_in_prod { bail!("local_file signer is not permitted in production; \ set SBOMSTASH_ALLOW_LOCAL_SIGNER_IN_PROD=true to override"); } warn!("using local_file signer — private key lives on disk"); Arc::new(LocalFileSigner::load_or_generate(&cfg)?) } Backend::VaultTransit => Arc::new(VaultSigner::connect(&cfg).await?), Backend::AwsKms => Arc::new(KmsSigner::connect(&cfg).await?), Backend::Pkcs11 => bail!("pkcs11 backend not implemented in v1"), }; ``` ## 7. Bau-Reihenfolge (Milestones) | M | Inhalt | Definition of Done | |---|---|---| | M0 | Cargo-Workspace, Traits, `MemoryStore` + `LocalFileSigner`, Config-Parsing, `/healthz` | `cargo test` grün, Server startet mit generiertem Dev-Key | | M1 | Postgres + Migrations + API-Keys + RBAC-Matrix | RBAC-Tests decken alle Rollen/Aktionen ab | | M2 | Ingest-Pfad end-to-end (Kanonisierung, Hash-Kette, Signatur, Manifest) | SBOM hochladen → Manifest zurück → 2. Upload = rev 2 mit korrektem prev-Hash | | M3 | S3/MinIO-Backend + Object Lock + Retention-Regeln | Verkürzungsversuch wird abgelehnt, Delete schlägt fehl | | M4 | Verify-Endpoint + Chain-Scan-Job | manipulierter DB-Eintrag wird erkannt | | M5 | Annotationen inkl. eigener Kette, Retraction, Rollentrennung | uploader kann nicht annotieren, Doppel-Widerruf → 409 | | M6 | Vanilla-JS-Frontend (4 Screens) | Key eingeben → Baum → Version → Detail → Annotation anlegen/widerrufen | | M7 | Export + Index-Rebuild + Vault-Backend | Offline-Verify eines Exports ohne laufenden Server | ## 8. Testschwerpunkte - RBAC-Matrix (vollständig, tabellengetrieben) - Hash-Kette: Einfügen/Löschen/Umsortieren muss erkannt werden - Kanonisierung: semantisch gleiches JSON mit anderer Key-Reihenfolge → gleicher Hash - Retention: Verkürzung, Floor-Unterschreitung, Modus-Wechsel → alles abgelehnt - Signatur-Roundtrip pro Backend (`local_file` immer, Vault via Testcontainer) - `local_file`: fehlende Datei, falsche Permissions, kaputtes PEM → Start bricht ab - Prod-Guard: `ENV=production` + `local_file` ohne Override → Start bricht ab - Retraction: Ziel existiert nicht / fremdes Manifest / bereits widerrufen / Retraction einer Retraction → alles abgelehnt - Index-Rebuild: DB löschen, aus S3 rekonstruieren, Ergebnis identisch ## 9. Offene Entscheidungen (vor M2 klären) 1. Annotationskette **pro Revision** (einfacher) oder **pro Version über alle Revisionen hinweg** (überlebt Republish, passt evtl. besser zum Audit-Alltag)? 2. Idempotenter Re-Upload identischen Inhalts: neue Revision oder No-op? 3. Erlaubte SBOM-Formate in v1 — nur CycloneDX JSON, oder SPDX gleich mit? 4. Default-Lock-Mode für neue Domains: `governance` (fehlertolerant) oder `compliance` (streng)? 5. Darf ein Auditor seine **eigene** Annotation widerrufen, oder braucht es dafür einen zweiten Auditor (Vier-Augen-Prinzip)? 

Da S3 Object Lock und PostgreSQL keine gemeinsamen ACID-Transaktionen unterstützen, muss die Systemkonsistenz bei Netzwerkabbrüchen sichergestellt werden.

Es gibt zwei Architektur-Pfade:
Pfad A: Der 3-Phasen-Upload (Sauber, aber komplex)

    Staging: Upload der SBOM nach S3 ohne Object Lock (Lifecycle-Rule löscht nach 24h).

    Commit: Tree-Update und Eintrag in die DB (status = 'pending_lock').

    Finalize: Object Lock in S3 per API aktivieren und DB auf locked setzen.
    Self-Healing: Ein asynchroner Rust-Worker (tokio) prüft regelmäßig auf pending_lock-Einträge und holt fehlende S3-Locks nach (Outbox Pattern).

Pfad B: Der pragmatische Ansatz ("Accept the Orphans")

    Direktes WORM: Upload nach S3 direkt mit Object Lock.

    Commit: Tree-Update und Eintrag in die DB.
    Risiko: Crasht die DB in Schritt 2, entsteht eine "Zombie-Datei" in S3, die nicht gelöscht werden kann.
    Rechtfertigung: Bei durchschnittlich kleinen SBOM-Dateien und extrem günstigen S3-Preisen (Bruchteile von Cent-Beträgen pro Jahr für Orphans) wird dieser Umstand zugunsten einer simpler, fehlerfreieren Codebase oft hingenommen.


Hier ist der exakte Inhalt der Datei `sbomStash_Architektur.md`:

```markdown
# Architektur-Konzept: sbomStash

**Compliance-fokussiertes SBOM-Archiv für den EU Cyber Resilience Act (CRA)**

`sbomStash` schließt die Lücke zwischen operativer Schwachstellenanalyse (z. B. Dependency-Track) und der gesetzlich vorgeschriebenen, revisionssicheren WORM-Archivierung (Write Once, Read Many) von Software Bill of Materials (SBOMs).

---

## 1. Technologie-Stack
*   **Backend:** Rust (Axum für High-Performance API)
*   **Datenbank:** PostgreSQL (via `sqlx` für typsichere, asynchrone Queries)
*   **Speicher:** S3-kompatibler Object Storage mit WORM-Schutz (Object Lock)
*   **Kryptografie:** Externe KMS/HSM-Integration (z. B. HashiCorp Vault) für Signierungen

---

## 2. Kryptografische Tamper-Evidence (Merkle Mountain Range)
Um nachträgliche Manipulationen auszuschließen und Auditoren lückenlose Beweise zu liefern, implementiert das System einen **Append-Only Merkle Tree** (inspiriert von Certificate Transparency Logs, RFC 6962).

*   **Zustandslos & Effizient:** Es wird nicht der gesamte Baum im Arbeitsspeicher gehalten. Der Status (die "Frontier" oder Bergspitzen der perfekten Subtrees) wird kompakt als Array in der Datenbank gespeichert.
*   **O(1) Memory / O(log N) Zeit:** Das Hinzufügen einer neuen SBOM erfordert lediglich das Laden von max. 32 Hashes (ca. 1 KB) aus der Datenbank, wenige lokale SHA256-Operationen und das Schreiben des neuen `Signed Tree Head` (STH).

### Kryptografische Audit-Beweise
Das Design ermöglicht zwei mathematisch unbestreitbare Beweise für Auditoren (TÜV, BSI)[cite: 1]:
1.  **Inclusion Proof:** Beweist in $\mathcal{O}(\log N)$ Schritten, dass eine spezifische SBOM unverändert im Archiv liegt[cite: 1].
2.  **Consistency Proof:** Beweist, dass das Archiv nur durch Anhängen gewachsen ist und historische Einträge (z. B. aus dem Vorjahr) nicht gelöscht oder manipuliert wurden (WORM-Garantie)[cite: 1].

---

## 3. Datenbank-Schema (PostgreSQL)

Das Schema minimiert Redundanz und ist für rasante Audit-Queries optimiert[cite: 1]:

```sql
-- 1. Historie der signierten Baum-Zustände (Die "Frontier")
CREATE TABLE signed_tree_heads (
    tree_size BIGINT PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,      -- Signiert durch KMS
    frontier BYTEA[] NOT NULL,     -- Array der Subtree-Wurzeln (max. 32 Einträge)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Das Append-Only Log der hochgeladenen SBOMs
CREATE TABLE merkel_leaves (
    seq_id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    sbom_s3_key VARCHAR(255) NOT NULL,
    leaf_hash BYTEA NOT NULL,
    status VARCHAR(50) NOT NULL,   -- z.B. 'pending_lock' oder 'locked'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Cache für alle Zwischenknoten (Für O(1) Proof-Generierung)
CREATE TABLE merkle_nodes (
    level INT NOT NULL,
    index BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    PRIMARY KEY (level, index)
);

4. Ausfallsicherheit & Distributed Transactions (DB vs. S3)

Da S3 Object Lock und PostgreSQL keine gemeinsamen ACID-Transaktionen unterstützen, muss die Systemkonsistenz bei Netzwerkabbrüchen sichergestellt werden[cite: 1].

Es gibt zwei Architektur-Pfade[cite: 1]:
Pfad A: Der 3-Phasen-Upload (Sauber, aber komplex)

    Staging: Upload der SBOM nach S3 ohne Object Lock (Lifecycle-Rule löscht nach 24h)[cite: 1].

    Commit: Tree-Update und Eintrag in die DB (status = 'pending_lock')[cite: 1].

    Finalize: Object Lock in S3 per API aktivieren und DB auf locked setzen[cite: 1].
    Self-Healing: Ein asynchroner Rust-Worker (tokio) prüft regelmäßig auf pending_lock-Einträge und holt fehlende S3-Locks nach (Outbox Pattern)[cite: 1].

Pfad B: Der pragmatische Ansatz ("Accept the Orphans")

    Direktes WORM: Upload nach S3 direkt mit Object Lock[cite: 1].

    Commit: Tree-Update und Eintrag in die DB[cite: 1].
    Risiko: Crasht die DB in Schritt 2, entsteht eine "Zombie-Datei" in S3, die nicht gelöscht werden kann[cite: 1].
    Rechtfertigung: Bei durchschnittlich kleinen SBOM-Dateien und extrem günstigen S3-Preisen (Bruchteile von Cent-Beträgen pro Jahr für Orphans) wird dieser Umstand zugunsten einer simpler, fehlerfreieren Codebase oft hingenommen[cite: 1].Da S3 Object Lock und PostgreSQL keine gemeinsamen ACID-Transaktionen unterstützen, muss die Systemkonsistenz bei Netzwerkabbrüchen sichergestellt werden.

Es gibt zwei Architektur-Pfade:
Pfad A: Der 3-Phasen-Upload (Sauber, aber komplex)

    Staging: Upload der SBOM nach S3 ohne Object Lock (Lifecycle-Rule löscht nach 24h).

    Commit: Tree-Update und Eintrag in die DB (status = 'pending_lock').

    Finalize: Object Lock in S3 per API aktivieren und DB auf locked setzen.
    Self-Healing: Ein asynchroner Rust-Worker (tokio) prüft regelmäßig auf pending_lock-Einträge und holt fehlende S3-Locks nach (Outbox Pattern).

Pfad B: Der pragmatische Ansatz ("Accept the Orphans")

    Direktes WORM: Upload nach S3 direkt mit Object Lock.

    Commit: Tree-Update und Eintrag in die DB.
    Risiko: Crasht die DB in Schritt 2, entsteht eine "Zombie-Datei" in S3, die nicht gelöscht werden kann.
    Rechtfertigung: Bei durchschnittlich kleinen SBOM-Dateien und extrem günstigen S3-Preisen (Bruchteile von Cent-Beträgen pro Jahr für Orphans) wird dieser Umstand zugunsten einer simpler, fehlerfreieren Codebase oft hingenommen.


Hier ist der exakte Inhalt der Datei `sbomStash_Architektur.md`:

```markdown
# Architektur-Konzept: sbomStash

**Compliance-fokussiertes SBOM-Archiv für den EU Cyber Resilience Act (CRA)**

`sbomStash` schließt die Lücke zwischen operativer Schwachstellenanalyse (z. B. Dependency-Track) und der gesetzlich vorgeschriebenen, revisionssicheren WORM-Archivierung (Write Once, Read Many) von Software Bill of Materials (SBOMs).

---

## 1. Technologie-Stack
*   **Backend:** Rust (Axum für High-Performance API)
*   **Datenbank:** PostgreSQL (via `sqlx` für typsichere, asynchrone Queries)
*   **Speicher:** S3-kompatibler Object Storage mit WORM-Schutz (Object Lock)
*   **Kryptografie:** Externe KMS/HSM-Integration (z. B. HashiCorp Vault) für Signierungen

---

## 2. Kryptografische Tamper-Evidence (Merkle Mountain Range)
Um nachträgliche Manipulationen auszuschließen und Auditoren lückenlose Beweise zu liefern, implementiert das System einen **Append-Only Merkle Tree** (inspiriert von Certificate Transparency Logs, RFC 6962).

*   **Zustandslos & Effizient:** Es wird nicht der gesamte Baum im Arbeitsspeicher gehalten. Der Status (die "Frontier" oder Bergspitzen der perfekten Subtrees) wird kompakt als Array in der Datenbank gespeichert.
*   **O(1) Memory / O(log N) Zeit:** Das Hinzufügen einer neuen SBOM erfordert lediglich das Laden von max. 32 Hashes (ca. 1 KB) aus der Datenbank, wenige lokale SHA256-Operationen und das Schreiben des neuen `Signed Tree Head` (STH).

### Kryptografische Audit-Beweise
Das Design ermöglicht zwei mathematisch unbestreitbare Beweise für Auditoren (TÜV, BSI)[cite: 1]:
1.  **Inclusion Proof:** Beweist in $\mathcal{O}(\log N)$ Schritten, dass eine spezifische SBOM unverändert im Archiv liegt[cite: 1].
2.  **Consistency Proof:** Beweist, dass das Archiv nur durch Anhängen gewachsen ist und historische Einträge (z. B. aus dem Vorjahr) nicht gelöscht oder manipuliert wurden (WORM-Garantie)[cite: 1].

---

## 3. Datenbank-Schema (PostgreSQL)

Das Schema minimiert Redundanz und ist für rasante Audit-Queries optimiert[cite: 1]:

```sql
-- 1. Historie der signierten Baum-Zustände (Die "Frontier")
CREATE TABLE signed_tree_heads (
    tree_size BIGINT PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,      -- Signiert durch KMS
    frontier BYTEA[] NOT NULL,     -- Array der Subtree-Wurzeln (max. 32 Einträge)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Das Append-Only Log der hochgeladenen SBOMs
CREATE TABLE merkel_leaves (
    seq_id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL,
    sbom_s3_key VARCHAR(255) NOT NULL,
    leaf_hash BYTEA NOT NULL,
    status VARCHAR(50) NOT NULL,   -- z.B. 'pending_lock' oder 'locked'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Cache für alle Zwischenknoten (Für O(1) Proof-Generierung)
CREATE TABLE merkle_nodes (
    level INT NOT NULL,
    index BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    PRIMARY KEY (level, index)
);

4. Ausfallsicherheit & Distributed Transactions (DB vs. S3)

Da S3 Object Lock und PostgreSQL keine gemeinsamen ACID-Transaktionen unterstützen, muss die Systemkonsistenz bei Netzwerkabbrüchen sichergestellt werden[cite: 1].

Es gibt zwei Architektur-Pfade[cite: 1]:
Pfad A: Der 3-Phasen-Upload (Sauber, aber komplex)

    Staging: Upload der SBOM nach S3 ohne Object Lock (Lifecycle-Rule löscht nach 24h)[cite: 1].

    Commit: Tree-Update und Eintrag in die DB (status = 'pending_lock')[cite: 1].

    Finalize: Object Lock in S3 per API aktivieren und DB auf locked setzen[cite: 1].
    Self-Healing: Ein asynchroner Rust-Worker (tokio) prüft regelmäßig auf pending_lock-Einträge und holt fehlende S3-Locks nach (Outbox Pattern)[cite: 1].

Pfad B: Der pragmatische Ansatz ("Accept the Orphans")

    Direktes WORM: Upload nach S3 direkt mit Object Lock[cite: 1].

    Commit: Tree-Update und Eintrag in die DB[cite: 1].
    Risiko: Crasht die DB in Schritt 2, entsteht eine "Zombie-Datei" in S3, die nicht gelöscht werden kann[cite: 1].
    Rechtfertigung: Bei durchschnittlich kleinen SBOM-Dateien und extrem günstigen S3-Preisen (Bruchteile von Cent-Beträgen pro Jahr für Orphans) wird dieser Umstand zugunsten einer simpler, fehlerfreieren Codebase oft hingenommen[cite: 1]
