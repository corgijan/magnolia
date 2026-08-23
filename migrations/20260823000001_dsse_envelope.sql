-- DSSE/in-toto migration: manifest signing moves from a hand-rolled
-- "sign the manifest JSON, hash the result" scheme to a standard DSSE
-- envelope wrapping an in-toto v1 Statement, verifiable with off-the-shelf
-- tooling (cosign, openssl) instead of trusting Magnolia's own code.
--
-- `signature` becomes nullable: legacy rows keep their old raw
-- Ed25519-over-manifest-JSON signature untouched; new rows leave it NULL
-- and populate `dsse_envelope` instead. There is no way to retroactively
-- produce a valid DSSE envelope for old manifest content, so old rows are
-- reported honestly as pre-dating this scheme, not silently "upgraded" —
-- same pattern already used for the Ed25519 signed-tree-head switch.
ALTER TABLE manifests ALTER COLUMN signature DROP NOT NULL;
ALTER TABLE manifests ADD COLUMN dsse_envelope JSONB;
