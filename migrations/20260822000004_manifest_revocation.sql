-- Manifest revocation: a status flag, not a delete. The manifest row, its
-- signature, and the Merkle leaf/hash it's chained from are untouched —
-- tamper-evidence and the append-only log are preserved. Revoking just
-- marks an entry as superseded/invalid for downstream consumers.
ALTER TABLE manifests ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE manifests ADD COLUMN revoked_at TIMESTAMPTZ;
ALTER TABLE manifests ADD COLUMN revoked_by VARCHAR(255);
