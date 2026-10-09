-- The branch or tag a caller asked for, when it did not know the exact
-- commit. `commit_sha` is still always the exact object id the analysis ran
-- against — resolved once, at request time — and this column is only the
-- record of what was asked for. It is never re-resolved.
ALTER TABLE analyses ADD COLUMN requested_ref TEXT;
