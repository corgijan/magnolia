//! Immutable, size-bounded checkout cache.
//!
//! A cache entry is keyed by `(repo_url, commit)` and, because a commit id
//! names an immutable tree, an entry is never invalidated — only evicted.
//! Entries are published by `rename()` from a `tmp-<uuid>` staging
//! directory, which is atomic on the same filesystem: a reader either sees
//! no entry or a complete one, never a half-fetched tree, even if the
//! process is killed mid-fetch.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::FetchError;

/// Where checkouts live, and how much room they get.
pub struct RepoCache {
    root: PathBuf,
    max_bytes: u64,
}

impl RepoCache {
    pub fn new(root: impl Into<PathBuf>, max_mb: u64) -> Self {
        Self { root: root.into(), max_bytes: max_mb * 1024 * 1024 }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<sha256(repo_url)[..16]>-<commit>`. The URL is hashed rather than
    /// slugified so that a URL cannot influence the directory name (no
    /// traversal, no collision with another entry's staging directory) and
    /// so that entry names have a fixed, bounded shape.
    pub fn key(repo_url: &str, commit: &str) -> String {
        let digest = Sha256::digest(repo_url.as_bytes());
        format!("{}-{}", &hex::encode(digest)[..16], commit)
    }

    pub fn entry_path(&self, repo_url: &str, commit: &str) -> PathBuf {
        self.root.join(Self::key(repo_url, commit))
    }

    /// An existing, complete entry, if any. Also bumps the entry's mtime so
    /// eviction sees it as recently used.
    pub fn get(&self, repo_url: &str, commit: &str) -> Option<PathBuf> {
        let path = self.entry_path(repo_url, commit);
        if path.is_dir() {
            let _ = filetime_touch(&path);
            Some(path)
        } else {
            None
        }
    }

    /// A fresh staging directory. Its name cannot collide with a real entry
    /// key (`tmp-` prefix, and keys are hex + '-' + hex).
    pub fn staging(&self) -> Result<PathBuf, FetchError> {
        std::fs::create_dir_all(&self.root).map_err(|e| FetchError::Other(e.to_string()))?;
        let path = self.root.join(format!("tmp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).map_err(|e| FetchError::Other(e.to_string()))?;
        Ok(path)
    }

    /// Publishes a staging directory as the entry for `(repo_url, commit)`.
    ///
    /// A concurrent worker may have published the same key first — that is a
    /// success, not a conflict, since the content is identical by
    /// construction. The loser's staging directory is removed.
    pub fn publish(&self, staging: &Path, repo_url: &str, commit: &str) -> Result<PathBuf, FetchError> {
        let target = self.entry_path(repo_url, commit);
        if target.exists() {
            let _ = std::fs::remove_dir_all(staging);
            return Ok(target);
        }
        match std::fs::rename(staging, &target) {
            Ok(()) => Ok(target),
            Err(_) if target.is_dir() => {
                let _ = std::fs::remove_dir_all(staging);
                Ok(target)
            }
            Err(e) => Err(FetchError::Other(format!("could not publish cache entry: {e}"))),
        }
    }

    /// Evicts least-recently-used entries until the cache fits in its
    /// budget. Called after each publish. Staging directories are skipped —
    /// another worker may be filling one right now.
    pub fn evict_to_budget(&self) {
        let mut entries: Vec<(PathBuf, std::time::SystemTime, u64)> = Vec::new();
        let Ok(read) = std::fs::read_dir(&self.root) else { return };
        for e in read.filter_map(Result::ok) {
            let path = e.path();
            if !path.is_dir() {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("tmp-")) {
                continue;
            }
            let used = e
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let size = super::dir_size_bytes(&path);
            entries.push((path, used, size));
        }

        let mut total: u64 = entries.iter().map(|(_, _, s)| *s).sum();
        if total <= self.max_bytes {
            return;
        }
        entries.sort_by_key(|(_, used, _)| *used);
        for (path, _, size) in entries {
            if total <= self.max_bytes {
                break;
            }
            if std::fs::remove_dir_all(&path).is_ok() {
                tracing::info!(entry = %path.display(), bytes = size, "evicted cache entry");
                total = total.saturating_sub(size);
            }
        }
    }
}

/// Marks a directory as recently used. Implemented by writing and removing a
/// marker file rather than pulling in a filetime crate for one call.
fn filetime_touch(dir: &Path) -> std::io::Result<()> {
    let marker = dir.join(".reach-touch");
    std::fs::write(&marker, b"")?;
    std::fs::remove_file(&marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_bounded_hex_and_cannot_be_influenced_by_the_url() {
        // A URL containing traversal must not produce a traversing key.
        let key = RepoCache::key("https://h/../../etc", &"a".repeat(40));
        assert!(!key.contains('/'));
        assert!(key.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert_eq!(key.len(), 16 + 1 + 40);
    }

    #[test]
    fn different_urls_with_the_same_commit_get_different_entries() {
        let sha = "b".repeat(40);
        assert_ne!(RepoCache::key("https://a/r", &sha), RepoCache::key("https://b/r", &sha));
    }

    #[test]
    fn publish_then_get_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RepoCache::new(dir.path(), 100);
        let sha = "c".repeat(40);
        assert!(cache.get("https://h/r", &sha).is_none());

        let staging = cache.staging().unwrap();
        std::fs::write(staging.join("f.txt"), "hello").unwrap();
        let published = cache.publish(&staging, "https://h/r", &sha).unwrap();

        assert!(published.join("f.txt").exists());
        assert_eq!(cache.get("https://h/r", &sha), Some(published));
        assert!(!staging.exists());
    }

    #[test]
    fn publishing_over_an_existing_entry_keeps_the_existing_one() {
        // Two workers analysing the same commit concurrently is normal, not
        // an error: the content is identical by construction.
        let dir = tempfile::tempdir().unwrap();
        let cache = RepoCache::new(dir.path(), 100);
        let sha = "d".repeat(40);

        let first = cache.staging().unwrap();
        std::fs::write(first.join("f.txt"), "original").unwrap();
        cache.publish(&first, "https://h/r", &sha).unwrap();

        let second = cache.staging().unwrap();
        std::fs::write(second.join("f.txt"), "duplicate").unwrap();
        let path = cache.publish(&second, "https://h/r", &sha).unwrap();

        assert_eq!(std::fs::read_to_string(path.join("f.txt")).unwrap(), "original");
        assert!(!second.exists());
    }

    #[test]
    fn eviction_removes_the_least_recently_used_entry_first() {
        let dir = tempfile::tempdir().unwrap();
        // 1 MB budget; each entry below is ~600 KB, so exactly one survives.
        let cache = RepoCache::new(dir.path(), 1);
        let payload = "x".repeat(600 * 1024);

        for (i, sha) in [("1", "e".repeat(40)), ("2", "f".repeat(40))] {
            let staging = cache.staging().unwrap();
            std::fs::write(staging.join("f.txt"), &payload).unwrap();
            cache.publish(&staging, &format!("https://h/{i}"), &sha).unwrap();
            // Distinct mtimes so "least recently used" is well-defined.
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }

        cache.evict_to_budget();
        assert!(cache.get("https://h/1", &"e".repeat(40)).is_none());
        assert!(cache.get("https://h/2", &"f".repeat(40)).is_some());
    }

    #[test]
    fn eviction_never_touches_a_staging_directory() {
        // Another worker may be mid-fetch in there.
        let dir = tempfile::tempdir().unwrap();
        let cache = RepoCache::new(dir.path(), 0);
        let staging = cache.staging().unwrap();
        std::fs::write(staging.join("f.txt"), "x".repeat(1024)).unwrap();
        cache.evict_to_budget();
        assert!(staging.exists());
    }
}
