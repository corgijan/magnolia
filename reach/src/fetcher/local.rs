//! Filesystem fetcher — offline demo and eval fixtures.
//!
//! `repo_url` is an absolute path to a git repository on this machine.
//! `git archive <sha> | tar -x` into a staging directory rather than copying
//! or checking out in place: the source repository is never written to (an
//! eval run must not be able to disturb its own fixture), and the extracted
//! tree contains exactly the commit's content with no `.git` directory.
//!
//! This is what makes the eval suite reproducible without a network, and
//! what lets the demo run with no internet at all.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;

use super::{cache::RepoCache, validate_commit, validate_repo_url, Checkout, FetchError, RepoFetcher, RepoTarget};

pub struct LocalPathFetcher {
    cache: RepoCache,
    timeout: Duration,
}

impl LocalPathFetcher {
    pub fn new(cache: RepoCache, timeout_secs: u64) -> Self {
        Self { cache, timeout: Duration::from_secs(timeout_secs) }
    }
}

#[async_trait]
impl RepoFetcher for LocalPathFetcher {
    async fn fetch(&self, repo_url: &str, commit: &str) -> Result<Checkout, FetchError> {
        let path = match validate_repo_url(repo_url)? {
            RepoTarget::Local(p) => p,
            RepoTarget::Https(_) => {
                return Err(FetchError::InvalidUrl(
                    "https URLs are served by GitFetcher, not LocalPathFetcher".to_string(),
                ))
            }
        };
        let commit = validate_commit(commit)?;

        if !path.is_dir() {
            return Err(FetchError::RepoNotFound);
        }
        let key = path.to_string_lossy().to_string();
        if let Some(hit) = self.cache.get(&key, &commit) {
            return Ok(Checkout { scan_root: hit.clone(), root: hit });
        }

        let staging = self.cache.staging()?;
        if let Err(e) = archive_into(&path, &commit, &staging, self.timeout).await {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }

        let published = self.cache.publish(&staging, &key, &commit)?;
        self.cache.evict_to_budget();
        Ok(Checkout { scan_root: published.clone(), root: published })
    }
}

/// `git archive --format=tar <sha>` piped into `tar -x`. Both processes are
/// spawned by us with piped stdio; nothing from the repository is executed.
async fn archive_into(
    repo: &Path,
    commit: &str,
    dest: &Path,
    timeout: Duration,
) -> Result<(), FetchError> {
    let mut archive = tokio::process::Command::new("git");
    archive
        .current_dir(repo)
        .args(["archive", "--format=tar", commit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("LC_ALL", "C");

    let out = match tokio::time::timeout(timeout, archive.output()).await {
        Err(_) => return Err(FetchError::Timeout(timeout.as_secs())),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FetchError::GitUnavailable(e.to_string()))
        }
        Ok(Err(e)) => return Err(FetchError::Other(e.to_string())),
        Ok(Ok(o)) => o,
    };
    if !out.status.success() {
        // A fixture repository that does not contain the requested commit is
        // the local equivalent of a force-pushed remote; the shared
        // classifier already knows both wordings git uses for it.
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(match super::git::classify_git_failure(&stderr) {
            FetchError::CommitUnavailable(_) => FetchError::CommitUnavailable(commit.to_string()),
            other => other,
        });
    }

    write_tar(&out.stdout, dest)
}

/// Extracts a tar stream with `tar -x`, refusing absolute paths and
/// traversal (`-P` is deliberately absent, which is what makes GNU/BSD tar
/// strip leading `/` and reject `..` members).
fn write_tar(tar_bytes: &[u8], dest: &Path) -> Result<(), FetchError> {
    use std::io::Write;

    let mut child = std::process::Command::new("tar")
        .current_dir(dest)
        .args(["-x", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| FetchError::Other(format!("tar unavailable: {e}")))?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| FetchError::Other("tar stdin unavailable".to_string()))?
        .write_all(tar_bytes)
        .map_err(|e| FetchError::Other(e.to_string()))?;
    // Dropping stdin signals EOF; without this `wait_with_output` deadlocks.
    drop(child.stdin.take());

    let out = child.wait_with_output().map_err(|e| FetchError::Other(e.to_string()))?;
    if !out.status.success() {
        return Err(FetchError::Other(format!(
            "tar extraction failed: {}",
            crate::ai::truncate(&String::from_utf8_lossy(&out.stderr), 200)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a throwaway git repository and returns its path and HEAD sha.
    fn fixture_repo() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(args)
                // A developer's global config (commit signing with a
                // passphrase-protected key, hooks) must not leak into a
                // throwaway fixture repository.
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["init", "--quiet"]);
        std::fs::write(dir.path().join("app.js"), "const x = lookup(1);\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "initial"]);
        let sha = run(&["rev-parse", "HEAD"]);
        (dir, sha)
    }

    #[tokio::test]
    async fn extracts_the_requested_commit_without_a_git_directory() {
        let (repo, sha) = fixture_repo();
        let cache_dir = tempfile::tempdir().unwrap();
        let f = LocalPathFetcher::new(RepoCache::new(cache_dir.path(), 100), 30);

        let checkout = f.fetch(repo.path().to_str().unwrap(), &sha).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(checkout.scan_root.join("app.js")).unwrap(),
            "const x = lookup(1);\n"
        );
        // `git archive` output carries no history, which is what we want:
        // the analysis only ever looks at one tree.
        assert!(!checkout.root.join(".git").exists());
    }

    #[tokio::test]
    async fn a_second_fetch_of_the_same_commit_is_served_from_cache() {
        let (repo, sha) = fixture_repo();
        let cache_dir = tempfile::tempdir().unwrap();
        let f = LocalPathFetcher::new(RepoCache::new(cache_dir.path(), 100), 30);
        let a = f.fetch(repo.path().to_str().unwrap(), &sha).await.unwrap();
        let b = f.fetch(repo.path().to_str().unwrap(), &sha).await.unwrap();
        assert_eq!(a.root, b.root);
    }

    #[tokio::test]
    async fn a_commit_missing_from_the_repository_is_reported_as_unavailable() {
        let (repo, _) = fixture_repo();
        let cache_dir = tempfile::tempdir().unwrap();
        let f = LocalPathFetcher::new(RepoCache::new(cache_dir.path(), 100), 30);
        let err = f.fetch(repo.path().to_str().unwrap(), &"a".repeat(40)).await.unwrap_err();
        assert!(matches!(err, FetchError::CommitUnavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_missing_directory_is_reported_as_repo_not_found() {
        let cache_dir = tempfile::tempdir().unwrap();
        let f = LocalPathFetcher::new(RepoCache::new(cache_dir.path(), 100), 30);
        let err = f.fetch("/nonexistent/fixture/repo", &"a".repeat(40)).await.unwrap_err();
        assert!(matches!(err, FetchError::RepoNotFound));
    }

    #[tokio::test]
    async fn a_failed_fetch_leaves_no_staging_directory_behind() {
        let cache_root = tempfile::tempdir().unwrap();
        let f = LocalPathFetcher::new(RepoCache::new(cache_root.path(), 100), 30);
        let (repo, _) = fixture_repo();
        let _ = f.fetch(repo.path().to_str().unwrap(), &"a".repeat(40)).await;

        let leftovers: Vec<_> = std::fs::read_dir(cache_root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "staging directories leaked: {leftovers:?}");
    }
}
