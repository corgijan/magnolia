//! `git`-CLI-backed fetcher.
//!
//! Uses the git binary rather than a Rust git library on purpose: the
//! security controls this needs (`GIT_ALLOW_PROTOCOL`, `GIT_TERMINAL_PROMPT`,
//! `core.symlinks=false`, credential handling through `GIT_CONFIG_*`) are
//! all first-class, well-documented git features, and reimplementing the
//! transport would mean reimplementing them too.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use super::{cache::RepoCache, validate_commit, validate_repo_url, Checkout, FetchError, RepoFetcher, RepoTarget};

pub struct GitFetcher {
    cache: RepoCache,
    token: Option<String>,
    timeout: Duration,
    max_repo_mb: u64,
}

impl GitFetcher {
    pub fn new(cache: RepoCache, token: Option<String>, timeout_secs: u64, max_repo_mb: u64) -> Self {
        Self { cache, token, timeout: Duration::from_secs(timeout_secs), max_repo_mb }
    }

    /// A `git` invocation with the hardened environment applied.
    ///
    /// `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` is how the token gets in: it
    /// becomes an `http.extraheader` config value in the child's environment
    /// only. It is never an argument (arguments are world-readable in `ps`)
    /// and never part of the URL (which git echoes back in error messages
    /// and which we log).
    async fn run(&self, dir: &Path, args: &[&str]) -> Result<String, FetchError> {
        run_hardened_git(dir, self.token.as_deref(), self.timeout, args).await
    }
}

/// A `git` invocation with the hardened environment applied. Shared by the
/// fetcher and by [`super::resolve::GitRefResolver`], so resolving a branch
/// name gets exactly the same protocol allowlist and credential handling as
/// fetching the commit it names.
///
/// `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` is how the token gets in: it
/// becomes an `http.extraheader` config value in the child's environment
/// only. It is never an argument (arguments are world-readable in `ps`)
/// and never part of the URL (which git echoes back in error messages
/// and which we log).
pub(crate) fn hardened_git(dir: &Path, token: Option<&str>) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Second lock on the scheme allowlist, inside git itself —
        // covers redirects and submodule URLs, which our own
        // `validate_repo_url` never sees.
        .env("GIT_ALLOW_PROTOCOL", "https:file")
        // Never block a worker on a credential prompt.
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        // Deterministic, locale-independent stderr for the classifier
        // below.
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1");

    match token {
        Some(token) => {
            use base64_lite::encode as b64;
            cmd.env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "http.extraheader")
                .env(
                    "GIT_CONFIG_VALUE_0",
                    format!("Authorization: Basic {}", b64(&format!("x-access-token:{token}"))),
                );
        }
        None => {
            cmd.env("GIT_CONFIG_COUNT", "0");
        }
    }
    cmd
}

/// Runs [`hardened_git`] with a timeout and maps failures onto the
/// analyst-facing taxonomy.
pub(crate) async fn run_hardened_git(
    dir: &Path,
    token: Option<&str>,
    timeout: Duration,
    args: &[&str],
) -> Result<String, FetchError> {
    let mut cmd = hardened_git(dir, token);
    cmd.args(args);

    let output = match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => return Err(FetchError::Timeout(timeout.as_secs())),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FetchError::GitUnavailable(e.to_string()))
        }
        Ok(Err(e)) => return Err(FetchError::Other(e.to_string())),
        Ok(Ok(o)) => o,
    };

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    Err(classify_git_failure(&String::from_utf8_lossy(&output.stderr)))
}

/// Maps git's stderr onto the analyst-facing taxonomy. Substring matching on
/// another program's messages is inherently brittle, so anything
/// unrecognised falls through to [`FetchError::Other`] carrying the real
/// text — a wrong guess would be worse than an honest passthrough.
pub fn classify_git_failure(stderr: &str) -> FetchError {
    let s = stderr.to_ascii_lowercase();
    if s.contains("authentication failed")
        || s.contains("could not read username")
        || s.contains("403")
        || s.contains("permission denied")
    {
        FetchError::AuthFailed
    } else if s.contains("could not resolve host")
        // git writes the URL between "repository" and "not found"
        // ("fatal: repository 'https://h/r' not found"), so these cannot be
        // matched as one adjacent phrase.
        || (s.contains("repository") && s.contains("not found"))
        || s.contains("does not appear to be a git repository")
        || s.contains("failed to connect")
        || s.contains("404")
    {
        FetchError::RepoNotFound
    } else if (s.contains("want") && s.contains("not valid"))
        || s.contains("couldn't find remote ref")
        || s.contains("did not send all necessary objects")
        || s.contains("upload-pack: not our ref")
        || s.contains("no such remote ref")
        || s.contains("unadvertised object")
        // `git archive` against a missing object, in both wordings git uses.
        || s.contains("not a valid object name")
        || s.contains("not a tree object")
    {
        FetchError::CommitUnavailable("requested object".to_string())
    // git says "transport 'ext' not allowed" when GIT_ALLOW_PROTOCOL blocks
    // it, and "not supported" when the binary lacks the helper entirely.
    } else if (s.contains("protocol") || s.contains("transport"))
        && (s.contains("not supported") || s.contains("not allowed"))
    {
        FetchError::InvalidUrl("protocol blocked by GIT_ALLOW_PROTOCOL".to_string())
    } else {
        FetchError::Other(crate::ai::truncate(stderr.trim(), 400))
    }
}

#[async_trait]
impl RepoFetcher for GitFetcher {
    async fn fetch(&self, repo_url: &str, commit: &str) -> Result<Checkout, FetchError> {
        let target = validate_repo_url(repo_url)?;
        let commit = validate_commit(commit)?;

        // A local path is handled by the local fetcher; routing it here would
        // silently bypass its `git archive` path.
        let url = match target {
            RepoTarget::Https(u) => u,
            RepoTarget::Local(_) => {
                return Err(FetchError::InvalidUrl(
                    "local paths are served by LocalPathFetcher, not GitFetcher".to_string(),
                ))
            }
        };

        if let Some(hit) = self.cache.get(&url, &commit) {
            tracing::info!(%url, %commit, "cache hit");
            return Ok(Checkout { scan_root: hit.clone(), root: hit });
        }

        let staging = self.cache.staging()?;
        // Any failure from here on must not leave a half-tree behind.
        let result = self.fetch_into(&staging, &url, &commit).await;
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }

        let size_mb = super::dir_size_bytes(&staging) / (1024 * 1024);
        if size_mb > self.max_repo_mb {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(FetchError::TooLarge(self.max_repo_mb));
        }

        let published = self.cache.publish(&staging, &url, &commit)?;
        self.cache.evict_to_budget();
        Ok(Checkout { scan_root: published.clone(), root: published })
    }
}

impl GitFetcher {
    /// init -> fetch one commit shallowly -> detach onto it.
    ///
    /// Note on `--filter=blob:limit=…`: the plan called for a partial clone,
    /// but a blob filter only defers work that `git checkout` immediately
    /// undoes — every filtered blob is lazily re-fetched, one request each,
    /// the moment the working tree is written. A `--depth 1` fetch plus the
    /// post-fetch size cap gets the same bound with one round trip, so that
    /// is what this does.
    async fn fetch_into(&self, dir: &Path, url: &str, commit: &str) -> Result<(), FetchError> {
        self.run(dir, &["init", "--quiet"]).await?;
        // `--` terminates option parsing: belt and braces alongside the
        // leading-dash rejection in `validate_repo_url`.
        self.run(dir, &["fetch", "--depth", "1", "--quiet", "--no-tags", "--", url, commit])
            .await
            .map_err(|e| match e {
                // At this point the URL resolved and we asked for one exact
                // object, so a generic failure is far more likely to be "that
                // object is not fetchable" than anything else. Keep the
                // commit id in the message, which is what the analyst needs.
                FetchError::CommitUnavailable(_) => FetchError::CommitUnavailable(commit.to_string()),
                other => other,
            })?;
        // `core.symlinks=false` writes symlinks as plain files containing
        // their target, so a hostile repository cannot make the indexer read
        // outside the checkout. The indexer refuses to follow links anyway.
        self.run(dir, &["-c", "core.symlinks=false", "checkout", "--quiet", "--detach", "FETCH_HEAD"])
            .await?;
        Ok(())
    }
}

/// Minimal base64 (standard alphabet, padded). Inlined rather than pulled in
/// as a dependency: it is used for exactly one Authorization header.
mod base64_lite {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_lite::encode(""), "");
        assert_eq!(base64_lite::encode("f"), "Zg==");
        assert_eq!(base64_lite::encode("fo"), "Zm8=");
        assert_eq!(base64_lite::encode("foo"), "Zm9v");
        assert_eq!(base64_lite::encode("foob"), "Zm9vYg==");
        assert_eq!(base64_lite::encode("x-access-token:secret"), "eC1hY2Nlc3MtdG9rZW46c2VjcmV0");
    }

    #[test]
    fn classifies_the_failures_an_analyst_needs_told_apart() {
        assert!(matches!(
            classify_git_failure("fatal: Authentication failed for 'https://h/r'"),
            FetchError::AuthFailed
        ));
        assert!(matches!(
            classify_git_failure("fatal: could not read Username for 'https://h': No such device"),
            FetchError::AuthFailed
        ));
        assert!(matches!(
            classify_git_failure("fatal: repository 'https://h/r' not found"),
            FetchError::RepoNotFound
        ));
        assert!(matches!(
            classify_git_failure("fatal: could not resolve host: nope.invalid"),
            FetchError::RepoNotFound
        ));
        // The force-push case: the commit we were told to analyse is gone.
        assert!(matches!(
            classify_git_failure("error: Server does not allow request for unadvertised object; couldn't find remote ref"),
            FetchError::CommitUnavailable(_)
        ));
        for blocked in [
            "fatal: transport 'ext' not supported",
            "fatal: transport 'ext' not allowed",
        ] {
            assert!(matches!(classify_git_failure(blocked), FetchError::InvalidUrl(_)));
        }
    }

    #[test]
    fn unrecognised_stderr_is_passed_through_rather_than_guessed_at() {
        let e = classify_git_failure("fatal: something entirely new");
        match e {
            FetchError::Other(msg) => assert!(msg.contains("something entirely new")),
            other => panic!("expected passthrough, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refuses_a_local_path_so_it_cannot_bypass_the_local_fetcher() {
        let dir = tempfile::tempdir().unwrap();
        let f = GitFetcher::new(RepoCache::new(dir.path(), 10), None, 5, 100);
        let err = f.fetch("/srv/somewhere", &"a".repeat(40)).await.unwrap_err();
        assert!(matches!(err, FetchError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn validation_runs_before_any_process_is_spawned() {
        let dir = tempfile::tempdir().unwrap();
        let f = GitFetcher::new(RepoCache::new(dir.path(), 10), None, 5, 100);
        assert!(matches!(
            f.fetch("ext::sh -c evil", &"a".repeat(40)).await.unwrap_err(),
            FetchError::InvalidUrl(_)
        ));
        assert!(matches!(
            f.fetch("https://h/r", "HEAD").await.unwrap_err(),
            FetchError::InvalidCommit(_)
        ));
    }
}
