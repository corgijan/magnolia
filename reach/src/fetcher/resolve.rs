//! Turning a ref name into the exact commit it names *right now*.
//!
//! Analyses still only ever run against an exact object id (see
//! [`super::validate_commit`]): a report pinned to a moving `main` could not
//! be reproduced or audited. What this module adds is a convenience at the
//! edge: a caller that only knows "the `main` branch of this repository"
//! (AISE, for a manifest uploaded without a recorded commit) may pass that
//! ref, and it is resolved **once, at request time**, to the commit it points
//! at. The analysis, the stored row and the report all carry that commit;
//! the ref is kept alongside it purely as a record of what was asked for.
//!
//! Resolution uses the same hardened git environment as fetching, so a ref
//! lookup cannot reach a protocol or leak a credential that a fetch could
//! not.

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;

use super::git::run_hardened_git;
use super::{validate_commit, validate_repo_url, FetchError, RepoTarget};

/// Upper bound on a ref lookup. It runs inside an HTTP request (AISE's
/// client gives up after 15 s), so it must fail fast rather than hang.
pub const RESOLVE_TIMEOUT_SECS: u64 = 10;

#[async_trait]
pub trait RefResolver: Send + Sync {
    /// Resolves `git_ref` in `repo_url` to a full, lower-case commit id.
    async fn resolve(&self, repo_url: &str, git_ref: &str) -> Result<String, FetchError>;
}

/// Accepts a conservative subset of git's ref-name rules. Anything outside
/// it is rejected rather than escaped: a ref reaches `git` as an argument,
/// so a leading `-` would be an option, and a name git itself would refuse
/// is better reported here with a readable message.
pub fn validate_ref(raw: &str) -> Result<String, FetchError> {
    let r = raw.trim();
    let bad = |why: &str| Err(FetchError::InvalidRef(format!("{} ({why})", crate::ai::truncate(r, 60))));

    if r.is_empty() {
        return bad("empty");
    }
    if r.len() > 200 {
        return bad("too long");
    }
    if r.starts_with('-') {
        return bad("must not start with '-'");
    }
    if r.starts_with('/') || r.ends_with('/') || r.ends_with('.') || r.ends_with(".lock") {
        return bad("not a valid ref name");
    }
    if r.contains("..") || r.contains("//") || r.contains("@{") {
        return bad("not a valid ref name");
    }
    if !r.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '+')) {
        return bad("contains characters outside [A-Za-z0-9._/+-]");
    }
    Ok(r.to_string())
}

/// Picks the commit `git_ref` names out of `git ls-remote` output.
///
/// Precedence follows `git rev-parse`: an exact full ref name, then
/// `refs/tags/<name>`, then `refs/heads/<name>`. For an annotated tag the
/// peeled `^{}` line is preferred, because it names the *commit* rather than
/// the tag object. Pure, so the precedence is unit-testable without a
/// network.
pub fn pick_from_ls_remote(output: &str, git_ref: &str) -> Option<String> {
    let refs: Vec<(&str, &str)> = output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?, parts.next()?))
        })
        .collect();

    let lookup = |name: &str| -> Option<String> {
        let peeled = format!("{name}^{{}}");
        refs.iter()
            .find(|(_, r)| *r == peeled)
            .or_else(|| refs.iter().find(|(_, r)| *r == name))
            .and_then(|(sha, _)| validate_commit(sha).ok())
    };

    let candidates: Vec<String> = if git_ref == "HEAD" || git_ref.starts_with("refs/") {
        vec![git_ref.to_string()]
    } else {
        vec![format!("refs/tags/{git_ref}"), format!("refs/heads/{git_ref}")]
    };
    candidates.iter().find_map(|c| lookup(c))
}

/// Resolves against real remotes with `git ls-remote`, and against local
/// fixture repositories with `git rev-parse`.
pub struct GitRefResolver {
    token: Option<String>,
    timeout: Duration,
}

impl GitRefResolver {
    pub fn new(token: Option<String>, timeout_secs: u64) -> Self {
        Self { token, timeout: Duration::from_secs(timeout_secs) }
    }
}

#[async_trait]
impl RefResolver for GitRefResolver {
    async fn resolve(&self, repo_url: &str, git_ref: &str) -> Result<String, FetchError> {
        let target = validate_repo_url(repo_url)?;
        // Already an exact id: nothing to look up, and nothing to spawn.
        if let Ok(commit) = validate_commit(git_ref) {
            return Ok(commit);
        }
        let git_ref = validate_ref(git_ref)?;

        match target {
            RepoTarget::Https(url) => {
                let scratch = std::env::temp_dir();
                let out = run_hardened_git(
                    &scratch,
                    self.token.as_deref(),
                    self.timeout,
                    &["ls-remote", "--", &url],
                )
                .await?;
                pick_from_ls_remote(&out, &git_ref).ok_or(FetchError::RefNotFound(git_ref))
            }
            RepoTarget::Local(path) => resolve_local(&path, &git_ref, self.timeout).await,
        }
    }
}

async fn resolve_local(path: &Path, git_ref: &str, timeout: Duration) -> Result<String, FetchError> {
    if !path.is_dir() {
        return Err(FetchError::RepoNotFound);
    }
    let spec = format!("{git_ref}^{{commit}}");
    let out = run_hardened_git(
        path,
        None,
        timeout,
        &["rev-parse", "--verify", "--quiet", "--end-of-options", &spec],
    )
    .await
    .map_err(|e| match e {
        // `--quiet` makes an unknown ref a bare non-zero exit with no
        // stderr, which the classifier passes through as `Other("")`.
        FetchError::Other(_) | FetchError::CommitUnavailable(_) => FetchError::RefNotFound(git_ref.to_string()),
        other => other,
    })?;
    validate_commit(out.trim()).map_err(|_| FetchError::RefNotFound(git_ref.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const D: &str = "dddddddddddddddddddddddddddddddddddddddd";

    fn ls_remote() -> String {
        format!(
            "{A}\tHEAD\n{A}\trefs/heads/main\n{B}\trefs/heads/release/1.x\n\
             {C}\trefs/tags/v1.0\n{D}\trefs/tags/v1.0^{{}}\n{B}\trefs/heads/v2\n{C}\trefs/tags/v2\n"
        )
    }

    #[test]
    fn resolves_branches_head_and_full_ref_names() {
        assert_eq!(pick_from_ls_remote(&ls_remote(), "main").as_deref(), Some(A));
        assert_eq!(pick_from_ls_remote(&ls_remote(), "HEAD").as_deref(), Some(A));
        assert_eq!(pick_from_ls_remote(&ls_remote(), "release/1.x").as_deref(), Some(B));
        assert_eq!(pick_from_ls_remote(&ls_remote(), "refs/heads/v2").as_deref(), Some(B));
    }

    #[test]
    fn an_annotated_tag_resolves_to_its_commit_not_the_tag_object() {
        assert_eq!(pick_from_ls_remote(&ls_remote(), "v1.0").as_deref(), Some(D));
    }

    #[test]
    fn a_tag_wins_over_a_branch_of_the_same_name_like_rev_parse() {
        assert_eq!(pick_from_ls_remote(&ls_remote(), "v2").as_deref(), Some(C));
    }

    #[test]
    fn a_suffix_match_is_not_a_match() {
        // `git ls-remote <url> x.x` would match refs/heads/release/1.x; we
        // must not pick a different branch that merely ends the same way.
        assert_eq!(pick_from_ls_remote(&ls_remote(), "1.x"), None);
        assert_eq!(pick_from_ls_remote(&ls_remote(), "nope"), None);
    }

    #[test]
    fn ref_validation_refuses_option_injection_and_git_syntax() {
        for ok in ["main", "release/1.x", "v1.2.3", "feature/foo-bar_baz", "HEAD", "refs/tags/v1"] {
            assert!(validate_ref(ok).is_ok(), "should accept {ok}");
        }
        for bad in [
            "",
            "--upload-pack=touch /tmp/x",
            "-c",
            "main..dev",
            "HEAD@{1}",
            "a b",
            "main~1",
            "main^",
            "/abs",
            "trailing/",
            "x.lock",
            "semi;colon",
        ] {
            assert!(validate_ref(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[tokio::test]
    async fn a_full_commit_id_is_returned_without_touching_git() {
        // A path that does not exist: if this spawned git, it would fail.
        let r = GitRefResolver::new(None, 1);
        assert_eq!(r.resolve("https://h.invalid/r", &"A".repeat(40)).await.unwrap(), "a".repeat(40));
    }

    #[tokio::test]
    async fn an_invalid_ref_is_refused_before_any_process_is_spawned() {
        let r = GitRefResolver::new(None, 1);
        let err = r.resolve("https://h.invalid/r", "--upload-pack=x").await.unwrap_err();
        assert!(matches!(err, FetchError::InvalidRef(_)));
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            // See the same note in `local.rs`'s fixture helper.
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .expect("git available in the test environment");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[tokio::test]
    async fn resolves_branches_and_annotated_tags_in_a_local_repository() {
        let repo = tempfile::tempdir().unwrap();
        let p = repo.path();
        git(p, &["init", "--quiet", "-b", "main"]);
        std::fs::write(p.join("a.txt"), "1").unwrap();
        git(p, &["add", "."]);
        git(p, &["commit", "--quiet", "-m", "one"]);
        let first = git(p, &["rev-parse", "HEAD"]);
        git(p, &["tag", "-a", "v1", "-m", "tag"]);
        std::fs::write(p.join("a.txt"), "2").unwrap();
        git(p, &["commit", "--quiet", "-am", "two"]);
        let second = git(p, &["rev-parse", "HEAD"]);

        let r = GitRefResolver::new(None, 10);
        let url = p.to_str().unwrap();
        assert_eq!(r.resolve(url, "main").await.unwrap(), second);
        assert_eq!(r.resolve(url, "HEAD").await.unwrap(), second);
        assert_eq!(r.resolve(url, "v1").await.unwrap(), first);
        assert!(matches!(r.resolve(url, "missing").await.unwrap_err(), FetchError::RefNotFound(_)));
    }
}
