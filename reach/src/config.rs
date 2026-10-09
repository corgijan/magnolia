//! Configuration — **env vars only**.
//!
//! Course constraint: swapping the inference server or model must require
//! zero code changes, so every knob that decides *which* model answers, and
//! how long we wait for it, is read from the environment here and nowhere
//! else. During development `REACH_AI_BASE_URL` points at an
//! OpenAI-compatible hosted endpoint; at submission it points at a local
//! Ollama / llama.cpp server. Nothing in this crate knows the difference.

use std::path::PathBuf;
use std::time::Duration;

/// Everything the process needs, resolved once at startup.
#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: String,
    pub server_addr: String,
    /// `None` disables authentication entirely — allowed only because a
    /// local dev run against a fixture repo shouldn't need a token. Startup
    /// logs a warning so it can never be silently true in a deployment.
    pub api_token: Option<String>,
    pub cache_dir: PathBuf,
    pub cache_mb: u64,
    pub ai: AiConfig,
    pub limits: Limits,
    /// Optional credential for private repos, passed to git via
    /// `GIT_CONFIG_*` env vars — never on the command line and never inside
    /// the URL, both of which leak into process listings and error strings.
    pub git_token: Option<String>,
    /// `REACH_TEST_MODE`: skip the startup inference check and answer every
    /// analysis with a canned report (see `pipeline::test_mode`). For
    /// exercising the AISE integration and UI without a model; never for
    /// anything an analyst relies on.
    pub test_mode: bool,
}

/// The OpenAI-compatible inference endpoint. `base_url` is joined with
/// `/v1/chat/completions`; no provider-specific SDK or endpoint appears
/// anywhere in this crate.
#[derive(Debug, Clone)]
pub struct AiConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub max_tokens: u32,
    pub temperature: f32,
}

/// Hard caps. Every one of these bounds work done on attacker-influenceable
/// input (advisory text, repository contents), so they are limits, not
/// tuning hints.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Refuse to index a checkout larger than this.
    pub max_repo_mb: u64,
    /// Most occurrences carried from stage C into the report.
    pub max_sites: usize,
    /// Most occurrences sent to the per-site LLM in stage D. Each one is a
    /// separate inference call, so this is the main latency knob.
    pub max_scored_sites: usize,
    /// Largest single source file the lexer will read.
    pub max_file_kb: u64,
    /// Advisory text is truncated to this many bytes before it reaches a
    /// prompt.
    pub max_advisory_chars: usize,
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// `1`, `true`, `yes`, `on` (any case) — anything else, including unset, is
/// false, so a typo leaves test mode *off*.
fn env_bool(key: &str) -> bool {
    env_string(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn env_parsed<T: std::str::FromStr>(key: &str, default: T) -> T {
    env_string(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Loads `.env` from the crate directory, then the working directory, if
/// either exists. Real environment variables always win — a value already
/// exported must not be silently overridden by a stale file.
///
/// Call this before [`Config::from_env`]. It is a no-op in Docker (no `.env`
/// is copied into the image); it exists so that the workflow `.env.example`
/// documents — copy it to `.env`, put your key in it, `cargo run` — actually
/// works for a native run.
pub fn load_dotenv() {
    // The crate directory first, so `cargo run` works from anywhere in the
    // tree; then the working directory, for a deployed binary sitting next to
    // its own config.
    let crate_env = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    if crate_env.is_file() {
        if let Err(e) = dotenvy::from_path(&crate_env) {
            eprintln!("warning: could not read {}: {e}", crate_env.display());
        }
    }
    // `dotenvy::dotenv` never overwrites an already-set variable, so this
    // cannot clobber what the block above (or the real environment) set.
    let _ = dotenvy::dotenv();
}

impl Config {
    /// Reads the environment. Never panics: a malformed number falls back to
    /// its default rather than taking the process down, since an operator
    /// typo in a cap should not be an outage.
    ///
    /// Call [`load_dotenv`] first if a `.env` file should be honoured.
    pub fn from_env() -> Self {
        Self {
            db_path: env_string("REACH_DB_PATH").unwrap_or_else(|| "reach.db".to_string()),
            server_addr: env_string("REACH_SERVER_ADDR")
                .unwrap_or_else(|| "127.0.0.1:3100".to_string()),
            api_token: env_string("REACH_API_TOKEN"),
            cache_dir: env_string("REACH_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./.reach-cache")),
            cache_mb: env_parsed("REACH_CACHE_MB", 2048),
            ai: AiConfig {
                base_url: env_string("REACH_AI_BASE_URL")
                    .unwrap_or_else(|| "http://localhost:11434".to_string()),
                model: env_string("REACH_AI_MODEL").unwrap_or_else(|| "gemma3:4b".to_string()),
                api_key: env_string("REACH_AI_API_KEY"),
                timeout: Duration::from_secs(env_parsed("REACH_AI_TIMEOUT_SECS", 60)),
                max_tokens: env_parsed("REACH_AI_MAX_TOKENS", 1024),
                // Deterministic by default: the same advisory should produce
                // the same ruleset across eval runs, otherwise the metrics in
                // `eval/` measure sampling noise as much as prompt quality.
                temperature: env_parsed("REACH_AI_TEMPERATURE", 0.0),
            },
            limits: Limits {
                max_repo_mb: env_parsed("REACH_MAX_REPO_MB", 512),
                max_sites: env_parsed("REACH_MAX_SITES", 50),
                max_scored_sites: env_parsed("REACH_MAX_SCORED_SITES", 5),
                max_file_kb: env_parsed("REACH_MAX_FILE_KB", 512),
                max_advisory_chars: env_parsed("REACH_MAX_ADVISORY_CHARS", 12000),
            },
            git_token: env_string("REACH_GIT_TOKEN"),
            test_mode: env_bool("REACH_TEST_MODE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_parsed_falls_back_on_garbage_instead_of_panicking() {
        // An operator typo in a cap must not be an outage.
        std::env::set_var("REACH_TEST_GARBAGE_NUM", "not-a-number");
        assert_eq!(env_parsed::<u64>("REACH_TEST_GARBAGE_NUM", 7), 7);
        std::env::remove_var("REACH_TEST_GARBAGE_NUM");
    }

    #[test]
    fn env_bool_is_off_unless_explicitly_on() {
        for (v, want) in [("true", true), ("ON", true), ("1", true), ("0", false), ("ture", false)] {
            std::env::set_var("REACH_TEST_BOOL", v);
            assert_eq!(env_bool("REACH_TEST_BOOL"), want, "{v}");
        }
        std::env::remove_var("REACH_TEST_BOOL");
        assert!(!env_bool("REACH_TEST_BOOL"));
    }

    #[test]
    fn env_string_treats_whitespace_only_as_unset() {
        // `${REACH_API_TOKEN:-}` in compose expands to an empty string when
        // the operator set nothing; that must read as "no token configured",
        // not as "the token is the empty string" (which would authenticate
        // an empty Authorization header).
        std::env::set_var("REACH_TEST_BLANK", "   ");
        assert_eq!(env_string("REACH_TEST_BLANK"), None);
        std::env::remove_var("REACH_TEST_BLANK");
    }
}
