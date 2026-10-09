//! Stage A — is the affected package present at all?
//!
//! Fully deterministic, and the only stage that can end an analysis on its
//! own: a repository with no trace of the package needs no inference calls,
//! which matters both for latency and for not spending a local model's
//! throughput on questions whose answer is already known.
//!
//! Two independent kinds of evidence, reported separately because they are
//! not equally strong:
//!
//! 1. **Declared** — the package name appears in a dependency manifest or
//!    lock file. Strong: something deliberately depends on it.
//! 2. **Referenced** — a distinctive token from the package name appears in
//!    the identifier index. Weaker, but it catches vendored code and
//!    manifests this scanner does not know about.
//!
//! Absence of both is reported as *no lexical trace in the scanned
//! revision*, never as "not affected" — a transitive dependency pulled in by
//! a lock file this scanner cannot read would look exactly the same, and
//! that gap is stated in the report.

use std::path::Path;

use crate::lexer::IdentifierIndex;

/// Manifests and lock files worth reading in full. Lock files carry
/// transitive dependencies, which is precisely the case a direct-manifest-
/// only scan would miss.
const MANIFESTS: &[&str] = &[
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "requirements.txt", "requirements-dev.txt",
    "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py", "setup.cfg",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "ivy.xml",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock", "gemspec",
    "packages.config", "paket.dependencies", "mix.exs", "mix.lock", "pubspec.yaml",
    "pubspec.lock", "Package.swift", "conanfile.txt", "vcpkg.json", "cabal.project",
];

/// Extensions whose files are always manifests (project files that carry a
/// project-specific name rather than a fixed one).
const MANIFEST_EXTS: &[&str] = &["csproj", "fsproj", "vbproj", "nuspec"];

/// Name fragments too generic to be evidence of anything on their own.
/// Without this list, a Maven coordinate like `org.apache.commons:commons-io`
/// would "match" every repository that contains the word `apache` in a
/// licence header.
const GENERIC_TOKENS: &[&str] = &[
    "org", "com", "io", "net", "www", "js", "py", "rb", "go", "rs", "lib", "libs", "core", "api",
    "app", "web", "src", "util", "utils", "common", "commons", "base", "main", "test", "tests",
    "sdk", "client", "server", "node", "java", "python", "ruby", "php", "npm", "pypi", "maven",
    "types", "plugin", "tool", "tools", "data", "http", "json", "xml", "sys", "std", "dev",
];

#[derive(Debug, Clone, Default)]
pub struct PresenceResult {
    /// `None` means "could not determine" — no package name was supplied,
    /// so absence of evidence says nothing. Distinct from `Some(false)`.
    pub present: Option<bool>,
    /// Analyst-facing lines, each citing where the evidence came from.
    pub evidence: Vec<String>,
    /// Manifest files read.
    pub manifests_scanned: usize,
}

/// Runs the presence check over an already-built index plus a fresh pass
/// over dependency manifests (which the identifier index deliberately does
/// not cover — lock files are excluded there as machine-generated noise).
pub fn check_presence(
    index: &IdentifierIndex,
    scan_root: &Path,
    package_name: Option<&str>,
    max_file_kb: u64,
) -> PresenceResult {
    let Some(package) = package_name.map(str::trim).filter(|p| !p.is_empty()) else {
        return PresenceResult {
            present: None,
            evidence: vec![
                "No package name was supplied, so package presence could not be checked; \
                 the symbol search below ran over the whole revision."
                    .to_string(),
            ],
            manifests_scanned: 0,
        };
    };

    let mut evidence = Vec::new();
    let (declared, manifests_scanned) = scan_manifests(scan_root, package, max_file_kb);
    evidence.extend(declared.iter().cloned());

    let tokens = distinctive_tokens(package);
    let mut referenced = false;
    for token in &tokens {
        let hits = index.lookup(token);
        if let Some(first) = hits.first() {
            referenced = true;
            evidence.push(format!(
                "Identifier `{token}` (from the package name) appears {} time(s), first at {}:{}",
                hits.len(),
                index.path_of(first),
                first.line
            ));
        }
    }

    let present = !declared.is_empty() || referenced;
    if !present {
        evidence.push(format!(
            "No occurrence of `{package}` in {} dependency manifest(s), and none of its \
             distinctive name tokens ({}) appear anywhere in the {} indexed file(s).",
            manifests_scanned,
            if tokens.is_empty() { "none extractable".to_string() } else { tokens.join(", ") },
            index.files.len()
        ));
    }

    PresenceResult { present: Some(present), evidence, manifests_scanned }
}

/// Splits a package coordinate into tokens distinctive enough to be worth
/// searching. Handles npm scopes (`@scope/name`), Maven coordinates
/// (`group:artifact`), Go module paths, and plain names.
pub fn distinctive_tokens(package: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    for raw in package.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let t = raw.trim().to_ascii_lowercase();
        if t.len() < 4 || GENERIC_TOKENS.contains(&t.as_str()) || t.chars().all(|c| c.is_numeric()) {
            continue;
        }
        if !tokens.contains(&t) {
            tokens.push(t);
        }
    }
    tokens
}

/// Reads dependency manifests under `root` and returns one evidence line per
/// file that mentions the package.
fn scan_manifests(root: &Path, package: &str, max_file_kb: u64) -> (Vec<String>, usize) {
    let needle = package.to_ascii_lowercase();
    // A Maven coordinate never appears verbatim in a pom (it is split across
    // <groupId>/<artifactId>), so the artifact half is searched too.
    let alt = needle.rsplit(':').next().unwrap_or(&needle).to_string();

    let mut evidence = Vec::new();
    let mut scanned = 0usize;

    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or("");
            !matches!(name, ".git" | "node_modules" | "target" | "dist" | "build" | ".venv")
        });

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() || !is_manifest(entry.path()) {
            continue;
        }
        if entry.metadata().map(|m| m.len() > max_file_kb * 1024 * 8).unwrap_or(true) {
            // Lock files are legitimately large, hence the ×8 allowance;
            // beyond that we skip rather than read a hundred megabytes.
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
        scanned += 1;
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");

        for (i, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains(&needle) || (alt != needle && lower.contains(&alt)) {
                evidence.push(format!(
                    "Declared in {}:{} — {}",
                    rel,
                    i + 1,
                    crate::ai::truncate(line.trim(), 160)
                ));
                break; // One citation per manifest is enough for a human.
            }
        }
    }

    (evidence, scanned)
}

fn is_manifest(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if MANIFESTS.contains(&name) {
        return true;
    }
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| MANIFEST_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(dir: &Path) -> IdentifierIndex {
        IdentifierIndex::build(dir, 512, 64)
    }

    #[test]
    fn generic_name_fragments_are_not_treated_as_evidence() {
        // `org`/`apache`/`commons` in a licence header must not count as a
        // dependency on commons-io.
        assert_eq!(distinctive_tokens("org.apache.commons:commons-io"), vec!["apache"]);
        assert_eq!(distinctive_tokens("@scope/leftpad"), vec!["scope", "leftpad"]);
        assert_eq!(distinctive_tokens("log4j-core"), vec!["log4j"]);
        assert_eq!(distinctive_tokens("io"), Vec::<String>::new());
    }

    #[test]
    fn a_package_declared_in_a_manifest_is_found_with_a_citation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            "{\n  \"dependencies\": {\n    \"leftpad\": \"1.0.0\"\n  }\n}\n",
        )
        .unwrap();
        let idx = index_of(dir.path());

        let r = check_presence(&idx, dir.path(), Some("leftpad"), 512);
        assert_eq!(r.present, Some(true));
        assert!(r.evidence.iter().any(|e| e.starts_with("Declared in package.json:3")));
    }

    #[test]
    fn a_transitive_package_in_a_lock_file_is_found() {
        // The case a direct-manifest-only scan would miss.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "[[package]]\nname = \"deepdep\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let idx = index_of(dir.path());
        assert_eq!(check_presence(&idx, dir.path(), Some("deepdep"), 512).present, Some(true));
    }

    #[test]
    fn a_maven_coordinate_matches_on_its_artifact_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            "<dependency><groupId>org.apache.logging.log4j</groupId>\n\
             <artifactId>log4j-core</artifactId></dependency>",
        )
        .unwrap();
        let idx = index_of(dir.path());
        let r = check_presence(
            &idx,
            dir.path(),
            Some("org.apache.logging.log4j:log4j-core"),
            512,
        );
        assert_eq!(r.present, Some(true));
    }

    #[test]
    fn an_absent_package_is_reported_as_no_lexical_trace_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{\"dependencies\":{\"other\":\"1\"}}")
            .unwrap();
        std::fs::write(dir.path().join("main.js"), "console.log('hi');\n").unwrap();
        let idx = index_of(dir.path());

        let r = check_presence(&idx, dir.path(), Some("leftpad"), 512);
        assert_eq!(r.present, Some(false));
        // The report must say what was searched, not just "no".
        assert!(r.evidence.iter().any(|e| e.contains("dependency manifest")));
        assert!(r.evidence.iter().any(|e| e.contains("leftpad")));
    }

    #[test]
    fn a_missing_package_name_yields_unknown_rather_than_absent() {
        // Absence of evidence is not evidence of absence: with no package
        // name there is nothing to look for, and claiming "not present"
        // would be a fabricated finding.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "x\n").unwrap();
        let idx = index_of(dir.path());
        let r = check_presence(&idx, dir.path(), None, 512);
        assert_eq!(r.present, None);
        assert!(!r.evidence.is_empty());
    }

    #[test]
    fn vendored_code_with_no_manifest_is_still_found_via_identifiers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("third_party")).unwrap();
        std::fs::write(dir.path().join("third_party/leftpad.js"), "function leftpad() {}\n")
            .unwrap();
        let idx = index_of(dir.path());
        let r = check_presence(&idx, dir.path(), Some("leftpad"), 512);
        assert_eq!(r.present, Some(true));
        assert!(r.evidence.iter().any(|e| e.contains("Identifier `leftpad`")));
    }
}
