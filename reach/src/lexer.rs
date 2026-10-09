//! Language-agnostic lexical identifier index.
//!
//! # Why not a parser
//!
//! The original design called for tree-sitter identifier tokens. This is a
//! hand-written scanner instead, and the trade is deliberate: tree-sitter
//! needs one compiled grammar per language, so "language-agnostic" would in
//! practice mean "the eight languages whose grammars we vendored", and a
//! polyglot repository's remaining files would silently contribute nothing.
//! The scanner below reads *every* text file the same way. It is strictly
//! lexical — it cannot resolve imports, aliases, or method dispatch, and it
//! never claims to. That limitation is the reason stages D and E exist, and
//! it is stated in the report.
//!
//! # Recall over precision, on purpose
//!
//! Identifiers are indexed wherever they appear, including inside comments
//! and string literals; the surrounding context is *tagged*
//! ([`Context`]) rather than filtered. So a wrong guess about a file's
//! comment syntax downgrades a tag, it never loses an occurrence — the
//! property that matters when the alternative is telling an analyst "no
//! references found" because the scanner misread a dialect.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Where in the file's lexical structure an occurrence sits. A secondary,
/// deterministic signal: a symbol that appears only in comments is weaker
/// evidence than one that appears in code, and stage D is told which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Code,
    Comment,
    StringLiteral,
}

impl Context {
    pub fn as_str(&self) -> &'static str {
        match self {
            Context::Code => "code",
            Context::Comment => "comment",
            Context::StringLiteral => "string",
        }
    }
}

/// One appearance of one identifier.
#[derive(Debug, Clone, Copy)]
pub struct Occurrence {
    /// Index into [`IdentifierIndex::files`].
    pub file: u32,
    /// 1-indexed.
    pub line: u32,
    pub context: Context,
}

/// Comment and string delimiters for one syntax family.
#[derive(Debug, Clone, Copy)]
pub struct Syntax {
    pub line_comments: &'static [&'static str],
    pub block_comment: Option<(&'static str, &'static str)>,
    /// Characters that open (and close) a string literal.
    pub string_delims: &'static [char],
}

/// The fallback: C-style *and* `#` line comments both recognised. Over-
/// recognising comments in an unknown dialect only ever weakens a tag (see
/// the module docs), so the broad guess is the safe one.
pub const DEFAULT_SYNTAX: Syntax = Syntax {
    line_comments: &["//", "#"],
    block_comment: Some(("/*", "*/")),
    string_delims: &['"', '\'', '`'],
};

pub const C_FAMILY: Syntax = Syntax {
    line_comments: &["//"],
    block_comment: Some(("/*", "*/")),
    string_delims: &['"', '\'', '`'],
};

pub const HASH_FAMILY: Syntax = Syntax {
    line_comments: &["#"],
    block_comment: None,
    string_delims: &['"', '\''],
};

pub const DASH_FAMILY: Syntax = Syntax {
    line_comments: &["--"],
    block_comment: Some(("/*", "*/")),
    string_delims: &['"', '\''],
};

pub const MARKUP_FAMILY: Syntax = Syntax {
    line_comments: &[],
    block_comment: Some(("<!--", "-->")),
    string_delims: &['"', '\''],
};

pub const LISP_FAMILY: Syntax = Syntax {
    line_comments: &[";"],
    block_comment: None,
    string_delims: &['"'],
};

pub fn syntax_for(path: &Path) -> Syntax {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "rs" | "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" | "hh" | "java" | "js" | "mjs" | "cjs"
        | "jsx" | "ts" | "tsx" | "go" | "cs" | "swift" | "kt" | "kts" | "scala" | "php" | "dart"
        | "m" | "mm" | "groovy" | "sol" | "zig" | "json" => C_FAMILY,
        "py" | "pyi" | "rb" | "sh" | "bash" | "zsh" | "pl" | "pm" | "r" | "jl" | "yaml" | "yml"
        | "toml" | "ini" | "cfg" | "conf" | "tf" | "ex" | "exs" | "nim" | "cmake" | "mk"
        | "gradle" | "properties" => HASH_FAMILY,
        "sql" | "lua" | "hs" | "elm" | "ada" => DASH_FAMILY,
        "html" | "htm" | "xml" | "vue" | "svelte" | "md" | "markdown" | "svg" => MARKUP_FAMILY,
        "clj" | "cljs" | "cljc" | "lisp" | "el" | "scm" | "rkt" => LISP_FAMILY,
        _ => DEFAULT_SYNTAX,
    }
}

/// Directories never worth indexing: build output and vendored dependencies.
/// Excluding `node_modules`/`vendor` is a real trade-off — a vulnerable
/// dependency's own source lives there — but stage A's presence check reads
/// dependency *manifests*, which is both cheaper and more reliable than
/// scanning a vendored tree, and indexing them would blow every cap on a
/// typical repository.
const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", "node_modules", "target", "dist", "build", "out", "vendor",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".gradle", ".idea",
    ".next", ".nuxt", "coverage", ".terraform",
];

/// Extensions that are certainly not source text. Content sniffing (a NUL
/// byte in the first block) catches the rest.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "bmp", "webp", "pdf", "zip", "gz", "tgz", "bz2", "xz",
    "7z", "jar", "war", "class", "so", "dylib", "dll", "exe", "bin", "o", "a", "wasm", "woff",
    "woff2", "ttf", "eot", "mp3", "mp4", "mov", "avi", "pyc", "lock",
];

/// A built index over one checkout.
pub struct IdentifierIndex {
    /// Repo-relative paths, in index order.
    pub files: Vec<String>,
    /// Identifier -> every place it appears.
    pub index: HashMap<String, Vec<Occurrence>>,
    pub root: PathBuf,
    /// Files skipped because they exceeded the per-file size cap.
    pub skipped_large: usize,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// True when the whole-checkout byte cap stopped the walk early — the
    /// index is then incomplete and the report says so.
    pub truncated: bool,
}

impl IdentifierIndex {
    /// Walks `root` and indexes every text file under it.
    ///
    /// Symlinks are never followed: a checkout is untrusted input, and a
    /// symlink pointing at `/etc/passwd` (or at a parent of `root`) must not
    /// become indexed content. `git` is separately configured with
    /// `core.symlinks=false`, so this is the second of two locks.
    pub fn build(root: &Path, max_file_kb: u64, max_total_mb: u64) -> Self {
        let max_file_bytes = max_file_kb * 1024;
        let max_total_bytes = max_total_mb * 1024 * 1024;

        let mut idx = IdentifierIndex {
            files: Vec::new(),
            index: HashMap::new(),
            root: root.to_path_buf(),
            skipped_large: 0,
            bytes_scanned: 0,
            truncated: false,
        };

        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_skipped_dir(e.file_name().to_str().unwrap_or("")));

        for entry in walker.filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if has_skipped_ext(path) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > max_file_bytes {
                idx.skipped_large += 1;
                continue;
            }
            if idx.bytes_scanned + meta.len() > max_total_bytes {
                idx.truncated = true;
                break;
            }
            let Ok(bytes) = std::fs::read(path) else { continue };
            if looks_binary(&bytes) {
                continue;
            }
            let Ok(text) = String::from_utf8(bytes) else { continue };

            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let file_id = idx.files.len() as u32;
            idx.files.push(rel);
            idx.bytes_scanned += meta.len();

            for (name, line, context) in scan_identifiers(&text, syntax_for(path)) {
                idx.index.entry(name).or_default().push(Occurrence { file: file_id, line, context });
            }
        }

        idx
    }

    /// Exact-identifier lookup.
    pub fn lookup(&self, term: &str) -> &[Occurrence] {
        self.index.get(term).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn path_of(&self, occ: &Occurrence) -> &str {
        self.files.get(occ.file as usize).map(|s| s.as_str()).unwrap_or("<unknown>")
    }

    pub fn identifier_count(&self) -> usize {
        self.index.len()
    }
}

fn is_skipped_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

fn has_skipped_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| SKIP_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// A NUL byte in the first 8 KiB means binary. Cheap, and the same heuristic
/// git itself uses.
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

/// The scanner. Returns `(identifier, line, context)` for every identifier
/// token in `text`.
///
/// Identifiers are `[A-Za-z_][A-Za-z0-9_]*` plus `$` (jQuery, PHP, shell) —
/// deliberately not Unicode-aware, because every symbol name that appears in
/// a CVE advisory is ASCII, and admitting Unicode word characters would fold
/// prose in non-Latin scripts into the index for no gain.
pub fn scan_identifiers(text: &str, syntax: Syntax) -> Vec<(String, u32, Context)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut line: u32 = 1;
    let mut i = 0usize;
    let mut context = Context::Code;
    // Which delimiter opened the current string / which block comment we are
    // inside, so we know what closes it.
    let mut string_delim: char = '\0';

    while i < bytes.len() {
        let b = bytes[i];

        if b == b'\n' {
            line += 1;
            // A line comment ends at the newline; a block comment or string
            // may legitimately span lines, so only the former resets.
            if context == Context::Comment && !in_block_comment(text, i, syntax) {
                context = Context::Code;
            }
            i += 1;
            continue;
        }

        match context {
            Context::Comment => {
                if let Some((_, close)) = syntax.block_comment {
                    if starts_with_at(text, i, close) {
                        i += close.len();
                        context = Context::Code;
                        continue;
                    }
                }
                // Inside a comment we still collect identifiers — tagged as
                // such — because "the only mention is in a comment" is
                // itself information an analyst wants.
                if is_ident_start(b) {
                    let (name, next) = read_ident(bytes, i);
                    out.push((name, line, Context::Comment));
                    i = next;
                    continue;
                }
                i += 1;
            }
            Context::StringLiteral => {
                if b == b'\\' {
                    // Skip the escaped byte so `"\""` does not close early.
                    i += 2;
                    continue;
                }
                if b as char == string_delim {
                    context = Context::Code;
                    i += 1;
                    continue;
                }
                if is_ident_start(b) {
                    let (name, next) = read_ident(bytes, i);
                    out.push((name, line, Context::StringLiteral));
                    i = next;
                    continue;
                }
                i += 1;
            }
            Context::Code => {
                if let Some((open, _)) = syntax.block_comment {
                    if starts_with_at(text, i, open) {
                        context = Context::Comment;
                        i += open.len();
                        continue;
                    }
                }
                if let Some(marker) = syntax.line_comments.iter().find(|m| starts_with_at(text, i, m))
                {
                    context = Context::Comment;
                    i += marker.len();
                    continue;
                }
                if syntax.string_delims.contains(&(b as char)) {
                    context = Context::StringLiteral;
                    string_delim = b as char;
                    i += 1;
                    continue;
                }
                if is_ident_start(b) {
                    let (name, next) = read_ident(bytes, i);
                    out.push((name, line, Context::Code));
                    i = next;
                    continue;
                }
                i += 1;
            }
        }
    }

    out
}

/// `text[i..].starts_with(needle)`, but never panics.
///
/// `i` walks forward one **byte** at a time through the loop above, and a
/// multi-byte UTF-8 character (an em dash, a curly quote, an emoji — all
/// completely ordinary in a source comment or string literal) leaves `i`
/// sitting on one of its continuation bytes for a beat. Plain `&str`
/// indexing panics the instant that happens; `str::get` is the same lookup
/// with the panic replaced by `None`, which is exactly the answer we want
/// here — a non-boundary position can never be the start of an ASCII marker
/// like `//` or `/*` in the first place, so treating it as "no match" is not
/// just safe, it is correct.
fn starts_with_at(text: &str, i: usize, needle: &str) -> bool {
    text.get(i..).is_some_and(|s| s.starts_with(needle))
}

/// Distinguishes "the newline ends this comment" from "we are inside a block
/// comment that happens to span lines". Only called at newlines, so the
/// backwards scan is bounded by the current line's length in practice.
fn in_block_comment(text: &str, pos: usize, syntax: Syntax) -> bool {
    let Some((open, close)) = syntax.block_comment else { return false };
    let before = &text[..pos];
    match (before.rfind(open), before.rfind(close)) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn read_ident(bytes: &[u8], start: usize) -> (String, usize) {
    let mut end = start;
    while end < bytes.len() && is_ident_continue(bytes[end]) {
        end += 1;
    }
    (String::from_utf8_lossy(&bytes[start..end]).into_owned(), end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str, syntax: Syntax) -> Vec<(String, u32, Context)> {
        scan_identifiers(text, syntax)
    }

    #[test]
    fn a_multi_byte_character_in_a_line_comment_does_not_panic() {
        // Regression test: the exact failure observed scanning a real
        // repository — an em dash inside a `///` doc comment. Before the
        // `starts_with_at` fix, the byte-at-a-time cursor could land inside
        // the em dash's continuation bytes and the next `&str` index panicked
        // the whole worker task.
        let src = "/// Standard library — functions defined in Lisp style.\nfn f() {}\n";
        let got = names(src, C_FAMILY);
        assert!(got.iter().any(|(n, _, c)| n == "f" && *c == Context::Code));
    }

    #[test]
    fn multi_byte_characters_survive_every_context_and_syntax_family() {
        // Comments, strings, and code, each with a character wide enough to
        // span multiple UTF-8 bytes (an em dash is 3, an emoji is 4) —
        // across every family, since each has its own comment/string
        // detection path that walks the same byte cursor.
        for (syntax, src) in [
            (C_FAMILY, "// caf\u{e9} — code\nreal_code\n"),
            (HASH_FAMILY, "# caf\u{e9} — code\nreal_code\n"),
            (DASH_FAMILY, "-- caf\u{e9} — code\nreal_code\n"),
            (MARKUP_FAMILY, "<!-- caf\u{e9} — code -->\nreal_code\n"),
            (LISP_FAMILY, "; caf\u{e9} — code\nreal_code\n"),
            (C_FAMILY, "let s = \"caf\u{e9} \u{1f600} string\"; real_code\n"),
            (C_FAMILY, "/* caf\u{e9} \u{1f600} block */ real_code\n"),
        ] {
            let got = names(src, syntax);
            assert!(
                got.iter().any(|(n, _, _)| n == "real_code"),
                "failed to keep scanning past multi-byte text for {src:?}"
            );
        }
    }

    #[test]
    fn a_multi_byte_character_at_the_very_end_of_the_file_does_not_panic() {
        let src = "real_code // \u{1f600}";
        let got = names(src, C_FAMILY);
        assert!(got.iter().any(|(n, _, _)| n == "real_code"));
    }

    #[test]
    fn tags_code_comment_and_string_separately() {
        let src = "let alpha = \"beta\"; // gamma\n";
        let got = names(src, C_FAMILY);
        let find = |n: &str| got.iter().find(|(x, _, _)| x == n).map(|(_, _, c)| *c);
        assert_eq!(find("alpha"), Some(Context::Code));
        assert_eq!(find("beta"), Some(Context::StringLiteral));
        assert_eq!(find("gamma"), Some(Context::Comment));
    }

    #[test]
    fn a_line_comment_ends_at_the_newline() {
        let src = "// commented\nreal_code\n";
        let got = names(src, C_FAMILY);
        assert_eq!(got.iter().find(|(n, _, _)| n == "real_code").unwrap().2, Context::Code);
    }

    #[test]
    fn a_block_comment_spans_lines() {
        let src = "/* one\n two */ three\n";
        let got = names(src, C_FAMILY);
        let ctx = |n: &str| got.iter().find(|(x, _, _)| x == n).unwrap().2;
        assert_eq!(ctx("one"), Context::Comment);
        assert_eq!(ctx("two"), Context::Comment);
        assert_eq!(ctx("three"), Context::Code);
    }

    #[test]
    fn line_numbers_are_one_indexed_and_survive_multiline_constructs() {
        let src = "a\n/* c1\nc2 */\nb\n";
        let got = names(src, C_FAMILY);
        assert_eq!(got.iter().find(|(n, _, _)| n == "a").unwrap().1, 1);
        assert_eq!(got.iter().find(|(n, _, _)| n == "c2").unwrap().1, 3);
        assert_eq!(got.iter().find(|(n, _, _)| n == "b").unwrap().1, 4);
    }

    #[test]
    fn an_escaped_quote_does_not_close_the_string() {
        let src = r#"x = "a \" still_string"; after"#;
        let got = names(src, C_FAMILY);
        let ctx = |n: &str| got.iter().find(|(x, _, _)| x == n).map(|(_, _, c)| *c);
        assert_eq!(ctx("still_string"), Some(Context::StringLiteral));
        assert_eq!(ctx("after"), Some(Context::Code));
    }

    #[test]
    fn identifiers_inside_comments_are_still_indexed() {
        // The whole point of tagging rather than filtering: "the only
        // mention of this symbol is in a comment" must remain findable.
        let got = names("// TODO call vulnerable_fn here\n", C_FAMILY);
        assert!(got.iter().any(|(n, _, c)| n == "vulnerable_fn" && *c == Context::Comment));
    }

    #[test]
    fn hash_family_treats_hash_as_a_comment_and_c_family_does_not() {
        let src = "value # note\n";
        assert_eq!(
            names(src, HASH_FAMILY).iter().find(|(n, _, _)| n == "note").unwrap().2,
            Context::Comment
        );
        // In Rust, `#` opens an attribute, not a comment.
        assert_eq!(
            names(src, C_FAMILY).iter().find(|(n, _, _)| n == "note").unwrap().2,
            Context::Code
        );
    }

    #[test]
    fn dollar_and_underscore_are_part_of_identifiers() {
        let got = names("$scope._private = 1;", C_FAMILY);
        let found: Vec<&str> = got.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(found.contains(&"$scope"));
        assert!(found.contains(&"_private"));
    }

    #[test]
    fn dotted_access_yields_the_member_name_separately() {
        // Stage C searches bare symbol names, so `obj.lookup()` must produce
        // a `lookup` token -- this is what makes method references findable
        // without resolving the receiver's type.
        let got = names("obj.lookup(x)", C_FAMILY);
        assert!(got.iter().any(|(n, _, _)| n == "lookup"));
    }

    #[test]
    fn syntax_is_selected_by_extension_with_a_broad_fallback() {
        assert_eq!(syntax_for(Path::new("a.py")).line_comments, HASH_FAMILY.line_comments);
        assert_eq!(syntax_for(Path::new("a.rs")).line_comments, C_FAMILY.line_comments);
        // Unknown extension: recognise both families rather than neither.
        assert_eq!(syntax_for(Path::new("a.wat")).line_comments, DEFAULT_SYNTAX.line_comments);
    }

    #[test]
    fn binary_content_is_detected_by_a_nul_byte() {
        assert!(looks_binary(b"abc\0def"));
        assert!(!looks_binary(b"plain text"));
    }

    #[test]
    fn builds_an_index_over_a_real_directory_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "fn lookup() {}\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        std::fs::write(dir.path().join("node_modules/pkg/b.js"), "lookup()\n").unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/c.py"), "def lookup():\n    pass\n").unwrap();

        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let hits = idx.lookup("lookup");
        // Two hits: a.rs and src/c.py. node_modules is skipped.
        assert_eq!(hits.len(), 2);
        let paths: Vec<&str> = hits.iter().map(|o| idx.path_of(o)).collect();
        assert!(paths.contains(&"a.rs"));
        assert!(paths.contains(&"src/c.py"));
        assert!(!paths.iter().any(|p| p.contains("node_modules")));
    }

    #[test]
    fn oversized_files_are_skipped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.txt"), "x".repeat(4096)).unwrap();
        std::fs::write(dir.path().join("small.txt"), "needle\n").unwrap();
        let idx = IdentifierIndex::build(dir.path(), 1, 64);
        assert_eq!(idx.skipped_large, 1);
        assert_eq!(idx.lookup("needle").len(), 1);
    }
}
