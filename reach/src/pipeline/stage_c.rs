//! Stage C — every occurrence of the ruleset's terms, with context.
//!
//! Deterministic. Stage B decides *what* to look for; this decides *where it
//! is*, and produces the snippets stages D and the report both use.
//!
//! Occurrences are ranked before the cap is applied, because which five of
//! two hundred hits reach the (expensive) per-site model decides how useful
//! the report is. Ranking is by how load-bearing the occurrence looks —
//! source code outranks a comment, first-party code outranks a test — and it
//! is deterministic, so the same revision always yields the same five.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::lexer::{Context, IdentifierIndex};
use crate::models::NestedCallPattern;

/// Lines of context on each side of the matching line, used when no
/// tree-sitter boundary is available (unvendored language, parse failure,
/// or a boundary wider than [`MAX_BOUNDARY_LINES`]).
const CONTEXT_LINES: u32 = 4;

/// Widest a tree-sitter-detected function/class boundary is trusted for a
/// snippet before falling back to the fixed window — a real function this
/// large is exactly the case where a small window is *more* useful, not
/// less; pasting all of it would bury the matched line instead of framing
/// it.
const MAX_BOUNDARY_LINES: u32 = 60;

/// Rank bonus for an occurrence found via [`crate::treesitter::find_nested_calls`]
/// rather than an independent lexical name match. A structural composition
/// match is strictly stronger evidence — the advisory described a specific
/// nesting, and this occurrence *is* that nesting, not just a place either
/// name happens to appear — so it should outrank every ordinary hit,
/// including code-context ones, before the usual test/example/generated
/// penalties in [`rank_of`] still apply on top.
const STRUCTURAL_MATCH_BONUS: i32 = 500;

/// One occurrence, before stage D has said anything about it.
#[derive(Debug, Clone)]
pub struct RawSite {
    pub path: String,
    pub line: u32,
    pub term: String,
    pub context: Context,
    /// Numbered source lines around the match — the enclosing function or
    /// class when [`crate::treesitter`] has a grammar for the file and
    /// found one within [`MAX_BOUNDARY_LINES`], otherwise the fixed
    /// [`CONTEXT_LINES`] window. Either way, real file line numbers, so
    /// stage D's citation can be checked against them.
    pub snippet: String,
    /// Deterministic rank; higher is more interesting. Reported so a reader
    /// can see why these sites and not others.
    pub rank: i32,
}

/// A file's contents, cached once per scan even though several terms (and
/// possibly a structural pattern too) routinely hit the same file. Keeps
/// both the raw text (tree-sitter parses bytes, not pre-split lines) and
/// the split lines (what the fixed-window fallback renders from), so
/// neither representation is rebuilt per occurrence.
struct CachedFile {
    text: String,
    lines: Vec<String>,
}

fn load_file(scan_root: &Path, path: &str) -> CachedFile {
    let text = std::fs::read_to_string(scan_root.join(path)).unwrap_or_default();
    let lines = text.lines().map(str::to_string).collect();
    CachedFile { text, lines }
}

/// The file extension tree-sitter support is keyed on — everything after
/// the last `.`, or empty for an extensionless file (which then simply
/// matches no vendored grammar, the same outcome as any other unsupported
/// extension).
fn extension_of(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or("")
}

#[derive(Debug, Clone, Default)]
pub struct OccurrenceScan {
    pub sites: Vec<RawSite>,
    /// Before the cap — the difference between this and `sites.len()` is
    /// what the report tells the analyst was left out.
    pub total_found: usize,
    /// Terms that matched nothing at all.
    pub terms_without_hits: Vec<String>,
}

/// Finds and ranks occurrences of `terms` plus any `nested_calls`
/// compositions, capped at `max_sites`.
pub fn find_occurrences(
    index: &IdentifierIndex,
    scan_root: &Path,
    terms: &[String],
    nested_calls: &[NestedCallPattern],
    max_sites: usize,
) -> OccurrenceScan {
    let mut scan = OccurrenceScan::default();
    let mut all: Vec<RawSite> = Vec::new();
    // Cache file contents: several terms (and structural patterns) routinely
    // hit the same file, and re-reading it per term is the difference
    // between one pass and dozens.
    let mut file_cache: HashMap<String, CachedFile> = HashMap::new();

    for term in terms {
        let hits = index.lookup(term);
        if hits.is_empty() {
            scan.terms_without_hits.push(term.clone());
            continue;
        }
        scan.total_found += hits.len();

        for occ in hits {
            let path = index.path_of(occ).to_string();
            let cached = file_cache.entry(path.clone()).or_insert_with(|| load_file(scan_root, &path));
            all.push(RawSite {
                rank: rank_of(&path, occ.context),
                snippet: snippet_for(cached, extension_of(&path), occ.line, None),
                path,
                line: occ.line,
                term: term.clone(),
                context: occ.context,
            });
        }
    }

    // Structural matches: independent of the term loop above, and only
    // attempted where cheap to be right about. Pre-filtered against the
    // lexical index first — a file that doesn't lexically contain *both*
    // names can't possibly contain the composition, so this never parses a
    // file that has no chance of matching.
    for pattern in nested_calls {
        let outer_files: HashSet<u32> = index.lookup(&pattern.outer).iter().map(|o| o.file).collect();
        let inner_files: HashSet<u32> = index.lookup(&pattern.inner).iter().map(|o| o.file).collect();

        for &file_id in outer_files.intersection(&inner_files) {
            let Some(path) = index.files.get(file_id as usize).cloned() else { continue };
            let ext = extension_of(&path).to_string();
            if !crate::treesitter::is_supported(&ext) {
                continue;
            }
            let cached = file_cache.entry(path.clone()).or_insert_with(|| load_file(scan_root, &path));
            for m in crate::treesitter::find_nested_calls(&cached.text, &ext, pattern) {
                scan.total_found += 1;
                all.push(RawSite {
                    rank: rank_of(&path, Context::Code) + STRUCTURAL_MATCH_BONUS,
                    snippet: snippet_for(cached, &ext, m.outer_line, Some(m.inner_line)),
                    path: path.clone(),
                    line: m.outer_line,
                    term: pattern.describe(),
                    context: Context::Code,
                });
            }
        }
    }

    // Rank descending, then path/line ascending so the order is total and
    // stable — an eval run must not depend on HashMap/HashSet iteration
    // order (both are used above).
    all.sort_by(|a, b| {
        b.rank
            .cmp(&a.rank)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.term.cmp(&b.term))
    });
    all.truncate(max_sites);
    scan.sites = all;
    scan
}

/// Deterministic interest score for one occurrence.
fn rank_of(path: &str, context: Context) -> i32 {
    let mut score = match context {
        // A call in code is what the analyst is looking for.
        Context::Code => 100,
        // A string can be a real dynamic reference (reflection, a config
        // key), so it beats a comment but not code.
        Context::StringLiteral => 40,
        // A mention in a comment is evidence that someone thought about the
        // symbol, not that the code calls it.
        Context::Comment => 10,
    };

    let lower = path.to_ascii_lowercase();
    // Test and example code exercises the vulnerable API by design, so a hit
    // there says much less about production exposure than a hit in `src/`.
    if lower.contains("/test") || lower.starts_with("test") || lower.contains("_test.")
        || lower.contains(".test.") || lower.contains("/spec") || lower.contains(".spec.")
        || lower.contains("/example") || lower.contains("/fixtures") || lower.contains("/mock")
    {
        score -= 60;
    }
    if lower.contains("/docs/") || lower.ends_with(".md") {
        score -= 30;
    }
    // Generated code is real, but reading it is rarely where a human starts.
    if lower.contains(".min.js") || lower.contains("generated") || lower.contains(".pb.") {
        score -= 20;
    }
    score
}

/// The matching line with context, each line prefixed by its real number.
/// The numbering is what makes stage D's citation checkable: the model is
/// told to cite a number from the snippet, and
/// [`crate::pipeline::verify_citation`] confirms it against the file.
/// Renders `lines[start..=end]` (1-indexed, inclusive, clamped to the file),
/// each line prefixed by its real file line number — the shared rendering
/// step under both [`snippet_for`]'s boundary-found and fallback paths, so
/// the two only ever differ in *which* range they picked, never in format.
fn render_range(lines: &[String], start: u32, end: u32) -> String {
    let start_idx = start.saturating_sub(1) as usize;
    let end_idx = (end as usize).min(lines.len());
    if lines.is_empty() || start_idx >= end_idx {
        return String::new();
    }
    lines[start_idx..end_idx]
        .iter()
        .enumerate()
        .map(|(i, text)| format!("{:>5} | {}", start_idx + i + 1, crate::ai::truncate(text, 300)))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The snippet for one occurrence: the real enclosing function/class when
/// [`crate::treesitter`] has a grammar for `ext` and finds a boundary
/// within [`MAX_BOUNDARY_LINES`] around `primary_line`, otherwise a fixed
/// [`CONTEXT_LINES`] window. `secondary_line` — the paired call site for a
/// structural match — is folded into the fallback window too, so a
/// composition never renders with one half of it missing even on a file
/// tree-sitter couldn't find a boundary in (e.g. a call at module top
/// level, outside any function).
fn snippet_for(file: &CachedFile, ext: &str, primary_line: u32, secondary_line: Option<u32>) -> String {
    if let Some((start, end)) =
        crate::treesitter::function_boundary(&file.text, ext, primary_line, MAX_BOUNDARY_LINES)
    {
        return render_range(&file.lines, start, end);
    }
    let lo = secondary_line.map_or(primary_line, |s| primary_line.min(s));
    let hi = secondary_line.map_or(primary_line, |s| primary_line.max(s));
    let start = lo.saturating_sub(CONTEXT_LINES).max(1);
    let end = hi + CONTEXT_LINES;
    render_range(&file.lines, start, end)
}

/// The eval suite's baseline: plain case-sensitive substring grep, no index,
/// no lexing, no ranking. Exists so the report's numbers can be compared
/// against the naive approach they are supposed to improve on — a
/// requirement of the course's evaluation deliverable, and the honest way to
/// show what the lexer and the model each actually add.
pub fn grep_baseline(scan_root: &Path, terms: &[String], max_sites: usize) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let walker = walkdir::WalkDir::new(scan_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            !matches!(
                e.file_name().to_str().unwrap_or(""),
                ".git" | "node_modules" | "target" | "dist" | "build"
            )
        });

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
        let rel = entry
            .path()
            .strip_prefix(scan_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        for (i, line) in text.lines().enumerate() {
            if terms.iter().any(|t| line.contains(t.as_str())) {
                out.push((rel.clone(), i as u32 + 1));
                if out.len() >= max_sites {
                    return out;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        dir
    }

    #[test]
    fn finds_occurrences_and_attaches_numbered_snippets() {
        let dir = setup(&[("src/a.js", "line1\nline2\nlookup(x)\nline4\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);

        assert_eq!(scan.sites.len(), 1);
        let site = &scan.sites[0];
        assert_eq!((site.path.as_str(), site.line), ("src/a.js", 3));
        // Line numbers in the snippet are real file numbers, which is what
        // makes the model's citation verifiable.
        assert!(site.snippet.contains("    3 | lookup(x)"));
        assert!(site.snippet.contains("    1 | line1"));
    }

    #[test]
    fn production_code_outranks_tests_comments_and_docs() {
        let dir = setup(&[
            ("src/prod.js", "lookup(x)\n"),
            ("test/prod.test.js", "lookup(x)\n"),
            ("src/commented.js", "// lookup mentioned\n"),
        ]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);

        let order: Vec<&str> = scan.sites.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(order[0], "src/prod.js", "production code should rank first");
        assert_eq!(order.last().copied(), Some("src/commented.js"), "a comment should rank last");
    }

    #[test]
    fn the_cap_is_applied_after_ranking_and_the_true_total_is_kept() {
        let mut files: Vec<(String, String)> = Vec::new();
        for i in 0..10 {
            files.push((format!("test/t{i}.js"), "lookup()\n".to_string()));
        }
        files.push(("src/real.js".to_string(), "lookup()\n".to_string()));
        let refs: Vec<(&str, &str)> =
            files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let dir = setup(&refs);

        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 2);

        assert_eq!(scan.total_found, 11, "the count must not be capped, only the list");
        assert_eq!(scan.sites.len(), 2);
        // The interesting one survived the cap.
        assert_eq!(scan.sites[0].path, "src/real.js");
    }

    #[test]
    fn ordering_is_stable_across_runs() {
        // Eval metrics would be meaningless if the five scored sites varied
        // between runs over the same revision.
        let dir = setup(&[("src/a.js", "lookup()\n"), ("src/b.js", "lookup()\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let first = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);
        for _ in 0..5 {
            let again = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);
            let a: Vec<_> = first.sites.iter().map(|s| (&s.path, s.line)).collect();
            let b: Vec<_> = again.sites.iter().map(|s| (&s.path, s.line)).collect();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn terms_that_match_nothing_are_reported_rather_than_dropped() {
        let dir = setup(&[("a.js", "lookup()\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan =
            find_occurrences(&idx, dir.path(), &["lookup".into(), "absent_symbol".into()], &[], 10);
        assert_eq!(scan.terms_without_hits, vec!["absent_symbol"]);
    }

    #[test]
    fn the_baseline_matches_substrings_where_the_index_matches_identifiers() {
        // This is the difference the eval suite is meant to quantify: grep
        // fires on `catalog` when searching for `log`; the index does not.
        let dir = setup(&[("a.js", "const catalog = 1;\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);

        assert!(find_occurrences(&idx, dir.path(), &["log".to_string()], &[], 10).sites.is_empty());
        assert_eq!(grep_baseline(dir.path(), &["log".to_string()], 10).len(), 1);
    }

    #[test]
    fn a_snippet_at_the_first_line_does_not_underflow() {
        let dir = setup(&[("a.js", "lookup()\nb\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);
        assert!(scan.sites[0].snippet.starts_with("    1 | lookup()"));
    }

    // ---------------------------------------------- tree-sitter boundaries

    #[test]
    fn a_match_inside_a_real_function_gets_the_whole_function_as_its_snippet() {
        // Wider than the fixed +/-4 line window, so this only passes if the
        // tree-sitter boundary path actually fired.
        let src = "fn unrelated() {}\n\nfn target() {\n    let a = 1;\n    let b = 2;\n    lookup(a, b);\n    let c = 3;\n    let d = 4;\n}\n\nfn after() {}\n";
        let dir = setup(&[("src/a.rs", src)]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);

        assert_eq!(scan.sites.len(), 1);
        let snippet = &scan.sites[0].snippet;
        assert!(snippet.contains("fn target()"), "should include the function signature: {snippet}");
        assert!(snippet.contains("let d = 4;"), "should include the whole body: {snippet}");
        assert!(!snippet.contains("fn unrelated()"), "should not spill into a neighbour: {snippet}");
        assert!(!snippet.contains("fn after()"), "should not spill into a neighbour: {snippet}");
    }

    #[test]
    fn a_match_with_no_vendored_grammar_still_uses_the_fixed_window() {
        // .rb has no vendored grammar; must fall back cleanly, not error.
        let src = "def unrelated\nend\n\ndef target\n  a = 1\n  lookup(a)\n  b = 2\nend\n";
        let dir = setup(&[("a.rb", src)]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let scan = find_occurrences(&idx, dir.path(), &["lookup".to_string()], &[], 10);
        // The fixed +/-4 window from line 6 spans lines 2-9, wide enough to
        // catch part of "unrelated" here -- the point is just that this
        // returns *something* sane rather than panicking or erroring.
        assert!(scan.sites[0].snippet.contains("lookup(a)"));
    }

    // ------------------------------------------------------ nested calls

    #[test]
    fn a_real_nested_call_is_found_and_ranked_above_ordinary_hits() {
        let dir = setup(&[(
            "src/a.rs",
            "fn noise() {\n    print(1);\n    test(2);\n}\n\nfn target() {\n    print(test(5));\n}\n",
        )]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        let scan = find_occurrences(&idx, dir.path(), &[], std::slice::from_ref(&pattern), 10);

        assert_eq!(scan.sites.len(), 1, "only the real composition, not the independent calls");
        let site = &scan.sites[0];
        assert_eq!(site.line, 7);
        assert_eq!(site.term, "print(...test(...)...)");
        assert!(site.rank > 100 + STRUCTURAL_MATCH_BONUS - 1);
        assert!(site.snippet.contains("fn target()"));
    }

    #[test]
    fn independent_uses_of_both_names_produce_no_structural_match() {
        // Exactly the false-positive stage C must not produce: `print` and
        // `test` both appear, called independently, never composed.
        let dir = setup(&[("src/a.rs", "fn f() {\n    print(1);\n    test(2);\n}\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        let scan = find_occurrences(&idx, dir.path(), &[], std::slice::from_ref(&pattern), 10);
        assert!(scan.sites.is_empty());
    }

    #[test]
    fn a_file_missing_either_name_lexically_is_never_parsed_for_structure() {
        // Only `print` appears at all -- the pre-filter must skip this file
        // for the structural pass entirely (nothing to prove here beyond
        // "no match", but this is the case the intersection pre-filter
        // exists to short-circuit cheaply).
        let dir = setup(&[("src/a.rs", "fn f() {\n    print(1);\n}\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert!(find_occurrences(&idx, dir.path(), &[], std::slice::from_ref(&pattern), 10).sites.is_empty());
    }

    #[test]
    fn structural_search_degrades_cleanly_for_an_unvendored_language() {
        let dir = setup(&[("a.rb", "print(test(5))\n")]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        // Both names are found lexically (Ruby has no grammar, but the
        // *lexer* still indexes it) -- structural search must still find
        // nothing rather than erroring, since there is no grammar to parse
        // Ruby's actual call syntax with.
        assert!(find_occurrences(&idx, dir.path(), &[], std::slice::from_ref(&pattern), 10).sites.is_empty());
    }

    #[test]
    fn lexical_and_structural_results_combine_in_one_scan() {
        let dir = setup(&[(
            "src/a.rs",
            "fn f() {\n    print(test(5));\n    other_symbol();\n}\n",
        )]);
        let idx = IdentifierIndex::build(dir.path(), 512, 64);
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        let scan = find_occurrences(
            &idx,
            dir.path(),
            &["other_symbol".to_string()],
            std::slice::from_ref(&pattern),
            10,
        );
        assert_eq!(scan.sites.len(), 2);
        // The structural match outranks the ordinary lexical one.
        assert_eq!(scan.sites[0].term, "print(...test(...)...)");
        assert_eq!(scan.sites[1].term, "other_symbol");
    }
}
