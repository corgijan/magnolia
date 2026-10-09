//! Structural refinement on top of the lexer, for a small, deliberately
//! limited set of languages.
//!
//! [`crate::lexer`] stays the universal baseline — a bare-token scanner that
//! works on any text file, with no per-language configuration, and it is
//! what stage A/C's actual identifier search depends on. This module is
//! strictly additive on top of that: for a file whose extension has a
//! vendored grammar, it can (a) find the real function/class boundary
//! around a matched line instead of a fixed context window, and (b) answer
//! a narrow structural question — "is symbol B called inside a call to
//! symbol A, anywhere in this file?" — that no amount of independent
//! per-name lexical matching can express. Everything here degrades to
//! "unavailable" for an unvendored language or a parse failure; nothing in
//! the pipeline depends on it succeeding.
//!
//! # Why only four languages
//!
//! Each grammar is a real Cargo dependency (a small generated C parser).
//! Vendoring "every language" would mean either an unbounded dependency
//! list or reintroducing the exact problem the lexer was chosen to avoid —
//! "language-agnostic" quietly meaning "the languages we bothered to
//! vendor". Rust, JavaScript, Python, and Go are enough to make the
//! feature real without pretending it is universal; the fallback path is
//! what keeps every other language correct, if less precise.
//!
//! # Why structural patterns are built by this code, never by the model
//!
//! [`NestedCallPattern`] carries only two already-grounded symbol names
//! (validated the same way `Ruleset::vulnerable_symbols` is: must appear
//! verbatim in the advisory text). The actual tree-sitter query text is
//! assembled here, from a fixed per-language template, with those two names
//! substituted in — never emitted by the LLM directly. An advisory-supplied
//! query string would be one more thing to sandbox and validate for no
//! real benefit; a model that can name two symbols and their relationship
//! is already expressive enough, and the query syntax itself stays
//! guaranteed-valid because Rust code wrote it.

use std::collections::HashMap;

use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

pub use crate::models::NestedCallPattern;

/// One structural match: `pattern.outer(...)` calling `pattern.inner(...)`
/// was found at this location. The `outer_line`/`inner_line` distinction
/// matters because the two calls are rarely on the same source line, and an
/// analyst needs to see the whole span, not just where `outer` starts.
#[derive(Debug, Clone)]
pub struct StructuralMatch {
    pub outer_line: u32,
    pub inner_line: u32,
}

/// A vendored grammar plus the small amount of per-language knowledge
/// needed to use it: which node kinds count as "a function or class" for
/// boundary detection, and the query template for nested-call matching.
struct LangSupport {
    language: fn() -> Language,
    /// Node kinds treated as a boundary for [`function_boundary`]. Checked
    /// against `Node::kind()`, walking up from the matched line.
    boundary_kinds: &'static [&'static str],
    /// A tree-sitter query template for "call to {outer} containing a call
    /// to {inner}", with `{outer}`/`{inner}` substituted by
    /// [`nested_call_query`]. Differs per grammar because node/field names
    /// for a call expression are not standardised across tree-sitter
    /// grammars (Python's is `call`, most C-family grammars use
    /// `call_expression`, and the callee/argument field names vary too).
    nested_call_template: &'static str,
}

fn registry() -> HashMap<&'static str, LangSupport> {
    let mut m = HashMap::new();
    m.insert(
        "rs",
        LangSupport {
            language: || tree_sitter_rust::LANGUAGE.into(),
            boundary_kinds: &["function_item", "impl_item", "trait_item", "closure_expression"],
            nested_call_template: r#"
                (call_expression
                  function: (identifier) @outer_name
                  arguments: (arguments
                    (call_expression
                      function: (identifier) @inner_name) @inner_call)
                  (#eq? @outer_name "{outer}")
                  (#eq? @inner_name "{inner}")) @outer_call
            "#,
        },
    );
    for ext in ["js", "mjs", "cjs", "jsx", "ts", "tsx"] {
        m.insert(
            ext,
            LangSupport {
                language: || tree_sitter_javascript::LANGUAGE.into(),
                boundary_kinds: &[
                    "function_declaration",
                    "function_expression",
                    "arrow_function",
                    "method_definition",
                    "class_declaration",
                ],
                nested_call_template: r#"
                    (call_expression
                      function: (identifier) @outer_name
                      arguments: (arguments
                        (call_expression
                          function: (identifier) @inner_name) @inner_call)
                      (#eq? @outer_name "{outer}")
                      (#eq? @inner_name "{inner}")) @outer_call
                "#,
            },
        );
    }
    m.insert(
        "py",
        LangSupport {
            language: || tree_sitter_python::LANGUAGE.into(),
            boundary_kinds: &["function_definition", "class_definition"],
            nested_call_template: r#"
                (call
                  function: (identifier) @outer_name
                  arguments: (argument_list
                    (call
                      function: (identifier) @inner_name) @inner_call)
                  (#eq? @outer_name "{outer}")
                  (#eq? @inner_name "{inner}")) @outer_call
            "#,
        },
    );
    m.insert(
        "go",
        LangSupport {
            language: || tree_sitter_go::LANGUAGE.into(),
            boundary_kinds: &["function_declaration", "method_declaration"],
            nested_call_template: r#"
                (call_expression
                  function: (identifier) @outer_name
                  arguments: (argument_list
                    (call_expression
                      function: (identifier) @inner_name) @inner_call)
                  (#eq? @outer_name "{outer}")
                  (#eq? @inner_name "{inner}")) @outer_call
            "#,
        },
    );
    m
}

fn support_for_extension(ext: &str) -> Option<LangSupport> {
    registry().remove(ext.to_ascii_lowercase().as_str())
}

/// Whether a grammar is vendored for this file extension — checked before
/// doing any real parsing work, so callers can skip straight to the
/// lexical-only path for the (overwhelming majority of) unvendored files.
pub fn is_supported(ext: &str) -> bool {
    registry().contains_key(ext.to_ascii_lowercase().as_str())
}

fn parse(source: &str, support: &LangSupport) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser.set_language(&(support.language)()).ok()?;
    parser.parse(source, None)
}

/// The enclosing function/class boundary around `target_line` (1-indexed),
/// as `(start_line, end_line)`, both 1-indexed and inclusive. `None` when
/// the extension is unvendored, the source fails to parse, or no
/// sufficiently boundary-like ancestor contains the line — any of which
/// means the caller should fall back to the fixed-window snippet.
///
/// `max_lines` bounds the result: a boundary wider than that is treated as
/// not found, rather than pasting an enormous function into a report. A
/// real function that happens to be huge is exactly the case where a fixed
/// small window is *more* useful, not less.
pub fn function_boundary(source: &str, ext: &str, target_line: u32, max_lines: u32) -> Option<(u32, u32)> {
    let support = support_for_extension(ext)?;
    let tree = parse(source, &support)?;
    let target_row = target_line.checked_sub(1)? as usize;

    let mut node = tree.root_node().descendant_for_point_range(
        tree_sitter::Point { row: target_row, column: 0 },
        tree_sitter::Point { row: target_row, column: 1 << 20 },
    )?;

    loop {
        if support.boundary_kinds.contains(&node.kind()) {
            let start = node.start_position().row as u32 + 1;
            let end = node.end_position().row as u32 + 1;
            if end.saturating_sub(start) < max_lines {
                return Some((start, end));
            }
            return None;
        }
        node = node.parent()?;
    }
}

/// Builds the concrete query text for one [`NestedCallPattern`], for one
/// language. Substitution only — `outer`/`inner` already passed the same
/// grounding and character-class checks as any other extracted symbol
/// before reaching here (see `pipeline::stage_b::ground_and_clean`), so
/// this never receives anything but `[A-Za-z_][A-Za-z0-9_]*`-shaped text.
fn nested_call_query(support: &LangSupport, pattern: &NestedCallPattern) -> Option<Query> {
    let text = support
        .nested_call_template
        .replace("{outer}", &pattern.outer)
        .replace("{inner}", &pattern.inner);
    Query::new(&(support.language)(), &text).ok()
}

/// Finds every place `pattern.outer(...)` calls `pattern.inner(...)` in
/// `source`. Empty (not an error) when the extension is unvendored, the
/// source fails to parse, or the query template failed to build for this
/// pair of names — all degrade to "no structural matches", never a panic
/// or a pipeline failure; the ordinary per-name lexical search is
/// unaffected either way and remains the fallback that always runs.
pub fn find_nested_calls(source: &str, ext: &str, pattern: &NestedCallPattern) -> Vec<StructuralMatch> {
    let Some(support) = support_for_extension(ext) else { return Vec::new() };
    let Some(tree) = parse(source, &support) else { return Vec::new() };
    let Some(query) = nested_call_query(&support, pattern) else { return Vec::new() };

    let outer_idx = query.capture_index_for_name("outer_name");
    let inner_idx = query.capture_index_for_name("inner_name");

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    let mut out = Vec::new();
    while let Some(m) = matches.next() {
        let outer_line = outer_idx
            .and_then(|i| m.nodes_for_capture_index(i).next())
            .map(|n| n.start_position().row as u32 + 1);
        let inner_line = inner_idx
            .and_then(|i| m.nodes_for_capture_index(i).next())
            .map(|n| n.start_position().row as u32 + 1);
        if let (Some(outer_line), Some(inner_line)) = (outer_line, inner_line) {
            out.push(StructuralMatch { outer_line, inner_line });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unvendored_extensions_report_no_support() {
        assert!(!is_supported("wat"));
        assert!(!is_supported("rb"));
        assert!(is_supported("rs"));
        assert!(is_supported("py"));
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        assert!(is_supported("RS"));
        assert!(is_supported("Py"));
    }

    // ---------------------------------------------------------- boundaries

    #[test]
    fn finds_the_enclosing_rust_function() {
        let src = "fn outer() {\n    let x = 1;\n}\n\nfn target() {\n    let y = 2;\n    let z = 3;\n}\n\nfn after() {}\n";
        // Line 6 ("let y = 2;") is inside `target`, lines 5-8.
        let (start, end) = function_boundary(src, "rs", 6, 100).unwrap();
        assert_eq!((start, end), (5, 8));
    }

    #[test]
    fn finds_the_enclosing_python_function() {
        let src = "def outer():\n    pass\n\ndef target():\n    x = 1\n    y = 2\n\ndef after():\n    pass\n";
        let (start, end) = function_boundary(src, "py", 5, 100).unwrap();
        assert_eq!((start, end), (4, 6));
    }

    #[test]
    fn finds_the_enclosing_javascript_function() {
        let src = "function target() {\n  const a = 1;\n  const b = 2;\n}\n";
        let (start, end) = function_boundary(src, "js", 2, 100).unwrap();
        assert_eq!((start, end), (1, 4));
    }

    #[test]
    fn finds_the_enclosing_go_function() {
        let src = "func target() {\n\tx := 1\n\ty := 2\n}\n";
        let (start, end) = function_boundary(src, "go", 2, 100).unwrap();
        assert_eq!((start, end), (1, 4));
    }

    #[test]
    fn an_unvendored_extension_returns_none() {
        assert!(function_boundary("fn x() {}\n", "wat", 1, 100).is_none());
    }

    #[test]
    fn unparseable_source_returns_none_not_a_panic() {
        // tree-sitter is an error-tolerant parser -- it produces a tree with
        // ERROR nodes rather than failing outright -- so this mainly proves
        // garbage input can't panic the walk, whatever tree comes back.
        let _ = function_boundary("{{{{ not rust at all ][[", "rs", 1, 100);
    }

    #[test]
    fn a_boundary_wider_than_the_cap_is_treated_as_not_found() {
        let mut src = String::from("fn target() {\n");
        for i in 0..50 {
            src.push_str(&format!("    let v{i} = {i};\n"));
        }
        src.push_str("}\n");
        assert!(function_boundary(&src, "rs", 25, 10).is_none());
        assert!(function_boundary(&src, "rs", 25, 100).is_some());
    }

    #[test]
    fn a_line_number_past_the_end_of_the_file_returns_none() {
        assert!(function_boundary("fn x() {}\n", "rs", 9999, 100).is_none());
    }

    // ------------------------------------------------------- nested calls

    #[test]
    fn finds_a_real_nested_call_in_rust() {
        let src = "fn f() {\n    print(test(5));\n}\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        let matches = find_nested_calls(src, "rs", &pattern);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].outer_line, 2);
        assert_eq!(matches[0].inner_line, 2);
    }

    #[test]
    fn does_not_match_when_the_calls_are_not_nested() {
        // The exact false-positive this exists to avoid: both symbols
        // appear, called independently, never composed.
        let src = "fn f() {\n    print(1);\n    test(5);\n}\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert!(find_nested_calls(src, "rs", &pattern).is_empty());
    }

    #[test]
    fn does_not_match_a_call_to_a_different_outer_function() {
        let src = "fn f() {\n    debug(test(5));\n}\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert!(find_nested_calls(src, "rs", &pattern).is_empty());
    }

    #[test]
    fn finds_a_nested_call_in_python() {
        let src = "def f():\n    print(test(5))\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        let matches = find_nested_calls(src, "py", &pattern);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn finds_a_nested_call_in_javascript() {
        let src = "function f() {\n  print(test(5));\n}\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert_eq!(find_nested_calls(src, "js", &pattern).len(), 1);
    }

    #[test]
    fn finds_a_nested_call_in_go() {
        let src = "func f() {\n\tprint(test(5))\n}\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert_eq!(find_nested_calls(src, "go", &pattern).len(), 1);
    }

    #[test]
    fn an_unvendored_extension_yields_no_structural_matches_not_an_error() {
        let src = "print(test(5))";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert!(find_nested_calls(src, "rb", &pattern).is_empty());
    }

    #[test]
    fn describe_reads_as_a_call_shape() {
        let p = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert_eq!(p.describe(), "print(...test(...)...)");
    }

    #[test]
    fn finds_multiple_occurrences_of_the_same_nesting() {
        let src = "fn a() { print(test(1)); }\nfn b() { print(test(2)); }\n";
        let pattern = NestedCallPattern { outer: "print".to_string(), inner: "test".to_string() };
        assert_eq!(find_nested_calls(src, "rs", &pattern).len(), 2);
    }
}
