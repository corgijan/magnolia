/// Minimal best-effort purl parser: extracts `type`/`namespace`/`name`,
/// stripping `@version`, qualifiers (`?...`), and subpath (`#...`). Not a
/// full purl-spec implementation (no percent-decoding of namespace/name
/// segments) — sufficient for mapping onto a registry's own per-ecosystem
/// naming convention, which is all any caller here needs it for.
pub struct ParsedPurl {
    pub purl_type: String,
    pub namespace: Option<String>,
    pub name: String,
}

pub fn parse_purl(purl: &str) -> Option<ParsedPurl> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let rest = rest.split('@').next()?;
    let mut segments = rest.split('/').filter(|s| !s.is_empty());
    let purl_type = segments.next()?.to_string();
    let parts: Vec<&str> = segments.collect();
    if parts.is_empty() {
        return None;
    }
    let (namespace, name) = if parts.len() == 1 {
        (None, parts[0].to_string())
    } else {
        (Some(parts[..parts.len() - 1].join("/")), parts[parts.len() - 1].to_string())
    };
    Some(ParsedPurl { purl_type, namespace, name })
}

/// Maps a purl onto [deps.dev](https://deps.dev)'s `system` enum and its own
/// per-ecosystem package-name convention. deps.dev has no purl-based lookup
/// endpoint (confirmed against its own API reference, docs.deps.dev/api/v3 —
/// `GetPackage`/`GetVersion` take `system`+`name` path parameters only), so
/// this reconstruction is required, unlike OSV's `querybatch` which accepts a
/// purl directly. Returns `None` for a purl deps.dev doesn't track or a
/// shape this mapping doesn't handle (e.g. Maven with no group namespace,
/// which shouldn't happen for a well-formed Maven purl but isn't assumed).
///
/// Per-ecosystem reconstruction, none of it verified against a live deps.dev
/// response (no real package's purl was round-tripped through this and
/// checked against what deps.dev itself calls that package) — re-check
/// against real data if results come back empty for a package you know
/// deps.dev tracks:
/// - npm: scoped packages become `@scope/name` (purl holds the scope as
///   `namespace`, without the leading `@`).
/// - PyPI/crates.io/NuGet/RubyGems: no namespace concept, name as-is.
/// - Go: deps.dev's name is the full module path — namespace and name
///   rejoined with `/`.
/// - Maven: deps.dev's name is `groupId:artifactId` — purl's namespace
///   (groupId) and name (artifactId) joined with `:`.
pub fn purl_to_depsdev_package(purl: &str) -> Option<(&'static str, String)> {
    let p = parse_purl(purl)?;
    match p.purl_type.as_str() {
        "npm" => {
            let name = match p.namespace {
                Some(ns) => format!("@{ns}/{}", p.name),
                None => p.name,
            };
            Some(("NPM", name))
        }
        "pypi" => Some(("PYPI", p.name)),
        "cargo" => Some(("CARGO", p.name)),
        "golang" => {
            let name = match p.namespace {
                Some(ns) => format!("{ns}/{}", p.name),
                None => p.name,
            };
            Some(("GO", name))
        }
        "maven" => {
            let group = p.namespace?;
            Some(("MAVEN", format!("{group}:{}", p.name)))
        }
        "nuget" => Some(("NUGET", p.name)),
        "gem" => Some(("RUBYGEMS", p.name)),
        _ => None,
    }
}

/// Maps a purl onto [OSV](https://osv.dev)'s own `ecosystem` enum
/// (google.github.io/osv.dev/ecosystems.html) and per-ecosystem package-name
/// convention — same shape as `purl_to_depsdev_package`, but OSV's
/// vocabulary differs (`npm`/`PyPI`/`crates.io`/`Go`/`Maven`/`NuGet`/
/// `RubyGems`, not deps.dev's `NPM`/`PYPI`/`CARGO`/`GO`/`MAVEN`/`NUGET`/
/// `RUBYGEMS`).
///
/// Exists because `OsvClient::query_batch`'s purl-based queries turned out
/// to be unreliable for Go specifically: verified live against a real
/// `MAL-` entry (MAL-2026-3620, `github.com/BufferZoneCorp/config-loader`)
/// — `POST /v1/querybatch` with `{"package":{"purl":
/// "pkg:golang/github.com/BufferZoneCorp/config-loader@v1.0.0"}}` returns no
/// match, but the *same* OSV request with `{"package":{"name":
/// "github.com/BufferZoneCorp/config-loader","ecosystem":"Go"},"version":
/// "1.0.0"}` finds it immediately, even though `GET /v1/vulns/MAL-2026-3620`
/// shows that exact purl in its own `affected[].package.purl` field. Purl
/// matching for Go modules on OSV's side appears to not reliably match its
/// own malicious-packages feed — an OSV-side inconsistency, not something
/// fixable here, so `malicious_check.rs` queries by ecosystem+name+version
/// whenever it can (i.e. whenever this returns `Some` and the component has
/// a version), falling back to purl-only otherwise. Not re-verified against
/// every other ecosystem — Go is the one case with live confirmation either
/// way.
pub fn purl_to_osv_ecosystem(purl: &str) -> Option<(&'static str, String)> {
    let p = parse_purl(purl)?;
    match p.purl_type.as_str() {
        "npm" => {
            let name = match p.namespace {
                Some(ns) => format!("@{ns}/{}", p.name),
                None => p.name,
            };
            Some(("npm", name))
        }
        "pypi" => Some(("PyPI", p.name)),
        "cargo" => Some(("crates.io", p.name)),
        "golang" => {
            let name = match p.namespace {
                Some(ns) => format!("{ns}/{}", p.name),
                None => p.name,
            };
            Some(("Go", name))
        }
        "maven" => {
            let group = p.namespace?;
            Some(("Maven", format!("{group}:{}", p.name)))
        }
        "nuget" => Some(("NuGet", p.name)),
        "gem" => Some(("RubyGems", p.name)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_scoped_package() {
        assert_eq!(
            purl_to_depsdev_package("pkg:npm/angular/animation@12.3.1"),
            Some(("NPM", "@angular/animation".to_string()))
        );
    }

    #[test]
    fn npm_unscoped_package() {
        assert_eq!(purl_to_depsdev_package("pkg:npm/lodash@4.17.21"), Some(("NPM", "lodash".to_string())));
    }

    #[test]
    fn pypi_package() {
        assert_eq!(purl_to_depsdev_package("pkg:pypi/requests@2.31.0"), Some(("PYPI", "requests".to_string())));
    }

    #[test]
    fn cargo_package() {
        assert_eq!(purl_to_depsdev_package("pkg:cargo/serde@1.0.0"), Some(("CARGO", "serde".to_string())));
    }

    #[test]
    fn go_module_path() {
        assert_eq!(
            purl_to_depsdev_package("pkg:golang/github.com/pkg/errors@0.9.1"),
            Some(("GO", "github.com/pkg/errors".to_string()))
        );
    }

    #[test]
    fn maven_group_and_artifact() {
        assert_eq!(
            purl_to_depsdev_package("pkg:maven/com.google.guava/guava@31.1-jre"),
            Some(("MAVEN", "com.google.guava:guava".to_string()))
        );
    }

    #[test]
    fn nuget_package() {
        assert_eq!(purl_to_depsdev_package("pkg:nuget/Newtonsoft.Json@13.0.1"), Some(("NUGET", "Newtonsoft.Json".to_string())));
    }

    #[test]
    fn gem_package() {
        assert_eq!(purl_to_depsdev_package("pkg:gem/rails@7.0.0"), Some(("RUBYGEMS", "rails".to_string())));
    }

    #[test]
    fn unsupported_type_returns_none() {
        assert_eq!(purl_to_depsdev_package("pkg:deb/debian/curl@7.74.0"), None);
    }

    #[test]
    fn malformed_purl_returns_none() {
        assert_eq!(purl_to_depsdev_package("not-a-purl"), None);
        assert_eq!(purl_to_depsdev_package("pkg:"), None);
    }

    #[test]
    fn strips_qualifiers_and_subpath() {
        let p = parse_purl("pkg:npm/lodash@4.17.21?foo=bar#sub/path").unwrap();
        assert_eq!(p.purl_type, "npm");
        assert_eq!(p.name, "lodash");
    }

    #[test]
    fn osv_go_module_path_matches_the_real_mal_advisory_case() {
        // MAL-2026-3620 — verified live against OSV during testing.
        assert_eq!(
            purl_to_osv_ecosystem("pkg:golang/github.com/BufferZoneCorp/config-loader@v1.0.0"),
            Some(("Go", "github.com/BufferZoneCorp/config-loader".to_string()))
        );
    }

    #[test]
    fn osv_npm_scoped_package() {
        assert_eq!(
            purl_to_osv_ecosystem("pkg:npm/angular/animation@12.3.1"),
            Some(("npm", "@angular/animation".to_string()))
        );
    }

    #[test]
    fn osv_pypi_package() {
        assert_eq!(purl_to_osv_ecosystem("pkg:pypi/requests@2.31.0"), Some(("PyPI", "requests".to_string())));
    }

    #[test]
    fn osv_cargo_package() {
        assert_eq!(purl_to_osv_ecosystem("pkg:cargo/serde@1.0.0"), Some(("crates.io", "serde".to_string())));
    }

    #[test]
    fn osv_maven_group_and_artifact() {
        assert_eq!(
            purl_to_osv_ecosystem("pkg:maven/com.google.guava/guava@31.1-jre"),
            Some(("Maven", "com.google.guava:guava".to_string()))
        );
    }

    #[test]
    fn osv_nuget_package() {
        assert_eq!(purl_to_osv_ecosystem("pkg:nuget/Newtonsoft.Json@13.0.1"), Some(("NuGet", "Newtonsoft.Json".to_string())));
    }

    #[test]
    fn osv_gem_package() {
        assert_eq!(purl_to_osv_ecosystem("pkg:gem/rails@7.0.0"), Some(("RubyGems", "rails".to_string())));
    }

    #[test]
    fn osv_unsupported_type_returns_none() {
        assert_eq!(purl_to_osv_ecosystem("pkg:deb/debian/curl@7.74.0"), None);
    }
}
