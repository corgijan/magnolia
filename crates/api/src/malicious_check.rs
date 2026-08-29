use std::collections::{HashMap, HashSet};

use magnolia_db::{Database, MaliciousFindingRecord, NewMaliciousFinding, NewSbomComponent};
use magnolia_osv::{OsvClient, PackageQuery};

/// Runs OSV's `MAL-`-prefixed malicious-package check for one manifest's
/// components and stores any hits — called from `index_manifest_components`
/// right after `insert_sbom_components` (upload time), and again later by
/// `malicious_sync`'s periodic rescan (catching a package that gets flagged
/// `MAL-` *after* it was already uploaded). Best-effort, same "secondary
/// concern can't block the primary flow" idiom used there and for
/// `record_audit`/`dtrack_sync`: any failure (network, unexpected response
/// shape) is logged and swallowed, never surfaced to the uploader or
/// reflected in the indexing count.
///
/// Skips components with no `purl` — OSV's query needs either a purl or an
/// (ecosystem, name, version) triple, and there's no reliable way to guess an
/// ecosystem from a bare SBOM component name alone.
///
/// Queries by (ecosystem, name, version) — via `purl_to_osv_ecosystem` —
/// whenever that's derivable and the component has a version, falling back
/// to a bare purl query otherwise. Not just a style choice: OSV's purl-based
/// `querybatch` matching turned out to be unreliable for Go specifically,
/// verified live against a real `MAL-` entry (MAL-2026-3620,
/// `github.com/BufferZoneCorp/config-loader`) that a purl query misses but
/// an ecosystem+name+version query for the exact same package finds — see
/// `purl_to_osv_ecosystem`'s doc comment for the full repro. Ecosystem+name
/// querying is used whenever available since it's the proven-reliable path,
/// not just as a Go-specific special case.
///
/// `Err(())` only for a querybatch/storage failure (reached OSV and, if
/// there were hits, stored them, is what `Ok` means) — `malicious_sync::sync_pass`
/// uses this to decide whether to advance `manifests.malicious_checked_at`,
/// an `Err` leaves it stale so the manifest gets retried on the next tick
/// instead of waiting out the full rescan interval. A failed summary fetch
/// for an individual `MAL-` id doesn't count as a failure (the finding
/// itself is still stored, just without a summary).
///
/// `Ok` carries only the findings genuinely new in this call (see
/// `Database::insert_malicious_findings`'s doc comment) — callers use a
/// non-empty result to decide whether to emit a `malicious.match_found`
/// webhook event, so a manifest re-confirmed as still-malicious on every
/// periodic rescan doesn't re-fire the same event forever.
pub async fn check_and_store_malicious_components(
    db: &Database,
    osv: &OsvClient,
    manifest_hash: &str,
    components: &[NewSbomComponent],
) -> Result<Vec<MaliciousFindingRecord>, ()> {
    let Some(result) = find_malicious_components(osv, components).await else {
        return Err(());
    };
    if result.malicious.is_empty() {
        return Ok(Vec::new());
    }
    match db.insert_malicious_findings(manifest_hash, &result.malicious).await {
        Ok(new_findings) => Ok(new_findings),
        Err(e) => {
            tracing::warn!(manifest_hash = %manifest_hash, error = %e, "malicious-package check: failed to store findings");
            Err(())
        }
    }
}

/// One component/vulnerability-id pair OSV's querybatch matched that is
/// *not* a `MAL-`-prefixed (confirmed-malicious-package) advisory — a CVE,
/// GHSA, or any other id in whatever vulnerability databases OSV
/// aggregates. Deliberately no severity/summary: getting that would mean
/// one `get_vuln` call per distinct id (same cost `distinct_mal_ids`
/// already bounds for `MAL-` ids), and for a large SBOM the general-vuln id
/// count can be far higher than the rare `MAL-` case — fetching detail for
/// all of them would turn `/verify` from "one querybatch call" into
/// "one call per finding." IDs only, for now.
#[derive(Debug, Clone, PartialEq)]
pub struct ComponentVulnerability {
    pub component_name: String,
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub vuln_id: String,
}

/// Everything one OSV `querybatch` call can tell us about a manifest's
/// components — `malicious` (the `MAL-`-prefixed hits `check_and_store_malicious_components`
/// has always looked for) and, from the exact same response,
/// `vulnerabilities` (every other id OSV matched — CVE/GHSA/etc. — which
/// used to be fetched and silently discarded). Splitting these into two
/// fields rather than one combined list keeps `/verify`'s existing
/// `malicious-packages` check (and its "never fails the verdict" semantics)
/// unchanged while adding a genuinely new `vulnerabilities` check next to
/// it, backed by data this call was already paying for.
#[derive(Debug, Clone)]
pub struct OsvCheckResult {
    pub malicious: Vec<NewMaliciousFinding>,
    pub vulnerabilities: Vec<ComponentVulnerability>,
}

/// The OSV querybatch call itself — everything `check_and_store_malicious_components`
/// does except the DB write, so a caller with nothing to persist (namely
/// `POST /verify`'s dry-run gate) can run the exact same check without a
/// `manifest_hash` to store against. `None` only on a querybatch/response-shape
/// failure (network, unexpected count) — an `OsvCheckResult` with both
/// fields empty is a completed check that found nothing, a meaningfully
/// different outcome for a caller deciding whether to report
/// "not evaluated" vs. "pass".
pub async fn find_malicious_components(
    osv: &OsvClient,
    components: &[NewSbomComponent],
) -> Option<OsvCheckResult> {
    let purled = purled_components(components);
    if purled.is_empty() {
        return Some(OsvCheckResult { malicious: Vec::new(), vulnerabilities: Vec::new() });
    }

    let queries: Vec<PackageQuery> = purled.iter().map(|c| build_query(c)).collect();

    let results = match osv.query_batch(&queries).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "malicious-package check: OSV querybatch failed; skipping");
            return None;
        }
    };
    if results.len() != purled.len() {
        tracing::warn!(
            expected = purled.len(),
            got = results.len(),
            "malicious-package check: OSV response count didn't match query count; skipping"
        );
        return None;
    }

    // A summary is fetched at most once per distinct MAL- id, even when
    // several components share the same malicious package/version.
    let mut summaries: HashMap<String, Option<String>> = HashMap::new();
    for id in distinct_mal_ids(&results) {
        let fetched = match osv.get_vuln(&id).await {
            Ok(detail) => detail.summary,
            Err(e) => {
                tracing::warn!(osv_id = %id, error = %e, "malicious-package check: failed to fetch advisory summary");
                None
            }
        };
        summaries.insert(id, fetched);
    }

    let malicious = build_findings(&purled, &results, &summaries);
    let vulnerabilities = build_vulnerabilities(&purled, &results);
    Some(OsvCheckResult { malicious, vulnerabilities })
}

/// Components with a usable `purl` — OSV's query needs either a purl or an
/// (ecosystem, name, version) triple, and there's no reliable way to guess an
/// ecosystem from a bare SBOM component name alone. Pure/no I/O so it's
/// unit-testable on its own.
fn purled_components(components: &[NewSbomComponent]) -> Vec<&NewSbomComponent> {
    components.iter().filter(|c| c.purl.as_deref().is_some_and(|p| !p.is_empty())).collect()
}

/// Builds one component's `PackageQuery` — ecosystem+name+version whenever
/// derivable (the proven-reliable path, see this module's top-level doc
/// comment), falling back to a bare purl query otherwise. Assumes `c.purl`
/// is `Some` and non-empty (only ever called on `purled_components`'
/// output). Pure/no I/O so it's unit-testable on its own.
fn build_query(c: &NewSbomComponent) -> PackageQuery {
    let purl = c.purl.clone().expect("build_query called on a component with no purl");
    match (magnolia_core::purl_to_osv_ecosystem(&purl), c.version.as_deref()) {
        (Some((ecosystem, name)), Some(version)) => PackageQuery::by_ecosystem(ecosystem, name, version),
        _ => PackageQuery::by_purl(purl),
    }
}

/// Every distinct `MAL-`-prefixed id across all of `results`, in first-seen
/// order — the set of ids `check_and_store_malicious_components` needs a
/// summary for, deduped so a package shared by several components only costs
/// one `get_vuln` call. Pure/no I/O.
fn distinct_mal_ids(results: &[Vec<String>]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for r in results {
        for id in r {
            if id.starts_with("MAL-") && seen.insert(id.clone()) {
                ids.push(id.clone());
            }
        }
    }
    ids
}

/// Cross-references `purled` (in the same order as `results`, as guaranteed
/// by OSV's `querybatch` response ordering) against each component's matched
/// vuln ids, keeping only `MAL-`-prefixed ones and attaching the
/// already-fetched summary for each. Pure/no I/O — the actual matching logic
/// under test, independent of the network calls that produce its inputs.
fn build_findings(
    purled: &[&NewSbomComponent],
    results: &[Vec<String>],
    summaries: &HashMap<String, Option<String>>,
) -> Vec<NewMaliciousFinding> {
    let mut findings = Vec::new();
    for (component, ids) in purled.iter().zip(results.iter()) {
        for id in ids {
            if !id.starts_with("MAL-") {
                continue;
            }
            findings.push(NewMaliciousFinding {
                component_name: component.name.clone(),
                component_version: component.version.clone(),
                purl: component.purl.clone(),
                osv_id: id.clone(),
                summary: summaries.get(id).cloned().flatten(),
            });
        }
    }
    findings
}

/// Same cross-reference as `build_findings`, but keeping the ids that
/// aren't `MAL-`-prefixed instead of discarding them — the general
/// vulnerability data OSV's querybatch was already returning and nobody
/// read. Pure/no I/O.
fn build_vulnerabilities(purled: &[&NewSbomComponent], results: &[Vec<String>]) -> Vec<ComponentVulnerability> {
    let mut vulns = Vec::new();
    for (component, ids) in purled.iter().zip(results.iter()) {
        for id in ids {
            if id.starts_with("MAL-") {
                continue;
            }
            vulns.push(ComponentVulnerability {
                component_name: component.name.clone(),
                component_version: component.version.clone(),
                purl: component.purl.clone(),
                vuln_id: id.clone(),
            });
        }
    }
    vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(name: &str, purl: Option<&str>) -> NewSbomComponent {
        NewSbomComponent {
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            purl: purl.map(|p| p.to_string()),
            cpe: None,
            is_primary: false,
            ecosystem: None,
            registry_name: None,
            license_expr: None,
        }
    }

    #[test]
    fn purled_components_skips_missing_and_empty_purls() {
        let components = vec![
            component("left-pad", Some("pkg:npm/left-pad@1.0.0")),
            component("no-purl", None),
            component("empty-purl", Some("")),
            component("requests", Some("pkg:pypi/requests@2.0.0")),
        ];

        let purled = purled_components(&components);

        assert_eq!(purled.len(), 2);
        assert_eq!(purled[0].name, "left-pad");
        assert_eq!(purled[1].name, "requests");
    }

    #[test]
    fn build_query_prefers_ecosystem_name_version_for_go() {
        // MAL-2026-3620's exact shape — purl-based querybatch misses this
        // real advisory on OSV's side, ecosystem+name+version finds it. See
        // this module's top-level doc comment for the live repro.
        let c = NewSbomComponent {
            name: "config-loader".to_string(),
            version: Some("v1.0.0".to_string()),
            purl: Some("pkg:golang/github.com/BufferZoneCorp/config-loader@v1.0.0".to_string()),
            cpe: None,
            is_primary: false,
            ecosystem: None,
            registry_name: None,
            license_expr: None,
        };

        assert_eq!(build_query(&c), PackageQuery::by_ecosystem("Go", "github.com/BufferZoneCorp/config-loader", "v1.0.0"));
    }

    #[test]
    fn build_query_falls_back_to_purl_when_no_version() {
        let c = NewSbomComponent {
            name: "arc".to_string(),
            version: None,
            purl: Some("pkg:golang/github.com/basekick-labs/arc".to_string()),
            cpe: None,
            is_primary: false,
            ecosystem: None,
            registry_name: None,
            license_expr: None,
        };

        assert_eq!(build_query(&c), PackageQuery::by_purl("pkg:golang/github.com/basekick-labs/arc"));
    }

    #[test]
    fn build_query_falls_back_to_purl_for_an_unmapped_ecosystem() {
        let c = component("libfoo", Some("pkg:deb/debian/libfoo@1.0"));

        assert_eq!(build_query(&c), PackageQuery::by_purl("pkg:deb/debian/libfoo@1.0"));
    }

    #[test]
    fn distinct_mal_ids_filters_prefix_and_dedups_in_first_seen_order() {
        let results = vec![
            vec!["MAL-2024-9999".to_string(), "CVE-2021-1234".to_string()],
            vec!["MAL-2024-0001".to_string(), "MAL-2024-9999".to_string()],
            vec!["GHSA-xxxx-yyyy-zzzz".to_string()],
        ];

        let ids = distinct_mal_ids(&results);

        assert_eq!(ids, vec!["MAL-2024-9999".to_string(), "MAL-2024-0001".to_string()]);
    }

    #[test]
    fn distinct_mal_ids_empty_when_no_malicious_hits() {
        let results = vec![vec!["CVE-2021-1234".to_string()], vec![]];
        assert!(distinct_mal_ids(&results).is_empty());
    }

    #[test]
    fn build_findings_ignores_non_mal_ids_and_attaches_summaries() {
        let left_pad = component("left-pad", Some("pkg:npm/left-pad@1.0.0"));
        let clean = component("clean-pkg", Some("pkg:npm/clean-pkg@1.0.0"));
        let purled = vec![&left_pad, &clean];
        let results = vec![
            vec!["MAL-2024-9999".to_string(), "CVE-2021-1234".to_string()],
            vec![],
        ];
        let mut summaries = HashMap::new();
        summaries.insert("MAL-2024-9999".to_string(), Some("known malicious package".to_string()));

        let findings = build_findings(&purled, &results, &summaries);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].component_name, "left-pad");
        assert_eq!(findings[0].osv_id, "MAL-2024-9999");
        assert_eq!(findings[0].summary.as_deref(), Some("known malicious package"));
    }

    #[test]
    fn build_findings_produces_one_finding_per_component_sharing_a_mal_id() {
        let a = component("pkg-a", Some("pkg:npm/pkg-a@1.0.0"));
        let b = component("pkg-b", Some("pkg:npm/pkg-b@1.0.0"));
        let purled = vec![&a, &b];
        let results = vec![vec!["MAL-2024-0001".to_string()], vec!["MAL-2024-0001".to_string()]];
        let summaries = HashMap::new(); // no summary fetched/available for this id

        let findings = build_findings(&purled, &results, &summaries);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].component_name, "pkg-a");
        assert_eq!(findings[1].component_name, "pkg-b");
        assert!(findings[0].summary.is_none());
    }

    #[test]
    fn build_findings_empty_when_results_shorter_than_purled() {
        // Defensive: matches how the caller already bails out when OSV's
        // response count doesn't match the query count, but build_findings
        // itself should never panic on a length mismatch either.
        let a = component("pkg-a", Some("pkg:npm/pkg-a@1.0.0"));
        let purled = vec![&a];
        let results: Vec<Vec<String>> = vec![];
        let summaries = HashMap::new();

        let findings = build_findings(&purled, &results, &summaries);

        assert!(findings.is_empty());
    }
}
