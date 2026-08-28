use std::collections::{HashMap, HashSet};

use magnolia_db::{Database, NewMaliciousFinding, NewSbomComponent};
use magnolia_osv::{OsvClient, PackageQuery};

/// Runs OSV's `MAL-`-prefixed malicious-package check for one manifest's
/// just-indexed components and stores any hits — called from
/// `index_manifest_components` right after `insert_sbom_components`.
/// Best-effort, same "secondary concern can't block the primary flow" idiom
/// used there and for `record_audit`/`dtrack_sync`: any failure (network,
/// unexpected response shape) is logged and swallowed, never surfaced to the
/// uploader or reflected in the indexing count.
///
/// Skips components with no `purl` — OSV's query needs either a purl or an
/// (ecosystem, name, version) triple, and there's no reliable way to guess an
/// ecosystem from a bare SBOM component name alone.
pub async fn check_and_store_malicious_components(
    db: &Database,
    osv: &OsvClient,
    manifest_hash: &str,
    components: &[NewSbomComponent],
) {
    let purled = purled_components(components);
    if purled.is_empty() {
        return;
    }

    let queries: Vec<PackageQuery> =
        purled.iter().map(|c| PackageQuery::by_purl(c.purl.clone().expect("filtered for Some purl above"))).collect();

    let results = match osv.query_batch(&queries).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(manifest_hash = %manifest_hash, error = %e, "malicious-package check: OSV querybatch failed; skipping");
            return;
        }
    };
    if results.len() != purled.len() {
        tracing::warn!(
            manifest_hash = %manifest_hash,
            expected = purled.len(),
            got = results.len(),
            "malicious-package check: OSV response count didn't match query count; skipping"
        );
        return;
    }

    // A summary is fetched at most once per distinct MAL- id, even when
    // several components in this manifest share the same malicious
    // package/version.
    let mut summaries: HashMap<String, Option<String>> = HashMap::new();
    for id in distinct_mal_ids(&results) {
        let fetched = match osv.get_vuln(&id).await {
            Ok(detail) => detail.summary,
            Err(e) => {
                tracing::warn!(manifest_hash = %manifest_hash, osv_id = %id, error = %e, "malicious-package check: failed to fetch advisory summary");
                None
            }
        };
        summaries.insert(id, fetched);
    }

    let findings = build_findings(&purled, &results, &summaries);
    if findings.is_empty() {
        return;
    }
    if let Err(e) = db.insert_malicious_findings(manifest_hash, &findings).await {
        tracing::warn!(manifest_hash = %manifest_hash, error = %e, "malicious-package check: failed to store findings");
    }
}

/// Components with a usable `purl` — OSV's query needs either a purl or an
/// (ecosystem, name, version) triple, and there's no reliable way to guess an
/// ecosystem from a bare SBOM component name alone. Pure/no I/O so it's
/// unit-testable on its own.
fn purled_components(components: &[NewSbomComponent]) -> Vec<&NewSbomComponent> {
    components.iter().filter(|c| c.purl.as_deref().is_some_and(|p| !p.is_empty())).collect()
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
