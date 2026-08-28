use serde::{Deserialize, Serialize};

/// One query for `POST /v1/querybatch`. Construct via
/// [`PackageQuery::by_ecosystem`] whenever an (ecosystem, name, version)
/// triple is derivable — `magnolia-api`'s malicious-package check prefers
/// this over [`PackageQuery::by_purl`] since purl-based matching turned out
/// to be unreliable for Go (verified live against a real `MAL-` entry; see
/// `magnolia_core::purl_to_osv_ecosystem`'s doc comment), falling back to
/// `by_purl` only when ecosystem+name can't be derived or no version is
/// known. OSV rejects a query carrying both `version` and a versioned purl
/// (400 Bad Request) — these two constructors keep that mutually exclusive
/// by construction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PackageQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    package: PackageRef,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct PackageRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
}

impl PackageQuery {
    pub fn by_purl(purl: impl Into<String>) -> Self {
        Self { version: None, package: PackageRef { name: None, ecosystem: None, purl: Some(purl.into()) } }
    }

    pub fn by_ecosystem(ecosystem: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            version: Some(version.into()),
            package: PackageRef { name: Some(name.into()), ecosystem: Some(ecosystem.into()), purl: None },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct QueryBatchResponse {
    #[serde(default)]
    pub results: Vec<QueryResult>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct QueryResult {
    #[serde(default)]
    pub vulns: Vec<VulnId>,
    // `next_page_token` deliberately ignored — see `OsvClient::query_batch`'s
    // doc comment for why pagination isn't followed here.
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct VulnId {
    pub id: String,
}

/// Only the fields `magnolia-api`'s malicious-package check actually uses —
/// OSV's full vulnerability schema has many more (affected, references,
/// severity, ...), deliberately not modeled since nothing here reads them.
#[derive(Debug, Clone, Deserialize)]
pub struct VulnDetail {
    pub id: String,
    pub summary: Option<String>,
}
