use serde::Deserialize;

/// One vulnerability finding, flattened from dtrack's nested response shape
/// into the flat form `magnolia-db`'s `dtrack_findings` table stores.
#[derive(Debug, Clone)]
pub struct DtrackFinding {
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub severity: String,
    pub description: Option<String>,
    pub analysis_state: Option<String>,
    /// Stable per-finding identity, used as half of `dtrack_findings`'
    /// primary key — see `From<RawFinding>` below for how it's derived.
    pub finding_key: String,
    /// dtrack's own UUIDs for the component and vulnerability this finding
    /// is about — needed to address `PUT /api/v1/analysis` (which identifies
    /// a finding by project+component+vulnerability UUID, not by
    /// `finding_key`) when pushing Magnolia's own triage back to dtrack.
    pub component_uuid: String,
    pub vulnerability_uuid: String,
}

/// Raw shape of one entry in dtrack's `GET /api/v1/finding/project/{uuid}`
/// response, as best understood from dtrack's public API docs — NOT
/// verified against a live running instance in this pass (see
/// `DTRACK_PLAN.md`'s "Confidence check on dtrack's actual API" section).
/// Deliberately permissive (`Option` on anything not load-bearing) so an
/// unexpected/missing field degrades gracefully instead of failing the
/// whole sync pass; re-verify this shape against a real instance's
/// `/api/openapi.json` before relying on it in production.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawFinding {
    pub component: RawComponent,
    pub vulnerability: RawVulnerability,
    pub analysis: Option<RawAnalysis>,
    /// `"<componentUuid>:<vulnUuid>"` — dtrack's own stable per-finding key.
    pub matrix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawComponent {
    pub uuid: String,
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawVulnerability {
    pub uuid: String,
    #[serde(rename = "vulnId")]
    pub vuln_id: String,
    pub severity: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawAnalysis {
    pub state: Option<String>,
}

impl From<RawFinding> for DtrackFinding {
    fn from(raw: RawFinding) -> Self {
        // Prefer dtrack's own `matrix` key; fall back to synthesizing one
        // from the component/vulnerability UUIDs so a finding with a
        // missing `matrix` field is never silently dropped.
        let finding_key = raw
            .matrix
            .clone()
            .unwrap_or_else(|| format!("{}:{}", raw.component.uuid, raw.vulnerability.uuid));
        DtrackFinding {
            component_name: raw.component.name,
            component_version: raw.component.version,
            vulnerability_id: raw.vulnerability.vuln_id,
            severity: raw.vulnerability.severity.unwrap_or_else(|| "UNASSIGNED".to_string()),
            description: raw.vulnerability.description,
            analysis_state: raw.analysis.and_then(|a| a.state),
            finding_key,
            component_uuid: raw.component.uuid,
            vulnerability_uuid: raw.vulnerability.uuid,
        }
    }
}
