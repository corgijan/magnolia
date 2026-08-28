use serde::Deserialize;

/// Only the fields this crate's callers actually use — deps.dev's real
/// `GetVersion` response (docs.deps.dev/api/v3) has many more (licenses,
/// advisories, SLSA provenance, ...), deliberately not modeled here.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct VersionDetail {
    #[serde(default)]
    pub related_projects: Vec<RelatedProject>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelatedProject {
    pub project_key: ProjectKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProjectKey {
    pub id: String,
}

/// Only the fields this crate's callers actually use — deps.dev's real
/// `GetProject` response carries much more project metadata; `scorecard` is
/// itself optional in a real response (absent when deps.dev has none for
/// this project).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProjectDetail {
    pub scorecard: Option<Scorecard>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scorecard {
    pub overall_score: Option<f32>,
    #[serde(default)]
    pub repository: Option<ScorecardRepository>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScorecardRepository {
    pub name: Option<String>,
}
