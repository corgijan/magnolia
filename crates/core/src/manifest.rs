use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    #[serde(rename = "cyclonedx")]
    CycloneDx,
    #[serde(rename = "spdx")]
    Spdx,
}
