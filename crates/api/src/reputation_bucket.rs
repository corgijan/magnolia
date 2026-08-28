//! Score-bucket thresholds for the "Package reputation" UI's color coding.
//!
//! Edit `RED_MAX`/`YELLOW_MAX` below to change what counts as red/yellow/
//! green anywhere in the app — the per-manifest panel, the deployment-wide
//! aggregation modal, and any future consumer all classify a score through
//! `bucket_for_score` below, so there is exactly one place this ever needs
//! to change. Deliberately kept as a small standalone module rather than
//! inlined into `handlers.rs`, since these two numbers are the one thing in
//! this feature likely to be retuned after watching it run for a while.

/// OpenSSF Scorecard scores range 0.0-10.0. A score `<= RED_MAX` is red,
/// `<= YELLOW_MAX` is yellow, anything higher is green.
pub const RED_MAX: f32 = 2.0;
pub const YELLOW_MAX: f32 = 4.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReputationBucket {
    Red,
    Yellow,
    Green,
}

pub fn bucket_for_score(score: f32) -> ReputationBucket {
    if score <= RED_MAX {
        ReputationBucket::Red
    } else if score <= YELLOW_MAX {
        ReputationBucket::Yellow
    } else {
        ReputationBucket::Green
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_are_inclusive_on_the_low_side() {
        assert_eq!(bucket_for_score(0.0), ReputationBucket::Red);
        assert_eq!(bucket_for_score(RED_MAX), ReputationBucket::Red);
        assert_eq!(bucket_for_score(RED_MAX + 0.1), ReputationBucket::Yellow);
        assert_eq!(bucket_for_score(YELLOW_MAX), ReputationBucket::Yellow);
        assert_eq!(bucket_for_score(YELLOW_MAX + 0.1), ReputationBucket::Green);
        assert_eq!(bucket_for_score(10.0), ReputationBucket::Green);
    }
}
