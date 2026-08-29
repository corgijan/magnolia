/// A component's staleness relative to the latest version deps.dev knows
/// about — computed at read time (not stored), so a policy change or a
/// newly-discovered latest version is reflected on every existing manifest
/// immediately, same "recompute live" convention `evaluate_license_policy`
/// and the compliance profiles already use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    /// The installed version is the latest known version, or newer
    /// (a pre-release/fork ahead of deps.dev's own pick).
    Current,
    /// Behind, but within the same major version — typically a safe,
    /// low-risk upgrade.
    Behind,
    /// Behind by at least one major version bump — a breaking-change
    /// upgrade, worth flagging more prominently than a same-major lag.
    MajorBehind,
    /// Either version isn't parseable SemVer (2.0.0-style
    /// `MAJOR.MINOR.PATCH`) — nothing to compare. `require_semver`
    /// (see the tenant setting of the same name) makes this rarer for a
    /// tenant that opts in, but doesn't guarantee every component's
    /// version string is one, so this is a real, expected outcome, not a
    /// bug.
    Unknown,
}

/// Compares an installed version against deps.dev's own "current" pick for
/// that package (see `freshness_sync.rs`'s doc comment on why that's not
/// necessarily the highest version number) and classifies how far behind it
/// is. A leading `v` (a common tag convention — `v1.2.3`) is stripped from
/// both sides before parsing, since `semver::Version::parse` itself doesn't
/// accept one.
pub fn classify_freshness(current_version: &str, latest_version: &str) -> FreshnessStatus {
    let Some(current) = parse_lenient(current_version) else {
        return FreshnessStatus::Unknown;
    };
    let Some(latest) = parse_lenient(latest_version) else {
        return FreshnessStatus::Unknown;
    };
    if current >= latest {
        FreshnessStatus::Current
    } else if current.major < latest.major {
        FreshnessStatus::MajorBehind
    } else {
        FreshnessStatus::Behind
    }
}

fn parse_lenient(version: &str) -> Option<semver::Version> {
    semver::Version::parse(version.trim().trim_start_matches('v')).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_version_is_current() {
        assert_eq!(classify_freshness("1.2.3", "1.2.3"), FreshnessStatus::Current);
    }

    #[test]
    fn newer_than_latest_is_current() {
        assert_eq!(classify_freshness("2.0.0", "1.9.0"), FreshnessStatus::Current);
    }

    #[test]
    fn same_major_behind_is_behind() {
        assert_eq!(classify_freshness("1.0.0", "1.5.0"), FreshnessStatus::Behind);
    }

    #[test]
    fn older_major_is_major_behind() {
        assert_eq!(classify_freshness("1.9.9", "2.0.0"), FreshnessStatus::MajorBehind);
    }

    #[test]
    fn v_prefix_is_stripped() {
        assert_eq!(classify_freshness("v1.0.0", "v2.0.0"), FreshnessStatus::MajorBehind);
    }

    #[test]
    fn unparseable_current_version_is_unknown() {
        assert_eq!(classify_freshness("not-a-version", "1.0.0"), FreshnessStatus::Unknown);
    }

    #[test]
    fn unparseable_latest_version_is_unknown() {
        assert_eq!(classify_freshness("1.0.0", "not-a-version"), FreshnessStatus::Unknown);
    }

    #[test]
    fn prerelease_current_orders_below_its_own_release() {
        assert_eq!(classify_freshness("1.0.0-rc.1", "1.0.0"), FreshnessStatus::Behind);
    }
}
