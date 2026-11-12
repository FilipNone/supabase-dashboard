//! Dokploy, the first deployment provider: its address and the versions
//! the dashboard works with.
//!
//! Dokploy is still on 0.x, and its API is generated from its tRPC
//! routers, so a minor release can rename or reshape the calls the
//! dashboard makes. The dashboard therefore accepts only the minor release
//! it was tested with. `docs/dokploy.md` lists the calls and the tested
//! version.

use std::fmt;

use crate::project::ProjectUrl;

/// The Dokploy release the provider tests run against
/// (`tests/fixtures/dokploy`).
pub const TESTED_DOKPLOY_VERSION: DokployVersion = DokployVersion {
    major: 0,
    minor: 31,
    patch: 1,
};

/// Longest version string accepted from Dokploy.
const MAX_VERSION_LEN: usize = 32;

/// Dokploy's base URL, such as `https://dokploy.example.com`, without
/// `/api`. Same shape rules as a project's API URL: http or https, a host,
/// no user name, password, query, or fragment, and no trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DokployUrl(ProjectUrl);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "enter Dokploy's address, for example https://dokploy.example.com, without a user name, query string, or fragment"
)]
pub struct InvalidDokployUrl;

impl DokployUrl {
    pub fn parse(raw: &str) -> Result<Self, InvalidDokployUrl> {
        ProjectUrl::parse(raw)
            .map(Self)
            .map_err(|_| InvalidDokployUrl)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The URL of one API call, such as `settings.getDokployVersion`.
    pub fn api(&self, call: &str) -> String {
        format!("{}/api/{call}", self.as_str())
    }
}

/// A Dokploy release number, as `settings.getDokployVersion` reports it
/// (`"v0.31.1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DokployVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl DokployVersion {
    /// Reads `v0.31.1` or `0.31.1`. Pre-release and build suffixes
    /// (`canary`, `-rc.1`) are refused: those builds are never supported.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.len() > MAX_VERSION_LEN {
            return None;
        }
        let digits = raw.strip_prefix('v').unwrap_or(raw);
        let mut parts = digits.split('.');
        let mut next = || {
            parts
                .next()
                .filter(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|part| part.parse::<u32>().ok())
        };
        let version = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        parts.next().is_none().then_some(version)
    }

    /// Whether the dashboard works with this release: the tested minor
    /// release, any patch.
    pub fn is_supported(self) -> bool {
        self.major == TESTED_DOKPLOY_VERSION.major && self.minor == TESTED_DOKPLOY_VERSION.minor
    }
}

impl fmt::Display for DokployVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The supported range in words, for messages: `v0.31.x`.
pub fn supported_dokploy_range() -> String {
    format!(
        "v{}.{}.x",
        TESTED_DOKPLOY_VERSION.major, TESTED_DOKPLOY_VERSION.minor
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn versions_are_read_with_or_without_the_v() {
        let tested = Some(TESTED_DOKPLOY_VERSION);
        assert_eq!(DokployVersion::parse("v0.31.1"), tested);
        assert_eq!(DokployVersion::parse("0.31.1"), tested);
        assert_eq!(TESTED_DOKPLOY_VERSION.to_string(), "v0.31.1");
    }

    #[test]
    fn other_version_strings_are_refused() {
        for raw in [
            "",
            "v",
            "canary",
            "latest",
            "v0.31",
            "v0.31.1.2",
            "v0.31.1-rc.1",
            "v0.31.x",
            "v0..1",
            " v0.31.1",
            "v0.31.+1",
            "v99999999999.0.0",
        ] {
            assert_eq!(DokployVersion::parse(raw), None, "{raw:?}");
        }
        assert_eq!(DokployVersion::parse(&"1".repeat(40)), None);
    }

    #[test]
    fn only_the_tested_minor_release_is_supported() {
        let supported = |raw| DokployVersion::parse(raw).unwrap().is_supported();
        assert!(supported("v0.31.0"));
        assert!(supported("v0.31.1"));
        assert!(supported("v0.31.9"));
        assert!(!supported("v0.30.10"));
        assert!(!supported("v0.32.0"));
        assert!(!supported("v1.31.1"));
        assert_eq!(supported_dokploy_range(), "v0.31.x");
    }

    #[test]
    fn the_fixture_and_the_docs_use_the_tested_version() {
        let fixture = include_str!("../../../tests/fixtures/dokploy/fixture.env");
        let docs = include_str!("../../../docs/dokploy.md");
        let tested = TESTED_DOKPLOY_VERSION.to_string();
        assert!(
            fixture.contains(&format!("DOKPLOY_VERSION={tested}\n")),
            "the fixture does not run Dokploy {tested}"
        );
        assert!(
            docs.contains(&tested),
            "docs/dokploy.md does not name {tested}"
        );
    }

    #[test]
    fn dokploy_urls_follow_the_api_url_rules() {
        let url = DokployUrl::parse(" https://dokploy.example.com/ ").unwrap();
        assert_eq!(url.as_str(), "https://dokploy.example.com");
        assert_eq!(
            url.api("settings.getDokployVersion"),
            "https://dokploy.example.com/api/settings.getDokployVersion"
        );
        for raw in [
            "",
            "dokploy.example.com",
            "ftp://dokploy.example.com",
            "https://user:pass@dokploy.example.com",
            "https://dokploy.example.com/?key=1",
        ] {
            assert_eq!(DokployUrl::parse(raw), Err(InvalidDokployUrl), "{raw:?}");
        }
    }
}
