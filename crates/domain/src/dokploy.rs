//! Dokploy, the first deployment provider: its address and the versions
//! the dashboard works with.
//!
//! Dokploy is still on 0.x, and its API is generated from its tRPC
//! routers, so a minor release can rename or reshape the calls the
//! dashboard makes. The dashboard therefore accepts only the minor release
//! it was tested with. `docs/dokploy.md` lists the calls and the tested
//! version.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{account::DisplayName, connection::UnreachableReason, project::ProjectUrl};

/// The Dokploy release the provider tests run against
/// (`tests/fixtures/dokploy`).
pub const TESTED_DOKPLOY_VERSION: DokployVersion = DokployVersion {
    major: 0,
    minor: 31,
    patch: 1,
};

/// Longest version string accepted from Dokploy.
const MAX_VERSION_LEN: usize = 32;

/// Longest Dokploy API key accepted. Dokploy's keys are far shorter; the
/// bound only keeps a pasted mistake from being sent or stored.
pub const DOKPLOY_KEY_MAX_LEN: usize = 512;

/// Dokploy's base URL, such as `https://dokploy.example.com`, without
/// `/api`. Same shape rules as a project's API URL: http or https, a host,
/// no user name, password, query, or fragment, and no trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
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

    /// Whether the key travels over HTTPS.
    pub fn is_encrypted(&self) -> bool {
        self.0.is_encrypted()
    }

    /// The host name or address, for audit records and messages. Never
    /// empty: parsing requires a host.
    pub fn host(&self) -> String {
        url::Url::parse(self.as_str())
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// The URL of one API call, such as `settings.getDokployVersion`.
    pub fn api(&self, call: &str) -> String {
        format!("{}/api/{call}", self.as_str())
    }
}

/// A Dokploy release number, as `settings.getDokployVersion` reports it
/// (`"v0.31.1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// Why a Dokploy call failed. The messages name no address, key, or
/// response text, so they can be shown to the admin as they are.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DokployError {
    #[error("Dokploy could not be reached. {}", .0.message())]
    Unreachable(UnreachableReason),
    /// Dokploy answers a revoked, expired, or rate-limited key alike.
    #[error(
        "Dokploy refused the API key. Check that it is current, not revoked, and has no rate limit."
    )]
    KeyRejected,
    #[error("Dokploy answered with HTTP {0}.")]
    Http(u16),
    #[error("Dokploy sent an answer the dashboard could not read.")]
    InvalidResponse,
    #[error(
        "Dokploy {found} is not supported. This dashboard works with Dokploy {}, tested with {}.",
        supported_dokploy_range(),
        TESTED_DOKPLOY_VERSION
    )]
    UnsupportedVersion { found: DokployVersion },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DokployKeyError {
    #[error("enter the Dokploy API key")]
    Empty,
    #[error("the Dokploy API key must be at most {DOKPLOY_KEY_MAX_LEN} characters")]
    TooLong,
    #[error("the Dokploy API key must not contain spaces or control characters")]
    InvalidCharacters,
}

/// Checks the shape of a pasted Dokploy API key and returns it without
/// surrounding whitespace. Whether Dokploy accepts it is learned only by
/// calling Dokploy with it.
pub fn check_dokploy_key(raw: &str) -> Result<&str, DokployKeyError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(DokployKeyError::Empty);
    }
    if value.len() > DOKPLOY_KEY_MAX_LEN {
        return Err(DokployKeyError::TooLong);
    }
    // Visible ASCII only: the key travels in an HTTP header.
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(DokployKeyError::InvalidCharacters);
    }
    Ok(value)
}

/// Who did something to the stored connection, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployChange {
    pub at: OffsetDateTime,
    pub by: ChangedBy,
}

/// Who made a change to the stored connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangedBy {
    Account(DisplayName),
    /// The account has been deleted since.
    DeletedAccount,
    /// The server, from the deployment's configuration.
    Deployment,
}

impl ChangedBy {
    /// From the stored account name and deployment flag.
    #[must_use]
    pub fn from_stored(account: Option<DisplayName>, by_deployment: bool) -> Self {
        match (account, by_deployment) {
            (Some(name), _) => Self::Account(name),
            (None, true) => Self::Deployment,
            (None, false) => Self::DeletedAccount,
        }
    }
}

/// The installation's Dokploy connection as the administrator page shows
/// it. It never holds the API key, only whether this server can read the
/// stored one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployConnectionSummary {
    pub url: DokployUrl,
    /// The version Dokploy reported when the key last connected.
    pub version: DokployVersion,
    /// When the stored key last connected: when it was connected, or last
    /// replaced.
    pub verified_at: OffsetDateTime,
    pub connected: DokployChange,
    /// The last key replacement, if the key was replaced since connecting.
    pub key_replaced: Option<DokployChange>,
    /// Whether this server can decrypt the stored key. `false` when it was
    /// written under an encryption key this server does not have.
    pub key_readable: bool,
    /// The deployment supplies the URL and key, so they cannot be replaced
    /// or removed from the administrator page.
    pub from_deployment: bool,
}

/// What the administrator page's Dokploy section shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployOverview {
    /// Whether the server has a credential encryption key, without which
    /// no key can be stored.
    pub storage_available: bool,
    /// `None` when Dokploy is not connected.
    pub connection: Option<DokployConnectionSummary>,
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
    fn keys_are_trimmed_and_bounded() {
        assert_eq!(check_dokploy_key("  abcDEF123_-.  \n"), Ok("abcDEF123_-."));
        assert_eq!(check_dokploy_key(" \t"), Err(DokployKeyError::Empty));
        assert_eq!(
            check_dokploy_key(&"k".repeat(DOKPLOY_KEY_MAX_LEN + 1)),
            Err(DokployKeyError::TooLong)
        );
        assert!(check_dokploy_key(&"k".repeat(DOKPLOY_KEY_MAX_LEN)).is_ok());
        for bad in ["two words", "tab\there", "nul\0", "é-key", "line\nbreak"] {
            assert_eq!(
                check_dokploy_key(bad),
                Err(DokployKeyError::InvalidCharacters),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn error_messages_name_no_address() {
        let messages = [
            DokployError::Unreachable(UnreachableReason::DestinationNotAllowed).to_string(),
            DokployError::KeyRejected.to_string(),
            DokployError::UnsupportedVersion {
                found: DokployVersion::parse("v0.32.0").unwrap(),
            }
            .to_string(),
        ];
        assert!(messages[2].contains("v0.32.0") && messages[2].contains("v0.31.x"));
        for message in messages {
            assert!(!message.contains("127.0.0.1"), "{message}");
            assert!(!message.contains("http"), "{message}");
        }
    }

    #[test]
    fn dokploy_urls_follow_the_api_url_rules() {
        let url = DokployUrl::parse(" https://dokploy.example.com/ ").unwrap();
        assert_eq!(url.as_str(), "https://dokploy.example.com");
        assert_eq!(url.host(), "dokploy.example.com");
        assert_eq!(
            DokployUrl::parse("http://10.0.0.5:3000").unwrap().host(),
            "10.0.0.5"
        );
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
