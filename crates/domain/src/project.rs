//! Dashboard projects: registry entries for existing self-hosted Supabase
//! stacks. A project belongs to one organization and points at one stack's
//! API gateway. Registering a project never creates or changes the stack,
//! and unregistering it never deletes anything there.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::authz::OrgRole;

pub const PROJECT_NAME_MAX_CHARS: usize = 64;
/// Upper bound on the stored API URL.
pub const PROJECT_URL_MAX_LEN: usize = 2048;
/// Upper bound on projects in one organization. Keeps the project list and
/// its query bounded.
pub const MAX_PROJECTS_PER_ORGANIZATION: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProjectInputError {
    #[error("enter a project name")]
    EmptyName,
    #[error("the project name must be at most {PROJECT_NAME_MAX_CHARS} characters")]
    NameTooLong,
    #[error("the project name must not contain control characters")]
    NameControlChars,
    #[error("enter the project's API URL, for example https://supabase.example.com")]
    InvalidUrl,
    #[error("the API URL must be at most {PROJECT_URL_MAX_LEN} characters")]
    UrlTooLong,
    #[error("the API URL must start with https:// or http://")]
    UrlScheme,
    #[error("the API URL must not contain a user name or password")]
    UrlCredentials,
    #[error("the API URL must not contain a query string or fragment")]
    UrlQuery,
    #[error(
        "this URL uses unencrypted HTTP; confirm that the network between the dashboard \
         and the project is trusted"
    )]
    UnencryptedNotConfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectName(String);

impl ProjectName {
    pub fn parse(raw: &str) -> Result<Self, ProjectInputError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(ProjectInputError::EmptyName);
        }
        if value.chars().count() > PROJECT_NAME_MAX_CHARS {
            return Err(ProjectInputError::NameTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(ProjectInputError::NameControlChars);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProjectName {
    type Error = ProjectInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ProjectName> for String {
    fn from(value: ProjectName) -> Self {
        value.0
    }
}

/// Base URL of a stack's API gateway (Kong in the standard self-hosted
/// setup), such as `https://supabase.example.com`.
///
/// It is an identifier, not a credential, so it may be shown to every
/// member. It must not carry a user name or password, a query string, or a
/// fragment. The stored form has no trailing slash.
///
/// Parsing checks the shape only. Whether the dashboard may connect to the
/// address it resolves to is decided on the server at connection time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectUrl(String);

impl ProjectUrl {
    pub fn parse(raw: &str) -> Result<Self, ProjectInputError> {
        let raw = raw.trim();
        if raw.len() > PROJECT_URL_MAX_LEN {
            return Err(ProjectInputError::UrlTooLong);
        }
        let parsed = url::Url::parse(raw).map_err(|_| ProjectInputError::InvalidUrl)?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(ProjectInputError::UrlScheme);
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(ProjectInputError::InvalidUrl);
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ProjectInputError::UrlCredentials);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ProjectInputError::UrlQuery);
        }
        let value = parsed.as_str().trim_end_matches('/').to_owned();
        if value.len() > PROJECT_URL_MAX_LEN {
            return Err(ProjectInputError::UrlTooLong);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether traffic to this URL is protected by TLS.
    pub fn is_encrypted(&self) -> bool {
        self.0.starts_with("https://")
    }
}

impl TryFrom<String> for ProjectUrl {
    type Error = ProjectInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ProjectUrl> for String {
    fn from(value: ProjectUrl) -> Self {
        value.0
    }
}

/// Validates a URL for registration. Plain HTTP needs an explicit
/// confirmation from the operator, because credentials stored for the
/// project will later travel over that connection.
pub fn check_registration_url(
    raw: &str,
    allow_unencrypted: bool,
) -> Result<ProjectUrl, ProjectInputError> {
    let url = ProjectUrl::parse(raw)?;
    if url.is_encrypted() || allow_unencrypted {
        Ok(url)
    } else {
        Err(ProjectInputError::UnencryptedNotConfirmed)
    }
}

/// A project as seen by a member of its organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: ProjectName,
    pub api_url: ProjectUrl,
    pub created_at: OffsetDateTime,
    /// The viewing account's role in the project's organization.
    pub role: OrgRole,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_trimmed_and_bounded() {
        assert_eq!(ProjectName::parse(" Prod ").unwrap().as_str(), "Prod");
        assert_eq!(ProjectName::parse("  "), Err(ProjectInputError::EmptyName));
        assert!(ProjectName::parse(&"ß".repeat(64)).is_ok());
        assert_eq!(
            ProjectName::parse(&"ß".repeat(65)),
            Err(ProjectInputError::NameTooLong)
        );
        assert_eq!(
            ProjectName::parse("a\tb"),
            Err(ProjectInputError::NameControlChars)
        );
    }

    #[test]
    fn urls_are_normalized() {
        for (raw, expected) in [
            (
                " https://Supabase.Example.test/ ",
                "https://supabase.example.test",
            ),
            (
                "https://supabase.example.test:8443",
                "https://supabase.example.test:8443",
            ),
            // The default port is dropped by the URL parser.
            (
                "https://supabase.example.test:443/",
                "https://supabase.example.test",
            ),
            (
                "http://10.0.0.5:8000/gateway/",
                "http://10.0.0.5:8000/gateway",
            ),
            ("http://[fd00::5]:8000", "http://[fd00::5]:8000"),
        ] {
            assert_eq!(ProjectUrl::parse(raw).unwrap().as_str(), expected, "{raw}");
        }
    }

    #[test]
    fn unsafe_or_malformed_urls_are_rejected() {
        use ProjectInputError as E;
        for (raw, expected) in [
            ("", E::InvalidUrl),
            ("supabase.example.test", E::InvalidUrl),
            ("ftp://supabase.example.test", E::UrlScheme),
            ("file:///etc/passwd", E::UrlScheme),
            ("javascript:alert(1)", E::UrlScheme),
            ("https://user:pw@supabase.example.test", E::UrlCredentials),
            ("https://user@supabase.example.test", E::UrlCredentials),
            ("https://supabase.example.test/?apikey=x", E::UrlQuery),
            ("https://supabase.example.test/#x", E::UrlQuery),
        ] {
            assert_eq!(ProjectUrl::parse(raw), Err(expected), "{raw}");
        }
        let long = format!("https://example.test/{}", "a".repeat(PROJECT_URL_MAX_LEN));
        assert_eq!(ProjectUrl::parse(&long), Err(E::UrlTooLong));
    }

    #[test]
    fn plain_http_needs_confirmation() {
        assert_eq!(
            check_registration_url("http://10.0.0.5:8000", false),
            Err(ProjectInputError::UnencryptedNotConfirmed)
        );
        assert!(check_registration_url("http://10.0.0.5:8000", true).is_ok());
        let https = check_registration_url("https://supabase.example.test", false).unwrap();
        assert!(https.is_encrypted());
    }

    #[test]
    fn deserialization_validates() {
        assert!(serde_json::from_str::<ProjectUrl>(r#""https://a:b@x.test""#).is_err());
        let ok: ProjectUrl = serde_json::from_str(r#""https://x.test/""#).unwrap();
        assert_eq!(ok.as_str(), "https://x.test");
    }
}
