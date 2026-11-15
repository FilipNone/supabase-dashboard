//! Dashboard API tokens: long random secrets an operator creates for
//! scripts and other programs that read the dashboard's API.
//!
//! A token acts as the account that created it, limited to its scopes. The
//! scopes only read: no token can change anything, open Studio, or read a
//! stack's keys. The dashboard stores a SHA-256 hash of each token and shows
//! the token itself once, to its creator.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Every token starts with this, so it is easy to recognize in a leaked
/// file or a secret scanner.
pub const API_TOKEN_PREFIX: &str = "sbd_";

/// How many characters of a token, after [`API_TOKEN_PREFIX`], are kept
/// and shown to tell tokens apart. 32 of a token's 256 random bits.
pub const API_TOKEN_DISPLAY_CHARS: usize = 8;

pub const API_TOKEN_NAME_MAX_CHARS: usize = 64;

/// Unexpired, unrevoked tokens one account may hold.
pub const MAX_ACTIVE_API_TOKENS: usize = 25;

/// Most tokens the token page lists. Revoked and expired tokens are kept
/// for [`API_TOKEN_KEEP_DAYS`] and then deleted, so this is enough.
pub const API_TOKEN_LIST_LIMIT: usize = 100;

/// Days a revoked or expired token stays listed before it is deleted.
pub const API_TOKEN_KEEP_DAYS: u16 = 30;

/// What a token may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApiTokenScope {
    /// The organizations the account belongs to, with its role in each.
    #[serde(rename = "organizations:read")]
    OrganizationsRead,
    /// Those organizations' projects and each project's last saved health
    /// check.
    #[serde(rename = "projects:read")]
    ProjectsRead,
}

impl ApiTokenScope {
    pub const ALL: [Self; 2] = [Self::OrganizationsRead, Self::ProjectsRead];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationsRead => "organizations:read",
            Self::ProjectsRead => "projects:read",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == value)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::OrganizationsRead => "Read organizations",
            Self::ProjectsRead => "Read projects and their health",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::OrganizationsRead => "Your organizations and your role in each.",
            Self::ProjectsRead => {
                "Their projects, API URLs, and each project's last saved health check. Never keys."
            }
        }
    }
}

/// A token's lifetime, chosen when it is created. There are no tokens
/// that never expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiTokenLifetime {
    #[serde(rename = "7")]
    Days7,
    #[serde(rename = "30")]
    Days30,
    #[serde(rename = "90")]
    Days90,
    #[serde(rename = "365")]
    Days365,
}

impl ApiTokenLifetime {
    pub const ALL: [Self; 4] = [Self::Days7, Self::Days30, Self::Days90, Self::Days365];

    pub const fn days(self) -> u16 {
        match self {
            Self::Days7 => 7,
            Self::Days30 => 30,
            Self::Days90 => 90,
            Self::Days365 => 365,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|lifetime| lifetime.days().to_string() == value)
    }

    pub fn label(self) -> String {
        match self {
            Self::Days365 => "1 year".to_owned(),
            other => format!("{} days", other.days()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiTokenInputError {
    #[error("give the token a name")]
    NameEmpty,
    #[error("the name can be at most {API_TOKEN_NAME_MAX_CHARS} characters")]
    NameTooLong,
    #[error("the name cannot contain control characters")]
    NameControl,
    #[error("choose at least one thing the token may read")]
    NoScopes,
    #[error("this is not a scope the dashboard knows")]
    UnknownScope,
    #[error("choose how long the token works")]
    UnknownLifetime,
}

/// A token's name, for the operator to recognize it. Not unique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApiTokenName(String);

impl ApiTokenName {
    pub fn parse(value: &str) -> Result<Self, ApiTokenInputError> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ApiTokenInputError::NameEmpty);
        }
        if value.chars().count() > API_TOKEN_NAME_MAX_CHARS {
            return Err(ApiTokenInputError::NameTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(ApiTokenInputError::NameControl);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ApiTokenName {
    type Error = ApiTokenInputError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ApiTokenName> for String {
    fn from(name: ApiTokenName) -> Self {
        name.0
    }
}

impl fmt::Display for ApiTokenName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Parses the scopes ticked on the form: at least one, each known, and
/// returned sorted without repeats.
pub fn parse_scopes<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<ApiTokenScope>, ApiTokenInputError> {
    let mut scopes = values
        .into_iter()
        .map(|value| ApiTokenScope::parse(value).ok_or(ApiTokenInputError::UnknownScope))
        .collect::<Result<Vec<_>, _>>()?;
    scopes.sort_unstable();
    scopes.dedup();
    if scopes.is_empty() {
        return Err(ApiTokenInputError::NoScopes);
    }
    Ok(scopes)
}

/// Whether a token still works.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiTokenState {
    Active,
    Expired,
    Revoked,
}

impl ApiTokenState {
    /// The state at `now` of a token revoked at `revoked_at` that expires
    /// at `expires_at`. Revocation wins.
    pub fn at(
        revoked_at: Option<OffsetDateTime>,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Self {
        if revoked_at.is_some() {
            Self::Revoked
        } else if expires_at <= now {
            Self::Expired
        } else {
            Self::Active
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "Active",
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
        }
    }
}

/// One token as its owner sees it. Holds no part of the token beyond the
/// short display prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiTokenSummary {
    pub id: Uuid,
    pub name: ApiTokenName,
    /// `sbd_` and the first [`API_TOKEN_DISPLAY_CHARS`] characters.
    pub display_prefix: String,
    pub scopes: Vec<ApiTokenScope>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    /// As of when the summary was read on the server.
    pub state: ApiTokenState,
}

/// The token itself. It is shown once, in the answer to the request that
/// created it, and never logged or stored in plain form.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApiTokenSecret(String);

impl ApiTokenSecret {
    pub const fn new(token: String) -> Self {
        Self(token)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiTokenSecret([REDACTED])")
    }
}

/// A newly created token, with the one copy of its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedApiToken {
    pub token: ApiTokenSummary,
    pub secret: ApiTokenSecret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_round_trip_their_names() {
        for scope in ApiTokenScope::ALL {
            let json = serde_json::to_value(scope).unwrap();
            assert_eq!(json, scope.as_str());
            assert_eq!(ApiTokenScope::parse(scope.as_str()), Some(scope));
        }
        assert_eq!(ApiTokenScope::parse("projects:write"), None);
    }

    #[test]
    fn scope_lists_are_checked_and_sorted() {
        assert_eq!(
            parse_scopes(["projects:read", "organizations:read", "projects:read"]),
            Ok(vec![
                ApiTokenScope::OrganizationsRead,
                ApiTokenScope::ProjectsRead
            ])
        );
        assert_eq!(parse_scopes([]), Err(ApiTokenInputError::NoScopes));
        assert_eq!(
            parse_scopes(["projects:read", "admin"]),
            Err(ApiTokenInputError::UnknownScope)
        );
    }

    #[test]
    fn lifetimes_are_fixed_choices() {
        assert_eq!(
            ApiTokenLifetime::parse("30"),
            Some(ApiTokenLifetime::Days30)
        );
        assert_eq!(ApiTokenLifetime::parse("0"), None);
        assert_eq!(ApiTokenLifetime::parse("never"), None);
        assert_eq!(ApiTokenLifetime::Days365.label(), "1 year");
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(ApiTokenName::parse("  CI  ").unwrap().as_str(), "CI");
        assert_eq!(ApiTokenName::parse(" "), Err(ApiTokenInputError::NameEmpty));
        assert_eq!(
            ApiTokenName::parse(&"x".repeat(API_TOKEN_NAME_MAX_CHARS + 1)),
            Err(ApiTokenInputError::NameTooLong)
        );
        assert_eq!(
            ApiTokenName::parse("a\u{0}b"),
            Err(ApiTokenInputError::NameControl)
        );
    }

    #[test]
    fn state_follows_revocation_then_expiry() {
        let now = OffsetDateTime::now_utc();
        let tomorrow = now + time::Duration::days(1);
        assert_eq!(
            ApiTokenState::at(None, tomorrow, now),
            ApiTokenState::Active
        );
        assert_eq!(ApiTokenState::at(None, now, now), ApiTokenState::Expired);
        assert_eq!(
            ApiTokenState::at(Some(now), tomorrow, now),
            ApiTokenState::Revoked
        );
    }

    #[test]
    fn the_secret_is_redacted_in_debug_output() {
        let secret = ApiTokenSecret::new("sbd_secretvalue".into());
        assert!(!format!("{secret:?}").contains("secretvalue"));
    }
}
