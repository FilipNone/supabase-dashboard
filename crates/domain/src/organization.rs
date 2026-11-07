//! Dashboard organizations: groups of operators and the projects they
//! manage. They are control-plane records owned by this application and are
//! unrelated to anything inside a managed Supabase stack.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    account::{DisplayName, Email},
    authz::OrgRole,
};

pub const ORGANIZATION_NAME_MAX_CHARS: usize = 64;

/// Upper bound on how many organizations one account may belong to. Keeps
/// the organization switcher and its query bounded.
pub const MAX_ORGANIZATIONS_PER_ACCOUNT: usize = 100;

/// Upper bound on members listed for one organization.
pub const MAX_MEMBERS_PER_ORGANIZATION: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrganizationInputError {
    #[error("enter an organization name")]
    EmptyName,
    #[error("the organization name must be at most {ORGANIZATION_NAME_MAX_CHARS} characters")]
    NameTooLong,
    #[error("the organization name must not contain control characters")]
    NameControlChars,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrganizationName(String);

impl OrganizationName {
    pub fn parse(raw: &str) -> Result<Self, OrganizationInputError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(OrganizationInputError::EmptyName);
        }
        if value.chars().count() > ORGANIZATION_NAME_MAX_CHARS {
            return Err(OrganizationInputError::NameTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(OrganizationInputError::NameControlChars);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OrganizationName {
    type Error = OrganizationInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<OrganizationName> for String {
    fn from(value: OrganizationName) -> Self {
        value.0
    }
}

/// An organization as seen by one of its members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationSummary {
    pub id: Uuid,
    pub name: OrganizationName,
    /// The viewing account's role in this organization.
    pub role: OrgRole,
}

/// One member as shown on the team page. No credentials, no session data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSummary {
    pub account_id: Uuid,
    pub email: Email,
    pub display_name: DisplayName,
    pub role: OrgRole,
    /// Whether this row is the account viewing the list.
    pub is_you: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_trimmed_and_bounded() {
        assert_eq!(
            OrganizationName::parse("  Acme Ops ").unwrap().as_str(),
            "Acme Ops"
        );
        assert_eq!(
            OrganizationName::parse(" \t "),
            Err(OrganizationInputError::EmptyName)
        );
        assert!(OrganizationName::parse(&"ö".repeat(64)).is_ok());
        assert_eq!(
            OrganizationName::parse(&"ö".repeat(65)),
            Err(OrganizationInputError::NameTooLong)
        );
        assert_eq!(
            OrganizationName::parse("Acme\u{7}"),
            Err(OrganizationInputError::NameControlChars)
        );
    }

    #[test]
    fn name_deserialization_validates() {
        assert!(serde_json::from_str::<OrganizationName>(r#""""#).is_err());
        let ok: OrganizationName = serde_json::from_str(r#"" Acme ""#).unwrap();
        assert_eq!(ok.as_str(), "Acme");
    }
}
