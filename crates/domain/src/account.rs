//! Dashboard operator accounts.
//!
//! These are the people who sign in to this dashboard. They are unrelated to
//! the end users stored in a managed project's Supabase Auth database.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest accepted email address (RFC 5321 path limit).
pub const EMAIL_MAX_LEN: usize = 254;
pub const DISPLAY_NAME_MAX_CHARS: usize = 100;
/// Passwords shorter than this are rejected. Length is the only composition
/// rule, following NIST SP 800-63B.
pub const PASSWORD_MIN_CHARS: usize = 12;
/// Upper bound so that hashing cost stays predictable.
pub const PASSWORD_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountInputError {
    #[error("enter a valid email address")]
    InvalidEmail,
    #[error("the email address is too long")]
    EmailTooLong,
    #[error("enter a display name")]
    EmptyDisplayName,
    #[error("the display name must be at most {DISPLAY_NAME_MAX_CHARS} characters")]
    DisplayNameTooLong,
    #[error("the display name must not contain control characters")]
    DisplayNameControlChars,
    #[error("the password must be at least {PASSWORD_MIN_CHARS} characters")]
    PasswordTooShort,
    #[error("the password must be at most {PASSWORD_MAX_BYTES} bytes")]
    PasswordTooLong,
}

/// A normalized email address used as the sign-in identifier.
///
/// Normalization trims surrounding whitespace and lowercases the whole
/// address, so `Ops@Example.test` and `ops@example.test` are one account.
/// Validation is deliberately shallow: it rejects obvious mistakes without
/// trying to implement the full RFC grammar.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, AccountInputError> {
        let value = raw.trim().to_lowercase();
        if value.len() > EMAIL_MAX_LEN {
            return Err(AccountInputError::EmailTooLong);
        }
        let Some((local, domain)) = value.split_once('@') else {
            return Err(AccountInputError::InvalidEmail);
        };
        let valid = !local.is_empty()
            && !domain.is_empty()
            && !domain.contains('@')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !value.chars().any(|c| c.is_whitespace() || c.is_control());
        if valid {
            Ok(Self(value))
        } else {
            Err(AccountInputError::InvalidEmail)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Email").field(&self.0).finish()
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Email {
    type Error = AccountInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Email> for String {
    fn from(value: Email) -> Self {
        value.0
    }
}

/// A human-readable account name shown in the UI and audit views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DisplayName(String);

impl DisplayName {
    pub fn parse(raw: &str) -> Result<Self, AccountInputError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(AccountInputError::EmptyDisplayName);
        }
        if value.chars().count() > DISPLAY_NAME_MAX_CHARS {
            return Err(AccountInputError::DisplayNameTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(AccountInputError::DisplayNameControlChars);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DisplayName {
    type Error = AccountInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DisplayName> for String {
    fn from(value: DisplayName) -> Self {
        value.0
    }
}

/// Checks a new password against the length policy. Existing passwords are
/// never re-validated at sign-in, so a policy change cannot lock anyone out.
pub fn check_new_password(password: &str) -> Result<(), AccountInputError> {
    if password.len() > PASSWORD_MAX_BYTES {
        return Err(AccountInputError::PasswordTooLong);
    }
    if password.chars().count() < PASSWORD_MIN_CHARS {
        return Err(AccountInputError::PasswordTooShort);
    }
    Ok(())
}

/// What the browser may know about the signed-in account. It carries no
/// credentials and no session identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummary {
    pub email: Email,
    pub display_name: DisplayName,
    pub is_installation_admin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_lowercased() {
        let email = Email::parse("  Ops@Example.TEST ").unwrap();
        assert_eq!(email.as_str(), "ops@example.test");
    }

    #[test]
    fn malformed_emails_are_rejected() {
        for raw in [
            "",
            "ops",
            "@example.test",
            "ops@",
            "ops@@example.test",
            "o ps@example.test",
            "ops@.example.test",
            "ops@example.test.",
            "ops\u{0}@example.test",
        ] {
            assert_eq!(
                Email::parse(raw),
                Err(AccountInputError::InvalidEmail),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn overlong_email_is_rejected() {
        let raw = format!("{}@example.test", "a".repeat(250));
        assert_eq!(Email::parse(&raw), Err(AccountInputError::EmailTooLong));
    }

    #[test]
    fn email_deserialization_validates() {
        let ok: Email = serde_json::from_str(r#""A@b.test""#).unwrap();
        assert_eq!(ok.as_str(), "a@b.test");
        assert!(serde_json::from_str::<Email>(r#""nope""#).is_err());
    }

    #[test]
    fn display_name_bounds() {
        assert_eq!(DisplayName::parse(" Ada ").unwrap().as_str(), "Ada");
        assert_eq!(
            DisplayName::parse("   "),
            Err(AccountInputError::EmptyDisplayName)
        );
        assert_eq!(
            DisplayName::parse(&"é".repeat(101)),
            Err(AccountInputError::DisplayNameTooLong)
        );
        assert!(DisplayName::parse(&"é".repeat(100)).is_ok());
        assert_eq!(
            DisplayName::parse("a\nb"),
            Err(AccountInputError::DisplayNameControlChars)
        );
    }

    #[test]
    fn password_policy_counts_characters_and_caps_bytes() {
        assert_eq!(
            check_new_password("short"),
            Err(AccountInputError::PasswordTooShort)
        );
        // 12 multi-byte characters satisfy the minimum.
        assert!(check_new_password(&"ü".repeat(12)).is_ok());
        assert!(check_new_password(&"x".repeat(256)).is_ok());
        assert_eq!(
            check_new_password(&"x".repeat(257)),
            Err(AccountInputError::PasswordTooLong)
        );
    }
}
