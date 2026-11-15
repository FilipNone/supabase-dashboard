//! Signing in to the dashboard through an OpenID Connect provider.
//!
//! An identity at the provider is the pair (issuer, subject). It signs in
//! only to the dashboard account it was explicitly linked to; email
//! addresses from the provider are never used to find or create accounts.

use serde::{Deserialize, Serialize};

/// Longest `sub` accepted. OpenID Connect Core limits it to 255 ASCII
/// characters.
pub const OIDC_SUBJECT_MAX_LEN: usize = 255;

/// Longest issuer URL stored with an identity.
pub const OIDC_ISSUER_MAX_LEN: usize = 2048;

/// Longest label kept for showing an identity, such as the email address
/// the provider reported when it was linked. Longer labels are cut.
pub const OIDC_LABEL_MAX_CHARS: usize = 254;

/// Longest name shown on the "Sign in with" button.
pub const OIDC_DISPLAY_NAME_MAX_CHARS: usize = 40;

/// A provider subject: 1 to [`OIDC_SUBJECT_MAX_LEN`] printable ASCII
/// characters.
pub fn valid_subject(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= OIDC_SUBJECT_MAX_LEN
        && raw.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// A label for display: control characters removed, cut to
/// [`OIDC_LABEL_MAX_CHARS`]. `None` when nothing printable is left.
pub fn display_label(raw: &str) -> Option<String> {
    let label: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(OIDC_LABEL_MAX_CHARS)
        .collect();
    let label = label.trim();
    (!label.is_empty()).then(|| label.to_owned())
}

/// An identity linked to the signed-in operator's account, as listed on the
/// account security page. The ID is for unlinking; it is not a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedIdentity {
    pub id: uuid::Uuid,
    pub issuer: String,
    /// What the provider called the identity when it was linked, such as
    /// an email address. For display only.
    pub label: Option<String>,
    pub linked_at: time::OffsetDateTime,
    pub last_used_at: Option<time::OffsetDateTime>,
    /// Whether the identity belongs to the provider this installation is
    /// configured with now, and so can be used to sign in.
    pub current_provider: bool,
}

/// An identity linked to an account, as an installation administrator sees
/// it in the account list. The ID is for unlinking; it is not a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLinkedIdentity {
    pub id: uuid::Uuid,
    pub issuer: String,
    /// What the provider called the identity when it was linked. For
    /// display only.
    pub label: Option<String>,
}

/// The account security page's single sign-on panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcOverview {
    /// The provider's name for the button, when the deployment configured
    /// one.
    pub provider_name: Option<String>,
    pub identities: Vec<LinkedIdentity>,
}

/// What the sign-in page offers besides a password.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInOptions {
    /// "Sign in with <name>", when a provider is configured.
    pub oidc_provider_name: Option<String>,
}

/// Checks a provider display name from configuration.
pub fn check_display_name(raw: &str) -> Result<&str, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("must not be empty");
    }
    if name.chars().count() > OIDC_DISPLAY_NAME_MAX_CHARS {
        return Err("must be at most 40 characters");
    }
    if name.chars().any(char::is_control) {
        return Err("must be a single line");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_are_bounded_printable_ascii() {
        assert!(valid_subject("248289761001"));
        assert!(valid_subject("a1b2c3d4-e5f6"));
        assert!(!valid_subject(""));
        assert!(!valid_subject(&"a".repeat(OIDC_SUBJECT_MAX_LEN + 1)));
        assert!(valid_subject(&"a".repeat(OIDC_SUBJECT_MAX_LEN)));
        assert!(!valid_subject("tab\there"));
        assert!(!valid_subject("é"));
    }

    #[test]
    fn labels_drop_control_characters_and_are_cut() {
        assert_eq!(
            display_label("alice@example.test").as_deref(),
            Some("alice@example.test")
        );
        assert_eq!(display_label("a\r\nb").as_deref(), Some("ab"));
        assert_eq!(display_label(" \n ").as_deref(), None);
        let long = "x".repeat(OIDC_LABEL_MAX_CHARS + 10);
        assert_eq!(
            display_label(&long).map(|l| l.chars().count()),
            Some(OIDC_LABEL_MAX_CHARS)
        );
    }

    #[test]
    fn display_names_are_short_single_lines() {
        assert_eq!(check_display_name(" Authentik "), Ok("Authentik"));
        assert!(check_display_name("").is_err());
        assert!(check_display_name("a\nb").is_err());
        assert!(check_display_name(&"n".repeat(41)).is_err());
    }
}
