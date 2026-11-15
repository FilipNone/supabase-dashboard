//! Outgoing email from the dashboard itself: invitation and password reset
//! links.
//!
//! This is the dashboard's own mail, separate from the SMTP settings of a
//! managed project's Auth service. The [`Mailer`] port is implemented by an
//! adapter (SMTP today); the services here only build messages and decide
//! when to send them.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use supabase_dashboard_domain::{
    account::{DisplayName, Email, PasswordResetCode},
    authz::OrgRole,
    invitation::InvitationCode,
    organization::OrganizationName,
};
use time::OffsetDateTime;

/// Longest subject line built here, in characters.
const MAX_SUBJECT_CHARS: usize = 200;

/// A plain-text message to one recipient. The body can hold a secret, such
/// as an invitation code, so it is never shown by `Debug` and must not be
/// logged.
#[derive(Clone)]
pub struct OutgoingEmail {
    pub to: Email,
    pub subject: String,
    pub body: String,
}

impl fmt::Debug for OutgoingEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingEmail")
            .field("to", &self.to)
            .field("subject", &self.subject)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

/// Why a message was not sent. Messages are for server logs and never hold
/// the message body or a mail server credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    #[error("the mail server did not answer in time")]
    Timeout,
    /// Connecting, TLS, or authentication failed, or the server answered
    /// with a temporary error.
    #[error("the mail server is unavailable: {0}")]
    Unavailable(String),
    /// The server refused the message or a recipient permanently.
    #[error("the mail server refused the message: {0}")]
    Refused(String),
    /// The message could not be built, for example from an address the
    /// mail library does not accept.
    #[error("the message could not be built: {0}")]
    Invalid(String),
}

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), MailError>> + Send + 'a>>;

/// Sends a message. Implementations bound the time a send may take and
/// never put credentials in errors or logs.
pub trait Mailer: Send + Sync {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a>;
}

/// Mail for invitations: the mailer and where the invitation page lives.
#[derive(Clone)]
pub struct InvitationMail {
    pub mailer: Arc<dyn Mailer>,
    /// Absolute URL of the invitation page, without a fragment, such as
    /// `https://dashboard.example.com/dashboard/invite`. The code is
    /// appended as the fragment, so opening the link does not send it to
    /// the server.
    pub invite_page_url: String,
}

/// What an invitation email says.
pub struct InvitationMessage<'a> {
    pub to: &'a Email,
    pub organization: &'a OrganizationName,
    pub inviter: &'a DisplayName,
    pub role: OrgRole,
    pub code: &'a InvitationCode,
    pub expires_at: OffsetDateTime,
}

impl InvitationMail {
    pub fn message(&self, invitation: &InvitationMessage<'_>) -> OutgoingEmail {
        let organization = single_line(invitation.organization.as_str());
        let inviter = single_line(invitation.inviter.as_str());
        let subject = truncate(
            &format!("Invitation to join {organization} on the dashboard"),
            MAX_SUBJECT_CHARS,
        );
        let link = format!("{}#{}", self.invite_page_url, invitation.code.expose());
        let body = format!(
            "{inviter} invited you to join the organization \"{organization}\" as {role}.\n\
             \n\
             Open this link to accept:\n\
             {link}\n\
             \n\
             The link works only for {email} and expires on {date} at {time} UTC. \
             Whoever has the link can see which organization sent it, so do not forward it.\n\
             \n\
             If you did not expect this invitation, ignore this email.\n",
            role = invitation.role.label(),
            email = invitation.to.as_str(),
            date = invitation.expires_at.date(),
            time = format_args!(
                "{:02}:{:02}",
                invitation.expires_at.hour(),
                invitation.expires_at.minute()
            ),
        );
        OutgoingEmail {
            to: invitation.to.clone(),
            subject,
            body,
        }
    }
}

/// Mail for password reset links: the mailer and where the reset page
/// lives.
#[derive(Clone)]
pub struct PasswordResetMail {
    pub mailer: Arc<dyn Mailer>,
    /// Absolute URL of the reset page, without a fragment, such as
    /// `https://dashboard.example.com/dashboard/reset-password`. The code is
    /// appended as the fragment, so opening the link does not send it to
    /// the server.
    pub reset_page_url: String,
}

impl PasswordResetMail {
    pub fn message(
        &self,
        to: &Email,
        code: &PasswordResetCode,
        expires_at: OffsetDateTime,
    ) -> OutgoingEmail {
        let link = format!("{}#{}", self.reset_page_url, code.expose());
        let body = format!(
            "Someone asked to reset the password of the dashboard account {email}.\n\
             \n\
             Open this link to choose a new password:\n\
             {link}\n\
             \n\
             The link works once and expires on {date} at {time} UTC. Setting a new password \
             signs the account out everywhere and revokes its API tokens.\n\
             \n\
             If you did not ask for this, ignore this email; your password stays the same.\n",
            email = to.as_str(),
            date = expires_at.date(),
            time = format_args!("{:02}:{:02}", expires_at.hour(), expires_at.minute()),
        );
        OutgoingEmail {
            to: to.clone(),
            subject: "Reset your dashboard password".to_owned(),
            body,
        }
    }
}

/// Replaces control characters, including CR and LF, with spaces. Names are
/// already validated without them; this keeps a header line single even if
/// that rule changes.
fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    struct Never;
    impl Mailer for Never {
        fn send<'a>(&'a self, _: &'a OutgoingEmail) -> SendFuture<'a> {
            Box::pin(async { Err(MailError::Timeout) })
        }
    }

    fn mail() -> InvitationMail {
        InvitationMail {
            mailer: Arc::new(Never),
            invite_page_url: "https://dash.example.test/dashboard/invite".into(),
        }
    }

    #[test]
    fn message_holds_the_link_and_details() {
        let to = Email::parse("new@example.test").unwrap();
        let organization = OrganizationName::parse("Acme").unwrap();
        let inviter = DisplayName::parse("Ada").unwrap();
        let code = InvitationCode::new("abc123".into());
        let expires_at = OffsetDateTime::from_unix_timestamp(1_795_343_415).unwrap();
        let message = mail().message(&InvitationMessage {
            to: &to,
            organization: &organization,
            inviter: &inviter,
            role: OrgRole::Developer,
            code: &code,
            expires_at,
        });
        assert_eq!(message.subject, "Invitation to join Acme on the dashboard");
        assert!(
            message
                .body
                .contains("https://dash.example.test/dashboard/invite#abc123")
        );
        assert!(message.body.contains("Ada invited you"));
        assert!(message.body.contains("as Developer"));
        assert!(message.body.contains("2026-11-22 at 10:30 UTC"));
        assert!(!format!("{message:?}").contains("abc123"));
    }

    #[test]
    fn reset_message_holds_the_link() {
        let mail = PasswordResetMail {
            mailer: Arc::new(Never),
            reset_page_url: "https://dash.example.test/dashboard/reset-password".into(),
        };
        let to = Email::parse("ops@example.test").unwrap();
        let code = PasswordResetCode::new("cd34".into());
        let expires_at = OffsetDateTime::from_unix_timestamp(1_795_343_415).unwrap();
        let message = mail.message(&to, &code, expires_at);
        assert_eq!(message.to.as_str(), "ops@example.test");
        assert!(
            message
                .body
                .contains("https://dash.example.test/dashboard/reset-password#cd34")
        );
        assert!(message.body.contains("2026-11-22 at 10:30 UTC"));
        assert!(!format!("{message:?}").contains("cd34"));
    }

    #[test]
    fn subject_is_one_bounded_line() {
        assert_eq!(single_line("a\r\nBcc: x"), "a  Bcc: x");
        let long = "x".repeat(500);
        assert_eq!(truncate(&long, 200).chars().count(), 200);
    }
}
