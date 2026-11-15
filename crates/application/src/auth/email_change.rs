//! Changing the sign-in email, confirmed from the new address.
//!
//! The operator confirms their current password (wrong ones count toward
//! the sign-in throttle) and names the new address. The dashboard emails a
//! one-time link to that address and changes nothing until the link is
//! used; the old address then gets a notice. Only a hash of each code is
//! stored. A link works once, for [`EMAIL_CHANGE_LIFETIME`], and stops
//! working when a newer one is requested, when the password changes, or
//! when the account's address changes some other way.
//!
//! Whether another account uses the new address is told to the requester
//! only after the password check, and each account gets at most
//! [`EMAIL_CHANGE_LIMIT`] requests past that check per hour, so the form
//! cannot be used to list accounts quickly. Audit events never hold an
//! address or a code.

use std::time::{Duration, Instant};

use secrecy::SecretString;
use supabase_dashboard_domain::account::{
    EMAIL_CHANGE_LIFETIME, EMAIL_CHANGE_LIMIT, Email, EmailChangeCode, EmailChangePreview,
    EmailChangeSent,
};
use supabase_dashboard_persistence::{
    PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    email_changes::{CompleteEmailChangeOutcome, CreateEmailChangeOutcome, NewEmailChange},
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AccountUpdateError, AuthError, AuthService, CurrentSession, RequestContext};
use crate::{
    mail::EmailChangeMail,
    throttle::{LoginThrottle, ThrottleConfig},
    token::RandomToken,
};

const REQUEST_ACTION: &str = "account.email_change_request";
const EMAIL_ACTION: &str = "account.email_change_email";
const CHANGE_ACTION: &str = "account.email_change";
const NOTICE_ACTION: &str = "account.email_change_notice";

/// The window [`EMAIL_CHANGE_LIMIT`] counts in.
const ATTEMPT_WINDOW: Duration = Duration::from_secs(3600);

pub(super) struct EmailChanger {
    mail: EmailChangeMail,
    /// Requests past the password check, per account ID. In memory, like
    /// the sign-in throttle.
    attempts: LoginThrottle,
}

impl EmailChanger {
    pub(super) fn new(mail: EmailChangeMail) -> Self {
        Self {
            mail,
            attempts: LoginThrottle::new(ThrottleConfig {
                max_failures: EMAIL_CHANGE_LIMIT,
                window: ATTEMPT_WINDOW,
                capacity: 10_000,
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmailChangeError {
    #[error(
        "this dashboard cannot send email, so the sign-in email cannot be changed here; \
         ask an installation administrator"
    )]
    NotConfigured,
    #[error("that is already your sign-in email")]
    SameEmail,
    #[error("another account already uses this email address")]
    Taken,
    #[error("too many email change requests; try again in {} minutes", .retry_after.as_secs().div_ceil(60).max(1))]
    TooMany { retry_after: Duration },
    #[error("the confirmation email could not be sent; try again later")]
    NotSent,
    #[error(transparent)]
    Account(#[from] AccountUpdateError),
}

impl From<PersistenceError> for EmailChangeError {
    fn from(err: PersistenceError) -> Self {
        Self::Account(err.into())
    }
}

impl From<AuthError> for EmailChangeError {
    fn from(err: AuthError) -> Self {
        Self::Account(AccountUpdateError::Internal(err))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfirmEmailChangeError {
    #[error(
        "this confirmation link is not valid: it may have expired, been used, \
         or been replaced by a newer one"
    )]
    InvalidLink,
    #[error("another account now uses this email address, so your sign-in email was not changed")]
    Taken,
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for ConfirmEmailChangeError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

impl AuthService {
    /// Whether operators can change their sign-in email here.
    pub const fn email_change_available(&self) -> bool {
        self.email_change.is_some()
    }

    /// Checks the current password and emails a confirmation link to
    /// `new_email`. Nothing changes until the link is used. A new request
    /// replaces the previous link.
    pub async fn request_email_change(
        &self,
        current: &CurrentSession,
        current_password: &SecretString,
        new_email: &str,
        ctx: RequestContext<'_>,
    ) -> Result<EmailChangeSent, EmailChangeError> {
        let account_id = current.account.id;
        let refuse = |error: EmailChangeError| async move {
            self.audit(
                Some(account_id),
                REQUEST_ACTION,
                Some(("account", account_id)),
                AuditOutcome::Denied,
                ctx,
            )
            .await;
            Err(error)
        };
        let Some(changer) = &self.email_change else {
            return refuse(EmailChangeError::NotConfigured).await;
        };
        let new_email = Email::parse(new_email).map_err(AccountUpdateError::from)?;
        let key = current.account.email.as_str();
        self.throttle
            .check(key, Instant::now())
            .map_err(|retry_after| AccountUpdateError::Throttled { retry_after })?;
        let stored = self
            .db
            .find_password_hash(account_id)
            .await?
            .ok_or(AccountUpdateError::Conflict)?;
        if !self
            .hashing
            .verify(current_password, &stored)
            .await
            .map_err(AuthError::from)?
        {
            self.throttle.record_failure(key, Instant::now());
            return refuse(AccountUpdateError::WrongPassword.into()).await;
        }
        self.throttle.record_success(key);
        if new_email == current.account.email {
            return Err(EmailChangeError::SameEmail);
        }
        let attempt_key = account_id.to_string();
        if let Err(retry_after) = changer.attempts.check(&attempt_key, Instant::now()) {
            return refuse(EmailChangeError::TooMany { retry_after }).await;
        }
        changer
            .attempts
            .record_failure(&attempt_key, Instant::now());

        let token = RandomToken::generate().map_err(AuthError::from)?;
        // Whole seconds, matching what the email shows.
        let expires_at = OffsetDateTime::now_utc()
            .checked_add(EMAIL_CHANGE_LIFETIME)
            .and_then(|at| at.replace_nanosecond(0).ok())
            .ok_or(AuthError::LifetimeOutOfRange)?;
        let event = AuditEvent {
            actor_account_id: Some(account_id),
            action: REQUEST_ACTION,
            target_type: Some("account"),
            target_id: Some(account_id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
            organization_id: None,
        };
        let saved = self
            .db
            .create_email_change(
                &NewEmailChange {
                    id: Uuid::now_v7(),
                    account_id,
                    old_email: &current.account.email,
                    new_email: &new_email,
                    token_hash: token.hash(),
                    expires_at,
                },
                &event,
            )
            .await?;
        match saved {
            CreateEmailChangeOutcome::Created => {}
            CreateEmailChangeOutcome::Taken => return refuse(EmailChangeError::Taken).await,
            CreateEmailChangeOutcome::NoAccount => {
                return refuse(AccountUpdateError::Conflict.into()).await;
            }
        }
        let code = EmailChangeCode::new(token.expose_code().to_owned());
        let message =
            changer
                .mail
                .confirmation(&current.account.email, &new_email, &code, expires_at);
        let sent = changer.mail.mailer.send(&message).await;
        let outcome = match &sent {
            Ok(()) => AuditOutcome::Success,
            Err(err) => {
                tracing::warn!(error = %err, "email change confirmation not sent");
                AuditOutcome::Failure
            }
        };
        self.audit(
            Some(account_id),
            EMAIL_ACTION,
            Some(("account", account_id)),
            outcome,
            ctx,
        )
        .await;
        sent.map_err(|_| EmailChangeError::NotSent)?;
        Ok(EmailChangeSent {
            new_email,
            expires_at,
        })
    }

    /// What a confirmation link is for, or `None` when it is not open.
    pub async fn preview_email_change(
        &self,
        code: &str,
    ) -> Result<Option<EmailChangePreview>, AuthError> {
        let Some(token) = RandomToken::parse(code) else {
            return Ok(None);
        };
        Ok(self
            .db
            .find_open_email_change(token.hash())
            .await?
            .map(|open| EmailChangePreview {
                new_email: open.new_email,
                expires_at: open.expires_at,
            }))
    }

    /// Uses a confirmation link: the account signs in with the new address
    /// from now on, and a notice goes to the old one. The code is the
    /// credential, so this needs no session. Returns the new address.
    pub async fn confirm_email_change(
        &self,
        code: &str,
        ctx: RequestContext<'_>,
    ) -> Result<Email, ConfirmEmailChangeError> {
        let Some(token) = RandomToken::parse(code) else {
            return Err(self.refuse_email_change_link(ctx).await);
        };
        let event = AuditEvent {
            actor_account_id: None,
            action: CHANGE_ACTION,
            target_type: None,
            target_id: None,
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
            organization_id: None,
        };
        match self.db.complete_email_change(token.hash(), &event).await? {
            CompleteEmailChangeOutcome::Changed {
                account_id,
                old_email,
                new_email,
            } => {
                self.send_email_change_notice(account_id, &old_email, &new_email, ctx)
                    .await;
                Ok(new_email)
            }
            CompleteEmailChangeOutcome::NotOpen => Err(self.refuse_email_change_link(ctx).await),
            CompleteEmailChangeOutcome::Taken { account_id } => {
                self.audit(
                    None,
                    CHANGE_ACTION,
                    Some(("account", account_id)),
                    AuditOutcome::Denied,
                    ctx,
                )
                .await;
                Err(ConfirmEmailChangeError::Taken)
            }
        }
    }

    /// Tells the old address that the sign-in email changed. Best effort:
    /// the change stands either way, and the attempt is audited.
    async fn send_email_change_notice(
        &self,
        account_id: Uuid,
        old_email: &Email,
        new_email: &Email,
        ctx: RequestContext<'_>,
    ) {
        let Some(changer) = &self.email_change else {
            return;
        };
        let message = changer.mail.notice(old_email, new_email);
        let outcome = match changer.mail.mailer.send(&message).await {
            Ok(()) => AuditOutcome::Success,
            Err(err) => {
                tracing::warn!(error = %err, "email change notice not sent");
                AuditOutcome::Failure
            }
        };
        self.audit(
            None,
            NOTICE_ACTION,
            Some(("account", account_id)),
            outcome,
            ctx,
        )
        .await;
    }

    /// Records a confirmation with a code that is malformed, unknown, used,
    /// replaced, or expired. The code itself is not recorded.
    async fn refuse_email_change_link(&self, ctx: RequestContext<'_>) -> ConfirmEmailChangeError {
        self.audit(None, CHANGE_ACTION, None, AuditOutcome::Failure, ctx)
            .await;
        ConfirmEmailChangeError::InvalidLink
    }
}
