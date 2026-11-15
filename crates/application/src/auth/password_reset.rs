//! Password reset by email, for operators who forgot their password.
//!
//! Asking for a link answers the same way whether or not an account uses
//! the address: the lookup, the saved request, and the email all happen in
//! a background task, so neither the answer nor its timing says whether the
//! account exists. Only a hash of each code is stored. A link works once,
//! for [`PASSWORD_RESET_LIFETIME`], and stops working when a newer one is
//! sent or the password changes. Using it sets the password, signs the
//! account out everywhere, and revokes its API tokens.

use std::sync::Arc;

use secrecy::{ExposeSecret as _, SecretString};
use supabase_dashboard_domain::account::{
    AccountInputError, Email, PASSWORD_RESET_LIFETIME, PASSWORD_RESET_LIMIT,
    PASSWORD_RESET_WINDOW_SECS, PasswordResetCode, PasswordResetPreview, check_new_password,
};
use supabase_dashboard_persistence::{
    Database,
    audit::{AuditEvent, AuditOutcome},
    password_resets::{CreateResetOutcome, NewPasswordReset},
};
use time::OffsetDateTime;
use tokio::{sync::Semaphore, task::JoinHandle};
use uuid::Uuid;

use super::{AuthError, AuthService, RequestContext};
use crate::{mail::PasswordResetMail, token::RandomToken};

/// Most reset requests handled at once. More are refused as busy rather
/// than queued, so a flood of requests cannot pile up work or mail.
const MAX_PENDING_REQUESTS: usize = 8;

const REQUEST_ACTION: &str = "account.password_reset_request";
const EMAIL_ACTION: &str = "account.password_reset_email";
const RESET_ACTION: &str = "account.password_reset";

pub(super) struct ResetMailer {
    mail: PasswordResetMail,
    permits: Arc<Semaphore>,
}

impl ResetMailer {
    pub(super) fn new(mail: PasswordResetMail) -> Self {
        Self {
            mail,
            permits: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordResetRequestError {
    #[error(
        "password reset by email is not set up on this dashboard; \
         ask an installation administrator to reset your password"
    )]
    NotConfigured,
    #[error("too many password reset requests are being handled; try again in a minute")]
    Busy,
    #[error(transparent)]
    Input(#[from] AccountInputError),
}

#[derive(Debug, thiserror::Error)]
pub enum CompletePasswordResetError {
    #[error(
        "this password reset link is not valid: it may have expired, been used, \
         or been replaced by a newer one"
    )]
    InvalidLink,
    #[error("the passwords do not match")]
    PasswordMismatch,
    #[error(transparent)]
    Input(#[from] AccountInputError),
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<supabase_dashboard_persistence::PersistenceError> for CompletePasswordResetError {
    fn from(err: supabase_dashboard_persistence::PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

/// A reset request being handled in the background. Dropping it lets the
/// work finish on its own; tests wait for it with [`Self::finished`].
#[must_use = "the request runs either way; await `finished` to wait for it"]
pub struct PasswordResetRequest {
    handle: JoinHandle<()>,
}

impl PasswordResetRequest {
    pub async fn finished(self) {
        if let Err(err) = self.handle.await {
            tracing::error!(error = %err, "password reset request task failed");
        }
    }
}

impl AuthService {
    /// Whether operators can ask for a reset link by email.
    pub const fn password_reset_available(&self) -> bool {
        self.reset_mail.is_some()
    }

    /// Starts sending a reset link to `email` if an enabled account uses it.
    /// The answer does not depend on whether one does. Each account gets at
    /// most [`PASSWORD_RESET_LIMIT`] links per hour; asking again replaces
    /// the previous link.
    pub fn request_password_reset(
        &self,
        email: &str,
        ctx: RequestContext<'_>,
    ) -> Result<PasswordResetRequest, PasswordResetRequestError> {
        let Some(reset) = &self.reset_mail else {
            return Err(PasswordResetRequestError::NotConfigured);
        };
        let email = Email::parse(email)?;
        let permit = Arc::clone(&reset.permits)
            .try_acquire_owned()
            .map_err(|_| PasswordResetRequestError::Busy)?;
        let db = self.db.clone();
        let mail = reset.mail.clone();
        let request_id = ctx.request_id.map(str::to_owned);
        let handle = tokio::spawn(async move {
            send_reset_link(&db, &mail, &email, request_id.as_deref()).await;
            drop(permit);
        });
        Ok(PasswordResetRequest { handle })
    }

    /// What a reset link is for, or `None` when it is not open.
    pub async fn preview_password_reset(
        &self,
        code: &str,
    ) -> Result<Option<PasswordResetPreview>, AuthError> {
        let Some(token) = RandomToken::parse(code) else {
            return Ok(None);
        };
        Ok(self
            .db
            .find_open_password_reset(token.hash())
            .await?
            .map(|open| PasswordResetPreview {
                email: open.email,
                expires_at: open.expires_at,
            }))
    }

    /// Sets a new password with a reset link, signs the account out of
    /// every session, and revokes its API tokens. The link works once.
    pub async fn complete_password_reset(
        &self,
        code: &str,
        password: &SecretString,
        confirmation: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<(), CompletePasswordResetError> {
        if password.expose_secret() != confirmation.expose_secret() {
            return Err(CompletePasswordResetError::PasswordMismatch);
        }
        check_new_password(password.expose_secret())?;
        let token = RandomToken::parse(code);
        // Checked before hashing, so a bad link costs no hashing work.
        let open = match &token {
            Some(token) => self.db.find_open_password_reset(token.hash()).await?,
            None => None,
        };
        let (Some(token), Some(open)) = (token, open) else {
            return Err(self.refuse_reset_link(ctx).await);
        };
        let password_hash = self.hashing.hash(password).await.map_err(AuthError::from)?;
        let event = AuditEvent {
            actor_account_id: None,
            action: RESET_ACTION,
            target_type: None,
            target_id: None,
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
            organization_id: None,
        };
        match self
            .db
            .complete_password_reset(token.hash(), &password_hash, &event)
            .await?
        {
            Some(_) => {
                // A forgotten password often follows failed sign-ins; the
                // new one should work right away.
                self.throttle.record_success(open.email.as_str());
                Ok(())
            }
            // Used or replaced while the password was hashed.
            None => Err(self.refuse_reset_link(ctx).await),
        }
    }

    async fn refuse_reset_link(&self, ctx: RequestContext<'_>) -> CompletePasswordResetError {
        self.audit(None, RESET_ACTION, None, AuditOutcome::Failure, ctx)
            .await;
        CompletePasswordResetError::InvalidLink
    }
}

/// Looks the account up, saves a request, and emails the link. Every outcome
/// is audited without the email address or the code: an unknown address as
/// a failed request with no target.
async fn send_reset_link(
    db: &Database,
    mail: &PasswordResetMail,
    email: &Email,
    request_id: Option<&str>,
) {
    let account = match db.find_credentials_by_email(email).await {
        Ok(Some(found)) => found.account,
        Ok(None) => {
            record(db, REQUEST_ACTION, None, AuditOutcome::Failure, request_id).await;
            return;
        }
        Err(err) => {
            tracing::warn!(error = %err, "could not look up an account for a password reset");
            return;
        }
    };
    if account.disabled {
        record(
            db,
            REQUEST_ACTION,
            Some(account.id),
            AuditOutcome::Denied,
            request_id,
        )
        .await;
        return;
    }
    let token = match RandomToken::generate() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!(error = %err, "could not generate a password reset code");
            return;
        }
    };
    // Whole seconds, matching what the email shows.
    let Some(expires_at) = OffsetDateTime::now_utc()
        .checked_add(PASSWORD_RESET_LIFETIME)
        .and_then(|at| at.replace_nanosecond(0).ok())
    else {
        return;
    };
    let saved = db
        .create_password_reset(
            &NewPasswordReset {
                id: Uuid::now_v7(),
                account_id: account.id,
                token_hash: token.hash(),
                expires_at,
            },
            PASSWORD_RESET_LIMIT,
            PASSWORD_RESET_WINDOW_SECS,
        )
        .await;
    let outcome = match saved {
        Ok(CreateResetOutcome::Created) => AuditOutcome::Success,
        Ok(CreateResetOutcome::TooMany | CreateResetOutcome::NoAccount) => AuditOutcome::Denied,
        Err(err) => {
            tracing::warn!(error = %err, "could not save a password reset request");
            AuditOutcome::Failure
        }
    };
    record(db, REQUEST_ACTION, Some(account.id), outcome, request_id).await;
    if outcome != AuditOutcome::Success {
        return;
    }
    let code = PasswordResetCode::new(token.expose_code().to_owned());
    let message = mail.message(&account.email, &code, expires_at);
    let sent = match mail.mailer.send(&message).await {
        Ok(()) => AuditOutcome::Success,
        Err(err) => {
            tracing::warn!(error = %err, "password reset email not sent");
            AuditOutcome::Failure
        }
    };
    record(db, EMAIL_ACTION, Some(account.id), sent, request_id).await;
}

async fn record(
    db: &Database,
    action: &'static str,
    account: Option<Uuid>,
    outcome: AuditOutcome,
    request_id: Option<&str>,
) {
    let event = AuditEvent {
        actor_account_id: None,
        action,
        target_type: account.map(|_| "account"),
        target_id: account.map(|id| id.to_string()),
        outcome,
        request_id,
        organization_id: None,
    };
    if let Err(err) = db.record_audit_event(&event).await {
        tracing::error!(error = %err, action, "could not record audit event");
    }
}
