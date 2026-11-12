//! Operator authentication: first-owner bootstrap, sign-in, session lookup,
//! sign-out, and session revocation.

use std::time::{Duration, Instant};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    account::{
        AccountInputError, AccountSummary, AdminAccountSummary, DisplayName, Email, SessionSummary,
        check_new_password,
    },
    admin::{ADMIN_RESOURCE_LIST_LIMIT, RegisteredResources},
    invitation::InvitationPreview,
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    accounts::{AccountRecord, NewAccount, SetDisabledOutcome},
    audit::{AuditEvent, AuditOutcome},
    invitations::AcceptNewAccountOutcome,
    sessions::NewSession,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    password::{PasswordError, PasswordHashing},
    throttle::{LoginThrottle, ThrottleConfig},
    token::{InvitationToken, RandomnessError, SessionToken},
};

#[derive(Debug, Clone, Copy)]
pub struct AuthConfig {
    /// Absolute session lifetime from sign-in.
    pub session_lifetime: Duration,
    /// A session unused for this long stops working.
    pub idle_timeout: Duration,
    pub max_concurrent_hashes: usize,
    pub throttle: ThrottleConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_lifetime: Duration::from_secs(12 * 3600),
            idle_timeout: Duration::from_secs(3600),
            max_concurrent_hashes: 4,
            throttle: ThrottleConfig::default(),
        }
    }
}

/// Per-request details recorded with audit events. Never holds credentials.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestContext<'a> {
    pub request_id: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Internal failure. Its message is for server logs; callers show a generic
/// error to the browser.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Password(#[from] PasswordError),
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
    #[error("session lifetime is out of range")]
    LifetimeOutOfRange,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(transparent)]
    Input(#[from] AccountInputError),
    #[error("an operator account already exists; bootstrap only runs on an empty installation")]
    AlreadyInitialized,
    #[error(transparent)]
    Internal(#[from] AuthError),
}

#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    /// Wrong email, wrong password, or disabled account. These are not
    /// distinguished, so the response does not reveal which accounts exist.
    #[error("invalid email or password")]
    InvalidCredentials,
    #[error("too many failed sign-in attempts")]
    Throttled { retry_after: Duration },
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for SignInError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

impl From<PasswordError> for SignInError {
    fn from(err: PasswordError) -> Self {
        Self::Internal(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvitationSignUpError {
    /// Unknown, used, withdrawn, or expired code. Not distinguished.
    #[error("this invitation is not valid: it may have expired, been used, or been withdrawn")]
    InvalidInvitation,
    #[error("an account with this email already exists; sign in to accept the invitation")]
    AccountExists,
    #[error(transparent)]
    Input(#[from] AccountInputError),
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for InvitationSignUpError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// Only installation administrators use the administration view.
    #[error("only installation administrators can do this")]
    Forbidden,
    #[error("account not found")]
    NotFound,
    #[error("you cannot disable your own account")]
    CannotDisableSelf,
    #[error("at least one installation administrator must stay enabled")]
    LastAdmin,
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for AdminError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordResetError {
    #[error("no account uses this email address")]
    UnknownAccount,
    #[error(transparent)]
    Input(#[from] AccountInputError),
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for PasswordResetError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountUpdateError {
    /// The current password given to confirm a change is wrong.
    #[error("the current password is not correct")]
    WrongPassword,
    #[error("too many failed attempts")]
    Throttled { retry_after: Duration },
    /// The account was disabled or its password changed meanwhile.
    #[error("your account changed while this was being saved; reload the page and try again")]
    Conflict,
    #[error(transparent)]
    Input(#[from] AccountInputError),
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<PersistenceError> for AccountUpdateError {
    fn from(err: PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

impl From<PasswordError> for AccountUpdateError {
    fn from(err: PasswordError) -> Self {
        Self::Internal(err.into())
    }
}

/// A successful sign-in. The caller writes `token` into the session cookie.
#[derive(Debug)]
pub struct SignedIn {
    pub token: SessionToken,
    pub expires_at: OffsetDateTime,
    pub account: AccountRecord,
}

/// The authenticated operator for one request.
#[derive(Debug, Clone)]
pub struct CurrentSession {
    pub session_id: Uuid,
    pub account: AccountRecord,
}

impl CurrentSession {
    pub fn summary(&self) -> AccountSummary {
        AccountSummary {
            email: self.account.email.clone(),
            display_name: self.account.display_name.clone(),
            is_installation_admin: self.account.is_installation_admin,
        }
    }
}

pub struct AuthService {
    db: Database,
    hashing: PasswordHashing,
    throttle: LoginThrottle,
    config: AuthConfig,
    /// Verified when the email is unknown, so that response timing does not
    /// reveal whether an account exists.
    dummy_hash: String,
}

impl AuthService {
    pub async fn new(db: Database, config: AuthConfig) -> Result<Self, AuthError> {
        let hashing = PasswordHashing::new(config.max_concurrent_hashes);
        let dummy_hash = hashing
            .hash(&SecretString::from("dummy password for timing parity"))
            .await?;
        Ok(Self {
            db,
            hashing,
            throttle: LoginThrottle::new(config.throttle),
            config,
            dummy_hash,
        })
    }

    pub const fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Whether any operator account exists. The sign-in page uses this to
    /// tell a fresh installation how to create the first owner.
    pub async fn is_initialized(&self) -> Result<bool, AuthError> {
        Ok(self.db.account_count().await? > 0)
    }

    /// Creates the first operator account as installation administrator.
    /// Refused once any account exists, so it cannot be used to add a second
    /// administrator or replace the first one.
    pub async fn bootstrap_owner(
        &self,
        email: &str,
        display_name: &str,
        password: &SecretString,
    ) -> Result<Uuid, BootstrapError> {
        use secrecy::ExposeSecret as _;
        let email = Email::parse(email)?;
        let display_name = DisplayName::parse(display_name)?;
        check_new_password(password.expose_secret())?;
        if self.is_initialized().await? {
            return Err(self.refuse_bootstrap().await);
        }
        let password_hash = self.hashing.hash(password).await.map_err(AuthError::from)?;
        let id = Uuid::now_v7();
        let created = self
            .db
            .create_first_account(
                &NewAccount {
                    id,
                    email: &email,
                    display_name: &display_name,
                    password_hash: &password_hash,
                    is_installation_admin: true,
                },
                &AuditEvent {
                    actor_account_id: None,
                    action: "account.bootstrap_owner",
                    target_type: Some("account"),
                    target_id: Some(id.to_string()),
                    outcome: AuditOutcome::Success,
                    request_id: None,
                },
            )
            .await
            .map_err(AuthError::from)?;
        if created {
            Ok(id)
        } else {
            Err(self.refuse_bootstrap().await)
        }
    }

    /// Records a refused bootstrap: someone with server access tried to add
    /// an owner to an installation that has accounts.
    async fn refuse_bootstrap(&self) -> BootstrapError {
        self.audit(
            None,
            "account.bootstrap_owner",
            None,
            AuditOutcome::Denied,
            RequestContext::default(),
        )
        .await;
        BootstrapError::AlreadyInitialized
    }

    pub async fn sign_in(
        &self,
        email: &str,
        password: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<SignedIn, SignInError> {
        let Ok(email) = Email::parse(email) else {
            return Err(SignInError::InvalidCredentials);
        };
        let key = email.as_str();
        self.throttle
            .check(key, Instant::now())
            .map_err(|retry_after| SignInError::Throttled { retry_after })?;

        let credentials = self.db.find_credentials_by_email(&email).await?;
        let Some(credentials) = credentials else {
            // Same work as a real check; the result is irrelevant.
            let _ = self.hashing.verify(password, &self.dummy_hash).await;
            self.throttle.record_failure(key, Instant::now());
            tracing::info!(outcome = "denied", "sign-in for unknown account");
            return Err(SignInError::InvalidCredentials);
        };

        let matches = self
            .hashing
            .verify(password, &credentials.password_hash)
            .await?;
        let account = credentials.account;
        if !matches || account.disabled {
            self.throttle.record_failure(key, Instant::now());
            self.audit(
                Some(account.id),
                "session.sign_in",
                Some(("account", account.id)),
                AuditOutcome::Denied,
                ctx,
            )
            .await;
            return Err(SignInError::InvalidCredentials);
        }

        self.throttle.record_success(key);
        let token = SessionToken::generate().map_err(AuthError::from)?;
        let lifetime = time::Duration::try_from(self.config.session_lifetime)
            .map_err(|_| AuthError::LifetimeOutOfRange)?;
        let expires_at = OffsetDateTime::now_utc()
            .checked_add(lifetime)
            .ok_or(AuthError::LifetimeOutOfRange)?;
        let session_id = Uuid::now_v7();
        self.db
            .create_session(&NewSession {
                id: session_id,
                account_id: account.id,
                token_hash: token.hash(),
                expires_at,
                user_agent: ctx.user_agent.map(|ua| truncate(ua, 256)),
            })
            .await?;
        self.audit(
            Some(account.id),
            "session.sign_in",
            Some(("session", session_id)),
            AuditOutcome::Success,
            ctx,
        )
        .await;
        Ok(SignedIn {
            token,
            expires_at,
            account,
        })
    }

    /// Resolves a session cookie value to the signed-in operator. Malformed,
    /// unknown, revoked, expired, and idle sessions all return `None`.
    pub async fn authenticate(
        &self,
        cookie_value: &str,
    ) -> Result<Option<CurrentSession>, AuthError> {
        let Some(token) = SessionToken::parse(cookie_value) else {
            return Ok(None);
        };
        let session = self
            .db
            .find_active_session(token.hash(), self.config.idle_timeout)
            .await?;
        Ok(session.map(|s| CurrentSession {
            session_id: s.session_id,
            account: s.account,
        }))
    }

    /// Revokes the session behind `cookie_value`, if any. Signing out twice
    /// or with a stale cookie is not an error.
    pub async fn sign_out(
        &self,
        cookie_value: &str,
        ctx: RequestContext<'_>,
    ) -> Result<(), AuthError> {
        let Some(token) = SessionToken::parse(cookie_value) else {
            return Ok(());
        };
        if let Some((session_id, account_id)) =
            self.db.revoke_session_by_token(token.hash()).await?
        {
            self.audit(
                Some(account_id),
                "session.sign_out",
                Some(("session", session_id)),
                AuditOutcome::Success,
                ctx,
            )
            .await;
        }
        Ok(())
    }

    /// The operator's live sessions, newest first, with the one making
    /// this request marked.
    pub async fn list_sessions(
        &self,
        current: &CurrentSession,
    ) -> Result<Vec<SessionSummary>, AuthError> {
        let sessions = self
            .db
            .list_live_sessions(current.account.id, self.config.idle_timeout)
            .await?;
        Ok(sessions
            .into_iter()
            .map(|s| SessionSummary {
                id: s.id,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
                user_agent: s.user_agent,
                is_current: s.id == current.session_id,
            })
            .collect())
    }

    /// Sets a new password for the account with this email and signs out
    /// all of its sessions. This is the recovery path for a forgotten
    /// password: it runs from the server command line, so it needs the same
    /// access as creating the first owner, and it is audited without an
    /// actor. It does not re-enable a disabled account. Returns how many
    /// sessions were signed out.
    pub async fn reset_password(
        &self,
        email: &str,
        password: &SecretString,
    ) -> Result<u64, PasswordResetError> {
        use secrecy::ExposeSecret as _;
        let email = Email::parse(email)?;
        check_new_password(password.expose_secret())?;
        let Some(account) = self
            .db
            .find_credentials_by_email(&email)
            .await?
            .map(|found| found.account)
        else {
            return Err(self.refuse_reset(None).await);
        };
        let password_hash = self.hashing.hash(password).await.map_err(AuthError::from)?;
        let event = AuditEvent {
            actor_account_id: None,
            action: "account.password_reset",
            target_type: Some("account"),
            target_id: Some(account.id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: None,
        };
        match self
            .db
            .reset_password(account.id, &password_hash, &event)
            .await?
        {
            Some(revoked) => Ok(revoked),
            None => Err(self.refuse_reset(Some(account.id)).await),
        }
    }

    /// Records a reset for an account that does not exist (or was deleted
    /// while the password was hashed). The email is not recorded.
    async fn refuse_reset(&self, account: Option<Uuid>) -> PasswordResetError {
        self.audit(
            None,
            "account.password_reset",
            account.map(|id| ("account", id)),
            AuditOutcome::Failure,
            RequestContext::default(),
        )
        .await;
        PasswordResetError::UnknownAccount
    }

    /// Every account of the installation, for installation administrators.
    pub async fn admin_list_accounts(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<Vec<AdminAccountSummary>, AdminError> {
        self.require_admin(current, "admin.account_list", None, ctx)
            .await?;
        let accounts = self.db.list_accounts().await?;
        Ok(accounts
            .into_iter()
            .map(|listing| AdminAccountSummary {
                is_you: listing.account.id == current.account.id,
                id: listing.account.id,
                email: listing.account.email,
                display_name: listing.account.display_name,
                is_installation_admin: listing.account.is_installation_admin,
                disabled: listing.account.disabled,
                created_at: listing.created_at,
                organization_count: listing.organization_count,
            })
            .collect())
    }

    /// Every organization and registered project of the installation, for
    /// installation administrators. Listing them grants no access: opening a
    /// project still requires membership in its organization.
    pub async fn admin_list_resources(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<RegisteredResources, AdminError> {
        self.require_admin(current, "admin.resource_list", None, ctx)
            .await?;
        Ok(self
            .db
            .list_registered_resources(ADMIN_RESOURCE_LIST_LIMIT)
            .await?)
    }

    /// Disables or re-enables another account. A disabled account cannot
    /// sign in and loses its sessions; its organization memberships stay,
    /// so re-enabling restores its access. Returns whether anything changed.
    pub async fn admin_set_account_disabled(
        &self,
        current: &CurrentSession,
        account_id: Uuid,
        disabled: bool,
        ctx: RequestContext<'_>,
    ) -> Result<bool, AdminError> {
        let action = if disabled {
            "admin.account_disable"
        } else {
            "admin.account_enable"
        };
        self.require_admin(current, action, Some(account_id), ctx)
            .await?;
        let refuse = |outcome, error| async move {
            self.audit(
                Some(current.account.id),
                action,
                Some(("account", account_id)),
                outcome,
                ctx,
            )
            .await;
            Err(error)
        };
        if account_id == current.account.id {
            return refuse(AuditOutcome::Denied, AdminError::CannotDisableSelf).await;
        }
        let event = AuditEvent {
            actor_account_id: Some(current.account.id),
            action,
            target_type: Some("account"),
            target_id: Some(account_id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
        };
        match self
            .db
            .set_account_disabled(account_id, disabled, &event)
            .await?
        {
            SetDisabledOutcome::Changed { .. } => Ok(true),
            SetDisabledOutcome::Unchanged => Ok(false),
            SetDisabledOutcome::NotFound => {
                refuse(AuditOutcome::Failure, AdminError::NotFound).await
            }
            SetDisabledOutcome::LastAdmin => {
                refuse(AuditOutcome::Denied, AdminError::LastAdmin).await
            }
        }
    }

    /// Refuses, and audits the refusal, unless the operator is an
    /// installation administrator. The flag is read from the database on
    /// every request, so revoking it takes effect immediately.
    async fn require_admin(
        &self,
        current: &CurrentSession,
        action: &'static str,
        target: Option<Uuid>,
        ctx: RequestContext<'_>,
    ) -> Result<(), AdminError> {
        if current.account.is_installation_admin {
            return Ok(());
        }
        self.audit(
            Some(current.account.id),
            action,
            target.map(|id| ("account", id)),
            AuditOutcome::Denied,
            ctx,
        )
        .await;
        Err(AdminError::Forbidden)
    }

    /// Changes the operator's display name.
    pub async fn update_display_name(
        &self,
        current: &CurrentSession,
        display_name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<AccountSummary, AccountUpdateError> {
        let display_name = DisplayName::parse(display_name)?;
        let event = AuditEvent {
            actor_account_id: Some(current.account.id),
            action: "account.update_profile",
            target_type: Some("account"),
            target_id: Some(current.account.id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
        };
        if !self
            .db
            .update_display_name(current.account.id, &display_name, &event)
            .await?
        {
            return Err(AccountUpdateError::Conflict);
        }
        Ok(AccountSummary {
            display_name,
            ..current.summary()
        })
    }

    /// Changes the operator's password after checking the current one, and
    /// signs out every other session. Wrong current passwords count toward
    /// the same throttle as failed sign-ins, so a stolen session cannot be
    /// used to guess the password faster than the sign-in form allows.
    /// Returns how many other sessions were signed out.
    pub async fn change_password(
        &self,
        current: &CurrentSession,
        current_password: &SecretString,
        new_password: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<u64, AccountUpdateError> {
        use secrecy::ExposeSecret as _;
        check_new_password(new_password.expose_secret())?;
        let key = current.account.email.as_str();
        self.throttle
            .check(key, Instant::now())
            .map_err(|retry_after| AccountUpdateError::Throttled { retry_after })?;
        let stored = self
            .db
            .find_password_hash(current.account.id)
            .await?
            .ok_or(AccountUpdateError::Conflict)?;
        if !self.hashing.verify(current_password, &stored).await? {
            self.throttle.record_failure(key, Instant::now());
            self.audit(
                Some(current.account.id),
                "account.password_change",
                Some(("account", current.account.id)),
                AuditOutcome::Denied,
                ctx,
            )
            .await;
            return Err(AccountUpdateError::WrongPassword);
        }
        self.throttle.record_success(key);
        let new_hash = self.hashing.hash(new_password).await?;
        let event = AuditEvent {
            actor_account_id: Some(current.account.id),
            action: "account.password_change",
            target_type: Some("account"),
            target_id: Some(current.account.id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
        };
        self.db
            .change_password(
                current.account.id,
                &stored,
                &new_hash,
                current.session_id,
                &event,
            )
            .await?
            .ok_or(AccountUpdateError::Conflict)
    }

    /// Revokes one of the current operator's own sessions. Returns `false`
    /// when the session does not exist or belongs to someone else; callers
    /// treat both the same so session IDs cannot be probed.
    pub async fn revoke_own_session(
        &self,
        current: &CurrentSession,
        session_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<bool, AuthError> {
        let revoked = self
            .db
            .revoke_account_session(current.account.id, session_id)
            .await?;
        // A miss is recorded too: the ID may be another operator's session.
        let outcome = if revoked {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        self.audit(
            Some(current.account.id),
            "session.revoke",
            Some(("session", session_id)),
            outcome,
            ctx,
        )
        .await;
        Ok(revoked)
    }

    /// Signs the current operator out everywhere else.
    pub async fn revoke_other_sessions(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<u64, AuthError> {
        let count = self
            .db
            .revoke_other_sessions(current.account.id, Some(current.session_id))
            .await?;
        self.audit(
            Some(current.account.id),
            "session.revoke_others",
            None,
            AuditOutcome::Success,
            ctx,
        )
        .await;
        Ok(count)
    }

    /// Deletes sessions that can no longer be used.
    pub async fn prune_sessions(&self) -> Result<u64, AuthError> {
        Ok(self
            .db
            .delete_dead_sessions(self.config.idle_timeout)
            .await?)
    }

    /// What an invitation code is for, or `None` when it is malformed,
    /// unknown, used, withdrawn, or expired. Needs no session: the code is
    /// the credential.
    pub async fn preview_invitation(
        &self,
        code: &str,
    ) -> Result<Option<InvitationPreview>, AuthError> {
        let Some(token) = InvitationToken::parse(code) else {
            return Ok(None);
        };
        let invitation = self.db.find_open_invitation_by_token(token.hash()).await?;
        Ok(invitation.map(|invitation| InvitationPreview {
            organization_name: invitation.organization_name,
            email: invitation.email,
            role: invitation.role,
            expires_at: invitation.expires_at,
            account_exists: invitation.account_exists,
        }))
    }

    /// Creates an operator account for the invited email and joins the
    /// organization. The new account is never an installation
    /// administrator. Returns the organization joined; the invitee then
    /// signs in as usual.
    pub async fn accept_invitation_with_new_account(
        &self,
        code: &str,
        display_name: &str,
        password: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, InvitationSignUpError> {
        use secrecy::ExposeSecret as _;
        let display_name = DisplayName::parse(display_name)?;
        check_new_password(password.expose_secret())?;
        let Some(token) = InvitationToken::parse(code) else {
            return Err(self.refuse_invitation_sign_up(None, ctx).await);
        };
        // Look the code up before hashing the password, so an invalid code
        // costs no Argon2 work.
        let Some(invitation) = self.db.find_open_invitation_by_token(token.hash()).await? else {
            return Err(self.refuse_invitation_sign_up(None, ctx).await);
        };
        if invitation.account_exists {
            return Err(InvitationSignUpError::AccountExists);
        }
        let password_hash = self.hashing.hash(password).await.map_err(AuthError::from)?;
        let account_id = Uuid::now_v7();
        let audit = [
            AuditEvent {
                actor_account_id: Some(account_id),
                action: "account.create_from_invitation",
                target_type: Some("account"),
                target_id: Some(account_id.to_string()),
                outcome: AuditOutcome::Success,
                request_id: ctx.request_id,
            },
            AuditEvent {
                actor_account_id: Some(account_id),
                action: "organization.invitation_accept",
                target_type: Some("organization_invitation"),
                target_id: Some(invitation.id.to_string()),
                outcome: AuditOutcome::Success,
                request_id: ctx.request_id,
            },
        ];
        let outcome = self
            .db
            .accept_invitation_with_new_account(
                invitation.id,
                token.hash(),
                &NewAccount {
                    id: account_id,
                    email: &invitation.email,
                    display_name: &display_name,
                    password_hash: &password_hash,
                    is_installation_admin: false,
                },
                &audit,
            )
            .await?;
        match outcome {
            AcceptNewAccountOutcome::Joined { organization_id } => Ok(organization_id),
            AcceptNewAccountOutcome::Invalid | AcceptNewAccountOutcome::EmailMismatch => Err(self
                .refuse_invitation_sign_up(Some(invitation.id), ctx)
                .await),
            AcceptNewAccountOutcome::AccountExists => Err(InvitationSignUpError::AccountExists),
        }
    }

    /// Records a sign-up with a code that is malformed, unknown, used,
    /// withdrawn, or expired. The code itself is not recorded.
    async fn refuse_invitation_sign_up(
        &self,
        invitation: Option<Uuid>,
        ctx: RequestContext<'_>,
    ) -> InvitationSignUpError {
        self.audit(
            None,
            "account.create_from_invitation",
            invitation.map(|id| ("organization_invitation", id)),
            AuditOutcome::Denied,
            ctx,
        )
        .await;
        InvitationSignUpError::InvalidInvitation
    }

    /// Audit writes are best effort for sign-in and sign-out: a failure is
    /// logged but does not block the operator.
    async fn audit(
        &self,
        actor: Option<Uuid>,
        action: &'static str,
        target: Option<(&'static str, Uuid)>,
        outcome: AuditOutcome,
        ctx: RequestContext<'_>,
    ) {
        let event = AuditEvent {
            actor_account_id: actor,
            action,
            target_type: target.map(|(kind, _)| kind),
            target_id: target.map(|(_, id)| id.to_string()),
            outcome,
            request_id: ctx.request_id,
        };
        if let Err(err) = self.db.record_audit_event(&event).await {
            tracing::error!(error = %err, action, "could not record audit event");
        }
    }
}

fn truncate(value: &str, max_chars: usize) -> &str {
    match value.char_indices().nth(max_chars) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}
