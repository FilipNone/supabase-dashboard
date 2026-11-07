//! Operator authentication: first-owner bootstrap, sign-in, session lookup,
//! sign-out, and session revocation.

use std::time::{Duration, Instant};

use secrecy::SecretString;
use supabase_dashboard_domain::account::{
    AccountInputError, AccountSummary, DisplayName, Email, check_new_password,
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    accounts::{AccountRecord, NewAccount},
    audit::{AuditEvent, AuditOutcome},
    sessions::{NewSession, SessionInfo},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    password::{PasswordError, PasswordHashing},
    throttle::{LoginThrottle, ThrottleConfig},
    token::{RandomnessError, SessionToken},
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
            return Err(BootstrapError::AlreadyInitialized);
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
            Err(BootstrapError::AlreadyInitialized)
        }
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

    pub async fn list_sessions(
        &self,
        current: &CurrentSession,
    ) -> Result<Vec<SessionInfo>, AuthError> {
        Ok(self
            .db
            .list_live_sessions(current.account.id, self.config.idle_timeout)
            .await?)
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
        if revoked {
            self.audit(
                Some(current.account.id),
                "session.revoke",
                Some(("session", session_id)),
                AuditOutcome::Success,
                ctx,
            )
            .await;
        }
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
