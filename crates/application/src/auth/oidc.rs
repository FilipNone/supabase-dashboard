//! Signing in through the deployment's OpenID Connect provider.
//!
//! The provider adapter runs the protocol: discovery, the authorization
//! request with PKCE, `state`, and `nonce`, the code exchange, and the ID
//! token checks (issuer, audience, signature, expiry, nonce). This module
//! decides what a verified identity may do:
//!
//! - An identity is the pair (issuer, `sub`). It signs in only to the
//!   account it was linked to. Email addresses from the provider are never
//!   used to find, link, or create accounts, and there is no sign-up.
//! - Linking is explicit: a signed-in operator starts it from their
//!   account's security page, and the identity is linked to that account
//!   only if the same session is still signed in when the provider sends
//!   the browser back.
//! - Disabled accounts cannot sign in this way, as with a password.
//! - A sign-in creates the same session as a password sign-in.
//!
//! Each flow is kept on the server, in memory, under its `state`, for
//! [`FLOW_LIFETIME`]. It is bound to the browser that started it by a
//! random value in a short-lived cookie, of which only a hash is kept. The
//! callback removes the flow before anything else, so a replayed callback
//! finds nothing, and a callback from another browser fails the binding
//! check and uses the flow up.
//!
//! Every account has a password, so unlinking an identity never leaves an
//! account without a way to sign in.
//!
//! Back-channel logout (OpenID Connect Back-Channel Logout 1.0): a session
//! started through the provider remembers the identity and the provider's
//! `sid`. When the provider posts a logout token, the adapter verifies it
//! (signature, issuer, audience, issue time, event, no nonce) and this
//! module refuses a token ID (`jti`) it has seen within
//! [`LOGOUT_TOKEN_MAX_AGE`] plus [`LOGOUT_TOKEN_CLOCK_SKEW`], then revokes
//! the matching sessions, which ends their Studio sessions too. Seen token
//! IDs are kept in memory only: after a restart, a token captured before it
//! could be replayed within that window, which at worst signs out sessions
//! the provider already ended.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use secrecy::SecretString;
use supabase_dashboard_domain::oidc::{
    LinkedIdentity, OIDC_ISSUER_MAX_LEN, OidcOverview, display_label, valid_subject,
};
use supabase_dashboard_persistence::{
    audit::{AuditEvent, AuditOutcome},
    oidc_identities::{LinkOidcOutcome, NewOidcIdentity},
    sessions::{OidcLogoutTarget, SessionOidcOrigin},
};
use uuid::Uuid;

use super::{AuthError, AuthService, CurrentSession, RequestContext, SignedIn};
use crate::token::RandomToken;

const SIGN_IN_ACTION: &str = "session.sign_in_oidc";
const LOGOUT_ACTION: &str = "session.oidc_backchannel_logout";
const LINK_ACTION: &str = "account.oidc_link";
const UNLINK_ACTION: &str = "account.oidc_unlink";

/// How long a started sign-in or link may take at the provider.
pub const FLOW_LIFETIME: Duration = Duration::from_secs(600);

/// Most flows kept at once. Starting one is open to anyone, so the store
/// is bounded; past this, new flows are refused until old ones expire.
const MAX_PENDING_FLOWS: usize = 10_000;

/// Longest `state` value looked up.
const MAX_STATE_LEN: usize = 256;

/// Longest `next` page kept with a flow.
const MAX_NEXT_LEN: usize = 2048;

/// How old a logout token's `iat` may be.
pub const LOGOUT_TOKEN_MAX_AGE: Duration = Duration::from_secs(300);

/// How far a logout token's `iat` may be in the future, and how far past
/// its `exp` it is still accepted, for clocks that disagree.
pub const LOGOUT_TOKEN_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Longest logout token read. Real ones are around a kilobyte.
pub const MAX_LOGOUT_TOKEN_LEN: usize = 8 * 1024;

/// Longest `jti` kept.
pub const MAX_LOGOUT_TOKEN_ID_LEN: usize = 256;

/// Most logout token IDs remembered at once. Only verified tokens are
/// remembered; past this, logouts are refused until old IDs expire.
const MAX_SEEN_LOGOUT_TOKENS: usize = 10_000;

/// Most logout requests verified at the same time. Anyone can post one, so
/// further requests are refused rather than queued.
const MAX_CONCURRENT_LOGOUTS: usize = 8;

/// What the adapter needs back at the callback to verify the answer. Both
/// are secrets until the flow ends.
pub struct OidcPending {
    pub pkce_verifier: SecretString,
    pub nonce: SecretString,
}

/// An authorization request to send the browser to.
pub struct OidcAuthorization {
    /// The provider's authorization endpoint with the request parameters.
    pub url: String,
    /// The `state` parameter in `url`.
    pub state: String,
    pub pending: OidcPending,
}

/// The identity in a verified ID token.
#[derive(Debug, Clone)]
pub struct OidcIdentityClaims {
    pub subject: String,
    /// The email or preferred username, kept only to show the operator
    /// which identity they linked.
    pub label: Option<String>,
    /// The provider's session ID (`sid`), when the ID token names one. A
    /// back-channel logout for that provider session ends the dashboard
    /// session it started.
    pub session_id: Option<String>,
}

/// What a verified logout token asks to end. At least one of `subject` and
/// `session_id` is set.
#[derive(Debug, Clone)]
pub struct OidcLogoutClaims {
    pub subject: Option<String>,
    /// The provider's session ID (`sid`).
    pub session_id: Option<String>,
    /// The token's ID (`jti`), for refusing replays.
    pub token_id: String,
}

/// Why the adapter could not produce a verified identity. The message is
/// for the server log; it never holds a token, a code, or a claim value.
#[derive(Debug, thiserror::Error)]
pub enum OidcProviderError {
    #[error("the provider could not be reached or answered unexpectedly: {0}")]
    Unavailable(String),
    #[error("the provider's answer failed verification: {0}")]
    Rejected(String),
}

pub type AuthorizeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcAuthorization, OidcProviderError>> + Send + 'a>>;
pub type ExchangeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcIdentityClaims, OidcProviderError>> + Send + 'a>>;
pub type LogoutTokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<OidcLogoutClaims, OidcProviderError>> + Send + 'a>>;

/// The provider adapter.
pub trait OidcProvider: Send + Sync {
    /// The issuer URL as configured; ID tokens must name exactly this.
    fn issuer(&self) -> &str;
    /// Starts an authorization code flow with PKCE, `state`, and `nonce`.
    fn authorize(&self) -> AuthorizeFuture<'_>;
    /// Exchanges `code` and verifies the ID token against `pending`.
    fn exchange<'a>(&'a self, code: &'a str, pending: &'a OidcPending) -> ExchangeFuture<'a>;
    /// Verifies a back-channel logout token: signature with the provider's
    /// keys, issuer, audience, `iat` within [`LOGOUT_TOKEN_MAX_AGE`] and
    /// [`LOGOUT_TOKEN_CLOCK_SKEW`], `exp` if present, the back-channel
    /// logout event, `sub` or `sid`, a `jti`, and no `nonce`. Replays are
    /// the caller's to refuse.
    fn verify_logout_token<'a>(&'a self, token: &'a str) -> LogoutTokenFuture<'a>;
}

/// The provider and its button name.
pub struct OidcSignIn {
    provider: Arc<dyn OidcProvider>,
    display_name: String,
    flows: Mutex<HashMap<String, PendingFlow>>,
    /// Logout token IDs seen, until they could no longer pass the `iat`
    /// check.
    seen_logout_tokens: Mutex<HashMap<String, Instant>>,
    logouts: tokio::sync::Semaphore,
}

impl OidcSignIn {
    pub fn new(provider: Arc<dyn OidcProvider>, display_name: impl Into<String>) -> Self {
        Self {
            provider,
            display_name: display_name.into(),
            flows: Mutex::new(HashMap::new()),
            seen_logout_tokens: Mutex::new(HashMap::new()),
            logouts: tokio::sync::Semaphore::new(MAX_CONCURRENT_LOGOUTS),
        }
    }

    /// Remembers a verified logout token's ID. `Err` when it was seen
    /// before (a replay) or when too many are remembered.
    fn remember_logout_token(&self, token_id: &str) -> Result<(), OidcLogoutError> {
        let mut seen = self
            .seen_logout_tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        seen.retain(|_, until| *until > now);
        if seen.contains_key(token_id) {
            return Err(OidcLogoutError::Replayed);
        }
        if seen.len() >= MAX_SEEN_LOGOUT_TOKENS {
            return Err(OidcLogoutError::Busy);
        }
        let until = now
            .checked_add(
                LOGOUT_TOKEN_MAX_AGE.saturating_add(LOGOUT_TOKEN_CLOCK_SKEW.saturating_mul(2)),
            )
            .ok_or(OidcLogoutError::Busy)?;
        seen.insert(token_id.to_owned(), until);
        Ok(())
    }

    fn insert(&self, state: String, flow: PendingFlow) -> Result<(), OidcError> {
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        flows.retain(|_, flow| flow.expires_at > now);
        if flows.len() >= MAX_PENDING_FLOWS {
            return Err(OidcError::Busy);
        }
        flows.insert(state, flow);
        Ok(())
    }

    fn take(&self, state: &str) -> Option<PendingFlow> {
        if state.is_empty() || state.len() > MAX_STATE_LEN {
            return None;
        }
        self.flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)
    }
}

enum Purpose {
    SignIn { next: Option<String> },
    Link { account_id: Uuid, session_id: Uuid },
}

impl Purpose {
    fn action(&self) -> &'static str {
        match self {
            Self::SignIn { .. } => SIGN_IN_ACTION,
            Self::Link { .. } => LINK_ACTION,
        }
    }

    fn actor(&self) -> Option<Uuid> {
        match self {
            Self::SignIn { .. } => None,
            Self::Link { account_id, .. } => Some(*account_id),
        }
    }
}

struct PendingFlow {
    browser_hash: [u8; 32],
    purpose: Purpose,
    pending: OidcPending,
    expires_at: Instant,
}

/// Where to send the browser, and the value for the flow's browser cookie.
pub struct OidcRedirect {
    pub url: String,
    browser_binding: RandomToken,
}

impl OidcRedirect {
    /// The cookie value binding the flow to this browser. Only the cookie
    /// writer should call this.
    pub fn browser_cookie_value(&self) -> &str {
        self.browser_binding.expose_cookie_value()
    }
}

/// What the provider sent the browser back with.
pub struct OidcCallback<'a> {
    pub state: &'a str,
    /// `None` when the provider returned an error instead of a code, such
    /// as the operator cancelling.
    pub code: Option<&'a str>,
}

#[derive(Debug)]
pub enum OidcFinished {
    /// Write `signed_in.token` into the session cookie and go to `next`
    /// (checked again by the caller).
    SignedIn {
        signed_in: SignedIn,
        next: Option<String>,
    },
    /// The identity is now linked to the signed-in account, or already was.
    Linked,
}

/// Why a flow ended without signing in or linking. The browser gets a
/// generic message per variant; specifics go to the log and the audit log.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("single sign-on is not configured")]
    NotConfigured,
    #[error("too many sign-ins are in progress")]
    Busy,
    /// Unknown, expired, already used, or from another browser.
    #[error("the sign-in request is not valid")]
    InvalidFlow,
    /// The provider returned an error instead of a code.
    #[error("the provider did not authorize the request")]
    ProviderDenied,
    #[error(transparent)]
    Provider(#[from] OidcProviderError),
    /// No account can sign in with this identity: it is not linked, or its
    /// account is disabled. Not distinguished.
    #[error("no account can sign in with this identity")]
    NotLinked,
    /// Linking: another account has this identity.
    #[error("this identity is linked to another account")]
    LinkedToOther,
    /// Linking: the account already has an identity at this provider.
    #[error("this account already has an identity at this provider")]
    IssuerTaken,
    /// Linking: the session that started it is no longer signed in here.
    #[error("the session that started linking is not signed in")]
    SessionChanged,
    #[error(transparent)]
    Internal(#[from] AuthError),
}

/// Why a back-channel logout request was refused. The provider gets a
/// generic answer; the reason goes to the log.
#[derive(Debug, thiserror::Error)]
pub enum OidcLogoutError {
    #[error("single sign-on is not configured")]
    NotConfigured,
    /// Too many logouts at once, or too many token IDs remembered.
    #[error("too many logout requests")]
    Busy,
    #[error("the logout token is malformed or failed verification: {0}")]
    Invalid(String),
    #[error("the logout token was used before")]
    Replayed,
    /// The provider's keys could not be fetched.
    #[error("the provider could not be reached: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Internal(#[from] AuthError),
}

impl From<supabase_dashboard_persistence::PersistenceError> for OidcLogoutError {
    fn from(err: supabase_dashboard_persistence::PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

impl From<supabase_dashboard_persistence::PersistenceError> for OidcError {
    fn from(err: supabase_dashboard_persistence::PersistenceError) -> Self {
        Self::Internal(err.into())
    }
}

impl AuthService {
    /// Signs in through `oidc` as well as with passwords.
    #[must_use]
    pub fn with_oidc(mut self, oidc: OidcSignIn) -> Self {
        self.oidc = Some(oidc);
        self
    }

    /// The provider's name for the "Sign in with" button, when configured.
    pub fn oidc_provider_name(&self) -> Option<&str> {
        self.oidc.as_ref().map(|oidc| oidc.display_name.as_str())
    }

    fn oidc(&self) -> Result<&OidcSignIn, OidcError> {
        self.oidc.as_ref().ok_or(OidcError::NotConfigured)
    }

    /// Starts signing in. `next` is the page to open afterwards; the caller
    /// checks it now and again when it is used.
    pub async fn begin_oidc_sign_in(&self, next: Option<&str>) -> Result<OidcRedirect, OidcError> {
        let next = next.filter(|next| next.len() <= MAX_NEXT_LEN);
        self.begin_oidc(Purpose::SignIn {
            next: next.map(str::to_owned),
        })
        .await
    }

    /// Starts linking an identity to the signed-in operator's account.
    pub async fn begin_oidc_link(
        &self,
        current: &CurrentSession,
    ) -> Result<OidcRedirect, OidcError> {
        self.begin_oidc(Purpose::Link {
            account_id: current.account.id,
            session_id: current.session_id,
        })
        .await
    }

    async fn begin_oidc(&self, purpose: Purpose) -> Result<OidcRedirect, OidcError> {
        let oidc = self.oidc()?;
        let authorization = oidc.provider.authorize().await?;
        let browser_binding = RandomToken::generate().map_err(AuthError::from)?;
        oidc.insert(
            authorization.state,
            PendingFlow {
                browser_hash: *browser_binding.hash(),
                purpose,
                pending: authorization.pending,
                expires_at: Instant::now()
                    .checked_add(FLOW_LIFETIME)
                    .ok_or(AuthError::LifetimeOutOfRange)?,
            },
        )?;
        Ok(OidcRedirect {
            url: authorization.url,
            browser_binding,
        })
    }

    /// Ends a flow at the callback. `browser_cookie` is the flow cookie
    /// sent with the callback; `current` is the session signed in on this
    /// browser, if any.
    pub async fn finish_oidc(
        &self,
        callback: OidcCallback<'_>,
        browser_cookie: Option<&str>,
        current: Option<&CurrentSession>,
        ctx: RequestContext<'_>,
    ) -> Result<OidcFinished, OidcError> {
        let oidc = self.oidc()?;
        // Removed first: whatever happens next, this state works once.
        let Some(flow) = oidc.take(callback.state) else {
            tracing::warn!("single sign-on callback with an unknown or used state");
            return Err(OidcError::InvalidFlow);
        };
        let action = flow.purpose.action();
        let actor = flow.purpose.actor();
        let same_browser = browser_cookie
            .and_then(RandomToken::parse)
            .is_some_and(|token| *token.hash() == flow.browser_hash);
        if !same_browser {
            tracing::warn!(action, "single sign-on callback from another browser");
            self.audit(actor, action, None, AuditOutcome::Denied, ctx)
                .await;
            return Err(OidcError::InvalidFlow);
        }
        if flow.expires_at <= Instant::now() {
            tracing::info!(action, "single sign-on callback after the flow expired");
            return Err(OidcError::InvalidFlow);
        }
        let Some(code) = callback.code else {
            tracing::info!(action, "the provider returned an error instead of a code");
            self.audit(actor, action, None, AuditOutcome::Failure, ctx)
                .await;
            return Err(OidcError::ProviderDenied);
        };
        let claims = match oidc.provider.exchange(code, &flow.pending).await {
            Ok(claims) => claims,
            Err(err) => {
                tracing::warn!(action, error = %err, "single sign-on verification failed");
                let outcome = match err {
                    OidcProviderError::Rejected(_) => AuditOutcome::Denied,
                    OidcProviderError::Unavailable(_) => AuditOutcome::Failure,
                };
                self.audit(actor, action, None, outcome, ctx).await;
                return Err(err.into());
            }
        };
        let issuer = oidc.provider.issuer();
        if !valid_subject(&claims.subject) || issuer.len() > OIDC_ISSUER_MAX_LEN {
            tracing::warn!(action, "the ID token's subject or issuer is out of range");
            self.audit(actor, action, None, AuditOutcome::Denied, ctx)
                .await;
            return Err(OidcError::Provider(OidcProviderError::Rejected(
                "subject out of range".to_owned(),
            )));
        }
        match flow.purpose {
            Purpose::SignIn { next } => {
                let signed_in = self.oidc_sign_in(issuer, &claims, ctx).await?;
                Ok(OidcFinished::SignedIn { signed_in, next })
            }
            Purpose::Link {
                account_id,
                session_id,
            } => {
                let same_session = current.is_some_and(|current| {
                    current.account.id == account_id && current.session_id == session_id
                });
                if !same_session {
                    tracing::warn!(
                        "single sign-on link finished without the session that began it"
                    );
                    self.audit(
                        Some(account_id),
                        LINK_ACTION,
                        None,
                        AuditOutcome::Denied,
                        ctx,
                    )
                    .await;
                    return Err(OidcError::SessionChanged);
                }
                self.link_oidc(account_id, issuer, &claims, ctx).await?;
                Ok(OidcFinished::Linked)
            }
        }
    }

    async fn oidc_sign_in(
        &self,
        issuer: &str,
        claims: &OidcIdentityClaims,
        ctx: RequestContext<'_>,
    ) -> Result<SignedIn, OidcError> {
        let Some(found) = self.db.find_oidc_account(issuer, &claims.subject).await? else {
            tracing::info!(outcome = "denied", "single sign-on identity is not linked");
            self.audit(None, SIGN_IN_ACTION, None, AuditOutcome::Denied, ctx)
                .await;
            return Err(OidcError::NotLinked);
        };
        let account = found.account;
        if account.disabled {
            self.audit(
                Some(account.id),
                SIGN_IN_ACTION,
                Some(("account", account.id)),
                AuditOutcome::Denied,
                ctx,
            )
            .await;
            return Err(OidcError::NotLinked);
        }
        let origin = SessionOidcOrigin {
            issuer,
            subject: &claims.subject,
            sid: claims
                .session_id
                .as_deref()
                .filter(|sid| valid_subject(sid)),
        };
        let (token, expires_at, session_id) =
            self.start_session(account.id, Some(origin), ctx).await?;
        if let Err(err) = self.db.touch_oidc_identity(found.identity_id).await {
            tracing::warn!(error = %err, "could not note the identity's last use");
        }
        self.audit(
            Some(account.id),
            SIGN_IN_ACTION,
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

    async fn link_oidc(
        &self,
        account_id: Uuid,
        issuer: &str,
        claims: &OidcIdentityClaims,
        ctx: RequestContext<'_>,
    ) -> Result<(), OidcError> {
        let id = Uuid::now_v7();
        let label = claims.label.as_deref().and_then(display_label);
        let event = AuditEvent {
            actor_account_id: Some(account_id),
            action: LINK_ACTION,
            target_type: Some("oidc_identity"),
            target_id: Some(id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
            organization_id: None,
        };
        let outcome = self
            .db
            .link_oidc_identity(
                &NewOidcIdentity {
                    id,
                    account_id,
                    issuer,
                    subject: &claims.subject,
                    label: label.as_deref(),
                },
                &event,
            )
            .await?;
        let refused = match outcome {
            LinkOidcOutcome::Linked | LinkOidcOutcome::AlreadyLinked => return Ok(()),
            LinkOidcOutcome::LinkedToOther => OidcError::LinkedToOther,
            LinkOidcOutcome::IssuerTaken => OidcError::IssuerTaken,
            LinkOidcOutcome::NoAccount => OidcError::SessionChanged,
        };
        self.audit(
            Some(account_id),
            LINK_ACTION,
            None,
            AuditOutcome::Denied,
            ctx,
        )
        .await;
        Err(refused)
    }

    /// Handles a back-channel logout from the provider: verifies
    /// `logout_token`, refuses a replayed one, and revokes the dashboard
    /// sessions it names. With a `sid`, those are the sessions started from
    /// that provider session (and, if `sub` is given too, that identity);
    /// with only `sub`, every session signed in with that identity. Password
    /// sessions are never touched. Each revocation is audited. Returns how
    /// many sessions were revoked; naming none is not an error.
    pub async fn oidc_backchannel_logout(
        &self,
        logout_token: &str,
        ctx: RequestContext<'_>,
    ) -> Result<usize, OidcLogoutError> {
        let oidc = self.oidc.as_ref().ok_or(OidcLogoutError::NotConfigured)?;
        if logout_token.is_empty() || logout_token.len() > MAX_LOGOUT_TOKEN_LEN {
            return Err(OidcLogoutError::Invalid("missing or too long".to_owned()));
        }
        let _permit = oidc
            .logouts
            .try_acquire()
            .map_err(|_| OidcLogoutError::Busy)?;
        let claims = oidc
            .provider
            .verify_logout_token(logout_token)
            .await
            .map_err(|err| match err {
                OidcProviderError::Rejected(reason) => OidcLogoutError::Invalid(reason),
                OidcProviderError::Unavailable(reason) => OidcLogoutError::Unavailable(reason),
            })?;
        let subject = claims.subject.as_deref();
        let sid = claims.session_id.as_deref();
        let in_range = |value: Option<&str>| value.is_none_or(valid_subject);
        if (subject.is_none() && sid.is_none())
            || !in_range(subject)
            || !in_range(sid)
            || claims.token_id.is_empty()
            || claims.token_id.len() > MAX_LOGOUT_TOKEN_ID_LEN
        {
            return Err(OidcLogoutError::Invalid(
                "sub, sid, or jti missing or out of range".to_owned(),
            ));
        }
        oidc.remember_logout_token(&claims.token_id)?;
        let revoked = self
            .db
            .revoke_oidc_sessions(
                OidcLogoutTarget {
                    issuer: oidc.provider.issuer(),
                    subject,
                    sid,
                },
                LOGOUT_ACTION,
                ctx.request_id,
            )
            .await?;
        tracing::info!(
            revoked = revoked.len(),
            by_sid = sid.is_some(),
            "back-channel logout from the provider"
        );
        Ok(revoked.len())
    }

    /// The signed-in operator's linked identities and the provider's name.
    pub async fn oidc_overview(&self, current: &CurrentSession) -> Result<OidcOverview, AuthError> {
        let issuer = self.oidc.as_ref().map(|oidc| oidc.provider.issuer());
        let identities = self
            .db
            .list_oidc_identities(current.account.id)
            .await?
            .into_iter()
            .map(|record| LinkedIdentity {
                current_provider: issuer == Some(record.issuer.as_str()),
                id: record.id,
                issuer: record.issuer,
                label: record.label,
                linked_at: record.created_at,
                last_used_at: record.last_used_at,
            })
            .collect();
        Ok(OidcOverview {
            provider_name: self.oidc_provider_name().map(str::to_owned),
            identities,
        })
    }

    /// Unlinks one of the signed-in operator's identities. Returns `false`
    /// when the account has no identity with that ID; callers treat that
    /// like any missing item. Every account keeps its password, so this
    /// never leaves an account without a way to sign in.
    pub async fn unlink_oidc_identity(
        &self,
        current: &CurrentSession,
        identity_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<bool, AuthError> {
        let event = AuditEvent {
            actor_account_id: Some(current.account.id),
            action: UNLINK_ACTION,
            target_type: Some("oidc_identity"),
            target_id: Some(identity_id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: ctx.request_id,
            organization_id: None,
        };
        let removed = self
            .db
            .unlink_oidc_identity(current.account.id, identity_id, &event)
            .await?;
        if !removed {
            self.audit(
                Some(current.account.id),
                UNLINK_ACTION,
                Some(("oidc_identity", identity_id)),
                AuditOutcome::Failure,
                ctx,
            )
            .await;
        }
        Ok(removed)
    }
}
