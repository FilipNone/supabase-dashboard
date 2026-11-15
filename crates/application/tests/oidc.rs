//! Single sign-on rules against a scratch metadata database, with a fake
//! provider that hands back whatever subject the test asks for. The
//! protocol checks themselves (signature, audience, expiry, nonce) are
//! covered by the server's tests against a mock provider. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use secrecy::SecretString;
use supabase_dashboard_application::auth::{
    AuthConfig, AuthService, CurrentSession, RequestContext,
    oidc::{
        AuthorizeFuture, ExchangeFuture, LogoutTokenFuture, OidcAuthorization, OidcCallback,
        OidcError, OidcFinished, OidcIdentityClaims, OidcLogoutClaims, OidcLogoutError,
        OidcPending, OidcProvider, OidcProviderError, OidcRedirect, OidcSignIn,
    },
};
use supabase_dashboard_persistence::Database;
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const PASSWORD: &str = "correct horse battery staple";
const ISSUER: &str = "https://idp.example.test/";

/// The code `sub:<subject>` signs in as `<subject>`; `rejected` fails
/// verification; anything else means the provider is unreachable.
struct FakeProvider {
    issuer: &'static str,
    next_state: AtomicU64,
}

impl OidcProvider for FakeProvider {
    fn issuer(&self) -> &str {
        self.issuer
    }

    fn authorize(&self) -> AuthorizeFuture<'_> {
        let n = self.next_state.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let state = format!("state-{n}");
            Ok(OidcAuthorization {
                url: format!("{}authorize?state={state}", self.issuer),
                state,
                pending: OidcPending {
                    pkce_verifier: SecretString::from("verifier"),
                    nonce: SecretString::from("nonce"),
                },
            })
        })
    }

    fn exchange<'a>(&'a self, code: &'a str, _pending: &'a OidcPending) -> ExchangeFuture<'a> {
        Box::pin(async move {
            if let Some(subject) = code.strip_prefix("sub:") {
                // `sub:<subject>@<sid>` names a provider session too.
                let (subject, sid) = match subject.split_once('@') {
                    Some((subject, sid)) => (subject, Some(sid.to_owned())),
                    None => (subject, None),
                };
                Ok(OidcIdentityClaims {
                    subject: subject.to_owned(),
                    label: Some(format!("{subject}@idp.example.test")),
                    session_id: sid,
                })
            } else if code == "rejected" {
                Err(OidcProviderError::Rejected("audience".to_owned()))
            } else {
                Err(OidcProviderError::Unavailable(
                    "connection refused".to_owned(),
                ))
            }
        })
    }

    /// `sub=<s>;sid=<s>;jti=<s>` with any part left out; `rejected` fails
    /// verification; `down` means the provider is unreachable.
    fn verify_logout_token<'a>(&'a self, token: &'a str) -> LogoutTokenFuture<'a> {
        Box::pin(async move {
            match token {
                "rejected" => return Err(OidcProviderError::Rejected("signature".to_owned())),
                "down" => {
                    return Err(OidcProviderError::Unavailable(
                        "connection refused".to_owned(),
                    ));
                }
                _ => {}
            }
            let part = |name: &str| {
                token
                    .split(';')
                    .find_map(|part| part.strip_prefix(&format!("{name}=")))
                    .map(str::to_owned)
            };
            Ok(OidcLogoutClaims {
                subject: part("sub"),
                session_id: part("sid"),
                token_id: part("jti").unwrap_or_default(),
            })
        })
    }
}

fn provider(issuer: &'static str) -> Arc<dyn OidcProvider> {
    Arc::new(FakeProvider {
        issuer,
        next_state: AtomicU64::new(0),
    })
}

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-oidc"),
        user_agent: Some("integration-test"),
    }
}

async fn audited(db: &Database, action: &str, outcome: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn service(scratch: &ScratchDb, issuer: &'static str) -> (Database, AuthService) {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let auth = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_oidc(OidcSignIn::new(provider(issuer), "Example IdP"));
    auth.bootstrap_owner("owner@example.test", "Owner", &SecretString::from(PASSWORD))
        .await
        .unwrap();
    (db, auth)
}

async fn add_account(db: &Database, email: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         SELECT gen_random_uuid(), $1, $1, password_hash FROM accounts \
         ORDER BY created_at LIMIT 1 RETURNING id",
    )
    .bind(email)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn session_for(auth: &AuthService, email: &str) -> CurrentSession {
    let signed_in = auth
        .sign_in(email, &SecretString::from(PASSWORD), ctx())
        .await
        .unwrap();
    auth.authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap()
}

fn state_of(redirect: &OidcRedirect) -> String {
    redirect.url.split("state=").nth(1).unwrap().to_owned()
}

/// Finishes `redirect` from the browser that started it.
async fn finish(
    auth: &AuthService,
    redirect: &OidcRedirect,
    code: Option<&str>,
    current: Option<&CurrentSession>,
) -> Result<OidcFinished, OidcError> {
    let state = state_of(redirect);
    auth.finish_oidc(
        OidcCallback {
            state: &state,
            code,
        },
        Some(redirect.browser_cookie_value()),
        current,
        ctx(),
    )
    .await
}

async fn link(
    auth: &AuthService,
    current: &CurrentSession,
    subject: &str,
) -> Result<OidcFinished, OidcError> {
    let redirect = auth.begin_oidc_link(current).await.unwrap();
    finish(
        auth,
        &redirect,
        Some(&format!("sub:{subject}")),
        Some(current),
    )
    .await
}

async fn sign_in(auth: &AuthService, subject: &str) -> Result<OidcFinished, OidcError> {
    let redirect = auth
        .begin_oidc_sign_in(Some("/dashboard/projects"))
        .await
        .unwrap();
    finish(auth, &redirect, Some(&format!("sub:{subject}")), None).await
}

/// The account a sign-in landed in.
async fn signed_in_as(auth: &AuthService, finished: OidcFinished) -> (Uuid, Option<String>) {
    let (signed_in, next) = match finished {
        OidcFinished::SignedIn { signed_in, next } => Some((signed_in, next)),
        OidcFinished::Linked => None,
    }
    .unwrap();
    let current = auth
        .authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    (current.account.id, next)
}

#[tokio::test]
async fn an_identity_signs_in_only_after_it_is_linked() {
    let Some(scratch) = ScratchDb::create("app_oidc_link").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let owner = session_for(&auth, "owner@example.test").await;

    // Not linked: refused, and nothing tells the browser which account
    // the provider's email might match.
    assert!(matches!(
        sign_in(&auth, "alice").await,
        Err(OidcError::NotLinked)
    ));
    assert_eq!(audited(&db, "session.sign_in_oidc", "denied").await, 1);

    assert!(matches!(
        link(&auth, &owner, "alice").await,
        Ok(OidcFinished::Linked)
    ));
    assert_eq!(audited(&db, "account.oidc_link", "success").await, 1);
    // Linking the same identity again changes nothing.
    assert!(matches!(
        link(&auth, &owner, "alice").await,
        Ok(OidcFinished::Linked)
    ));
    assert_eq!(audited(&db, "account.oidc_link", "success").await, 1);

    let overview = auth.oidc_overview(&owner).await.unwrap();
    assert_eq!(overview.provider_name.as_deref(), Some("Example IdP"));
    assert_eq!(overview.identities.len(), 1);
    assert_eq!(overview.identities[0].issuer, ISSUER);
    assert_eq!(
        overview.identities[0].label.as_deref(),
        Some("alice@idp.example.test")
    );
    assert!(overview.identities[0].current_provider);
    assert!(overview.identities[0].last_used_at.is_none());

    let (account, next) = signed_in_as(&auth, sign_in(&auth, "alice").await.unwrap()).await;
    assert_eq!(account, owner.account.id);
    assert_eq!(next.as_deref(), Some("/dashboard/projects"));
    assert_eq!(audited(&db, "session.sign_in_oidc", "success").await, 1);
    let overview = auth.oidc_overview(&owner).await.unwrap();
    assert!(overview.identities[0].last_used_at.is_some());

    // A second identity at the same provider is refused.
    assert!(matches!(
        link(&auth, &owner, "alice-2").await,
        Err(OidcError::IssuerTaken)
    ));

    // Nothing in the audit log holds the subject, the code, or the label.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE '%oidc%' \
         AND (coalesce(target_id, '') LIKE '%alice%' OR coalesce(target_type, '') LIKE '%alice%')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(leaked, 0);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn identities_never_cross_accounts() {
    let Some(scratch) = ScratchDb::create("app_oidc_isolation").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let bob_id = add_account(&db, "bob@example.test").await;
    let owner = session_for(&auth, "owner@example.test").await;
    let bob = session_for(&auth, "bob@example.test").await;

    link(&auth, &owner, "alice").await.unwrap();
    // Bob cannot take Alice's identity, even with the same email at the
    // provider.
    assert!(matches!(
        link(&auth, &bob, "alice").await,
        Err(OidcError::LinkedToOther)
    ));
    assert_eq!(audited(&db, "account.oidc_link", "denied").await, 1);
    link(&auth, &bob, "bob").await.unwrap();

    let (account, _) = signed_in_as(&auth, sign_in(&auth, "alice").await.unwrap()).await;
    assert_eq!(account, owner.account.id);
    let (account, _) = signed_in_as(&auth, sign_in(&auth, "bob").await.unwrap()).await;
    assert_eq!(account, bob_id);

    // Bob cannot see or unlink the owner's identity.
    let owner_identity = auth.oidc_overview(&owner).await.unwrap().identities[0].id;
    let bob_view = auth.oidc_overview(&bob).await.unwrap();
    assert_eq!(bob_view.identities.len(), 1);
    assert_ne!(bob_view.identities[0].id, owner_identity);
    assert!(
        !auth
            .unlink_oidc_identity(&bob, owner_identity, ctx())
            .await
            .unwrap()
    );
    assert_eq!(audited(&db, "account.oidc_unlink", "failure").await, 1);
    let (account, _) = signed_in_as(&auth, sign_in(&auth, "alice").await.unwrap()).await;
    assert_eq!(account, owner.account.id);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn unlinked_identities_and_disabled_accounts_cannot_sign_in() {
    let Some(scratch) = ScratchDb::create("app_oidc_unlink").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let bob_id = add_account(&db, "bob@example.test").await;
    let owner = session_for(&auth, "owner@example.test").await;
    let bob = session_for(&auth, "bob@example.test").await;
    link(&auth, &owner, "alice").await.unwrap();
    link(&auth, &bob, "bob").await.unwrap();

    let identity = auth.oidc_overview(&owner).await.unwrap().identities[0].id;
    assert!(
        auth.unlink_oidc_identity(&owner, identity, ctx())
            .await
            .unwrap()
    );
    assert_eq!(audited(&db, "account.oidc_unlink", "success").await, 1);
    assert!(
        auth.oidc_overview(&owner)
            .await
            .unwrap()
            .identities
            .is_empty()
    );
    assert!(matches!(
        sign_in(&auth, "alice").await,
        Err(OidcError::NotLinked)
    ));
    // The password still works.
    session_for(&auth, "owner@example.test").await;

    assert!(
        auth.admin_set_account_disabled(&owner, bob_id, true, ctx())
            .await
            .unwrap()
    );
    assert!(matches!(
        sign_in(&auth, "bob").await,
        Err(OidcError::NotLinked)
    ));
    assert_eq!(audited(&db, "session.sign_in_oidc", "denied").await, 2);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn a_flow_works_once_and_only_in_its_own_browser() {
    let Some(scratch) = ScratchDb::create("app_oidc_flows").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let owner = session_for(&auth, "owner@example.test").await;
    link(&auth, &owner, "alice").await.unwrap();

    // Replaying a finished callback fails.
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    finish(&auth, &redirect, Some("sub:alice"), None)
        .await
        .unwrap();
    assert!(matches!(
        finish(&auth, &redirect, Some("sub:alice"), None).await,
        Err(OidcError::InvalidFlow)
    ));

    // Another browser's callback fails, and uses the flow up.
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    let other = auth.begin_oidc_sign_in(None).await.unwrap();
    let state = state_of(&redirect);
    for cookie in [
        None,
        Some(other.browser_cookie_value()),
        Some("not-a-token"),
    ] {
        let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
        let state = state_of(&redirect);
        assert!(matches!(
            auth.finish_oidc(
                OidcCallback {
                    state: &state,
                    code: Some("sub:alice")
                },
                cookie,
                None,
                ctx(),
            )
            .await,
            Err(OidcError::InvalidFlow)
        ));
        assert!(matches!(
            finish(&auth, &redirect, Some("sub:alice"), None).await,
            Err(OidcError::InvalidFlow)
        ));
    }
    assert!(matches!(
        auth.finish_oidc(
            OidcCallback {
                state: &state,
                code: Some("sub:alice")
            },
            Some(other.browser_cookie_value()),
            None,
            ctx(),
        )
        .await,
        Err(OidcError::InvalidFlow)
    ));
    // Unknown and oversized states.
    for state in ["", "state-unknown", "s".repeat(300).as_str()] {
        assert!(matches!(
            auth.finish_oidc(
                OidcCallback {
                    state,
                    code: Some("sub:alice")
                },
                Some(redirect.browser_cookie_value()),
                None,
                ctx(),
            )
            .await,
            Err(OidcError::InvalidFlow)
        ));
    }

    // Cancelled at the provider, refused by verification, provider down.
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    assert!(matches!(
        finish(&auth, &redirect, None, None).await,
        Err(OidcError::ProviderDenied)
    ));
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    assert!(matches!(
        finish(&auth, &redirect, Some("rejected"), None).await,
        Err(OidcError::Provider(OidcProviderError::Rejected(_)))
    ));
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    assert!(matches!(
        finish(&auth, &redirect, Some("down"), None).await,
        Err(OidcError::Provider(OidcProviderError::Unavailable(_)))
    ));
    // Subjects outside the OpenID Connect limits are refused.
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    let long = format!("sub:{}", "a".repeat(256));
    assert!(matches!(
        finish(&auth, &redirect, Some(&long), None).await,
        Err(OidcError::Provider(OidcProviderError::Rejected(_)))
    ));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn linking_needs_the_session_that_started_it() {
    let Some(scratch) = ScratchDb::create("app_oidc_link_session").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    add_account(&db, "bob@example.test").await;
    let owner = session_for(&auth, "owner@example.test").await;
    let owner_again = session_for(&auth, "owner@example.test").await;
    let bob = session_for(&auth, "bob@example.test").await;

    for current in [None, Some(&bob), Some(&owner_again)] {
        let redirect = auth.begin_oidc_link(&owner).await.unwrap();
        assert!(matches!(
            finish(&auth, &redirect, Some("sub:alice"), current).await,
            Err(OidcError::SessionChanged)
        ));
    }
    assert!(
        auth.oidc_overview(&owner)
            .await
            .unwrap()
            .identities
            .is_empty()
    );
    assert!(
        auth.oidc_overview(&bob)
            .await
            .unwrap()
            .identities
            .is_empty()
    );
    assert_eq!(audited(&db, "account.oidc_link", "denied").await, 3);

    // Finished in the session that started it, the link goes through.
    assert!(matches!(
        link(&auth, &owner, "alice").await,
        Ok(OidcFinished::Linked)
    ));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn identities_of_another_provider_are_listed_but_do_not_sign_in() {
    let Some(scratch) = ScratchDb::create("app_oidc_issuer").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let owner = session_for(&auth, "owner@example.test").await;
    link(&auth, &owner, "alice").await.unwrap();

    // The deployment switches providers: the same subject at another
    // issuer is a different identity.
    let other = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_oidc(OidcSignIn::new(
            provider("https://other-idp.example.test/"),
            "Other IdP",
        ));
    assert!(matches!(
        sign_in(&other, "alice").await,
        Err(OidcError::NotLinked)
    ));
    let overview = other.oidc_overview(&owner).await.unwrap();
    assert_eq!(overview.identities.len(), 1);
    assert!(!overview.identities[0].current_provider);

    // Without a provider, nothing starts.
    let none = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap();
    assert!(none.oidc_provider_name().is_none());
    assert!(matches!(
        none.begin_oidc_sign_in(None).await,
        Err(OidcError::NotConfigured)
    ));
    assert!(matches!(
        none.begin_oidc_link(&owner).await,
        Err(OidcError::NotConfigured)
    ));
    db.close().await;
    scratch.drop().await;
}

/// The cookie value of a single sign-on as `code` (`sub:<subject>@<sid>`).
async fn oidc_session(auth: &AuthService, code: &str) -> String {
    let redirect = auth.begin_oidc_sign_in(None).await.unwrap();
    let signed_in = match finish(auth, &redirect, Some(code), None).await.unwrap() {
        OidcFinished::SignedIn { signed_in, .. } => Some(signed_in),
        OidcFinished::Linked => None,
    };
    signed_in.unwrap().token.expose_cookie_value().to_owned()
}

async fn alive(auth: &AuthService, cookie: &str) -> bool {
    auth.authenticate(cookie).await.unwrap().is_some()
}

#[tokio::test]
async fn backchannel_logout_revokes_only_the_sessions_it_names() {
    let Some(scratch) = ScratchDb::create("app_oidc_logout").await else {
        return;
    };
    let (db, auth) = service(&scratch, ISSUER).await;
    let owner = session_for(&auth, "owner@example.test").await;
    link(&auth, &owner, "alice").await.unwrap();
    let password = auth
        .sign_in("owner@example.test", &SecretString::from(PASSWORD), ctx())
        .await
        .unwrap()
        .token
        .expose_cookie_value()
        .to_owned();
    let first = oidc_session(&auth, "sub:alice@sid-1").await;
    let second = oidc_session(&auth, "sub:alice@sid-2").await;
    let no_sid = oidc_session(&auth, "sub:alice").await;

    // By sid: only that provider session ends.
    assert_eq!(
        auth.oidc_backchannel_logout("sid=sid-1;jti=j1", ctx())
            .await
            .unwrap(),
        1
    );
    assert!(!alive(&auth, &first).await);
    assert!(alive(&auth, &second).await);
    assert!(alive(&auth, &no_sid).await);

    // The same token again is a replay.
    assert!(matches!(
        auth.oidc_backchannel_logout("sid=sid-1;jti=j1", ctx())
            .await,
        Err(OidcLogoutError::Replayed)
    ));
    // An unknown sid, or a sid with another subject, ends nothing.
    for token in ["sid=unknown;jti=j2", "sub=bob;sid=sid-2;jti=j3"] {
        assert_eq!(auth.oidc_backchannel_logout(token, ctx()).await.unwrap(), 0);
    }
    assert!(alive(&auth, &second).await);

    // Refused tokens.
    for token in ["sid=sid-2", "jti=j4", "rejected", ""] {
        assert!(
            matches!(
                auth.oidc_backchannel_logout(token, ctx()).await,
                Err(OidcLogoutError::Invalid(_))
            ),
            "{token}"
        );
    }
    assert!(matches!(
        auth.oidc_backchannel_logout("down", ctx()).await,
        Err(OidcLogoutError::Unavailable(_))
    ));

    // By sub: every single sign-on session of the identity, and never the
    // password session of the same account.
    assert_eq!(
        auth.oidc_backchannel_logout("sub=alice;jti=j5", ctx())
            .await
            .unwrap(),
        2
    );
    assert!(!alive(&auth, &second).await);
    assert!(!alive(&auth, &no_sid).await);
    assert!(alive(&auth, &password).await);
    assert_eq!(
        audited(&db, "session.oidc_backchannel_logout", "success").await,
        3
    );

    // Another provider's logout never touches these sessions.
    let fresh = oidc_session(&auth, "sub:alice@sid-9").await;
    let other = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_oidc(OidcSignIn::new(
            provider("https://other-idp.example.test/"),
            "Other IdP",
        ));
    assert_eq!(
        other
            .oidc_backchannel_logout("sub=alice;sid=sid-9;jti=j6", ctx())
            .await
            .unwrap(),
        0
    );
    assert!(alive(&auth, &fresh).await);

    // Without a provider there is nothing to log out of.
    let none = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap();
    assert!(matches!(
        none.oidc_backchannel_logout("sub=alice;jti=j7", ctx())
            .await,
        Err(OidcLogoutError::NotConfigured)
    ));
    db.close().await;
    scratch.drop().await;
}
