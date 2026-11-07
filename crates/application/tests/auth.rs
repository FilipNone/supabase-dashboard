//! Auth service against a scratch metadata database. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use secrecy::SecretString;
use supabase_dashboard_application::{
    auth::{
        AccountUpdateError, AuthConfig, AuthService, BootstrapError, RequestContext, SignInError,
    },
    throttle::ThrottleConfig,
};
use supabase_dashboard_persistence::Database;

// Shares the scratch-database helper with the persistence tests.
#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const PASSWORD: &str = "correct horse battery staple";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-1"),
        user_agent: Some("integration-test"),
    }
}

async fn service(scratch: &ScratchDb) -> (Database, AuthService) {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let config = AuthConfig {
        throttle: ThrottleConfig {
            max_failures: 3,
            window: Duration::from_secs(60),
            capacity: 100,
        },
        ..AuthConfig::default()
    };
    let auth = AuthService::new(db.clone(), config).await.unwrap();
    (db, auth)
}

async fn bootstrap(auth: &AuthService) {
    auth.bootstrap_owner("Owner@Example.test", "Owner", &SecretString::from(PASSWORD))
        .await
        .unwrap();
}

#[tokio::test]
async fn bootstrap_validates_and_runs_once() {
    let Some(scratch) = ScratchDb::create("app_bootstrap").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    assert!(!auth.is_initialized().await.unwrap());

    let weak = auth
        .bootstrap_owner("owner@example.test", "Owner", &SecretString::from("short"))
        .await;
    assert!(matches!(weak, Err(BootstrapError::Input(_))));

    bootstrap(&auth).await;
    assert!(auth.is_initialized().await.unwrap());
    let again = auth
        .bootstrap_owner(
            "second@example.test",
            "Second",
            &SecretString::from(PASSWORD),
        )
        .await;
    assert!(matches!(again, Err(BootstrapError::AlreadyInitialized)));

    let stored: String = sqlx::query_scalar("SELECT password_hash FROM accounts")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$"));
    assert!(!stored.contains(PASSWORD));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn sign_in_authenticate_and_sign_out() {
    let Some(scratch) = ScratchDb::create("app_sign_in").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;

    let signed_in = auth
        .sign_in("owner@example.test", &SecretString::from(PASSWORD), ctx())
        .await
        .unwrap();
    let cookie = signed_in.token.expose_cookie_value().to_owned();

    // Only the hash of the token is stored.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(stored.as_slice(), signed_in.token.hash());

    let current = auth.authenticate(&cookie).await.unwrap().unwrap();
    assert_eq!(current.account.email.as_str(), "owner@example.test");
    assert!(current.summary().is_installation_admin);
    assert!(auth.authenticate("garbage").await.unwrap().is_none());

    auth.sign_out(&cookie, ctx()).await.unwrap();
    assert!(auth.authenticate(&cookie).await.unwrap().is_none());
    // A second sign-out with the same cookie is harmless.
    auth.sign_out(&cookie, ctx()).await.unwrap();

    assert_eq!(db.count_audit_events("session.sign_in").await.unwrap(), 1);
    assert_eq!(db.count_audit_events("session.sign_out").await.unwrap(), 1);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn wrong_password_unknown_email_and_disabled_account_look_the_same() {
    let Some(scratch) = ScratchDb::create("app_denied").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;

    let wrong = auth
        .sign_in(
            "owner@example.test",
            &SecretString::from("not the password"),
            ctx(),
        )
        .await;
    assert!(matches!(wrong, Err(SignInError::InvalidCredentials)));
    let unknown = auth
        .sign_in("nobody@example.test", &SecretString::from(PASSWORD), ctx())
        .await;
    assert!(matches!(unknown, Err(SignInError::InvalidCredentials)));
    let malformed = auth
        .sign_in("not-an-email", &SecretString::from(PASSWORD), ctx())
        .await;
    assert!(matches!(malformed, Err(SignInError::InvalidCredentials)));

    sqlx::query("UPDATE accounts SET disabled_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    let disabled = auth
        .sign_in("owner@example.test", &SecretString::from(PASSWORD), ctx())
        .await;
    assert!(matches!(disabled, Err(SignInError::InvalidCredentials)));

    let denied: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'session.sign_in' AND outcome = 'denied'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(denied, 2, "denials against a real account are audited");
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn repeated_failures_are_throttled_even_with_the_right_password() {
    let Some(scratch) = ScratchDb::create("app_throttle").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;
    for _ in 0..3 {
        let _ = auth
            .sign_in(
                "owner@example.test",
                &SecretString::from("wrong password!"),
                ctx(),
            )
            .await;
    }
    let blocked = auth
        .sign_in("OWNER@example.test", &SecretString::from(PASSWORD), ctx())
        .await;
    assert!(matches!(blocked, Err(SignInError::Throttled { .. })));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn sessions_can_be_listed_and_revoked_only_by_their_owner() {
    let Some(scratch) = ScratchDb::create("app_revoke").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;
    let password = SecretString::from(PASSWORD);
    let first = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();
    let second = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();
    let third = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();

    let current = auth
        .authenticate(first.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    let sessions = auth.list_sessions(&current).await.unwrap();
    assert_eq!(sessions.len(), 3);
    assert_eq!(sessions[0].user_agent.as_deref(), Some("integration-test"));
    assert_eq!(
        sessions
            .iter()
            .filter(|s| s.is_current)
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        vec![current.session_id]
    );

    let other = auth
        .authenticate(second.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    assert!(
        auth.revoke_own_session(&current, other.session_id, ctx())
            .await
            .unwrap()
    );
    assert!(
        !auth
            .revoke_own_session(&current, other.session_id, ctx())
            .await
            .unwrap(),
        "already revoked"
    );
    assert!(
        auth.authenticate(second.token.expose_cookie_value())
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        auth.revoke_other_sessions(&current, ctx()).await.unwrap(),
        1
    );
    assert!(
        auth.authenticate(third.token.expose_cookie_value())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.authenticate(first.token.expose_cookie_value())
            .await
            .unwrap()
            .is_some(),
        "the current session survives"
    );
    assert_eq!(auth.prune_sessions().await.unwrap(), 2);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn display_name_changes_are_validated_and_audited() {
    let Some(scratch) = ScratchDb::create("app_profile").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;
    let signed_in = auth
        .sign_in("owner@example.test", &SecretString::from(PASSWORD), ctx())
        .await
        .unwrap();
    let current = auth
        .authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();

    let empty = auth.update_display_name(&current, "   ", ctx()).await;
    assert!(matches!(empty, Err(AccountUpdateError::Input(_))));

    let summary = auth
        .update_display_name(&current, "  Ada Owner ", ctx())
        .await
        .unwrap();
    assert_eq!(summary.display_name.as_str(), "Ada Owner");
    assert_eq!(summary.email.as_str(), "owner@example.test");
    let reloaded = auth
        .authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.account.display_name.as_str(), "Ada Owner");
    assert_eq!(
        db.count_audit_events("account.update_profile")
            .await
            .unwrap(),
        1
    );
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn password_change_checks_the_old_password_and_signs_out_elsewhere() {
    let Some(scratch) = ScratchDb::create("app_password").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;
    let password = SecretString::from(PASSWORD);
    let here = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();
    let elsewhere = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();
    let current = auth
        .authenticate(here.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    let new_password = SecretString::from("a different long passphrase");

    let weak = auth
        .change_password(&current, &password, &SecretString::from("short"), ctx())
        .await;
    assert!(matches!(weak, Err(AccountUpdateError::Input(_))));

    let wrong = auth
        .change_password(
            &current,
            &SecretString::from("not the password"),
            &new_password,
            ctx(),
        )
        .await;
    assert!(matches!(wrong, Err(AccountUpdateError::WrongPassword)));

    let revoked = auth
        .change_password(&current, &password, &new_password, ctx())
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    assert!(
        auth.authenticate(elsewhere.token.expose_cookie_value())
            .await
            .unwrap()
            .is_none(),
        "other sessions are signed out"
    );
    assert!(
        auth.authenticate(here.token.expose_cookie_value())
            .await
            .unwrap()
            .is_some(),
        "the session that changed the password stays signed in"
    );
    assert!(matches!(
        auth.sign_in("owner@example.test", &password, ctx()).await,
        Err(SignInError::InvalidCredentials)
    ));
    auth.sign_in("owner@example.test", &new_password, ctx())
        .await
        .unwrap();
    assert_eq!(
        db.count_audit_events("account.password_change")
            .await
            .unwrap(),
        2,
        "one refusal and one success"
    );
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM accounts")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(!stored.contains("a different long passphrase"));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn wrong_current_passwords_share_the_sign_in_throttle() {
    let Some(scratch) = ScratchDb::create("app_password_throttle").await else {
        return;
    };
    let (db, auth) = service(&scratch).await;
    bootstrap(&auth).await;
    let password = SecretString::from(PASSWORD);
    let here = auth
        .sign_in("owner@example.test", &password, ctx())
        .await
        .unwrap();
    let current = auth
        .authenticate(here.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap();
    let guess = SecretString::from("a wrong guess here");
    let new_password = SecretString::from("a different long passphrase");
    for _ in 0..3 {
        let result = auth
            .change_password(&current, &guess, &new_password, ctx())
            .await;
        assert!(matches!(result, Err(AccountUpdateError::WrongPassword)));
    }
    // Blocked now, even with the right password, here and at sign-in.
    let blocked = auth
        .change_password(&current, &password, &new_password, ctx())
        .await;
    assert!(matches!(blocked, Err(AccountUpdateError::Throttled { .. })));
    assert!(matches!(
        auth.sign_in("owner@example.test", &password, ctx()).await,
        Err(SignInError::Throttled { .. })
    ));
    db.close().await;
    scratch.drop().await;
}
