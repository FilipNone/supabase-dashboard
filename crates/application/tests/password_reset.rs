//! Password reset by email against a scratch metadata database and a fake
//! mailer. Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use supabase_dashboard_application::{
    auth::{
        AuthConfig, AuthService, CompletePasswordResetError, PasswordResetRequestError,
        RequestContext, SignInError,
    },
    mail::{MailError, Mailer, OutgoingEmail, PasswordResetMail, SendFuture},
};
use supabase_dashboard_domain::account::PASSWORD_RESET_LIMIT;
use supabase_dashboard_persistence::Database;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const PAGE: &str = "https://dash.example.test/dashboard/reset-password";
const OLD: &str = "correct horse battery staple";
const NEW: &str = "a brand new passphrase";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-reset"),
        user_agent: None,
    }
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

#[derive(Default)]
struct FakeMailer {
    sent: Mutex<Vec<OutgoingEmail>>,
    fail: bool,
}

impl Mailer for FakeMailer {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(message.clone());
            if self.fail {
                Err(MailError::Unavailable("connection refused".into()))
            } else {
                Ok(())
            }
        })
    }
}

impl FakeMailer {
    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    /// The code in the newest message's link.
    fn last_code(&self) -> String {
        let sent = self.sent.lock().unwrap();
        let body = &sent.last().unwrap().body;
        let start = body.find(&format!("{PAGE}#")).unwrap() + PAGE.len() + 1;
        body[start..start + 64].to_owned()
    }
}

async fn setup(scratch: &ScratchDb, mailer: &Arc<FakeMailer>) -> (Database, AuthService) {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let auth = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_password_reset_mail(PasswordResetMail {
            mailer: Arc::clone(mailer) as Arc<dyn Mailer>,
            reset_page_url: PAGE.into(),
        });
    auth.bootstrap_owner("ops@example.test", "Ops", &secret(OLD))
        .await
        .unwrap();
    (db, auth)
}

async fn request(auth: &AuthService, email: &str) {
    auth.request_password_reset(email, ctx())
        .unwrap()
        .finished()
        .await;
}

async fn events(db: &Database, action: &str, outcome: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn audit_rows_containing(db: &Database, needle: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events a WHERE strpos(row_to_json(a)::text, $1) > 0",
    )
    .bind(needle)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn a_reset_link_sets_the_password_once_and_signs_out_everywhere() {
    let Some(scratch) = ScratchDb::create("app_reset_link").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    assert!(auth.password_reset_available());
    let signed_in = auth
        .sign_in("ops@example.test", &secret(OLD), ctx())
        .await
        .unwrap();

    request(&auth, "OPS@example.test").await;
    assert_eq!(mailer.count(), 1);
    let message = mailer.sent.lock().unwrap()[0].clone();
    assert_eq!(message.to.as_str(), "ops@example.test");
    assert_eq!(message.subject, "Reset your dashboard password");
    let code = mailer.last_code();

    let preview = auth.preview_password_reset(&code).await.unwrap().unwrap();
    assert_eq!(preview.email.as_str(), "ops@example.test");
    assert!(
        auth.preview_password_reset(&"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );

    assert!(matches!(
        auth.complete_password_reset(&code, &secret(NEW), &secret("something else"), ctx())
            .await,
        Err(CompletePasswordResetError::PasswordMismatch)
    ));
    assert!(matches!(
        auth.complete_password_reset(&code, &secret("short"), &secret("short"), ctx())
            .await,
        Err(CompletePasswordResetError::Input(_))
    ));
    auth.complete_password_reset(&code, &secret(NEW), &secret(NEW), ctx())
        .await
        .unwrap();

    // The old session and password stop working; the new password works.
    assert!(
        auth.authenticate(signed_in.token.expose_cookie_value())
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        auth.sign_in("ops@example.test", &secret(OLD), ctx()).await,
        Err(SignInError::InvalidCredentials)
    ));
    auth.sign_in("ops@example.test", &secret(NEW), ctx())
        .await
        .unwrap();

    // The link works once.
    assert!(auth.preview_password_reset(&code).await.unwrap().is_none());
    assert!(matches!(
        auth.complete_password_reset(&code, &secret(NEW), &secret(NEW), ctx())
            .await,
        Err(CompletePasswordResetError::InvalidLink)
    ));

    assert_eq!(
        events(&db, "account.password_reset_request", "success").await,
        1
    );
    assert_eq!(
        events(&db, "account.password_reset_email", "success").await,
        1
    );
    assert_eq!(events(&db, "account.password_reset", "success").await, 1);
    assert_eq!(events(&db, "account.password_reset", "failure").await, 1);
    // The code never reaches the audit log.
    assert_eq!(audit_rows_containing(&db, &code).await, 0);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn unknown_and_disabled_accounts_get_no_email_and_the_same_answer() {
    let Some(scratch) = ScratchDb::create("app_reset_unknown").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    request(&auth, "nobody@example.test").await;
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        events(&db, "account.password_reset_request", "failure").await,
        1
    );
    assert_eq!(audit_rows_containing(&db, "nobody@example.test").await, 0);

    sqlx::query("UPDATE accounts SET disabled_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    request(&auth, "ops@example.test").await;
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        events(&db, "account.password_reset_request", "denied").await,
        1
    );

    assert!(matches!(
        auth.request_password_reset("not an email", ctx()),
        Err(PasswordResetRequestError::Input(_))
    ));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn newer_links_password_changes_and_disabling_void_a_link() {
    let Some(scratch) = ScratchDb::create("app_reset_void").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;

    request(&auth, "ops@example.test").await;
    let first = mailer.last_code();
    request(&auth, "ops@example.test").await;
    let second = mailer.last_code();
    assert_ne!(first, second);
    assert!(auth.preview_password_reset(&first).await.unwrap().is_none());
    assert!(
        auth.preview_password_reset(&second)
            .await
            .unwrap()
            .is_some()
    );

    // A password change from the server command line voids the link.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    auth.reset_password("ops@example.test", &secret(NEW))
        .await
        .unwrap();
    assert!(
        auth.preview_password_reset(&second)
            .await
            .unwrap()
            .is_none()
    );

    sqlx::query("DELETE FROM password_reset_requests")
        .execute(db.pool())
        .await
        .unwrap();
    request(&auth, "ops@example.test").await;
    let third = mailer.last_code();
    sqlx::query("UPDATE accounts SET disabled_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(matches!(
        auth.complete_password_reset(&third, &secret(OLD), &secret(OLD), ctx())
            .await,
        Err(CompletePasswordResetError::InvalidLink)
    ));
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn each_account_gets_a_bounded_number_of_links() {
    let Some(scratch) = ScratchDb::create("app_reset_limit").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    for _ in 0..PASSWORD_RESET_LIMIT + 2 {
        request(&auth, "ops@example.test").await;
    }
    assert_eq!(mailer.count(), PASSWORD_RESET_LIMIT as usize);
    assert_eq!(
        events(&db, "account.password_reset_request", "denied").await,
        2
    );
    // The last link sent still works.
    let code = mailer.last_code();
    assert!(auth.preview_password_reset(&code).await.unwrap().is_some());
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn a_failed_email_is_audited_and_not_configured_is_refused() {
    let Some(scratch) = ScratchDb::create("app_reset_mail_fail").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer {
        fail: true,
        ..FakeMailer::default()
    });
    let (db, auth) = setup(&scratch, &mailer).await;
    request(&auth, "ops@example.test").await;
    assert_eq!(mailer.count(), 1);
    assert_eq!(
        events(&db, "account.password_reset_email", "failure").await,
        1
    );

    let plain = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap();
    assert!(!plain.password_reset_available());
    assert!(matches!(
        plain.request_password_reset("ops@example.test", ctx()),
        Err(PasswordResetRequestError::NotConfigured)
    ));
    db.close().await;
    scratch.drop().await;
}
