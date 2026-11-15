//! Changing the sign-in email against a scratch metadata database and a
//! fake mailer. Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use supabase_dashboard_application::{
    auth::{
        AccountUpdateError, AuthConfig, AuthService, ConfirmEmailChangeError, CurrentSession,
        EmailChangeError, RequestContext, SignInError,
    },
    mail::{EmailChangeMail, MailError, Mailer, OutgoingEmail, PasswordResetMail, SendFuture},
};
use supabase_dashboard_domain::account::EMAIL_CHANGE_LIMIT;
use supabase_dashboard_persistence::Database;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const PAGE: &str = "https://dash.example.test/dashboard/confirm-email";
const RESET_PAGE: &str = "https://dash.example.test/dashboard/reset-password";
const PASSWORD: &str = "correct horse battery staple";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-email"),
        user_agent: None,
    }
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

#[derive(Default)]
struct FakeMailer {
    sent: Mutex<Vec<OutgoingEmail>>,
    fail: Mutex<bool>,
}

impl Mailer for FakeMailer {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(message.clone());
            if *self.fail.lock().unwrap() {
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

    fn last(&self) -> OutgoingEmail {
        self.sent.lock().unwrap().last().unwrap().clone()
    }

    /// The code in the newest message with a link to `page`.
    fn last_code(&self, page: &str) -> String {
        let sent = self.sent.lock().unwrap();
        let body = &sent
            .iter()
            .rev()
            .find(|m| m.body.contains(page))
            .unwrap()
            .body;
        let start = body.find(&format!("{page}#")).unwrap() + page.len() + 1;
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
            reset_page_url: RESET_PAGE.into(),
        })
        .with_email_change_mail(EmailChangeMail {
            mailer: Arc::clone(mailer) as Arc<dyn Mailer>,
            confirm_page_url: PAGE.into(),
        });
    auth.bootstrap_owner("ops@example.test", "Ops", &secret(PASSWORD))
        .await
        .unwrap();
    (db, auth)
}

/// Adds an account with the same password as the first one.
async fn add_account(db: &Database, email: &str) -> uuid::Uuid {
    sqlx::query_scalar(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         SELECT gen_random_uuid(), $1, 'Other', password_hash FROM accounts \
         ORDER BY created_at LIMIT 1 RETURNING id",
    )
    .bind(email)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn session(auth: &AuthService, email: &str) -> CurrentSession {
    let signed_in = auth.sign_in(email, &secret(PASSWORD), ctx()).await.unwrap();
    auth.authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap()
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
async fn a_confirmed_link_changes_the_sign_in_email_once() {
    let Some(scratch) = ScratchDb::create("app_email_change").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    assert!(auth.email_change_available());
    let ops = session(&auth, "ops@example.test").await;

    let sent = auth
        .request_email_change(&ops, &secret(PASSWORD), " New@Example.test ", ctx())
        .await
        .unwrap();
    assert_eq!(sent.new_email.as_str(), "new@example.test");
    assert_eq!(mailer.count(), 1);
    let message = mailer.last();
    assert_eq!(message.to.as_str(), "new@example.test");
    assert_eq!(message.subject, "Confirm your new dashboard sign-in email");
    assert!(message.body.contains("ops@example.test"));
    let code = mailer.last_code(PAGE);

    // Nothing changes before the link is used.
    assert!(
        auth.sign_in("new@example.test", &secret(PASSWORD), ctx())
            .await
            .is_err()
    );
    let preview = auth.preview_email_change(&code).await.unwrap().unwrap();
    assert_eq!(preview.new_email.as_str(), "new@example.test");
    assert_eq!(preview.expires_at, sent.expires_at);
    assert!(
        auth.preview_email_change(&"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );

    let changed = auth.confirm_email_change(&code, ctx()).await.unwrap();
    assert_eq!(changed.as_str(), "new@example.test");
    // A notice goes to the old address.
    let notice = mailer.last();
    assert_eq!(notice.to.as_str(), "ops@example.test");
    assert_eq!(notice.subject, "Your dashboard sign-in email was changed");
    assert!(notice.body.contains("new@example.test"));
    assert!(!notice.body.contains(&code));
    assert_eq!(mailer.count(), 2);

    // The new address signs in; the old one does not. The existing session
    // stays and shows the new address.
    assert!(
        auth.sign_in("new@example.test", &secret(PASSWORD), ctx())
            .await
            .is_ok()
    );
    assert!(matches!(
        auth.sign_in("ops@example.test", &secret(PASSWORD), ctx())
            .await
            .unwrap_err(),
        SignInError::InvalidCredentials
    ));
    let again = auth
        .authenticate(
            auth.sign_in("new@example.test", &secret(PASSWORD), ctx())
                .await
                .unwrap()
                .token
                .expose_cookie_value(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.account.id, ops.account.id);

    // The link works once.
    assert!(auth.preview_email_change(&code).await.unwrap().is_none());
    assert!(matches!(
        auth.confirm_email_change(&code, ctx()).await.unwrap_err(),
        ConfirmEmailChangeError::InvalidLink
    ));

    assert_eq!(
        events(&db, "account.email_change_request", "success").await,
        1
    );
    assert_eq!(
        events(&db, "account.email_change_email", "success").await,
        1
    );
    assert_eq!(events(&db, "account.email_change", "success").await, 1);
    assert_eq!(
        events(&db, "account.email_change_notice", "success").await,
        1
    );
    assert_eq!(events(&db, "account.email_change", "failure").await, 1);
    // Audit rows hold neither the code nor an address.
    assert_eq!(audit_rows_containing(&db, &code).await, 0);
    assert_eq!(audit_rows_containing(&db, "@example.test").await, 0);
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM email_change_requests \
         WHERE strpos(encode(token_hash, 'hex'), $1) > 0",
    )
    .bind(&code)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stored, 0, "only a hash of the code is stored");

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn wrong_passwords_are_refused_and_throttled() {
    let Some(scratch) = ScratchDb::create("app_email_change_pw").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    let ops = session(&auth, "ops@example.test").await;

    for _ in 0..5 {
        assert!(matches!(
            auth.request_email_change(&ops, &secret("wrong password!!"), "new@example.test", ctx())
                .await
                .unwrap_err(),
            EmailChangeError::Account(AccountUpdateError::WrongPassword)
        ));
    }
    // The failures count toward the sign-in throttle: neither the form nor
    // sign-in accepts the right password now.
    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "new@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::Account(AccountUpdateError::Throttled { .. })
    ));
    assert!(matches!(
        auth.sign_in("ops@example.test", &secret(PASSWORD), ctx())
            .await
            .unwrap_err(),
        SignInError::Throttled { .. }
    ));
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        events(&db, "account.email_change_request", "denied").await,
        5
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM email_change_requests")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0);

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn taken_and_same_addresses_are_refused() {
    let Some(scratch) = ScratchDb::create("app_email_change_taken").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    add_account(&db, "taken@example.test").await;
    let ops = session(&auth, "ops@example.test").await;

    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "Taken@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::Taken
    ));
    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "ops@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::SameEmail
    ));
    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "not an address", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::Account(AccountUpdateError::Input(_))
    ));
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        events(&db, "account.email_change_request", "denied").await,
        1
    );

    // An address free at request time but taken before the link is used.
    auth.request_email_change(&ops, &secret(PASSWORD), "later@example.test", ctx())
        .await
        .unwrap();
    let code = mailer.last_code(PAGE);
    add_account(&db, "later@example.test").await;
    assert!(matches!(
        auth.confirm_email_change(&code, ctx()).await.unwrap_err(),
        ConfirmEmailChangeError::Taken
    ));
    assert!(
        auth.sign_in("ops@example.test", &secret(PASSWORD), ctx())
            .await
            .is_ok(),
        "the address did not change"
    );
    assert_eq!(events(&db, "account.email_change", "denied").await, 1);

    // Requests past the password check are limited per account.
    let fresh = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_email_change_mail(EmailChangeMail {
            mailer: Arc::clone(&mailer) as Arc<dyn Mailer>,
            confirm_page_url: PAGE.into(),
        });
    for i in 0..EMAIL_CHANGE_LIMIT {
        let _ = fresh
            .request_email_change(
                &ops,
                &secret(PASSWORD),
                &format!("n{i}@example.test"),
                ctx(),
            )
            .await
            .unwrap();
    }
    assert!(matches!(
        fresh
            .request_email_change(&ops, &secret(PASSWORD), "taken@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::TooMany { .. }
    ));

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn links_stop_working_when_expired_replaced_or_the_password_changes() {
    let Some(scratch) = ScratchDb::create("app_email_change_links").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    let ops = session(&auth, "ops@example.test").await;
    let password = secret(PASSWORD);
    let request = |to: &'static str| auth.request_email_change(&ops, &password, to, ctx());

    // Replaced by a newer request.
    request("first@example.test").await.unwrap();
    let first = mailer.last_code(PAGE);
    request("second@example.test").await.unwrap();
    let second = mailer.last_code(PAGE);
    assert!(auth.preview_email_change(&first).await.unwrap().is_none());
    assert!(matches!(
        auth.confirm_email_change(&first, ctx()).await.unwrap_err(),
        ConfirmEmailChangeError::InvalidLink
    ));

    // Expired.
    sqlx::query(
        "UPDATE email_change_requests SET created_at = now() - interval '2 hours', \
         expires_at = now() - interval '1 hour' WHERE revoked_at IS NULL",
    )
    .execute(db.pool())
    .await
    .unwrap();
    assert!(matches!(
        auth.confirm_email_change(&second, ctx()).await.unwrap_err(),
        ConfirmEmailChangeError::InvalidLink
    ));

    // A password change withdraws an open link.
    request("third@example.test").await.unwrap();
    let third = mailer.last_code(PAGE);
    auth.change_password(
        &ops,
        &secret(PASSWORD),
        &secret("another long passphrase"),
        ctx(),
    )
    .await
    .unwrap();
    assert!(matches!(
        auth.confirm_email_change(&third, ctx()).await.unwrap_err(),
        ConfirmEmailChangeError::InvalidLink
    ));
    assert!(matches!(
        auth.confirm_email_change("not-a-code", ctx())
            .await
            .unwrap_err(),
        ConfirmEmailChangeError::InvalidLink
    ));
    assert_eq!(events(&db, "account.email_change", "failure").await, 4);
    assert!(
        auth.sign_in(
            "ops@example.test",
            &secret("another long passphrase"),
            ctx()
        )
        .await
        .is_ok()
    );

    // A confirmed change withdraws reset links sent to the old address.
    let ops = session_with(&auth, "ops@example.test", "another long passphrase").await;
    auth.request_password_reset("ops@example.test", ctx())
        .unwrap()
        .finished()
        .await;
    let reset = mailer.last_code(RESET_PAGE);
    auth.request_email_change(
        &ops,
        &secret("another long passphrase"),
        "fourth@example.test",
        ctx(),
    )
    .await
    .unwrap();
    let fourth = mailer.last_code(PAGE);
    auth.confirm_email_change(&fourth, ctx()).await.unwrap();
    assert!(auth.preview_password_reset(&reset).await.unwrap().is_none());

    db.close().await;
    scratch.drop().await;
}

async fn session_with(auth: &AuthService, email: &str, password: &str) -> CurrentSession {
    let signed_in = auth.sign_in(email, &secret(password), ctx()).await.unwrap();
    auth.authenticate(signed_in.token.expose_cookie_value())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn requests_act_only_on_the_requesting_account() {
    let Some(scratch) = ScratchDb::create("app_email_change_iso").await else {
        return;
    };
    let mailer = Arc::new(FakeMailer::default());
    let (db, auth) = setup(&scratch, &mailer).await;
    let bob_id = add_account(&db, "bob@example.test").await;
    let ops = session(&auth, "ops@example.test").await;
    let bob = session(&auth, "bob@example.test").await;

    auth.request_email_change(&ops, &secret(PASSWORD), "ops2@example.test", ctx())
        .await
        .unwrap();
    let ops_code = mailer.last_code(PAGE);
    auth.request_email_change(&bob, &secret(PASSWORD), "bob2@example.test", ctx())
        .await
        .unwrap();
    let bob_code = mailer.last_code(PAGE);

    // Bob's request did not replace Ops's link, and each link changes only
    // its own account.
    auth.confirm_email_change(&ops_code, ctx()).await.unwrap();
    let emails: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT id, email FROM accounts ORDER BY email")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        emails,
        vec![
            (bob_id, "bob@example.test".to_owned()),
            (ops.account.id, "ops2@example.test".to_owned()),
        ]
    );
    auth.confirm_email_change(&bob_code, ctx()).await.unwrap();
    let bob_email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(bob_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(bob_email, "bob2@example.test");

    // A failed send says so; the link was never delivered.
    *mailer.fail.lock().unwrap() = true;
    let ops = session(&auth, "ops2@example.test").await;
    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "ops3@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::NotSent
    ));
    assert_eq!(
        events(&db, "account.email_change_email", "failure").await,
        1
    );

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn without_mail_the_change_is_refused() {
    let Some(scratch) = ScratchDb::create("app_email_change_off").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let auth = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap();
    auth.bootstrap_owner("ops@example.test", "Ops", &secret(PASSWORD))
        .await
        .unwrap();
    assert!(!auth.email_change_available());
    let ops = session(&auth, "ops@example.test").await;
    assert!(matches!(
        auth.request_email_change(&ops, &secret(PASSWORD), "new@example.test", ctx())
            .await
            .unwrap_err(),
        EmailChangeError::NotConfigured
    ));
    assert_eq!(
        events(&db, "account.email_change_request", "denied").await,
        1
    );

    db.close().await;
    scratch.drop().await;
}
