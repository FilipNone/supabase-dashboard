//! SMTP mailer against the disposable Mailpit fixture
//! (`tests/fixtures/mail`). Skipped unless
//! `SUPABASE_DASHBOARD_TEST_MAIL_FIXTURE` is set (to any value) after
//! `tests/fixtures/mail/setup.sh` has run.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use secrecy::SecretString;
use supabase_dashboard_adapters::{
    mail::{SmtpEndpoint, SmtpMailer, SmtpSecurity, SmtpSettings},
    tls::ExtraRoots,
};
use supabase_dashboard_application::mail::{MailError, Mailer, OutgoingEmail};
use supabase_dashboard_domain::account::Email;

const ENV: &str = "SUPABASE_DASHBOARD_TEST_MAIL_FIXTURE";
const PLAIN_SMTP: u16 = 54350;
const PLAIN_API: u16 = 54351;
const TLS_SMTP: u16 = 54352;
const TLS_API: u16 = 54353;
const USERNAME: &str = "dashboard";
const PASSWORD: &str = "fixture-only-password";

fn enabled() -> bool {
    let on = std::env::var_os(ENV).is_some();
    if !on {
        eprintln!("skipping: {ENV} is not set");
    }
    on
}

fn fixture_ca() -> ExtraRoots {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/mail/certs/ca.crt"
    );
    let pem = std::fs::read(path).expect("run tests/fixtures/mail/setup.sh first");
    ExtraRoots::from_pem(&pem).unwrap()
}

fn settings(
    port: u16,
    security: SmtpSecurity,
    credentials: Option<(&str, &str)>,
    extra_roots: ExtraRoots,
) -> SmtpSettings {
    SmtpSettings {
        endpoint: SmtpEndpoint {
            host: "localhost".into(),
            port,
            security,
        },
        credentials: credentials
            .map(|(user, password)| (user.to_owned(), SecretString::from(password.to_owned()))),
        from: "Dashboard <dashboard@example.test>".into(),
        timeout: Duration::from_secs(10),
        hello_name: Some("dash.example.test".into()),
        extra_roots,
    }
}

/// A message with a subject no other test uses.
fn message(tag: &str) -> OutgoingEmail {
    OutgoingEmail {
        to: Email::parse("invitee@example.test").unwrap(),
        subject: format!("Invitation {tag} {}", uuid_like()),
        body: "Open this link to accept:\nhttps://dash.example.test/dashboard/invite#code\n".into(),
    }
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// The messages Mailpit holds with exactly `subject`.
async fn received(api_port: u16, subject: &str) -> Vec<serde_json::Value> {
    let body = http_get(api_port, "/api/v1/messages?limit=200").await;
    let list: serde_json::Value = serde_json::from_str(&body).unwrap();
    list["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["Subject"] == subject)
        .cloned()
        .collect()
}

/// A plain HTTP/1.0 GET against the fixture's API on loopback.
async fn http_get(port: u16, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    raw.split_once("\r\n\r\n").unwrap().1.to_owned()
}

#[tokio::test]
async fn plain_smtp_delivers_a_plain_text_message() {
    if !enabled() {
        return;
    }
    let mailer = SmtpMailer::new(settings(
        PLAIN_SMTP,
        SmtpSecurity::Plaintext,
        None,
        ExtraRoots::default(),
    ))
    .unwrap();
    let message = message("plain");
    mailer.send(&message).await.unwrap();

    let found = received(PLAIN_API, &message.subject).await;
    assert_eq!(found.len(), 1);
    let id = found[0]["ID"].as_str().unwrap();
    let full: serde_json::Value =
        serde_json::from_str(&http_get(PLAIN_API, &format!("/api/v1/message/{id}")).await).unwrap();
    assert_eq!(full["To"][0]["Address"], "invitee@example.test");
    assert_eq!(full["From"]["Address"], "dashboard@example.test");
    assert_eq!(full["From"]["Name"], "Dashboard");
    assert!(
        full["Text"]
            .as_str()
            .unwrap()
            .contains("https://dash.example.test/dashboard/invite#code")
    );
    assert_eq!(full["HTML"], "");
}

#[tokio::test]
async fn starttls_with_the_fixture_ca_logs_in_and_delivers() {
    if !enabled() {
        return;
    }
    let mailer = SmtpMailer::new(settings(
        TLS_SMTP,
        SmtpSecurity::StartTls,
        Some((USERNAME, PASSWORD)),
        fixture_ca(),
    ))
    .unwrap();
    let message = message("starttls");
    mailer.send(&message).await.unwrap();
    assert_eq!(received(TLS_API, &message.subject).await.len(), 1);
}

#[tokio::test]
async fn an_untrusted_certificate_stops_the_send() {
    if !enabled() {
        return;
    }
    // The bundled roots alone do not trust the fixture's authority.
    let mailer = SmtpMailer::new(settings(
        TLS_SMTP,
        SmtpSecurity::StartTls,
        Some((USERNAME, PASSWORD)),
        ExtraRoots::default(),
    ))
    .unwrap();
    let message = message("untrusted");
    let err = mailer.send(&message).await.unwrap_err();
    assert!(matches!(err, MailError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains(PASSWORD));
    assert!(received(TLS_API, &message.subject).await.is_empty());
}

#[tokio::test]
async fn a_wrong_password_is_refused_and_not_echoed() {
    if !enabled() {
        return;
    }
    let wrong = "not-the-fixture-password";
    let mailer = SmtpMailer::new(settings(
        TLS_SMTP,
        SmtpSecurity::StartTls,
        Some((USERNAME, wrong)),
        fixture_ca(),
    ))
    .unwrap();
    let message = message("wrong-password");
    let err = mailer.send(&message).await.unwrap_err();
    assert!(!err.to_string().contains(wrong), "{err}");
    assert!(received(TLS_API, &message.subject).await.is_empty());
}

#[tokio::test]
async fn the_tls_server_refuses_mail_without_starttls() {
    if !enabled() {
        return;
    }
    let mailer = SmtpMailer::new(settings(
        TLS_SMTP,
        SmtpSecurity::Plaintext,
        None,
        ExtraRoots::default(),
    ))
    .unwrap();
    let message = message("no-starttls");
    mailer.send(&message).await.unwrap_err();
    assert!(received(TLS_API, &message.subject).await.is_empty());
}
