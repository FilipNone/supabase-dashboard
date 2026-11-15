//! The Resend mailer against an in-process HTTP server that imitates
//! `POST /emails`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    resend::{ResendMailer, ResendSettings},
    tls::ExtraRoots,
};
use supabase_dashboard_application::mail::{MailError, Mailer, OutgoingEmail};
use supabase_dashboard_domain::account::Email;

const KEY: &str = "re_test_0123456789abcdef";

#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>);

async fn serve(router: Router) -> url::Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

fn mailer(api_url: url::Url, timeout: Duration) -> ResendMailer {
    ResendMailer::new(ResendSettings {
        api_key: SecretString::from(KEY.to_owned()),
        from: "Dashboard <dash@example.test>".into(),
        timeout,
        extra_roots: ExtraRoots::default(),
        api_url,
    })
    .unwrap()
}

fn message() -> OutgoingEmail {
    OutgoingEmail {
        to: Email::parse("invitee@example.test").unwrap(),
        subject: "Invitation".into(),
        body: "Open https://dash.example.test/dashboard/invite#code".into(),
    }
}

/// Answers like Resend: 200 with an ID for the right key, otherwise its
/// 401, and a 422 that repeats the recipient for a chosen address.
async fn emails(
    State(seen): State<Seen>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    seen.0.lock().unwrap().push((headers.clone(), body.clone()));
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    if auth != Some(&format!("Bearer {KEY}")) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "statusCode": 401, "message": "API key is invalid", "name": "validation_error"
            })),
        )
            .into_response();
    }
    if body["to"][0] == "refused@example.test" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "statusCode": 422,
                "message": "Invalid `to` field: refused@example.test",
                "name": "validation_error"
            })),
        )
            .into_response();
    }
    Json(serde_json::json!({ "id": "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794" })).into_response()
}

#[tokio::test]
async fn a_message_is_posted_as_plain_text_with_the_key() {
    let seen = Seen::default();
    let url = serve(
        Router::new()
            .route("/emails", post(emails))
            .with_state(seen.clone()),
    )
    .await;
    mailer(url, Duration::from_secs(5))
        .send(&message())
        .await
        .unwrap();
    let seen = seen.0.lock().unwrap();
    let (headers, body) = &seen[0];
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        body,
        &serde_json::json!({
            "from": "Dashboard <dash@example.test>",
            "to": ["invitee@example.test"],
            "subject": "Invitation",
            "text": "Open https://dash.example.test/dashboard/invite#code",
        })
    );
}

#[tokio::test]
async fn refusals_name_the_code_but_not_the_address_or_key() {
    let url = serve(
        Router::new()
            .route("/emails", post(emails))
            .with_state(Seen::default()),
    )
    .await;
    let mut refused = message();
    refused.to = Email::parse("refused@example.test").unwrap();
    let err = mailer(url.clone(), Duration::from_secs(5))
        .send(&refused)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        MailError::Refused("Resend answered 422 (validation_error)".into())
    );

    let wrong_key = ResendMailer::new(ResendSettings {
        api_key: SecretString::from("re_wrong_key_value".to_owned()),
        from: "dash@example.test".into(),
        timeout: Duration::from_secs(5),
        extra_roots: ExtraRoots::default(),
        api_url: url,
    })
    .unwrap();
    let err = wrong_key.send(&message()).await.unwrap_err();
    assert!(matches!(err, MailError::Unavailable(_)), "{err:?}");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("re_wrong_key_value"), "{text}");
    assert!(!text.contains("invitee@example.test"), "{text}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let seen = Seen::default();
    let url = serve(
        Router::new()
            .route(
                "/emails",
                post(|| async { Redirect::temporary("/elsewhere/emails") }),
            )
            .route("/elsewhere/emails", post(emails))
            .with_state(seen.clone()),
    )
    .await;
    let err = mailer(url, Duration::from_secs(5))
        .send(&message())
        .await
        .unwrap_err();
    assert_eq!(err, MailError::Unavailable("Resend answered 307".into()));
    assert!(seen.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_slow_answer_times_out() {
    let url = serve(Router::new().route(
        "/emails",
        post(|| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::OK
        }),
    ))
    .await;
    let started = std::time::Instant::now();
    let err = mailer(url, Duration::from_millis(300))
        .send(&message())
        .await
        .unwrap_err();
    assert_eq!(err, MailError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5));
}
