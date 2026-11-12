//! Dokploy client against an in-process server that imitates Dokploy's
//! API. `dokploy_fixture.rs` covers a real Dokploy.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::{
    Router,
    extract::RawQuery,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::get,
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    dokploy::{DokployClient, DokployError, DokploySettings},
    net::TargetPolicy,
};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    dokploy::{DokployUrl, DokployVersion, TESTED_DOKPLOY_VERSION},
};

const GOOD_KEY: &str = "good-dokploy-key";
const VERSION_PATH: &str = "/api/settings.getDokployVersion";

async fn serve(router: Router) -> DokployUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    DokployUrl::parse(&format!("http://{addr}")).unwrap()
}

/// Answers the version call the way Dokploy does: 401 without a valid
/// key, otherwise `answer` as JSON.
fn dokploy(answer: &'static str) -> Router {
    Router::new().route(
        VERSION_PATH,
        get(
            move |headers: HeaderMap, RawQuery(query): RawQuery| async move {
                assert_eq!(query, None, "nothing goes in the query string");
                if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
                    return (StatusCode::UNAUTHORIZED, r#"{"message":"Unauthorized"}"#)
                        .into_response();
                }
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    answer,
                )
                    .into_response()
            },
        ),
    )
}

fn client() -> DokployClient {
    DokployClient::new(DokploySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..DokploySettings::default()
    })
    .unwrap()
}

fn key(raw: &str) -> SecretString {
    SecretString::from(raw.to_owned())
}

#[tokio::test]
async fn a_supported_version_connects() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let connection = client().connect(&url, &key(GOOD_KEY)).await.unwrap();
    assert_eq!(connection.version, TESTED_DOKPLOY_VERSION);
}

#[tokio::test]
async fn another_minor_release_is_refused_with_its_version() {
    let url = serve(dokploy(r#""v0.32.0""#)).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(
        err,
        DokployError::UnsupportedVersion {
            found: DokployVersion::parse("v0.32.0").unwrap()
        }
    );
    assert_eq!(
        err.to_string(),
        "Dokploy v0.32.0 is not supported. This dashboard works with Dokploy v0.31.x, tested with v0.31.1."
    );
    // The version itself is still readable, for diagnostics.
    let version = client().version(&url, &key(GOOD_KEY)).await.unwrap();
    assert_eq!(version.to_string(), "v0.32.0");
}

#[tokio::test]
async fn a_wrong_key_is_rejected() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let err = client().connect(&url, &key("wrong")).await.unwrap_err();
    assert_eq!(err, DokployError::KeyRejected);
}

#[tokio::test]
async fn unreadable_versions_are_invalid_responses() {
    for answer in [r#""canary""#, r#"{"version":"v0.31.1"}"#, "v0.31.1", ""] {
        let url = serve(dokploy(answer)).await;
        let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
        assert_eq!(err, DokployError::InvalidResponse, "{answer:?}");
    }
}

#[tokio::test]
async fn oversized_answers_are_not_read() {
    let big: &'static str = Box::leak(format!("\"{}\"", "1".repeat(8 * 1024)).into_boxed_str());
    let url = serve(dokploy(big)).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::InvalidResponse);
}

#[tokio::test]
async fn errors_and_redirects_are_reported_not_followed() {
    let router = Router::new()
        .route(
            VERSION_PATH,
            get(|| async { Redirect::temporary("http://169.254.169.254/latest") }),
        )
        .route(
            "/other/api/settings.getDokployVersion",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
    let url = serve(router).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::Http(307));

    let other = DokployUrl::parse(&format!("{}/other", url.as_str())).unwrap();
    let err = client().connect(&other, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::Http(500));
}

#[tokio::test]
async fn refused_destinations_are_not_contacted() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let strict = DokployClient::new(DokploySettings::default()).unwrap();
    assert_eq!(
        strict.connect(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
    let named = DokployUrl::parse("http://localhost:9").unwrap();
    assert_eq!(
        strict.connect(&named, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
    let metadata = DokployUrl::parse("http://169.254.169.254").unwrap();
    assert_eq!(
        strict.connect(&metadata, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
}

#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = DokployUrl::parse(&format!("http://{addr}")).unwrap();
    assert_eq!(
        client().connect(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::Connect)
    );
}

#[tokio::test]
async fn errors_never_carry_the_key() {
    let secret = "sk-dokploy-must-not-leak";
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let err = client().connect(&url, &key(secret)).await.unwrap_err();
    assert!(!err.to_string().contains(secret));
    assert!(!format!("{err:?}").contains(secret));
    // A key that cannot be a header value is refused without a request.
    let err = client().connect(&url, &key("bad\nkey")).await.unwrap_err();
    assert_eq!(err, DokployError::KeyRejected);
}

#[tokio::test]
async fn the_application_connector_reports_the_version_or_the_refusal() {
    // A trait object, as the server holds it.
    let connector = DokployClient::shared(DokploySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..DokploySettings::default()
    })
    .unwrap();
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    assert_eq!(
        connector.connect(&url, &key(GOOD_KEY)).await.unwrap(),
        TESTED_DOKPLOY_VERSION
    );
    assert_eq!(
        connector.connect(&url, &key("wrong")).await.unwrap_err(),
        DokployError::KeyRejected
    );
    let newer = serve(dokploy(r#""v0.32.0""#)).await;
    assert!(matches!(
        connector.connect(&newer, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::UnsupportedVersion { .. }
    ));
}
