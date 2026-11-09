//! Gateway probe against an in-process HTTP server that imitates a stack's
//! API gateway. The fixture-backed test in `gateway_fixture.rs` covers the
//! real Kong configuration.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::get,
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
    connection::{ServiceStatus, StackService, UnreachableReason},
    project::ProjectUrl,
};

const GOOD_KEY: &str = "good-key";

fn has_good_key(headers: &HeaderMap) -> bool {
    headers.get("apikey").and_then(|v| v.to_str().ok()) == Some(GOOD_KEY)
}

async fn serve(router: Router) -> ProjectUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    ProjectUrl::parse(&format!("http://{addr}")).unwrap()
}

fn gateway() -> Router {
    Router::new()
        .route(
            "/auth/v1/health",
            get(|headers: HeaderMap| async move {
                if has_good_key(&headers) {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"version":"v2.197.0","name":"GoTrue","description":"x"}"#,
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::UNAUTHORIZED,
                        r#"{"message":"Invalid authentication credentials"}"#,
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/rest/v1/",
            get(|headers: HeaderMap| async move {
                if has_good_key(&headers) {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                }
            }),
        )
}

fn probe(policy: TargetPolicy) -> GatewayProbe {
    GatewayProbe::new(GatewaySettings {
        policy,
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_millis(800),
    })
    .unwrap()
}

fn loopback() -> TargetPolicy {
    TargetPolicy {
        allow_loopback: true,
    }
}

#[tokio::test]
async fn healthy_services_report_status_and_version() {
    let url = serve(gateway()).await;
    let probe = probe(loopback());
    let key = SecretString::from(GOOD_KEY);
    let auth = probe.check(&url, StackService::Auth, &key).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));
    assert!(auth.latency_ms.is_some());
    let rest = probe.check(&url, StackService::Rest, &key).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
}

#[tokio::test]
async fn rejected_keys_are_reported() {
    let url = serve(gateway()).await;
    let probe = probe(loopback());
    let key = SecretString::from("wrong");
    assert_eq!(
        probe.check(&url, StackService::Auth, &key).await.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
    assert_eq!(
        probe.check(&url, StackService::Rest, &key).await.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );
}

#[tokio::test]
async fn loopback_is_refused_without_opt_in() {
    let url = serve(gateway()).await;
    let check = probe(TargetPolicy::default())
        .check(&url, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::DestinationNotAllowed
        }
    );
}

#[tokio::test]
async fn names_resolving_to_loopback_are_refused() {
    let url = serve(gateway()).await;
    let port = url.as_str().rsplit(':').next().unwrap();
    let by_name = ProjectUrl::parse(&format!("http://localhost:{port}")).unwrap();
    let check = probe(TargetPolicy::default())
        .check(&by_name, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::DestinationNotAllowed
        }
    );
    // With loopback allowed, the same name works, so the refusal above came
    // from the policy and not from the name.
    let ok = probe(loopback())
        .check(&by_name, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(ok.status, ServiceStatus::Healthy);
}

#[tokio::test]
async fn metadata_addresses_are_never_contacted() {
    let url = ProjectUrl::parse("http://169.254.169.254").unwrap();
    let check = probe(loopback())
        .check(&url, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::DestinationNotAllowed
        }
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let url = serve(Router::new().route(
        "/auth/v1/health",
        get(|| async { Redirect::temporary("http://169.254.169.254/latest/meta-data/") }),
    ))
    .await;
    let check = probe(loopback())
        .check(&url, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(check.status, ServiceStatus::Unhealthy { http_status: 307 });
}

#[tokio::test]
async fn slow_services_time_out() {
    let url = serve(Router::new().route(
        "/auth/v1/health",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "late"
        }),
    ))
    .await;
    let check = probe(loopback())
        .check(&url, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Timeout
        }
    );
}

#[tokio::test]
async fn oversized_health_bodies_are_refused() {
    let url =
        serve(Router::new().route("/auth/v1/health", get(|| async { "x".repeat(200 * 1024) })))
            .await;
    let check = probe(loopback())
        .check(&url, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::InvalidResponse
        }
    );
}

#[tokio::test]
async fn closed_ports_are_connection_failures() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = ProjectUrl::parse(&format!("http://{addr}")).unwrap();
    let check = probe(loopback())
        .check(&url, StackService::Rest, &SecretString::from(GOOD_KEY))
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Connect
        }
    );
}

#[tokio::test]
async fn untrusted_certificates_fail_as_tls_errors() {
    // A plain HTTP server spoken to over HTTPS fails the handshake; this
    // stands in for a self-signed certificate without generating one.
    let url = serve(gateway()).await;
    let https = ProjectUrl::parse(&url.as_str().replacen("http://", "https://", 1)).unwrap();
    let check = probe(loopback())
        .check(&https, StackService::Auth, &SecretString::from(GOOD_KEY))
        .await;
    assert!(
        matches!(
            check.status,
            ServiceStatus::Unreachable {
                reason: UnreachableReason::Tls | UnreachableReason::Connect
            }
        ),
        "{:?}",
        check.status
    );
}

/// Imitates the gateway's Studio route: basic auth in front of a Studio
/// that redirects `/` to its project page.
fn studio_gateway(protected: bool) -> Router {
    // "supabase:studio-password-for-tests"
    const GOOD: &str = "Basic c3VwYWJhc2U6c3R1ZGlvLXBhc3N3b3JkLWZvci10ZXN0cw==";
    Router::new().route(
        "/",
        get(move |headers: HeaderMap| async move {
            let authorized = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some(GOOD);
            if protected && !authorized {
                StatusCode::UNAUTHORIZED.into_response()
            } else {
                Redirect::temporary("/project/default").into_response()
            }
        }),
    )
}

#[tokio::test]
async fn studio_login_is_checked_and_an_open_studio_is_reported() {
    let good = SecretString::from("supabase:studio-password-for-tests");
    let bad = SecretString::from("supabase:wrong-password-for-tests");
    let probe = probe(loopback());

    let url = serve(studio_gateway(true)).await;
    let check = probe.check(&url, StackService::Studio, &good).await;
    assert_eq!(check.status, ServiceStatus::Healthy);
    let check = probe.check(&url, StackService::Studio, &bad).await;
    assert_eq!(
        check.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );

    let url = serve(studio_gateway(false)).await;
    let check = probe.check(&url, StackService::Studio, &good).await;
    assert_eq!(
        check.status,
        ServiceStatus::Unprotected { http_status: 307 }
    );
}
