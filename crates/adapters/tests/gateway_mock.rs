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
        .route(
            "/storage/v1/version",
            get(|| async { (StatusCode::OK, "1.89.12") }),
        )
        .route(
            "/realtime/v1/api/ping",
            get(|headers: HeaderMap| async move {
                if has_good_key(&headers) {
                    (StatusCode::OK, r#"{"message":"Success"}"#).into_response()
                } else {
                    StatusCode::UNAUTHORIZED.into_response()
                }
            }),
        )
        .route("/functions/v1/", get(functions_router))
}

/// Upstream's Edge Functions router: it checks the JWT in `Authorization`
/// and answers a request without a function name with its own 404.
async fn functions_router(headers: HeaderMap) -> axum::response::Response {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let (status, code) = if bearer == Some(&format!("Bearer {GOOD_KEY}")) {
        (StatusCode::NOT_FOUND, "NOT_FOUND")
    } else {
        (StatusCode::UNAUTHORIZED, "UNAUTHORIZED_INVALID_JWT_FORMAT")
    };
    (
        status,
        [("sb-error-code", code)],
        format!(r#"{{"code":"{code}","message":"x"}}"#),
    )
        .into_response()
}

/// A gateway that routes only Auth, like a stack without Storage or
/// Realtime.
fn auth_only_gateway() -> Router {
    Router::new().route(
        "/auth/v1/health",
        get(|| async { (StatusCode::OK, r#"{"version":"v2.197.0"}"#) }),
    )
}

/// A gateway that routes only Auth and sends every other path to Studio's
/// basic-auth login, as upstream's Kong and Envoy configurations do.
fn auth_and_studio_gateway() -> Router {
    auth_only_gateway().fallback(|| async {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, r#"Basic realm="service""#)],
            "Unauthorized",
        )
    })
}

fn probe(policy: TargetPolicy) -> GatewayProbe {
    GatewayProbe::new(GatewaySettings {
        policy,
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_millis(800),
        ..GatewaySettings::default()
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
    let auth = probe.check(&url, StackService::Auth, &key, None).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));
    assert!(auth.latency_ms.is_some());
    assert_eq!(
        auth.certificate_expires_at, None,
        "plain HTTP has no certificate"
    );
    let rest = probe.check(&url, StackService::Rest, &key, None).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    let storage = probe.check(&url, StackService::Storage, &key, None).await;
    assert_eq!(storage.status, ServiceStatus::Healthy);
    assert_eq!(storage.version.as_deref(), Some("1.89.12"));
    let realtime = probe.check(&url, StackService::Realtime, &key, None).await;
    assert_eq!(realtime.status, ServiceStatus::Healthy);
    let functions = probe.check(&url, StackService::Functions, &key, None).await;
    assert_eq!(functions.status, ServiceStatus::Healthy);
    assert!(functions.latency_ms.is_some());
}

#[tokio::test]
async fn an_older_functions_router_counts_as_healthy() {
    // Routers from before 2025 refused a missing function name with a 400.
    let old = |body: &'static str| {
        Router::new().route(
            "/functions/v1/",
            get(move || async move { (StatusCode::BAD_REQUEST, body) }),
        )
    };
    let probe = probe(loopback());
    let key = SecretString::from(GOOD_KEY);
    let url = serve(old(r#"{"msg":"missing function name in request"}"#)).await;
    assert_eq!(
        probe
            .check(&url, StackService::Functions, &key, None)
            .await
            .status,
        ServiceStatus::Healthy
    );
    let url = serve(old(r#"{"msg":"something else"}"#)).await;
    assert_eq!(
        probe
            .check(&url, StackService::Functions, &key, None)
            .await
            .status,
        ServiceStatus::Unhealthy { http_status: 400 }
    );
}

#[tokio::test]
async fn services_without_a_route_are_reported_as_not_found() {
    let url = serve(auth_only_gateway()).await;
    let probe = probe(loopback());
    let key = SecretString::from(GOOD_KEY);
    // The gateway's own 404 has no `sb-error-code`, so it is not taken for
    // the functions router's answer.
    for service in [
        StackService::Storage,
        StackService::Realtime,
        StackService::Functions,
    ] {
        assert_eq!(
            probe.check(&url, service, &key, None).await.status,
            ServiceStatus::Unhealthy { http_status: 404 },
            "{service:?}"
        );
    }
}

#[tokio::test]
async fn services_that_reach_the_studio_login_have_no_route() {
    let url = serve(auth_and_studio_gateway()).await;
    let probe = probe(loopback());
    let key = SecretString::from(GOOD_KEY);
    for service in [
        StackService::Rest,
        StackService::Storage,
        StackService::Realtime,
        StackService::Functions,
    ] {
        assert_eq!(
            probe.check(&url, service, &key, None).await.status,
            ServiceStatus::NotRouted { http_status: 401 },
            "{service:?}"
        );
    }
    assert_eq!(
        probe
            .check(&url, StackService::Auth, &key, None)
            .await
            .status,
        ServiceStatus::Healthy
    );
}

#[tokio::test]
async fn rejected_keys_are_reported() {
    let url = serve(gateway()).await;
    let probe = probe(loopback());
    let key = SecretString::from("wrong");
    assert_eq!(
        probe
            .check(&url, StackService::Auth, &key, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
    assert_eq!(
        probe
            .check(&url, StackService::Rest, &key, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );
    assert_eq!(
        probe
            .check(&url, StackService::Realtime, &key, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
    assert_eq!(
        probe
            .check(&url, StackService::Functions, &key, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn loopback_is_refused_without_opt_in() {
    let url = serve(gateway()).await;
    let check = probe(TargetPolicy::default())
        .check(
            &url,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &by_name,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &by_name,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
        .await;
    assert_eq!(ok.status, ServiceStatus::Healthy);
}

#[tokio::test]
async fn metadata_addresses_are_never_contacted() {
    let url = ProjectUrl::parse("http://169.254.169.254").unwrap();
    let check = probe(loopback())
        .check(
            &url,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &url,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &url,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &url,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &url,
            StackService::Rest,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
        .check(
            &https,
            StackService::Auth,
            &SecretString::from(GOOD_KEY),
            None,
        )
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
    let check = probe.check(&url, StackService::Studio, &good, None).await;
    assert_eq!(check.status, ServiceStatus::Healthy);
    let check = probe.check(&url, StackService::Studio, &bad, None).await;
    assert_eq!(
        check.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );

    let url = serve(studio_gateway(false)).await;
    let check = probe.check(&url, StackService::Studio, &good, None).await;
    assert_eq!(
        check.status,
        ServiceStatus::Unprotected { http_status: 307 }
    );
}
