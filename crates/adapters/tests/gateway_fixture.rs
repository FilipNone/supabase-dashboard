//! Gateway probe and Studio forwarding against the disposable Supabase
//! fixture's Kong gateway (`tests/fixtures/supabase`). Skipped unless
//! `SUPABASE_DASHBOARD_TEST_FIXTURE_URL` is set, for example to
//! `http://127.0.0.1:54321`. Keys and the Studio login come from the
//! fixture's env file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use axum::http::{HeaderMap, Method, StatusCode, header};
use http_body_util::BodyExt;
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
    studio_proxy::{ProxyBody, ProxyRequest, StudioProxy, StudioProxySettings, StudioSite},
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
    connection::{ServiceStatus, StackService},
    project::ProjectUrl,
};

const ENV: &str = "SUPABASE_DASHBOARD_TEST_FIXTURE_URL";

fn fixture_url() -> Option<ProjectUrl> {
    match std::env::var(ENV) {
        Ok(raw) => Some(ProjectUrl::parse(&raw).unwrap()),
        Err(_) => {
            eprintln!("skipping: {ENV} is not set");
            None
        }
    }
}

/// The fixture binds to loopback.
fn loopback() -> TargetPolicy {
    TargetPolicy {
        allow_loopback: true,
    }
}

fn studio_login() -> SecretString {
    SecretString::from(format!(
        "{}:{}",
        fixture_value("DASHBOARD_USERNAME"),
        fixture_value("DASHBOARD_PASSWORD")
    ))
}

fn fixture_value(name: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/supabase/fixture.env"
    );
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} missing from fixture.env"))
        .to_owned()
}

#[tokio::test]
async fn fixture_gateway_reports_auth_and_rest() {
    let Some(url) = fixture_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();
    let anon = SecretString::from(fixture_value("ANON_KEY"));
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));

    let auth = probe.check(&url, StackService::Auth, &anon).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));

    // Upstream limits the PostgREST root to the service role.
    let rest = probe.check(&url, StackService::Rest, &service).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    let rest_anon = probe.check(&url, StackService::Rest, &anon).await;
    assert_eq!(
        rest_anon.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );

    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe.check(&url, StackService::Auth, &wrong).await.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_gateway_reports_storage_and_realtime() {
    let Some(url) = fixture_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();
    let anon = SecretString::from(fixture_value("ANON_KEY"));

    let storage = probe.check(&url, StackService::Storage, &anon).await;
    assert_eq!(storage.status, ServiceStatus::Healthy);
    assert_eq!(storage.version.as_deref(), Some("1.89.12"));

    let realtime = probe.check(&url, StackService::Realtime, &anon).await;
    assert_eq!(realtime.status, ServiceStatus::Healthy);
    assert_eq!(realtime.version, None);

    // Realtime sits behind the gateway's key check; Storage checks keys
    // itself and leaves its version path open, as upstream does.
    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe
            .check(&url, StackService::Realtime, &wrong)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_studio_route_needs_the_login() {
    let Some(url) = fixture_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();
    let studio = probe
        .check(&url, StackService::Studio, &studio_login())
        .await;
    assert_eq!(studio.status, ServiceStatus::Healthy);
    let wrong = SecretString::from("supabase:notthefixturepassword0123");
    assert_eq!(
        probe.check(&url, StackService::Studio, &wrong).await.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_studio_is_reached_through_the_proxy() {
    let Some(url) = fixture_url() else { return };
    let proxy = StudioProxy::new(StudioProxySettings {
        policy: loopback(),
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(30),
        ..StudioProxySettings::default()
    })
    .unwrap();
    let site = StudioSite {
        host: "0123456789abcdef0123456789abcdef.studio.localhost:3000",
        proto: "http",
        session_cookie: "sd-studio",
    };
    let get = |path: &str, headers: HeaderMap| ProxyRequest {
        method: Method::GET,
        path_and_query: path.to_owned(),
        headers,
        body: ProxyBody::empty(),
    };

    // Studio's root redirects to its project page; the gateway's own
    // address never reaches the browser.
    let response = proxy
        .forward(&url, &studio_login(), site, get("/", HeaderMap::new()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()[header::LOCATION], "/project/default");

    // A browser's own basic-auth header is replaced by the stored login.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        "Basic c3VwYWJhc2U6d3Jvbmc=".parse().unwrap(),
    );
    headers.insert(header::COOKIE, "sd-studio=session".parse().unwrap());
    let response = proxy
        .forward(
            &url,
            &studio_login(),
            site,
            get("/project/default", headers),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(content_type.starts_with("text/html"), "{content_type}");

    // Studio's own API answers through the same route.
    let response = proxy
        .forward(
            &url,
            &studio_login(),
            site,
            get("/api/platform/profile", HeaderMap::new()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(profile.is_object(), "{profile}");

    // Without the right login the gateway refuses, and the refusal is
    // passed back as it is.
    let response = proxy
        .forward(
            &url,
            &SecretString::from("supabase:notthefixturepassword0123"),
            site,
            get("/project/default", HeaderMap::new()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
