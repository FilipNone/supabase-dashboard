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

/// A gateway that translates the opaque `sb_` keys: the fixture's Envoy,
/// for example `http://127.0.0.1:54323`. Kong runs in legacy key mode.
const NEW_KEYS_ENV: &str = "SUPABASE_DASHBOARD_TEST_FIXTURE_NEW_KEYS_URL";

fn new_keys_url() -> Option<ProjectUrl> {
    match std::env::var(NEW_KEYS_ENV) {
        Ok(raw) => Some(ProjectUrl::parse(&raw).unwrap()),
        Err(_) => {
            eprintln!("skipping: {NEW_KEYS_ENV} is not set");
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

    let auth = probe.check(&url, StackService::Auth, &anon, None).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));

    // Upstream limits the PostgREST root to the service role.
    let rest = probe.check(&url, StackService::Rest, &service, None).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    assert_eq!(rest.version.as_deref(), Some("14.18"));
    let rest_anon = probe.check(&url, StackService::Rest, &anon, None).await;
    assert_eq!(
        rest_anon.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );

    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe
            .check(&url, StackService::Auth, &wrong, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

/// A key signed with the stack's own JWT secret whose `exp` has passed.
fn expired_key(role: &str) -> SecretString {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"role":"{role}","iss":"supabase","iat":{},"exp":{}}}"#,
        now - 7200,
        now - 3600
    ));
    let signed = format!("{header}.{claims}");
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(fixture_value("JWT_SECRET").as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    SecretString::from(format!("{signed}.{signature}"))
}

#[tokio::test]
async fn fixture_gateway_rejects_expired_keys() {
    let Some(url) = fixture_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();

    // Correctly signed but expired: rejected, not healthy or unreachable.
    let anon = expired_key("anon");
    assert_eq!(
        probe
            .check(&url, StackService::Auth, &anon, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
    let service = expired_key("service_role");
    assert_eq!(
        probe
            .check(&url, StackService::Rest, &service, None)
            .await
            .status,
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

    let storage = probe.check(&url, StackService::Storage, &anon, None).await;
    assert_eq!(storage.status, ServiceStatus::Healthy);
    assert_eq!(storage.version.as_deref(), Some("1.89.12"));

    let realtime = probe.check(&url, StackService::Realtime, &anon, None).await;
    assert_eq!(realtime.status, ServiceStatus::Healthy);
    assert_eq!(realtime.version, None);

    // Realtime sits behind the gateway's key check; Storage checks keys
    // itself and leaves its version path open, as upstream does.
    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe
            .check(&url, StackService::Realtime, &wrong, None)
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_gateway_reports_edge_functions() {
    let Some(url) = fixture_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();
    // The fixture runs upstream's main router with VERIFY_JWT on, so the
    // key is checked by the router itself, not by the gateway.
    for key in ["ANON_KEY", "SERVICE_ROLE_KEY"] {
        let check = probe
            .check(
                &url,
                StackService::Functions,
                &SecretString::from(fixture_value(key)),
                None,
            )
            .await;
        assert_eq!(check.status, ServiceStatus::Healthy, "{key}");
        assert_eq!(check.version, None);
    }
    assert_eq!(
        probe
            .check(
                &url,
                StackService::Functions,
                &SecretString::from("not-a-key"),
                None
            )
            .await
            .status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_gateway_accepts_the_new_api_keys() {
    let Some(url) = new_keys_url() else { return };
    let probe = GatewayProbe::new(GatewaySettings {
        policy: loopback(),
        ..GatewaySettings::default()
    })
    .unwrap();
    let publishable = SecretString::from(fixture_value("SUPABASE_PUBLISHABLE_KEY"));
    let secret = SecretString::from(fixture_value("SUPABASE_SECRET_KEY"));
    let check = |service, key: &SecretString| {
        let (probe, url, key) = (probe.clone(), url.clone(), key.clone());
        async move { probe.check(&url, service, &key, None).await }
    };

    // The opaque keys stand in for the anon and service role JWTs, with the
    // same results: only the secret key opens the PostgREST root.
    for key in [&publishable, &secret] {
        let auth = check(StackService::Auth, key).await;
        assert_eq!(auth.status, ServiceStatus::Healthy);
        assert_eq!(auth.version.as_deref(), Some("v2.197.0"));
        for service in [
            StackService::Storage,
            StackService::Realtime,
            StackService::Functions,
        ] {
            assert_eq!(
                check(service, key).await.status,
                ServiceStatus::Healthy,
                "{service:?}"
            );
        }
    }
    let rest = check(StackService::Rest, &secret).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    assert_eq!(rest.version.as_deref(), Some("14.18"));
    assert_eq!(
        check(StackService::Rest, &publishable).await.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );

    // A key the stack never issued is refused.
    for unknown in [
        "sb_publishable_unknown.to.this.stack",
        "sb_secret_unknown.to.this.stack",
    ] {
        let unknown = SecretString::from(unknown);
        for service in [
            StackService::Auth,
            StackService::Rest,
            StackService::Realtime,
            StackService::Functions,
        ] {
            assert_eq!(
                check(service, &unknown).await.status,
                ServiceStatus::KeyRejected { http_status: 401 },
                "{service:?}"
            );
        }
    }
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
        .check(&url, StackService::Studio, &studio_login(), None)
        .await;
    assert_eq!(studio.status, ServiceStatus::Healthy);
    let wrong = SecretString::from("supabase:notthefixturepassword0123");
    assert_eq!(
        probe
            .check(&url, StackService::Studio, &wrong, None)
            .await
            .status,
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
        .forward(
            &url,
            &studio_login(),
            None,
            site,
            get("/", HeaderMap::new()),
        )
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
            None,
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
            None,
            site,
            get("/api/platform/profile", HeaderMap::new()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let profile: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(profile.is_object(), "{profile}");

    // Studio's Edge Functions page lists the functions in its mounted
    // folder; the fixture's synthetic `hello` is one, the router is not.
    let response = proxy
        .forward(
            &url,
            &studio_login(),
            None,
            site,
            get("/api/v1/projects/default/functions", HeaderMap::new()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let functions: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let slugs: Vec<&str> = functions
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["slug"].as_str())
        .collect();
    assert_eq!(slugs, ["hello"], "{functions}");

    // The SQL editor's saved snippets live in the folder the fixture gives
    // Studio; without it Studio answers 500 here.
    let response = proxy
        .forward(
            &url,
            &studio_login(),
            None,
            site,
            get(
                "/api/platform/projects/default/content/count?type=sql",
                HeaderMap::new(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let counts: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(counts["private"].is_number(), "{counts}");

    // Without the right login the gateway refuses, and the refusal is
    // passed back as it is.
    let response = proxy
        .forward(
            &url,
            &SecretString::from("supabase:notthefixturepassword0123"),
            None,
            site,
            get("/project/default", HeaderMap::new()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
