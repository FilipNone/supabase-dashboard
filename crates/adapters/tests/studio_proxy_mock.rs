//! Studio forwarding against an in-process server that imitates a stack's
//! gateway: basic auth in front of a Studio-like app that echoes what it
//! received.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use http_body_util::BodyExt;
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    net::TargetPolicy,
    studio_proxy::{
        ProxyBody, ProxyError, ProxyRequest, StudioProxy, StudioProxySettings, StudioSite,
    },
};
use supabase_dashboard_domain::project::ProjectUrl;

/// `supabase:studio-password-for-tests`, base64.
const EXPECTED_AUTH: &str = "Basic c3VwYWJhc2U6c3R1ZGlvLXBhc3N3b3JkLWZvci10ZXN0cw==";
const LOGIN: &str = "supabase:studio-password-for-tests";

const SITE: StudioSite<'static> = StudioSite {
    host: "abc.studio.example.test",
    proto: "https",
    session_cookie: "sd-studio",
};

async fn serve(router: Router) -> ProjectUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    ProjectUrl::parse(&format!("http://{addr}")).unwrap()
}

/// Answers 401 without the expected login, like the gateway's Studio
/// route, and otherwise echoes the request.
fn gateway(gateway_origin: &'static str) -> Router {
    Router::new().fallback(any(
        move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| async move {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            if auth != Some(EXPECTED_AUTH) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            if uri.path() == "/" {
                return Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header(
                        header::LOCATION,
                        format!("{gateway_origin}/project/default"),
                    )
                    .header(header::SET_COOKIE, "sd-studio=forged; Path=/")
                    .header(header::SET_COOKIE, "studio=1; Domain=example.test; Path=/")
                    .body(Body::empty())
                    .unwrap();
            }
            let header = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_owned()
            };
            let echo = serde_json::json!({
                "method": method.as_str(),
                "uri": uri.to_string(),
                "cookie": header("cookie"),
                "forwarded_host": header("x-forwarded-host"),
                "forwarded_proto": header("x-forwarded-proto"),
                "forwarded_for": header("x-forwarded-for"),
                "body": String::from_utf8_lossy(&body),
            });
            (
                [(header::CONTENT_TYPE, "application/json")],
                echo.to_string(),
            )
                .into_response()
        },
    ))
}

fn proxy(policy: TargetPolicy) -> StudioProxy {
    StudioProxy::new(StudioProxySettings {
        policy,
        connect_timeout: Duration::from_secs(2),
        read_timeout: Duration::from_secs(2),
        ..StudioProxySettings::default()
    })
    .unwrap()
}

fn loopback() -> TargetPolicy {
    TargetPolicy {
        allow_loopback: true,
    }
}

fn request(method: Method, path: &str, headers: HeaderMap, body: ProxyBody) -> ProxyRequest {
    ProxyRequest {
        method,
        path_and_query: path.to_owned(),
        headers,
        body,
    }
}

async fn read(
    response: Response<supabase_dashboard_adapters::studio_proxy::UpstreamBody>,
) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn requests_reach_studio_with_the_stored_login_only() {
    let url = serve(gateway("http://unused.invalid")).await;
    let login = SecretString::from(LOGIN);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        "Basic YnJvd3Nlcjpzbm9vcA==".parse().unwrap(),
    );
    headers.insert(
        header::COOKIE,
        "sd-studio=token; theme=dark".parse().unwrap(),
    );
    headers.insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

    // The body is streamed in pieces, as it would arrive from a browser.
    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
        Ok(Bytes::from_static(b"{\"query\":")),
        Ok(Bytes::from_static(b"\"select 1\"}")),
    ];
    let body = ProxyBody::from_stream(futures_util::stream::iter(chunks));
    let response = proxy(loopback())
        .forward(
            &url,
            &login,
            SITE,
            request(
                Method::POST,
                "/api/platform/pg-meta/default/query?key=x",
                headers,
                body,
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let echo: serde_json::Value = serde_json::from_str(&read(response).await).unwrap();
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["uri"], "/api/platform/pg-meta/default/query?key=x");
    assert_eq!(echo["cookie"], "theme=dark");
    assert_eq!(echo["forwarded_host"], SITE.host);
    assert_eq!(echo["forwarded_proto"], "https");
    assert_eq!(echo["forwarded_for"], "-");
    assert_eq!(echo["body"], r#"{"query":"select 1"}"#);
}

#[tokio::test]
async fn a_wrong_login_gets_the_gateway_refusal() {
    let url = serve(gateway("http://unused.invalid")).await;
    let response = proxy(loopback())
        .forward(
            &url,
            &SecretString::from("supabase:not-the-password-at-all"),
            SITE,
            request(
                Method::GET,
                "/project/default",
                HeaderMap::new(),
                ProxyBody::empty(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn redirects_are_passed_back_not_followed() {
    // The gateway names its own address in the redirect; the browser gets
    // a path on the Studio host instead.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin: &'static str = Box::leak(format!("http://{addr}").into_boxed_str());
    tokio::spawn(async move { axum::serve(listener, gateway(origin)).await.unwrap() });
    let url = ProjectUrl::parse(origin).unwrap();
    let response = proxy(loopback())
        .forward(
            &url,
            &SecretString::from(LOGIN),
            SITE,
            request(Method::GET, "/", HeaderMap::new(), ProxyBody::empty()),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()[header::LOCATION], "/project/default");
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .collect();
    assert_eq!(cookies, ["studio=1; Path=/"]);
}

#[tokio::test]
async fn loopback_gateways_are_refused_by_default() {
    let url = serve(gateway("http://unused.invalid")).await;
    let err = proxy(TargetPolicy::default())
        .forward(
            &url,
            &SecretString::from(LOGIN),
            SITE,
            request(Method::GET, "/", HeaderMap::new(), ProxyBody::empty()),
        )
        .await
        .unwrap_err();
    assert_eq!(err, ProxyError::DestinationNotAllowed);
}

#[tokio::test]
async fn closed_ports_are_reported_as_connect_failures() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = ProjectUrl::parse(&format!("http://{addr}")).unwrap();
    let err = proxy(loopback())
        .forward(
            &url,
            &SecretString::from(LOGIN),
            SITE,
            request(Method::GET, "/", HeaderMap::new(), ProxyBody::empty()),
        )
        .await
        .unwrap_err();
    assert_eq!(err, ProxyError::Connect);
}
