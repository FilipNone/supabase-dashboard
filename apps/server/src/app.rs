//! HTTP router and middleware stack.

use std::time::Duration;

use axum::{
    Router,
    http::{HeaderName, HeaderValue, Request, StatusCode, header},
    response::Redirect,
    routing::get,
};
use leptos::prelude::provide_context;
use leptos_axum::{LeptosRoutes, generate_route_list};
use supabase_dashboard_web::{
    app::{App, HOME_PATH, shell},
    server_fns::HealthProbe,
};
use tower::ServiceBuilder;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{health, state::AppState};

pub struct HttpLimits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
}

pub fn router(state: AppState, limits: &HttpLimits) -> Router {
    let routes = generate_route_list(App);
    let probe = HealthProbe::new({
        let db = state.db.clone();
        let timeout = state.readiness_timeout;
        move || health::check(db.clone(), timeout)
    });
    let leptos_options = state.leptos_options.clone();
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/", get(home_redirect))
        .route("/dashboard", get(home_redirect))
        .route("/healthz", get(health::live))
        .route("/readyz", get(health::ready))
        .leptos_routes_with_context(
            &state,
            routes,
            move || provide_context(probe.clone()),
            move || shell(leptos_options.clone()),
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                // Outermost first: mark credentials as sensitive before anything
                // can record them, then assign a request ID used by every log line.
                .layer(SetSensitiveRequestHeadersLayer::new([
                    header::AUTHORIZATION,
                    header::COOKIE,
                    header::PROXY_AUTHORIZATION,
                ]))
                .layer(SetRequestIdLayer::new(
                    x_request_id.clone(),
                    MakeRequestUuid,
                ))
                .layer(TraceLayer::new_for_http().make_span_with(request_span::<axum::body::Body>))
                .layer(PropagateRequestIdLayer::new(x_request_id))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("same-origin"),
                ))
                .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    limits.request_timeout,
                )),
        )
}

async fn home_redirect() -> Redirect {
    Redirect::to(HOME_PATH)
}

/// Span for one request. Records only the method, path, and request ID:
/// never the query string, headers, or body, which may contain secrets.
fn request_span<B>(request: &Request<B>) -> tracing::Span {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .unwrap_or("-");
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        request_id = %request_id,
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use leptos::config::LeptosOptions;
    use secrecy::SecretString;
    use supabase_dashboard_persistence::{Database, DatabaseSettings};
    use tower::ServiceExt;

    use super::*;

    fn test_router() -> Router {
        // Port 1 on loopback is never a PostgreSQL server, so readiness fails
        // quickly without any external dependency.
        let settings = DatabaseSettings {
            url: SecretString::from("postgres://u:secret-pw@127.0.0.1:1/db"),
            max_connections: 1,
            acquire_timeout: Duration::from_secs(1),
            statement_timeout: Duration::from_secs(1),
        };
        let state = AppState {
            leptos_options: LeptosOptions::builder()
                .output_name("supabase-dashboard")
                .site_root("target/site")
                .build(),
            db: Database::connect_lazy(&settings).unwrap(),
            readiness_timeout: Duration::from_secs(1),
        };
        router(
            state,
            &HttpLimits {
                max_body_bytes: 1024,
                request_timeout: Duration::from_secs(5),
            },
        )
    }

    async fn send(request: Request<Body>) -> (http::response::Parts, String) {
        let response = test_router().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get(path: &str) -> Request<Body> {
        Request::get(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn liveness_responds_with_request_id_and_security_headers() {
        let (parts, body) = send(get("/healthz")).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(body, r#"{"status":"ok"}"#);
        assert!(parts.headers.contains_key("x-request-id"));
        assert_eq!(parts.headers["x-content-type-options"], "nosniff");
        assert_eq!(parts.headers["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn incoming_request_id_is_preserved() {
        let request = Request::get("/healthz")
            .header("x-request-id", "abc-123")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = send(request).await;
        assert_eq!(parts.headers["x-request-id"], "abc-123");
    }

    #[tokio::test]
    async fn readiness_reports_unavailable_database_without_leaking_url() {
        let (parts, body) = send(get("/readyz")).await;
        assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains(r#""status":"unavailable""#), "{body}");
        assert!(!body.contains("secret-pw"));
        assert!(!body.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let request = Request::post("/healthz")
            .header(header::CONTENT_LENGTH, "4096")
            .body(Body::from(vec![b'x'; 4096]))
            .unwrap();
        let (parts, _) = send(request).await;
        assert_eq!(parts.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn dashboard_shell_renders_on_the_server() {
        let (parts, body) = send(get("/dashboard/organizations")).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("No organizations yet"), "{body}");
        assert!(body.contains(r#"data-theme="system""#));
    }

    #[tokio::test]
    async fn theme_cookie_selects_initial_theme() {
        let request = Request::get("/dashboard/organizations")
            .header(header::COOKIE, "sd-theme=dark")
            .body(Body::empty())
            .unwrap();
        let (_, body) = send(request).await;
        assert!(body.contains(r#"data-theme="dark""#));
    }

    #[tokio::test]
    async fn root_redirects_to_home() {
        for path in ["/", "/dashboard"] {
            let (parts, _) = send(get(path)).await;
            assert_eq!(parts.status, StatusCode::SEE_OTHER, "{path}");
            assert_eq!(parts.headers[header::LOCATION], HOME_PATH);
        }
    }

    #[tokio::test]
    async fn unknown_pages_return_404() {
        let (parts, body) = send(get("/dashboard/does-not-exist")).await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND);
        assert!(body.contains("Page not found"));
    }
}
