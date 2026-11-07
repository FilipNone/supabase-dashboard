//! HTTP router and middleware stack.

use std::time::Duration;

use axum::{
    Router,
    http::{HeaderName, HeaderValue, Request, StatusCode, header},
    middleware,
    response::Redirect,
    routing::{any, get, post},
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

use crate::{error, health, session, state::AppState};

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
    let organizations = state.organizations.clone();
    let leptos_options = state.leptos_options.clone();
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/", get(home_redirect))
        .route("/dashboard", get(home_redirect))
        .route("/healthz", get(health::live))
        .route("/readyz", get(health::ready))
        .route("/auth/sign-in", post(session::sign_in))
        .route("/auth/sign-out", post(session::sign_out))
        .route("/api/{*rest}", any(error::api_not_found))
        .leptos_routes_with_context(
            &state,
            routes,
            move || {
                provide_context(probe.clone());
                provide_context(organizations.clone());
            },
            move || shell(leptos_options.clone()),
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        // Route layers run outer-last: the Origin check runs before the
        // session guard, so a cross-site POST never touches the database.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::guard,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::verify_origin,
        ))
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
    use std::sync::Arc;

    use axum::body::Body;
    use http_body_util::BodyExt;
    use leptos::{config::LeptosOptions, server_fn::ServerFn};
    use secrecy::SecretString;
    use supabase_dashboard_application::{
        auth::{AuthConfig, AuthService},
        organizations::OrganizationService,
    };
    use supabase_dashboard_persistence::{Database, DatabaseSettings};
    use supabase_dashboard_web::{
        app::SIGN_IN_PATH,
        server_fns::{
            CreateOrganization, GetCurrentAccount, GetInstallationHealth, GetOrganization,
            ListOrganizations, RenameOrganization,
        },
    };
    use tower::ServiceExt;

    use super::*;
    use crate::{scratch_db::ScratchDb, session::CookieSettings};

    const HOST: &str = "dash.localhost:3000";
    const ORIGIN: &str = "http://dash.localhost:3000";

    async fn router_for(db: Database) -> Router {
        let auth = AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap();
        let state = AppState {
            leptos_options: LeptosOptions::builder()
                .output_name("supabase-dashboard")
                .site_root("target/site")
                .build(),
            organizations: Arc::new(OrganizationService::new(db.clone())),
            db,
            readiness_timeout: Duration::from_secs(1),
            auth: Arc::new(auth),
            cookie: CookieSettings::new(false, 3600),
            expected_origin: None,
        };
        router(
            state,
            &HttpLimits {
                max_body_bytes: 1024,
                request_timeout: Duration::from_secs(5),
            },
        )
    }

    /// Router whose metadata database is unreachable: port 1 on loopback is
    /// never PostgreSQL, so anything that touches it fails fast.
    async fn offline_router() -> Router {
        let settings = DatabaseSettings {
            url: SecretString::from("postgres://u:secret-pw@127.0.0.1:1/db"),
            max_connections: 1,
            acquire_timeout: Duration::from_secs(1),
            statement_timeout: Duration::from_secs(1),
        };
        router_for(Database::connect_lazy(&settings).unwrap()).await
    }

    async fn send(router: &Router, request: Request<Body>) -> (http::response::Parts, String) {
        let response = router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get(path: &str) -> Request<Body> {
        Request::get(path)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap()
    }

    fn get_with_cookie(path: &str, cookie: &str) -> Request<Body> {
        Request::get(path)
            .header(header::HOST, HOST)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap()
    }

    fn form_post(path: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
        let mut builder = Request::post(path)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Body::from(body.to_owned())).unwrap()
    }

    fn location(parts: &http::response::Parts) -> &str {
        parts.headers[header::LOCATION].to_str().unwrap()
    }

    #[tokio::test]
    async fn liveness_responds_with_request_id_and_security_headers() {
        let (parts, body) = send(&offline_router().await, get("/healthz")).await;
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
        let (parts, _) = send(&offline_router().await, request).await;
        assert_eq!(parts.headers["x-request-id"], "abc-123");
    }

    #[tokio::test]
    async fn readiness_reports_unavailable_database_without_leaking_url() {
        let (parts, body) = send(&offline_router().await, get("/readyz")).await;
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
        let (parts, _) = send(&offline_router().await, request).await;
        assert_eq!(parts.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn pages_redirect_to_sign_in_without_a_session() {
        let router = offline_router().await;
        for path in [
            "/",
            "/dashboard",
            "/dashboard/organizations",
            "/dashboard/status",
            "/dashboard/does-not-exist",
            "/elsewhere",
        ] {
            let (parts, _) = send(&router, get(path)).await;
            assert_eq!(parts.status, StatusCode::SEE_OTHER, "{path}");
            assert_eq!(location(&parts), SIGN_IN_PATH, "{path}");
        }
    }

    #[tokio::test]
    async fn sign_in_page_is_public_and_themed() {
        let request = Request::get(SIGN_IN_PATH)
            .header(header::COOKIE, "sd-theme=dark")
            .body(Body::empty())
            .unwrap();
        let (parts, body) = send(&offline_router().await, request).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains(r#"action="/auth/sign-in""#), "{body}");
        assert!(body.contains(r#"autocomplete="current-password""#));
        assert!(body.contains(r#"data-theme="dark""#));
    }

    #[tokio::test]
    async fn sign_in_errors_are_fixed_messages() {
        let router = offline_router().await;
        let (_, body) = send(&router, get(&format!("{SIGN_IN_PATH}?error=throttled"))).await;
        assert!(body.contains("Too many failed attempts"), "{body}");
        let (_, body) = send(
            &router,
            get(&format!("{SIGN_IN_PATH}?error=echo-marker-42")),
        )
        .await;
        assert!(body.contains("Invalid email or password"));
        assert!(
            !body.contains("echo-marker-42"),
            "unknown codes are not echoed"
        );
    }

    #[tokio::test]
    async fn api_paths_need_a_session() {
        let router = offline_router().await;
        let (parts, body) = send(&router, get("/api/v1/does-not-exist")).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
        assert_eq!(parts.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            body,
            r#"{"error":{"code":"unauthenticated","message":"sign in to continue"}}"#
        );
        let (parts, _) = send(&router, form_post(GetInstallationHealth::PATH, "", None)).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cross_origin_posts_are_refused() {
        let router = offline_router().await;
        let attempts = [
            vec![(header::ORIGIN.as_str(), "https://evil.example")],
            vec![
                ("sec-fetch-site", "cross-site"),
                (header::ORIGIN.as_str(), ORIGIN),
            ],
            vec![],
        ];
        for headers in attempts {
            let mut builder = Request::post("/auth/sign-in")
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            for (name, value) in &headers {
                builder = builder.header(*name, *value);
            }
            let request = builder.body(Body::from("email=a&password=b")).unwrap();
            let (parts, body) = send(&router, request).await;
            assert_eq!(parts.status, StatusCode::FORBIDDEN, "{headers:?}");
            assert!(body.contains("cross_origin_request"));
        }
    }

    #[tokio::test]
    async fn sign_in_reports_unavailable_database_generically() {
        let (parts, _) = send(
            &offline_router().await,
            form_post(
                "/auth/sign-in",
                "email=a%40b.test&password=whatever-password",
                None,
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert_eq!(
            location(&parts),
            format!("{SIGN_IN_PATH}?error=unavailable")
        );
        assert!(!parts.headers.contains_key(header::SET_COOKIE));
    }

    /// Full browser flow against a scratch metadata database. Skipped
    /// unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.
    #[tokio::test]
    async fn sign_in_browse_and_sign_out() {
        let Some(scratch) = ScratchDb::create("http_flow").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_for(db.clone()).await;
        let credentials = "email=Owner%40Example.test&password=correct+horse+battery+staple";

        // Fresh installation: the sign-in page explains how to bootstrap.
        let (parts, _) = send(&router, form_post("/auth/sign-in", credentials, None)).await;
        assert_eq!(location(&parts), format!("{SIGN_IN_PATH}?error=setup"));

        AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap()
            .bootstrap_owner(
                "owner@example.test",
                "Owner",
                &SecretString::from("correct horse battery staple"),
            )
            .await
            .unwrap();

        let wrong = "email=owner%40example.test&password=wrong+password+here";
        let (parts, _) = send(&router, form_post("/auth/sign-in", wrong, None)).await;
        assert_eq!(location(&parts), format!("{SIGN_IN_PATH}?error=invalid"));

        let (parts, _) = send(&router, form_post("/auth/sign-in", credentials, None)).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert_eq!(location(&parts), HOME_PATH);
        let set_cookie = parts.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let token = cookie.split_once('=').unwrap().1;
        assert_eq!(token.len(), 64);

        let (parts, body) = send(&router, get_with_cookie(HOME_PATH, &cookie)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
        assert!(
            body.contains("You are not a member of any organization"),
            "{body}"
        );
        assert!(
            !body.contains(token),
            "the session token must not reach the page"
        );

        let (parts, _) = send(&router, get_with_cookie(SIGN_IN_PATH, &cookie)).await;
        assert_eq!(location(&parts), HOME_PATH);
        let (parts, _) = send(&router, get_with_cookie("/dashboard/nope", &cookie)).await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND);

        let (parts, body) = send(
            &router,
            form_post(GetCurrentAccount::PATH, "", Some(&cookie)),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains("owner@example.test"), "{body}");
        assert!(!body.contains(token));

        let (parts, _) = send(&router, form_post("/auth/sign-out", "", Some(&cookie))).await;
        assert_eq!(location(&parts), SIGN_IN_PATH);
        assert!(
            parts.headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let (parts, _) = send(&router, get_with_cookie(HOME_PATH, &cookie)).await;
        assert_eq!(
            location(&parts),
            SIGN_IN_PATH,
            "revoked cookie no longer works"
        );

        db.close().await;
        scratch.drop().await;
    }

    /// Signs in and returns the `name=value` cookie pair.
    async fn sign_in_cookie(router: &Router, email: &str) -> String {
        let body = format!("email={email}&password=correct+horse+battery+staple");
        let (parts, _) = send(router, form_post("/auth/sign-in", &body, None)).await;
        assert_eq!(location(&parts), HOME_PATH);
        let set_cookie = parts.headers[header::SET_COOKIE].to_str().unwrap();
        set_cookie.split(';').next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn organizations_are_isolated_over_http() {
        let Some(scratch) = ScratchDb::create("http_orgs").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_for(db.clone()).await;
        AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap()
            .bootstrap_owner(
                "alice@example.test",
                "Alice",
                &SecretString::from("correct horse battery staple"),
            )
            .await
            .unwrap();
        // A second operator with the same password; invitations will
        // replace this direct insert.
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;

        let call = |path: &'static str, body: String, cookie: &str| {
            send(&router, form_post(path, &body, Some(cookie)))
        };
        let (parts, body) = call(CreateOrganization::PATH, "name=Acme+Secret".into(), &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        assert_eq!(acme["role"], "owner");
        let (parts, _) = call(CreateOrganization::PATH, "name=Globex".into(), &bob).await;
        assert_eq!(parts.status, StatusCode::OK);

        // Bob sees only his own organization.
        let (_, body) = call(ListOrganizations::PATH, String::new(), &bob).await;
        assert!(body.contains("Globex") && !body.contains("Acme"), "{body}");

        // Alice's organization ID gets the same answer as a made-up one.
        let made_up = uuid::Uuid::now_v7().to_string();
        let mut answers = Vec::new();
        for id in [&acme_id, &made_up] {
            let (parts, body) = call(GetOrganization::PATH, format!("id={id}"), &bob).await;
            assert!(!parts.status.is_success());
            assert!(
                body.contains("NotFound") && !body.contains("Acme"),
                "{body}"
            );
            answers.push((parts.status, body));
            let (_, body) =
                call(RenameOrganization::PATH, format!("id={id}&name=Mine"), &bob).await;
            assert!(body.contains("NotFound"), "{body}");
        }
        assert_eq!(answers[0], answers[1]);

        // The page for Alice's organization does not leak its name either.
        let page = format!("/dashboard/org/{acme_id}/general");
        let (parts, body) = send(&router, get_with_cookie(&page, &bob)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Organization unavailable"), "{body}");
        assert!(!body.contains("Acme"), "{body}");
        let (_, body) = send(&router, get_with_cookie(&page, &alice)).await;
        assert!(body.contains("Acme Secret"), "{body}");

        // A cross-site form cannot rename it, even with Alice's cookie.
        let forged = Request::post(RenameOrganization::PATH)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, "https://evil.example")
            .header(header::COOKIE, &alice)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("id={acme_id}&name=Pwned")))
            .unwrap();
        let (parts, _) = send(&router, forged).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1::uuid")
            .bind(&acme_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(name, "Acme Secret");

        db.close().await;
        scratch.drop().await;
    }
}
