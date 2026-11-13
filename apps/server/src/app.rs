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

use crate::{access_export, error, health, session, state::AppState, studio};

pub struct HttpLimits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub studio_max_body_bytes: usize,
    pub studio_request_timeout: Duration,
}

pub fn router(state: AppState, limits: &HttpLimits) -> Router {
    let routes = generate_route_list(App);
    let probe = HealthProbe::new({
        let db = state.db.clone();
        let timeout = state.readiness_timeout;
        move || health::check(db.clone(), timeout)
    });
    let organizations = state.organizations.clone();
    let projects = state.projects.clone();
    let connections = state.connections.clone();
    let studio_access = state.studio_access.clone();
    let dokploy = state.dokploy.clone();
    let provisioning = state.provisioning.clone();
    let auth = state.auth.clone();
    let leptos_options = state.leptos_options.clone();
    let x_request_id = HeaderName::from_static("x-request-id");
    // Studio hosts get their own routes, body limit, and timeout.
    let studio_hosts = state.studio.clone().map(|gateway| {
        let hosts = gateway.hosts.clone();
        let routes = studio::router(gateway).layer(
            ServiceBuilder::new()
                .layer(RequestBodyLimitLayer::new(limits.studio_max_body_bytes))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::GATEWAY_TIMEOUT,
                    limits.studio_request_timeout,
                )),
        );
        (hosts, routes)
    });

    Router::new()
        .route("/", get(home_redirect))
        .route("/dashboard", get(home_redirect))
        .route("/healthz", get(health::live))
        .route("/readyz", get(health::ready))
        .route("/auth/sign-in", post(session::sign_in))
        .route("/auth/sign-out", post(session::sign_out))
        .route("/dashboard/project/{project_id}", get(studio::launch))
        .route(studio::TLS_ASK_PATH, get(studio::tls_ask))
        .route(
            "/dashboard/project/{project_id}/studio-access.csv",
            get(access_export::studio_access_csv_download),
        )
        .route("/api/{*rest}", any(error::api_not_found))
        .leptos_routes_with_context(
            &state,
            routes,
            move || {
                provide_context(probe.clone());
                provide_context(organizations.clone());
                provide_context(projects.clone());
                provide_context(connections.clone());
                provide_context(studio_access.clone());
                provide_context(dokploy.clone());
                provide_context(provisioning.clone());
                provide_context(auth.clone());
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
                .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    limits.request_timeout,
                )),
        )
        // Outside the dashboard's own limits and middleware: requests for a
        // Studio host never reach the dashboard's routes.
        .layer(middleware::from_fn(move |request, next| {
            studio::dispatch(studio_hosts.clone(), request, next)
        }))
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
    use supabase_dashboard_adapters::net::TargetPolicy;
    use supabase_dashboard_application::{
        auth::{AuthConfig, AuthService},
        connections::ConnectionService,
        organizations::OrganizationService,
        projects::ProjectService,
        provisioning::ProvisioningService,
        studio_access::{StudioAccessRecorder, StudioAccessService},
    };
    use supabase_dashboard_persistence::{Database, DatabaseSettings};
    use supabase_dashboard_web::{
        app::SIGN_IN_PATH,
        server_fns::{
            AdminListAccounts, AdminSetAccountDisabled, ChangePassword, CheckProjectHealth,
            ClearDokployPlacement, ConfirmDokployPlacement, ConnectDokploy, CreateInvitation,
            CreateOrganization, DisconnectDokploy, GetCurrentAccount, GetDokployConnection,
            GetDokployPlacement, GetInstallationHealth, GetOrganization, GetProject,
            GetProjectAuthorities, GetProjectCredentials, GetProjectDeployment, GetProjectHealth,
            GetProvisionJob, GetProvisionTargets, GetStudioAccessLog, ListOrganizations,
            ListProjects, ListProvisionJobs, ListSessions, PreviewInvitation, QueueStackAction,
            QueueStackRemoval, RegisterProject, RemoveProjectAuthorities, RemoveProjectCredential,
            RenameOrganization, ReplaceDokployKey, ReplaceProjectAuthorities,
            ReplaceProjectCredential, ReplaceStudioLogin, RevokeSession, SignUpWithInvitation,
            StartProvisioning, UnregisterProject, UpdateProfile,
        },
    };
    use tower::ServiceExt;

    use super::*;
    use crate::{scratch_db::ScratchDb, session::CookieSettings};

    const HOST: &str = "dash.localhost:3000";
    const ORIGIN: &str = "http://dash.localhost:3000";

    async fn router_for(db: Database) -> Router {
        router_with_cipher(db, None).await
    }

    async fn router_with_cipher(
        db: Database,
        cipher: Option<supabase_dashboard_application::secrets::CredentialCipher>,
    ) -> Router {
        router_with_options(db, cipher, None).await
    }

    async fn router_with_options(
        db: Database,
        cipher: Option<supabase_dashboard_application::secrets::CredentialCipher>,
        access_log_days: Option<u16>,
    ) -> Router {
        router_with_dokploy_policy(db, cipher, access_log_days, TargetPolicy::default()).await
    }

    /// A Dokploy service whose connector applies `policy`.
    fn dokploy_service(
        db: &Database,
        cipher: Option<supabase_dashboard_application::secrets::CredentialCipher>,
        policy: TargetPolicy,
    ) -> Arc<supabase_dashboard_application::dokploy::DokployService> {
        Arc::new(
            supabase_dashboard_application::dokploy::DokployService::new(
                db.clone(),
                cipher,
                supabase_dashboard_adapters::dokploy::DokployClient::shared(
                    supabase_dashboard_adapters::dokploy::DokploySettings {
                        policy,
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
            .with_public_host(Some(TEST_PUBLIC_HOST)),
        )
    }

    /// The public host the test servers' Dokploy service looks for.
    const TEST_PUBLIC_HOST: &str = "dashboard.http-test.fixture.test";

    async fn router_with_dokploy_policy(
        db: Database,
        cipher: Option<supabase_dashboard_application::secrets::CredentialCipher>,
        access_log_days: Option<u16>,
        dokploy_policy: TargetPolicy,
    ) -> Router {
        let auth = AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap();
        let studio_access = Arc::new(StudioAccessService::new(db.clone(), access_log_days));
        let dokploy = dokploy_service(&db, cipher.clone(), dokploy_policy);
        let state = AppState {
            leptos_options: LeptosOptions::builder()
                .output_name("supabase-dashboard")
                .site_root("target/site")
                .build(),
            organizations: Arc::new(OrganizationService::new(db.clone())),
            projects: Arc::new(ProjectService::new(db.clone())),
            provisioning: Arc::new(ProvisioningService::new(
                db.clone(),
                cipher.clone(),
                Arc::clone(&dokploy),
            )),
            dokploy,
            connections: Arc::new(ConnectionService::new(
                db.clone(),
                cipher,
                supabase_dashboard_adapters::gateway::GatewayProbe::shared(Default::default())
                    .unwrap(),
            )),
            db,
            readiness_timeout: Duration::from_secs(1),
            auth: Arc::new(auth),
            cookie: CookieSettings::new(false, 3600),
            expected_origin: None,
            studio: None,
            studio_access,
        };
        router(state, &test_limits())
    }

    fn test_limits() -> HttpLimits {
        HttpLimits {
            max_body_bytes: 1024,
            request_timeout: Duration::from_secs(5),
            studio_max_body_bytes: 4096,
            studio_request_timeout: Duration::from_secs(5),
        }
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
        // Dashboard pages come back after sign-in; other paths do not.
        for (path, expected) in [
            ("/", SIGN_IN_PATH),
            ("/dashboard", SIGN_IN_PATH),
            ("/elsewhere", SIGN_IN_PATH),
            ("/dashboard/", "/dashboard/sign-in?next=%2Fdashboard%2F"),
            (
                "/dashboard/organizations",
                "/dashboard/sign-in?next=%2Fdashboard%2Forganizations",
            ),
            (
                "/dashboard/status?tab=a%20b",
                "/dashboard/sign-in?next=%2Fdashboard%2Fstatus%3Ftab%3Da%2520b",
            ),
            (
                "/dashboard//evil.test",
                "/dashboard/sign-in?next=%2Fdashboard%2F%2Fevil.test",
            ),
        ] {
            let (parts, _) = send(&router, get(path)).await;
            assert_eq!(parts.status, StatusCode::SEE_OTHER, "{path}");
            assert_eq!(location(&parts), expected, "{path}");
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
            "/dashboard/sign-in?next=%2Fdashboard%2Forganizations",
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
            assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");
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

    #[tokio::test]
    async fn projects_are_isolated_over_http() {
        let Some(scratch) = ScratchDb::create("http_projects").await else {
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
        let (_, body) = call(CreateOrganization::PATH, "name=Acme".into(), &alice).await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();

        // The checkbox field is absent when unchecked, so plain HTTP is
        // refused until the operator confirms it.
        let (parts, body) = call(
            RegisterProject::PATH,
            format!("organization_id={acme_id}&name=Lab&api_url=http%3A%2F%2F10.0.0.5%3A8000"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body.contains("plain HTTP") || body.contains("unencrypted"),
            "{body}"
        );
        let (parts, body) = call(
            RegisterProject::PATH,
            format!(
                "organization_id={acme_id}&name=Lab&api_url=http%3A%2F%2F10.0.0.5%3A8000\
                 &allow_unencrypted=true"
            ),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let (parts, body) = call(
            RegisterProject::PATH,
            format!(
                "organization_id={acme_id}&name=Acme+Prod\
                 &api_url=https%3A%2F%2Fsupabase.acme.example%2F"
            ),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let project: serde_json::Value = serde_json::from_str(&body).unwrap();
        let project_id = project["id"].as_str().unwrap().to_owned();
        assert_eq!(project["api_url"], "https://supabase.acme.example");

        let (_, body) = call(
            ListProjects::PATH,
            format!("organization_id={acme_id}"),
            &alice,
        )
        .await;
        assert!(body.contains("Acme Prod") && body.contains("Lab"), "{body}");

        // Bob gets the same answer for Alice's project as for a made-up ID,
        // and cannot list, register into, or unregister anything of hers.
        let made_up = uuid::Uuid::now_v7().to_string();
        let mut answers = Vec::new();
        for id in [&project_id, &made_up] {
            let (parts, body) = call(GetProject::PATH, format!("id={id}"), &bob).await;
            assert!(
                body.contains("NotFound") && !body.contains("acme"),
                "{body}"
            );
            answers.push((parts.status, body));
            let (_, body) = call(
                UnregisterProject::PATH,
                format!("id={id}&confirmation=Acme+Prod"),
                &bob,
            )
            .await;
            assert!(body.contains("NotFound"), "{body}");
        }
        assert_eq!(answers[0], answers[1]);
        let (_, body) = call(
            ListProjects::PATH,
            format!("organization_id={acme_id}"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");
        let (_, body) = call(
            RegisterProject::PATH,
            format!("organization_id={acme_id}&name=Mine&api_url=https%3A%2F%2Fevil.example"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");

        // The project page renders for Alice and leaks nothing to Bob.
        let page = format!("/dashboard/org/{acme_id}/projects/{project_id}");
        let (parts, body) = send(&router, get_with_cookie(&page, &bob)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Project unavailable"), "{body}");
        assert!(!body.contains("acme.example"), "{body}");
        let (_, body) = send(&router, get_with_cookie(&page, &alice)).await;
        assert!(body.contains("Acme Prod") && body.contains("https://supabase.acme.example"));
        // The organization in the path has to be the project's own.
        let elsewhere = format!("/dashboard/org/{made_up}/projects/{project_id}");
        let (_, body) = send(&router, get_with_cookie(&elsewhere, &alice)).await;
        assert!(body.contains("Project unavailable"), "{body}");
        assert!(!body.contains("acme.example"), "{body}");

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn provisioning_is_isolated_over_http() {
        let Some(scratch) = ScratchDb::create("http_provisioning").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_with_cipher(db.clone(), Some(test_cipher())).await;
        let (alice, bob) = admin_and_member(&db, &router).await;
        let call = |path: &'static str, body: String, cookie: &str| {
            send(&router, form_post(path, &body, Some(cookie)))
        };
        let (_, body) = call(CreateOrganization::PATH, "name=Acme".into(), &alice).await;
        let org: serde_json::Value = serde_json::from_str(&body).unwrap();
        let org_id = org["id"].as_str().unwrap().to_owned();
        // A job as the server queues it, with a marker only its saved
        // data holds.
        let job_id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO jobs (id, kind, organization_id, state, step, data, created_by) \
             SELECT $1::uuid, 'provision_stack', $2::uuid, 'queued', 'mounts', $3::jsonb, id \
             FROM accounts WHERE email = 'alice@example.test'",
        )
        .bind(&job_id)
        .bind(&org_id)
        .bind(serde_json::json!({
            "project_id": uuid::Uuid::now_v7(),
            "name": "Synthetic Stack",
            "environment_id": "env-marker-7f3a",
            "server_id": null,
            "host": "synthetic.example.test",
            "https": true,
            "compose_name": format!("sd-{job_id}"),
        }))
        .execute(db.pool())
        .await
        .unwrap();
        let start = |org: &str, host: &str| {
            format!(
                "organization_id={org}&name=Synthetic+Two&target=envSynthetic1\
                 &host={host}&https=true"
            )
        };
        let job_page = format!("/dashboard/org/{org_id}/provisioning/{job_id}");
        let new_stack = format!("/dashboard/new/{org_id}/stack");

        // Bob is not a member: every call answers as for a made-up ID.
        for (path, body) in [
            (GetProvisionJob::PATH, format!("id={job_id}")),
            (
                GetProvisionJob::PATH,
                format!("id={}", uuid::Uuid::now_v7()),
            ),
            (ListProvisionJobs::PATH, format!("organization_id={org_id}")),
            (
                GetProvisionTargets::PATH,
                format!("organization_id={org_id}"),
            ),
            (
                StartProvisioning::PATH,
                start(&org_id, "synthetic-two.example.test"),
            ),
        ] {
            let (parts, response) = call(path, body, &bob).await;
            assert_eq!(parts.status, StatusCode::NOT_FOUND, "{path}: {response}");
            assert!(!response.contains("Synthetic"), "{path}: {response}");
        }
        let (_, body) = send(&router, get_with_cookie(&job_page, &bob)).await;
        assert!(body.contains("Organization unavailable"), "{body}");
        assert!(!body.contains("synthetic.example.test"), "{body}");

        // As a viewer he follows the job but may not create stacks.
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             SELECT $1::uuid, id, 'viewer' FROM accounts WHERE email = 'bob@example.test'",
        )
        .bind(&org_id)
        .execute(db.pool())
        .await
        .unwrap();
        let (parts, body) = call(GetProvisionJob::PATH, format!("id={job_id}"), &bob).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let job: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(job["name"], "Synthetic Stack");
        assert_eq!(job["state"], "queued");
        assert_eq!(job["step"], "mounts");
        assert!(!body.contains("env-marker"), "{body}");
        let (parts, body) = call(
            ListProvisionJobs::PATH,
            format!("organization_id={org_id}"),
            &bob,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(
            body.contains(&job_id) && !body.contains("env-marker"),
            "{body}"
        );
        for (path, body) in [
            (
                GetProvisionTargets::PATH,
                format!("organization_id={org_id}"),
            ),
            (
                StartProvisioning::PATH,
                start(&org_id, "synthetic-two.example.test"),
            ),
        ] {
            let (parts, response) = call(path, body, &bob).await;
            assert_eq!(parts.status, StatusCode::FORBIDDEN, "{path}: {response}");
        }
        let denied: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE action = 'project.provision' AND outcome = 'denied'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(denied, 1);
        let (_, body) = send(&router, get_with_cookie(&job_page, &bob)).await;
        assert!(body.contains("New stack: Synthetic Stack"), "{body}");
        assert!(body.contains("https://synthetic.example.test"), "{body}");
        assert!(body.contains("Write the configuration files"), "{body}");
        let (_, body) = send(&router, get_with_cookie(&new_stack, &bob)).await;
        assert!(body.contains("You cannot create stacks here"), "{body}");
        let org_page = format!("/dashboard/org/{org_id}");
        let (_, body) = send(&router, get_with_cookie(&org_page, &bob)).await;
        assert!(
            body.contains("New stacks") && body.contains(&job_page),
            "{body}"
        );
        assert!(!body.contains("Create a new stack"), "{body}");
        // The job has to be in the organization of the path.
        let (_, body) = call(CreateOrganization::PATH, "name=Other".into(), &alice).await;
        let other: serde_json::Value = serde_json::from_str(&body).unwrap();
        let elsewhere = format!(
            "/dashboard/org/{}/provisioning/{job_id}",
            other["id"].as_str().unwrap()
        );
        let (_, body) = send(&router, get_with_cookie(&elsewhere, &alice)).await;
        assert!(body.contains("New stack unavailable"), "{body}");
        assert!(!body.contains("synthetic.example.test"), "{body}");

        // Alice may create stacks, but nothing is connected, and bad input
        // is refused with a sentence.
        let (parts, body) = call(
            GetProvisionTargets::PATH,
            format!("organization_id={org_id}"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, r#""NotConnected""#);
        let (_, body) = send(&router, get_with_cookie(&new_stack, &alice)).await;
        assert!(body.contains("Dokploy is not connected"), "{body}");
        let (parts, body) =
            call(StartProvisioning::PATH, start(&org_id, "localhost"), &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Enter a host name"), "{body}");
        let (parts, body) = call(
            StartProvisioning::PATH,
            start(&org_id, "synthetic-two.example.test"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Dokploy is not connected"), "{body}");
        let (_, body) = send(&router, get_with_cookie(&org_page, &alice)).await;
        assert!(body.contains("Create a new stack"), "{body}");
        let jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(jobs, 1);

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn the_dokploy_service_panel_follows_membership() {
        let Some(scratch) = ScratchDb::create("http_project_deployment").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_with_cipher(db.clone(), Some(test_cipher())).await;
        let (alice, bob) = admin_and_member(&db, &router).await;
        let call = |body: String, cookie: &str| {
            send(
                &router,
                form_post(GetProjectDeployment::PATH, &body, Some(cookie)),
            )
        };
        let (_, body) = send(
            &router,
            form_post(CreateOrganization::PATH, "name=Acme", Some(&alice)),
        )
        .await;
        let org: serde_json::Value = serde_json::from_str(&body).unwrap();
        let org_id = org["id"].as_str().unwrap().to_owned();
        // One registered project and one the dashboard provisioned.
        let registered = uuid::Uuid::now_v7().to_string();
        let provisioned = uuid::Uuid::now_v7().to_string();
        for (id, name) in [(&registered, "Registered"), (&provisioned, "Provisioned")] {
            sqlx::query(
                "INSERT INTO projects (id, organization_id, name, api_url) \
                 VALUES ($1::uuid, $2::uuid, $3, 'https://stack.example.test')",
            )
            .bind(id)
            .bind(&org_id)
            .bind(name)
            .execute(db.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO project_dokploy_services \
             (project_id, compose_id, app_name, environment_id, job_id) \
             VALUES ($1::uuid, 'composeMarker1', 'sd-app-marker', 'envMarker1', $2)",
        )
        .bind(&provisioned)
        .bind(uuid::Uuid::now_v7())
        .execute(db.pool())
        .await
        .unwrap();

        // Bob is not a member: the project answers as a made-up one would.
        for id in [provisioned.clone(), uuid::Uuid::now_v7().to_string()] {
            let (parts, body) = call(format!("id={id}"), &bob).await;
            assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");
            assert!(!body.contains("Marker"), "{body}");
        }

        // As a viewer he sees the service's state. Dokploy is not
        // connected here, so there is nothing to read from it.
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             SELECT $1::uuid, id, 'viewer' FROM accounts WHERE email = 'bob@example.test'",
        )
        .bind(&org_id)
        .execute(db.pool())
        .await
        .unwrap();
        let (parts, body) = call(format!("id={provisioned}"), &bob).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, r#"{"kind":"not_connected"}"#);
        let (parts, body) = call(format!("id={registered}"), &bob).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, r#"{"kind":"not_provisioned"}"#);

        let page = format!("/dashboard/org/{org_id}/projects/{provisioned}");
        // The panel loads after the page; the page itself carries none of
        // the recorded service's IDs.
        let (parts, body) = send(&router, get_with_cookie(&page, &bob)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Loading the Dokploy service"), "{body}");
        assert!(!body.contains("Marker"), "{body}");

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn only_owners_and_admins_queue_stack_actions() {
        let Some(scratch) = ScratchDb::create("http_stack_actions").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_with_cipher(db.clone(), Some(test_cipher())).await;
        let (alice, bob) = admin_and_member(&db, &router).await;
        let call = |body: String, cookie: &str| {
            send(
                &router,
                form_post(QueueStackAction::PATH, &body, Some(cookie)),
            )
        };
        let (_, body) = send(
            &router,
            form_post(CreateOrganization::PATH, "name=Acme", Some(&alice)),
        )
        .await;
        let org: serde_json::Value = serde_json::from_str(&body).unwrap();
        let org_id = org["id"].as_str().unwrap().to_owned();
        let registered = uuid::Uuid::now_v7().to_string();
        let provisioned = uuid::Uuid::now_v7().to_string();
        for (id, name) in [(&registered, "Registered"), (&provisioned, "Provisioned")] {
            sqlx::query(
                "INSERT INTO projects (id, organization_id, name, api_url) \
                 VALUES ($1::uuid, $2::uuid, $3, 'https://stack.example.test')",
            )
            .bind(id)
            .bind(&org_id)
            .bind(name)
            .execute(db.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO project_dokploy_services \
             (project_id, compose_id, app_name, environment_id, job_id) \
             VALUES ($1::uuid, 'composeMarker1', 'sd-app-marker', 'envMarker1', $2)",
        )
        .bind(&provisioned)
        .bind(uuid::Uuid::now_v7())
        .execute(db.pool())
        .await
        .unwrap();
        let jobs = || async {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs WHERE kind = 'stack_action'")
                .fetch_one(db.pool())
                .await
                .unwrap()
        };

        // Not a member, then a viewer: neither may operate the stack.
        let stop = format!("id={provisioned}&action=stop&confirm=true");
        let (parts, body) = call(stop.clone(), &bob).await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND, "{body}");
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             SELECT $1::uuid, id, 'viewer' FROM accounts WHERE email = 'bob@example.test'",
        )
        .bind(&org_id)
        .execute(db.pool())
        .await
        .unwrap();
        let (parts, body) = call(stop.clone(), &bob).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN, "{body}");
        // The role is checked before the confirmation.
        let (parts, body) = call(format!("id={provisioned}&action=stop"), &bob).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(jobs().await, 0);

        // Stopping must be confirmed; a registered stack is not operated.
        let (parts, body) = call(format!("id={provisioned}&action=stop"), &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (parts, body) = call(format!("id={registered}&action=redeploy"), &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("did not create"), "{body}");
        let (parts, body) = call(format!("id={provisioned}&action=delete"), &alice).await;
        // An action that does not exist is refused when decoded.
        assert_ne!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(jobs().await, 0);

        // Removal needs its own endpoint, the role, and the exact name.
        let removal = |body: String, cookie: &str| {
            send(
                &router,
                form_post(QueueStackRemoval::PATH, &body, Some(cookie)),
            )
        };
        let (parts, body) = removal(
            format!("id={provisioned}&action=remove&name=Provisioned"),
            &bob,
        )
        .await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN, "{body}");
        let (parts, body) = call(format!("id={provisioned}&action=destroy"), &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (parts, body) = removal(
            format!("id={provisioned}&action=stop&name=Provisioned"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (parts, body) = removal(
            format!("id={provisioned}&action=destroy&name=provisioned"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("name exactly"), "{body}");
        assert_eq!(jobs().await, 0);

        // The owner queues one action; a second waits for it.
        let (parts, body) = call(stop, &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let (parts, body) = call(format!("id={provisioned}&action=start"), &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("still running"), "{body}");
        assert_eq!(jobs().await, 1);
        let audited: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'stack.stop'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(audited, 3, "two denied, one queued");

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn the_access_log_downloads_as_csv_for_owners_only() {
        let Some(scratch) = ScratchDb::create("http_access_csv").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_with_options(db.clone(), None, Some(7)).await;
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
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', '=cmd|calc', password_hash \
             FROM accounts",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;
        let (_, body) = send(
            &router,
            form_post(CreateOrganization::PATH, "name=Acme", Some(&alice)),
        )
        .await;
        let org: serde_json::Value = serde_json::from_str(&body).unwrap();
        let org_id = org["id"].as_str().unwrap().to_owned();
        let (parts, body) = send(
            &router,
            form_post(
                RegisterProject::PATH,
                &format!(
                    "organization_id={org_id}&name=Lab&api_url=http%3A%2F%2F10.0.0.5%3A8000\
                     &allow_unencrypted=true"
                ),
                Some(&alice),
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let project: serde_json::Value = serde_json::from_str(&body).unwrap();
        let project_id = project["id"].as_str().unwrap().to_owned();
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             SELECT $1::uuid, id, 'viewer' FROM accounts WHERE email = 'bob@example.test'",
        )
        .bind(&org_id)
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO studio_access_log (project_id, account_id, at, method, path, status) \
             SELECT $1::uuid, a.id, now() - make_interval(secs => n), 'GET', '/p/' || n, 200 \
             FROM accounts a, generate_series(1, 3) AS n",
        )
        .bind(&project_id)
        .execute(db.pool())
        .await
        .unwrap();
        let path = format!("/dashboard/project/{project_id}/studio-access.csv");

        let (parts, body) = send(&router, get_with_cookie(&path, &alice)).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(
            parts.headers[header::CONTENT_TYPE],
            "text/csv; charset=utf-8"
        );
        assert_eq!(
            parts.headers[header::CONTENT_DISPOSITION],
            format!("attachment; filename=\"studio-access-{project_id}.csv\"").as_str()
        );
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
        let lines: Vec<_> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(lines[0], "id,time_utc,member,email,method,path,status");
        assert_eq!(lines.len(), 7, "{body}");
        // Bob's display name is defused, not a formula.
        assert!(body.contains("\"'=cmd|calc\",bob@example.test"), "{body}");

        // One member's requests only.
        let bob_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'bob@example.test'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let (parts, body) = send(
            &router,
            get_with_cookie(&format!("{path}?member={bob_id}"), &alice),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(body.matches("bob@example.test").count(), 3, "{body}");
        assert!(!body.contains("alice@example.test"));
        let (parts, _) = send(
            &router,
            get_with_cookie(&format!("{path}?member=nope"), &alice),
        )
        .await;
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);

        // A viewer is refused, and so is anyone outside the organization.
        let (parts, body) = send(&router, get_with_cookie(&path, &bob)).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        assert!(!body.contains("/p/1"));
        let elsewhere = format!(
            "/dashboard/project/{}/studio-access.csv",
            uuid::Uuid::now_v7()
        );
        let (parts, _) = send(&router, get_with_cookie(&elsewhere, &alice)).await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND);
        // Without a session, the sign-in page.
        let (parts, _) = send(&router, get(&path)).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert!(location(&parts).starts_with("/dashboard/sign-in"));

        let audited: Vec<(String, String)> = sqlx::query_as(
            "SELECT outcome, target_id FROM audit_events \
             WHERE action = 'studio_access.export' ORDER BY id",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        let outcomes: Vec<_> = audited.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(outcomes, ["success", "success", "denied"]);
        assert!(audited.iter().all(|(_, target)| *target == project_id));
    }

    #[tokio::test]
    async fn api_keys_never_come_back_over_http() {
        let Some(scratch) = ScratchDb::create("http_keys").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        // A fixed test key (32 zero bytes, base64).
        let cipher = supabase_dashboard_application::secrets::CredentialCipher::from_base64(
            &SecretString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        )
        .unwrap();
        let router = router_with_cipher(db.clone(), Some(cipher)).await;
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
        let (_, body) = call(CreateOrganization::PATH, "name=Acme".into(), &alice).await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        // Loopback is refused by the default target policy, so the check
        // below never leaves the process.
        let (parts, body) = call(
            RegisterProject::PATH,
            format!(
                "organization_id={acme_id}&name=Lab&api_url=http%3A%2F%2F127.0.0.1%3A9\
                 &allow_unencrypted=true"
            ),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let project: serde_json::Value = serde_json::from_str(&body).unwrap();
        let project_id = project["id"].as_str().unwrap().to_owned();

        const MARKER: &str = "sb_publishable_redaction-marker-7f3a";
        let (parts, body) = call(
            ReplaceProjectCredential::PATH,
            format!("id={project_id}&kind=anon_key&value={MARKER}"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(!body.contains("redaction-marker"), "{body}");

        // Bob cannot replace or read keys on Alice's project.
        let (_, body) = call(
            ReplaceProjectCredential::PATH,
            format!("id={project_id}&kind=anon_key&value=sb_publishable_bob"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");
        let (_, body) = call(
            GetProjectCredentials::PATH,
            format!("id={project_id}"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");

        // The Studio login is stored even though the gateway cannot be
        // reached to confirm it, and its password never comes back either.
        let (parts, body) = call(
            ReplaceStudioLogin::PATH,
            format!("id={project_id}&username=supabase&password=redaction-marker-studio"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains("unconfirmed"), "{body}");
        assert!(!body.contains("redaction-marker"), "{body}");
        let (_, body) = call(
            ReplaceStudioLogin::PATH,
            format!("id={project_id}&username=supabase&password=bob-studio-password-0123"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");

        let mut bodies = Vec::new();
        for path in [
            GetProjectCredentials::PATH,
            CheckProjectHealth::PATH,
            GetProjectHealth::PATH,
        ] {
            let (parts, body) = call(path, format!("id={project_id}"), &alice).await;
            assert_eq!(parts.status, StatusCode::OK, "{path}: {body}");
            bodies.push(body);
        }
        assert!(bodies[0].contains(r#""state":"set""#), "{}", bodies[0]);
        assert!(
            bodies[1].contains("destination_not_allowed"),
            "{}",
            bodies[1]
        );
        let page = format!("/dashboard/org/{acme_id}/projects/{project_id}/settings");
        let (parts, body) = send(&router, get_with_cookie(&page, &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        bodies.push(body);
        // The setup page registration leads to shows the same forms in order
        // and never the stored value either.
        let setup = format!("/dashboard/org/{acme_id}/projects/{project_id}/setup");
        let (parts, body) = send(&router, get_with_cookie(&setup, &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Set up this project"), "{body}");
        let keys = body.find(r#"id="api-keys""#).expect("api keys step");
        let login = body
            .find(r#"id="studio-login""#)
            .expect("studio login step");
        let check = body.find(r#"id="first-check""#).expect("first check step");
        assert!(keys < login && login < check);
        bodies.push(body);
        // The overview's connection guidance lists the service addresses
        // and names the key variables without showing a stored key.
        let overview = format!("/dashboard/org/{acme_id}/projects/{project_id}");
        let (parts, body) = send(&router, get_with_cookie(&overview, &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Connect to this project"), "{body}");
        assert!(body.contains("http://127.0.0.1:9/rest/v1/"), "{body}");
        assert!(body.contains("ws://127.0.0.1:9/realtime/v1/websocket"));
        bodies.push(body);
        for body in &bodies {
            assert!(!body.contains("redaction-marker"), "{body}");
        }
        let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT ciphertext FROM project_credentials")
            .fetch_all(db.pool())
            .await
            .unwrap();
        assert_eq!(stored.len(), 2);
        assert!(
            stored
                .iter()
                .all(|c| !String::from_utf8_lossy(c).contains("redaction-marker"))
        );

        for kind in ["anon_key", "studio_login"] {
            let (parts, body) = call(
                RemoveProjectCredential::PATH,
                format!("id={project_id}&kind={kind}"),
                &alice,
            )
            .await;
            assert_eq!(parts.status, StatusCode::OK, "{kind}: {body}");
        }
        let (_, body) = call(
            GetProjectCredentials::PATH,
            format!("id={project_id}"),
            &alice,
        )
        .await;
        assert!(!body.contains(r#""state":"set""#), "{body}");

        // Certificate authorities: the settings page has the section, and a
        // private key pasted by mistake is refused, not stored, and not
        // echoed back.
        assert!(bodies[3].contains("Certificate authorities"));
        assert!(bodies[3].contains(r#"name="pem""#));
        let pasted_key =
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1tYXJrZXI=\n-----END PRIVATE KEY-----\n";
        let (_, body) = call(
            ReplaceProjectAuthorities::PATH,
            format!(
                "id={project_id}&pem={}",
                pasted_key
                    .replace(' ', "%20")
                    .replace('\n', "%0A")
                    .replace('=', "%3D")
            ),
            &alice,
        )
        .await;
        assert!(body.contains("Only certificates are accepted"), "{body}");
        assert!(!body.contains("c2VjcmV0LWtleS1tYXJrZXI"), "{body}");
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM project_authorities")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(stored, 0);
        let (parts, body) = call(
            GetProjectAuthorities::PATH,
            format!("id={project_id}"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, "null");
        let (_, body) = call(
            RemoveProjectAuthorities::PATH,
            format!("id={project_id}"),
            &alice,
        )
        .await;
        assert!(
            body.contains("No certificate authorities are stored"),
            "{body}"
        );
        let (_, body) = call(
            GetProjectAuthorities::PATH,
            format!("id={project_id}"),
            &bob,
        )
        .await;
        assert!(body.contains("NotFound"), "{body}");

        db.close().await;
        scratch.drop().await;
    }

    /// A gateway that answers Studio requests only with the right login and
    /// echoes the Cookie header it received.
    async fn mock_studio_gateway() -> String {
        use axum::http::HeaderMap;
        const EXPECTED: &str = "Basic c3VwYWJhc2U6c3R1ZGlvLXBhc3N3b3JkLWZvci10ZXN0cw==";
        let app = Router::new().fallback(|headers: HeaderMap| async move {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            if auth != Some(EXPECTED) {
                return (StatusCode::UNAUTHORIZED, String::new());
            }
            let cookie = headers
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-");
            (StatusCode::OK, format!("studio page; cookie={cookie}"))
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn studio_get(host: &str, path: &str, cookie: Option<&str>) -> Request<Body> {
        let mut builder = Request::get(path)
            .header(header::HOST, host)
            .header("sec-fetch-mode", "navigate");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// A router with Studio hosts under `studio.localhost:3000` and an
    /// owner, alice, already bootstrapped.
    async fn studio_router(db: &Database) -> (Router, crate::studio_host::StudioHosts) {
        use supabase_dashboard_adapters::studio_proxy::{StudioProxy, StudioProxySettings};
        use supabase_dashboard_application::{secrets::CredentialCipher, studio::StudioService};

        use crate::{studio::StudioGateway, studio_host::StudioHosts};

        let cipher = CredentialCipher::from_base64(&SecretString::from(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ))
        .unwrap();
        let auth = AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap();
        auth.bootstrap_owner(
            "alice@example.test",
            "Alice",
            &SecretString::from("correct horse battery staple"),
        )
        .await
        .unwrap();
        let public = url::Url::parse(ORIGIN).unwrap();
        let hosts = StudioHosts::parse("studio.localhost:3000", &public).unwrap();
        let gateway = StudioGateway::new(
            hosts.clone(),
            Arc::new(StudioService::new(
                db.clone(),
                Some(cipher.clone()),
                Duration::from_secs(3600),
            )),
            StudioProxy::new(StudioProxySettings {
                policy: TargetPolicy {
                    allow_loopback: true,
                },
                ..StudioProxySettings::default()
            })
            .unwrap(),
            ORIGIN.to_owned(),
        )
        .with_access_log(StudioAccessRecorder::start(db.clone()));
        let dokploy = dokploy_service(db, Some(cipher.clone()), TargetPolicy::default());
        let state = AppState {
            leptos_options: LeptosOptions::builder()
                .output_name("supabase-dashboard")
                .site_root("target/site")
                .build(),
            organizations: Arc::new(OrganizationService::new(db.clone())),
            projects: Arc::new(ProjectService::new(db.clone())),
            dokploy: Arc::clone(&dokploy),
            provisioning: Arc::new(ProvisioningService::new(
                db.clone(),
                Some(cipher.clone()),
                dokploy,
            )),
            // The gateways in these tests listen on loopback.
            connections: Arc::new(ConnectionService::new(
                db.clone(),
                Some(cipher),
                supabase_dashboard_adapters::gateway::GatewayProbe::shared(
                    supabase_dashboard_adapters::gateway::GatewaySettings {
                        policy: TargetPolicy {
                            allow_loopback: true,
                        },
                        ..Default::default()
                    },
                )
                .unwrap(),
            )),
            db: db.clone(),
            readiness_timeout: Duration::from_secs(1),
            auth: Arc::new(auth),
            cookie: CookieSettings::new(false, 3600),
            expected_origin: None,
            studio: Some(Arc::new(gateway)),
            studio_access: Arc::new(StudioAccessService::new(db.clone(), Some(7))),
        };
        let router = router(state, &test_limits());
        (router, hosts)
    }

    #[tokio::test]
    async fn studio_opens_only_through_the_dashboard() {
        let Some(scratch) = ScratchDb::create("http_studio").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let (router, hosts) = studio_router(&db).await;

        let bob_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts \
             RETURNING id",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;
        let call = |path: &'static str, body: String, cookie: &str| {
            send(&router, form_post(path, &body, Some(cookie)))
        };
        let (_, body) = call(CreateOrganization::PATH, "name=Acme".into(), &alice).await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             VALUES ($1::uuid, $2, 'viewer')",
        )
        .bind(&acme_id)
        .bind(bob_id)
        .execute(db.pool())
        .await
        .unwrap();
        let gateway_url = mock_studio_gateway().await;
        let mut ids = Vec::new();
        for name in ["Main", "Other"] {
            let (_, body) = call(
                RegisterProject::PATH,
                format!(
                    "organization_id={acme_id}&name={name}&allow_unencrypted=true&api_url={}",
                    url::form_urlencoded::byte_serialize(gateway_url.as_bytes())
                        .collect::<String>()
                ),
                &alice,
            )
            .await;
            let project: serde_json::Value = serde_json::from_str(&body).unwrap();
            ids.push(
                project["id"]
                    .as_str()
                    .unwrap()
                    .parse::<uuid::Uuid>()
                    .unwrap(),
            );
        }
        let (main, other) = (ids[0], ids[1]);
        let launch = |id: uuid::Uuid| format!("/dashboard/project/{id}");

        // A reverse proxy asks, without a session, before it gets a
        // certificate on demand. Only a registered project's Studio host,
        // as a bare name, is allowed.
        let ask = |domain: String| {
            send(
                &router,
                get(&format!("{}?domain={domain}", crate::studio::TLS_ASK_PATH)),
            )
        };
        let (parts, _) = ask(format!("{}.studio.localhost", main.simple())).await;
        assert_eq!(parts.status, StatusCode::OK);
        for refused in [
            format!("{}.studio.localhost", uuid::Uuid::from_u128(7).simple()),
            format!("{}.studio.localhost:3000", main.simple()),
            format!("{}.studio.localhost.", main.simple()),
            format!("{main}.studio.localhost"),
            "studio.localhost".to_owned(),
            "localhost".to_owned(),
            "example.com".to_owned(),
        ] {
            let (parts, _) = ask(refused.clone()).await;
            assert_eq!(parts.status, StatusCode::NOT_FOUND, "{refused}");
        }
        let (parts, _) = send(&router, get(crate::studio::TLS_ASK_PATH)).await;
        assert!(parts.status.is_client_error());

        // Until the keys and the Studio login are saved, the project page
        // lists what is missing to every member, and only those who can
        // save them get the links.
        let page = format!("/dashboard/org/{acme_id}/projects/{main}");
        let (_, body) = send(&router, get_with_cookie(&page, &alice)).await;
        assert!(body.contains("Finish connecting this project"), "{body}");
        assert!(body.contains("0 of 3 saved."));
        assert!(body.contains("Save the Studio login in Settings"));
        assert!(body.contains("/settings#studio-login"));
        let (_, body) = send(&router, get_with_cookie(&page, &bob)).await;
        assert!(body.contains("Finish connecting this project"));
        assert!(!body.contains("Save the Studio login in Settings"));
        assert!(body.contains("An owner or admin can save them."));

        // Without a saved login, the member is sent to the project page.
        let (parts, _) = send(&router, get_with_cookie(&launch(main), &alice)).await;
        assert_eq!(
            location(&parts),
            format!("/dashboard/org/{acme_id}/projects/{main}?studio=not_configured")
        );
        for id in [main, other] {
            let (parts, body) = call(
                ReplaceStudioLogin::PATH,
                format!("id={id}&username=supabase&password=studio-password-for-tests"),
                &alice,
            )
            .await;
            assert_eq!(parts.status, StatusCode::OK, "{body}");
        }

        // The project page offers Studio to the owner, explains a refusal
        // with a fixed text, and offers nothing to a viewer.
        let (_, body) = send(&router, get_with_cookie(&page, &alice)).await;
        assert!(body.contains("1 of 3 saved."), "{body}");
        assert!(!body.contains("Save the Studio login in Settings"));
        assert!(
            body.contains(&format!(r#"href="{}" rel="external""#, launch(main))),
            "{body}"
        );
        assert!(body.contains("full access to the database"));
        let (_, body) = send(
            &router,
            get_with_cookie(&format!("{page}?studio=forbidden"), &bob),
        )
        .await;
        assert!(!body.contains("Open Studio"));
        assert!(
            body.contains("Your role can't open this project's Studio"),
            "{body}"
        );
        let (_, body) = send(
            &router,
            get_with_cookie(&format!("{page}?studio=%3Cscript%3E"), &alice),
        )
        .await;
        assert!(!body.contains("<script>"));
        // Cards open Studio for the owner and the project page for a viewer.
        let org_page = format!("/dashboard/org/{acme_id}");
        let (_, body) = send(&router, get_with_cookie(&org_page, &alice)).await;
        assert!(body.contains(&format!(r#"href="{}" rel="external""#, launch(main))));
        let (_, body) = send(&router, get_with_cookie(&org_page, &bob)).await;
        assert!(!body.contains(&launch(main)), "{body}");
        assert!(body.contains(&page));

        // Signed out: the launcher asks for a session first, and signing
        // in leads back to it.
        let launch_main = format!("{}?path=%2Fproject%2Fdefault%2Fsql", launch(main));
        let (parts, _) = send(&router, get(&launch_main)).await;
        let sign_in = location(&parts).to_owned();
        assert!(sign_in.starts_with("/dashboard/sign-in?next="), "{sign_in}");
        // The page carries the launcher in a hidden field. Leptos's query
        // map decodes `next` once more than the server encoded it, so the
        // nested `path` arrives unescaped; the launcher reads it either way.
        let (_, body) = send(&router, get(&sign_in)).await;
        assert!(
            body.contains(&format!(r#"name="next" value="{}?path="#, launch(main))),
            "{body}"
        );
        let next = url::form_urlencoded::byte_serialize(launch_main.as_bytes()).collect::<String>();
        let (parts, _) = send(
            &router,
            form_post(
                "/auth/sign-in",
                &format!("email=alice%40example.test&password=wrong-password-here&next={next}"),
                None,
            ),
        )
        .await;
        assert_eq!(
            location(&parts),
            format!("/dashboard/sign-in?error=invalid&next={next}"),
            "a failed attempt keeps the page to return to"
        );
        let (parts, _) = send(
            &router,
            form_post(
                "/auth/sign-in",
                &format!(
                    "email=alice%40example.test&password=correct+horse+battery+staple&next={next}"
                ),
                None,
            ),
        )
        .await;
        assert_eq!(location(&parts), launch_main);
        // Another site, or the sign-in page itself, is never a return target.
        for next in [
            "%2F%2Fevil.test",
            "https%3A%2F%2Fevil.test",
            "%2F%5Cevil.test",
            "%2Fdashboard%2Fsign-in",
        ] {
            let (parts, _) = send(
                &router,
                form_post(
                    "/auth/sign-in",
                    &format!(
                        "email=alice%40example.test&password=correct+horse+battery+staple&next={next}"
                    ),
                    None,
                ),
            )
            .await;
            assert_eq!(location(&parts), HOME_PATH, "{next}");
        }
        // A viewer is refused and told why.
        let (parts, _) = send(&router, get_with_cookie(&launch(main), &bob)).await;
        assert_eq!(
            location(&parts),
            format!("/dashboard/org/{acme_id}/projects/{main}?studio=forbidden")
        );
        let (parts, _) = send(
            &router,
            get_with_cookie(&launch(uuid::Uuid::now_v7()), &alice),
        )
        .await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND);

        // The owner gets a one-time code for the project's Studio host.
        let (parts, _) = send(
            &router,
            get_with_cookie(
                &format!("{}?path=%2Fproject%2Fdefault%2Fsql", launch(main)),
                &alice,
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert_eq!(parts.headers[header::REFERRER_POLICY], "no-referrer");
        let target = url::Url::parse(location(&parts)).unwrap();
        let main_host = hosts.host(main);
        assert_eq!(
            target.host_str(),
            Some(main_host.split(':').next().unwrap())
        );
        assert_eq!(target.path(), "/__dashboard/handoff");
        let handoff = format!("{}?{}", target.path(), target.query().unwrap());

        // The code does not work on another project's host.
        let other_host = hosts.host(other);
        let (parts, _) = send(&router, studio_get(&other_host, &handoff, None)).await;
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
        // It was used up by that attempt; get a fresh one.
        let (parts, _) = send(&router, get_with_cookie(&launch(main), &alice)).await;
        let target = url::Url::parse(location(&parts)).unwrap();
        let handoff = format!("{}?{}", target.path(), target.query().unwrap());
        let (parts, _) = send(&router, studio_get(&main_host, &handoff, None)).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert_eq!(location(&parts), "/project/default");
        let set_cookie = parts.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.starts_with("sd-studio="), "{set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        let studio_cookie = set_cookie.split(';').next().unwrap().to_owned();
        let (parts, _) = send(&router, studio_get(&main_host, &handoff, None)).await;
        assert_eq!(parts.status, StatusCode::BAD_REQUEST, "codes work once");

        // Studio answers through the dashboard, which adds the login and
        // keeps its own cookie to itself.
        let cookies = format!("{studio_cookie}; theme=dark");
        let (parts, body) = send(
            &router,
            studio_get(&main_host, "/project/default", Some(&cookies)),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, "studio page; cookie=theme=dark");

        // The cookie does not open another project's Studio.
        let (parts, _) = send(
            &router,
            studio_get(&other_host, "/project/default", Some(&studio_cookie)),
        )
        .await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert!(location(&parts).starts_with(&format!("{ORIGIN}{}", launch(other))));

        // The access log records the request without its query string, for
        // owners and admins only.
        let _ = send(
            &router,
            studio_get(
                &main_host,
                "/project/default/sql?q=select-secret",
                Some(&cookies),
            ),
        )
        .await;
        let mut log = String::new();
        for _ in 0..50 {
            let (parts, body) = call(GetStudioAccessLog::PATH, format!("id={main}"), &alice).await;
            assert_eq!(parts.status, StatusCode::OK, "{body}");
            log = body;
            if log.contains("/project/default/sql") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(log.contains(r#""path":"/project/default""#), "{log}");
        assert!(log.contains(r#""path":"/project/default/sql""#), "{log}");
        assert!(!log.contains("select-secret"), "{log}");
        assert!(log.contains("Alice"), "{log}");
        let (parts, _) = call(GetStudioAccessLog::PATH, format!("id={main}"), &bob).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);

        // A write from another origin is refused, even with the cookie.
        let forged = Request::post("/api/platform/pg-meta/default/query")
            .header(header::HOST, &main_host)
            .header(header::COOKIE, &studio_cookie)
            .header("sec-fetch-site", "same-site")
            .body(Body::from("{}"))
            .unwrap();
        let (parts, _) = send(&router, forged).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);

        // Studio hosts have their own body limit (4096 in these tests): a
        // body over the dashboard's 1024 reaches Studio, one over the
        // Studio limit does not.
        let upload = |len: usize| {
            Request::post("/api/platform/storage/default/upload")
                .header(header::HOST, &main_host)
                .header(header::COOKIE, &studio_cookie)
                .header("sec-fetch-site", "same-origin")
                .header(header::CONTENT_LENGTH, len.to_string())
                .body(Body::from(vec![b'x'; len]))
                .unwrap()
        };
        let (parts, body) = send(&router, upload(2048)).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let (parts, _) = send(&router, upload(8192)).await;
        assert_eq!(parts.status, StatusCode::PAYLOAD_TOO_LARGE);

        // Without a cookie, page loads go back to the launcher with the path
        // and API calls get 401.
        let (parts, _) = send(
            &router,
            studio_get(&main_host, "/project/default/sql?x=1", None),
        )
        .await;
        assert_eq!(
            location(&parts),
            format!(
                "{ORIGIN}{}?path=%2Fproject%2Fdefault%2Fsql%3Fx%3D1",
                launch(main)
            )
        );
        let api = Request::get("/api/profile")
            .header(header::HOST, &main_host)
            .header("sec-fetch-mode", "cors")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = send(&router, api).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

        // Names under the Studio domain that are not projects get 404, and
        // the dashboard's own routes are not served there.
        let (parts, _) = send(&router, studio_get("www.studio.localhost:3000", "/", None)).await;
        assert_eq!(parts.status, StatusCode::NOT_FOUND);

        // Signing out of the dashboard ends Studio access at once.
        let (parts, _) = send(&router, form_post("/auth/sign-out", "", Some(&alice))).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        let (parts, _) = send(
            &router,
            studio_get(&main_host, "/project/default", Some(&studio_cookie)),
        )
        .await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        assert!(
            parts.headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );

        let opened: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action = 'studio.open' AND outcome = 'success'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(opened, 2);

        db.close().await;
        scratch.drop().await;
    }

    /// A value from the disposable stack's env file.
    fn fixture_value(name: &str) -> String {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/supabase/fixture.env"
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap()
            .to_owned()
    }

    /// The same flow against the disposable stack's real Studio and Kong
    /// gateway (`tests/fixtures/supabase`). Skipped unless both
    /// `SUPABASE_DASHBOARD_TEST_DATABASE_URL` and
    /// `SUPABASE_DASHBOARD_TEST_FIXTURE_URL` are set.
    #[tokio::test]
    async fn studio_opens_the_fixture_studio() {
        let Ok(fixture_url) = std::env::var("SUPABASE_DASHBOARD_TEST_FIXTURE_URL") else {
            eprintln!("skipping: SUPABASE_DASHBOARD_TEST_FIXTURE_URL is not set");
            return;
        };
        let Some(scratch) = ScratchDb::create("http_studio_fixture").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let (router, hosts) = studio_router(&db).await;
        let bob_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts \
             RETURNING id",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;
        let (_, body) = send(
            &router,
            form_post(CreateOrganization::PATH, "name=Acme", Some(&alice)),
        )
        .await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             VALUES ($1::uuid, $2, 'viewer')",
        )
        .bind(&acme_id)
        .bind(bob_id)
        .execute(db.pool())
        .await
        .unwrap();
        let (_, body) = send(
            &router,
            form_post(
                RegisterProject::PATH,
                &format!(
                    "organization_id={acme_id}&name=Fixture&allow_unencrypted=true&api_url={}",
                    url::form_urlencoded::byte_serialize(fixture_url.as_bytes())
                        .collect::<String>()
                ),
                Some(&alice),
            ),
        )
        .await;
        let project: serde_json::Value = serde_json::from_str(&body).unwrap();
        let id: uuid::Uuid = project["id"].as_str().unwrap().parse().unwrap();
        // A login the gateway refuses is not saved; the real one is
        // confirmed by the gateway before it is stored.
        let (parts, body) = send(
            &router,
            form_post(
                ReplaceStudioLogin::PATH,
                &format!(
                    "id={id}&username={}&password=not-the-fixture-password",
                    fixture_value("DASHBOARD_USERNAME"),
                ),
                Some(&alice),
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("refused this Studio login"), "{body}");
        let (parts, body) = send(
            &router,
            form_post(
                ReplaceStudioLogin::PATH,
                &format!(
                    "id={id}&username={}&password={}",
                    fixture_value("DASHBOARD_USERNAME"),
                    fixture_value("DASHBOARD_PASSWORD")
                ),
                Some(&alice),
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains(r#""result":"confirmed""#), "{body}");
        let launch = format!("/dashboard/project/{id}");

        // A viewer is refused before anything reaches the gateway, and a
        // non-member sees the same page as for a project that does not exist.
        let (parts, _) = send(&router, get_with_cookie(&launch, &bob)).await;
        assert_eq!(
            location(&parts),
            format!("/dashboard/org/{acme_id}/projects/{id}?studio=forbidden")
        );
        let mut members = Vec::new();
        for (name, role) in [
            ("carol", Some("admin")),
            ("dave", Some("developer")),
            ("erin", None),
        ] {
            let account: uuid::Uuid = sqlx::query_scalar(
                "INSERT INTO accounts (id, email, display_name, password_hash) \
                 SELECT gen_random_uuid(), $1, $2, password_hash FROM accounts LIMIT 1 \
                 RETURNING id",
            )
            .bind(format!("{name}@example.test"))
            .bind(name)
            .fetch_one(db.pool())
            .await
            .unwrap();
            if let Some(role) = role {
                sqlx::query(
                    "INSERT INTO organization_members (organization_id, account_id, role) \
                     VALUES ($1::uuid, $2, $3)",
                )
                .bind(&acme_id)
                .bind(account)
                .bind(role)
                .execute(db.pool())
                .await
                .unwrap();
            }
            let cookie = sign_in_cookie(&router, &format!("{name}%40example.test")).await;
            members.push((name, role.is_some(), cookie));
        }
        let host = hosts.host(id);
        for (name, member, cookie) in &members {
            let (parts, body) = send(&router, get_with_cookie(&launch, cookie)).await;
            if !member {
                assert_eq!(parts.status, StatusCode::NOT_FOUND, "{name}");
                assert!(!body.contains(&host), "{name}");
                continue;
            }
            // Admins and developers reach the fixture's Studio page.
            let target = url::Url::parse(location(&parts)).unwrap();
            let handoff = format!("{}?{}", target.path(), target.query().unwrap());
            let (parts, _) = send(&router, studio_get(&host, &handoff, None)).await;
            assert_eq!(location(&parts), "/project/default", "{name}");
            let cookie = parts.headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let (parts, _) = send(
                &router,
                studio_get(&host, "/project/default", Some(&cookie)),
            )
            .await;
            assert_eq!(parts.status, StatusCode::OK, "{name}");
        }

        // The owner is handed over to the project's Studio host.
        let (parts, _) = send(&router, get_with_cookie(&launch, &alice)).await;
        let target = url::Url::parse(location(&parts)).unwrap();
        let handoff = format!("{}?{}", target.path(), target.query().unwrap());
        let (parts, _) = send(&router, studio_get(&host, &handoff, None)).await;
        assert_eq!(location(&parts), "/project/default");
        let studio_cookie = parts.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        // Studio's root sends the browser to its project page, as a path on
        // the Studio host, and the page itself loads.
        let (parts, _) = send(&router, studio_get(&host, "/", Some(&studio_cookie))).await;
        assert_eq!(parts.status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&parts), "/project/default");
        let (parts, body) = send(
            &router,
            studio_get(&host, "/project/default", Some(&studio_cookie)),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("<title"), "{body}");

        // Studio's SQL endpoint runs a query for a same-origin request and
        // never sees one from another site.
        let query = |site: &'static str| {
            Request::post("/api/platform/pg-meta/default/query")
                .header(header::HOST, &host)
                .header(header::COOKIE, &studio_cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", site)
                .header("sec-fetch-mode", "cors")
                .body(Body::from(r#"{"query":"select 40 + 2 as answer"}"#))
                .unwrap()
        };
        let (parts, body) = send(&router, query("same-origin")).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let rows: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(rows[0]["answer"], 42);
        let (parts, _) = send(&router, query("same-site")).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);

        // Signing out ends Studio access on the next request.
        let (parts, _) = send(&router, form_post("/auth/sign-out", "", Some(&alice))).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        let (parts, _) = send(&router, query("same-origin")).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

        db.close().await;
        scratch.drop().await;
    }

    /// The opaque `sb_` keys, stored through the settings forms, pass a
    /// health check through a gateway that translates them (the fixture's
    /// Envoy). Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` and
    /// `SUPABASE_DASHBOARD_TEST_FIXTURE_NEW_KEYS_URL` are set.
    #[tokio::test]
    async fn the_new_api_keys_pass_a_fixture_check() {
        let Ok(fixture_url) = std::env::var("SUPABASE_DASHBOARD_TEST_FIXTURE_NEW_KEYS_URL") else {
            eprintln!("skipping: SUPABASE_DASHBOARD_TEST_FIXTURE_NEW_KEYS_URL is not set");
            return;
        };
        let Some(scratch) = ScratchDb::create("http_new_keys_fixture").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let (router, _) = studio_router(&db).await;
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let call =
            |path: &'static str, body: String| send(&router, form_post(path, &body, Some(&alice)));
        let (_, body) = call(CreateOrganization::PATH, "name=Acme".into()).await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        let (_, body) = call(
            RegisterProject::PATH,
            format!(
                "organization_id={acme_id}&name=Fixture&allow_unencrypted=true&api_url={}",
                url::form_urlencoded::byte_serialize(fixture_url.as_bytes()).collect::<String>()
            ),
        )
        .await;
        let project: serde_json::Value = serde_json::from_str(&body).unwrap();
        let id = project["id"].as_str().unwrap().to_owned();
        for (kind, name) in [
            ("anon_key", "SUPABASE_PUBLISHABLE_KEY"),
            ("service_role_key", "SUPABASE_SECRET_KEY"),
        ] {
            let (parts, body) = call(
                ReplaceProjectCredential::PATH,
                format!("id={id}&kind={kind}&value={}", fixture_value(name)),
            )
            .await;
            assert_eq!(parts.status, StatusCode::OK, "{body}");
        }
        let (parts, body) = call(
            ReplaceStudioLogin::PATH,
            format!(
                "id={id}&username={}&password={}",
                fixture_value("DASHBOARD_USERNAME"),
                fixture_value("DASHBOARD_PASSWORD")
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");

        let (parts, body) = call(CheckProjectHealth::PATH, format!("id={id}")).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let report: supabase_dashboard_domain::connection::HealthReport =
            serde_json::from_str(&body).unwrap();
        assert_eq!(report.checks.len(), 6, "{body}");
        assert!(report.failing().is_empty(), "{body}");
        assert!(report.not_checked().is_empty(), "{body}");
        // Neither key comes back in the report.
        assert!(!body.contains("sb_publishable_"), "{body}");
        assert!(!body.contains("sb_secret_"), "{body}");

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn invitation_links_work_without_a_session() {
        let Some(scratch) = ScratchDb::create("http_invites").await else {
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
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let (_, body) = send(
            &router,
            form_post(CreateOrganization::PATH, "name=Acme", Some(&alice)),
        )
        .await;
        let acme: serde_json::Value = serde_json::from_str(&body).unwrap();
        let acme_id = acme["id"].as_str().unwrap().to_owned();
        let (parts, body) = send(
            &router,
            form_post(
                CreateInvitation::PATH,
                &format!("organization_id={acme_id}&email=Carol%40Example.test&role=developer"),
                Some(&alice),
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let issued: serde_json::Value = serde_json::from_str(&body).unwrap();
        let code = issued["code"].as_str().unwrap().to_owned();
        assert_eq!(code.len(), 64);
        assert_eq!(issued["invitation"]["email"], "carol@example.test");

        // The page and the preview need no session, and are not cached.
        let (parts, _) = send(&router, get("/dashboard/invite")).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
        let (parts, body) = send(
            &router,
            form_post(PreviewInvitation::PATH, &format!("code={code}"), None),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
        let preview: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(preview["invitation"]["organization_name"], "Acme");
        assert_eq!(preview["invitation"]["account_exists"], false);
        assert!(preview["signed_in_as"].is_null());
        let wrong = "0".repeat(64);
        let (_, body) = send(
            &router,
            form_post(PreviewInvitation::PATH, &format!("code={wrong}"), None),
        )
        .await;
        assert!(body.contains(r#""invitation":null"#), "{body}");

        // Other paths under the same prefix still need a session.
        let (parts, _) = send(&router, form_post("/auth/invitation/other", "", None)).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

        let sign_up = |password_confirmation: &str| {
            format!(
                "code={code}&display_name=Carol&password=correct+horse+battery+staple\
                 &password_confirmation={password_confirmation}"
            )
        };
        // A cross-site form cannot create the account.
        let forged = Request::post(SignUpWithInvitation::PATH)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, "https://evil.example")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(sign_up("correct+horse+battery+staple")))
            .unwrap();
        let (parts, _) = send(&router, forged).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);
        let (parts, body) = send(
            &router,
            form_post(
                SignUpWithInvitation::PATH,
                &sign_up("different+password+here"),
                None,
            ),
        )
        .await;
        assert!(!parts.status.is_success());
        assert!(body.contains("passwords do not match"), "{body}");

        let (parts, body) = send(
            &router,
            form_post(
                SignUpWithInvitation::PATH,
                &sign_up("correct+horse+battery+staple"),
                None,
            ),
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(!parts.headers.contains_key(header::SET_COOKIE));
        let (parts, _) = send(
            &router,
            form_post(
                SignUpWithInvitation::PATH,
                &sign_up("correct+horse+battery+staple"),
                None,
            ),
        )
        .await;
        assert!(!parts.status.is_success(), "the code is single use");

        let carol = sign_in_cookie(&router, "carol%40example.test").await;
        let (_, body) = send(
            &router,
            form_post(ListOrganizations::PATH, "", Some(&carol)),
        )
        .await;
        assert!(
            body.contains("Acme") && body.contains("developer"),
            "{body}"
        );
        let (_, body) = send(
            &router,
            form_post(
                PreviewInvitation::PATH,
                &format!("code={code}"),
                Some(&carol),
            ),
        )
        .await;
        assert!(body.contains(r#""invitation":null"#), "{body}");
        assert!(body.contains("carol@example.test"), "{body}");

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn account_settings_act_only_on_the_signed_in_account() {
        let Some(scratch) = ScratchDb::create("http_account").await else {
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
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts",
        )
        .execute(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let alice_elsewhere = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;
        let call = |path: &'static str, body: String, cookie: &str| {
            send(&router, form_post(path, &body, Some(cookie)))
        };

        // The pages need a session and render for the signed-in operator.
        let (parts, _) = send(&router, get("/dashboard/account/security")).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        for page in ["/dashboard/account/me", "/dashboard/account/security"] {
            let (parts, body) = send(&router, get_with_cookie(page, &alice)).await;
            assert_eq!(parts.status, StatusCode::OK, "{page}");
            assert!(body.contains("Account settings"), "{page}: {body}");
        }

        // Sessions: Alice sees her two, with this one marked, and no tokens.
        let (parts, body) = call(ListSessions::PATH, String::new(), &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let sessions: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions.iter().filter(|s| s["is_current"] == true).count(),
            1
        );
        for cookie in [&alice, &alice_elsewhere] {
            let token = cookie.split_once('=').unwrap().1;
            assert!(!body.contains(token), "session token leaked");
        }
        let current_id = sessions.iter().find(|s| s["is_current"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();

        // Bob's session ID gets the same answer as a made-up one, and
        // survives; Alice cannot end her own current session this way.
        let bob_session: uuid::Uuid = sqlx::query_scalar(
            "SELECT s.id FROM sessions s JOIN accounts a ON a.id = s.account_id \
             WHERE a.email = 'bob@example.test'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        for id in [bob_session, uuid::Uuid::now_v7()] {
            let (_, body) = call(RevokeSession::PATH, format!("session_id={id}"), &alice).await;
            assert!(body.contains("NotFound"), "{body}");
        }
        let (parts, _) = call(ListSessions::PATH, String::new(), &bob).await;
        assert_eq!(parts.status, StatusCode::OK);
        let (_, body) = call(
            RevokeSession::PATH,
            format!("session_id={current_id}"),
            &alice,
        )
        .await;
        assert!(body.contains("Use Sign out"), "{body}");

        // Profile changes apply to Alice only.
        let (parts, body) =
            call(UpdateProfile::PATH, "display_name=Alice+Ops".into(), &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let (_, body) = call(GetCurrentAccount::PATH, String::new(), &alice).await;
        assert!(body.contains("Alice Ops"), "{body}");
        let (_, body) = call(GetCurrentAccount::PATH, String::new(), &bob).await;
        assert!(body.contains("\"Bob\""), "{body}");

        // Password changes need the current password and matching new ones.
        let new = "new_password=a+brand+new+passphrase";
        let (_, body) = call(
            ChangePassword::PATH,
            format!(
                "current_password=correct+horse+battery+staple&{new}&new_password_confirmation=other+passphrase+x"
            ),
            &alice,
        )
        .await;
        assert!(body.contains("do not match"), "{body}");
        let (_, body) = call(
            ChangePassword::PATH,
            format!(
                "current_password=a+wrong+guess+here&{new}&new_password_confirmation=a+brand+new+passphrase"
            ),
            &alice,
        )
        .await;
        assert!(body.contains("not correct"), "{body}");
        assert!(!body.contains("brand"), "{body}");

        // A cross-site form cannot change it, even with the cookie.
        let forged = Request::post(ChangePassword::PATH)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, "https://evil.example")
            .header(header::COOKIE, &alice)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "current_password=correct+horse+battery+staple&{new}&new_password_confirmation=a+brand+new+passphrase"
            )))
            .unwrap();
        let (parts, _) = send(&router, forged).await;
        assert_eq!(parts.status, StatusCode::FORBIDDEN);

        let (parts, body) = call(
            ChangePassword::PATH,
            format!(
                "current_password=correct+horse+battery+staple&{new}&new_password_confirmation=a+brand+new+passphrase"
            ),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, "1", "one other session signed out");
        let (parts, _) = call(ListSessions::PATH, String::new(), &alice_elsewhere).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);
        let (parts, _) = call(ListSessions::PATH, String::new(), &alice).await;
        assert_eq!(parts.status, StatusCode::OK);
        let (parts, _) = call(ListSessions::PATH, String::new(), &bob).await;
        assert_eq!(parts.status, StatusCode::OK, "Bob is not affected");

        let body = "email=alice%40example.test&password=a+brand+new+passphrase";
        let (parts, _) = send(&router, form_post("/auth/sign-in", body, None)).await;
        assert_eq!(location(&parts), HOME_PATH);

        db.close().await;
        scratch.drop().await;
    }

    #[tokio::test]
    async fn only_installation_admins_reach_account_administration() {
        let Some(scratch) = ScratchDb::create("http_admin").await else {
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
        let bob_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts \
             RETURNING id",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let alice = sign_in_cookie(&router, "alice%40example.test").await;
        let bob = sign_in_cookie(&router, "bob%40example.test").await;
        let call = |path: &'static str, body: String, cookie: &str| {
            send(&router, form_post(path, &body, Some(cookie)))
        };

        // Bob is not an administrator: refused, and the page shows nothing.
        let (parts, body) = call(AdminListAccounts::PATH, String::new(), &bob).await;
        assert!(!parts.status.is_success());
        assert!(
            body.contains("Forbidden") && !body.contains("alice"),
            "{body}"
        );
        let alice_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'alice@example.test'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let (_, body) = call(
            AdminSetAccountDisabled::PATH,
            format!("account_id={alice_id}&disabled=true"),
            &bob,
        )
        .await;
        assert!(body.contains("Forbidden"), "{body}");
        let (parts, body) = send(&router, get_with_cookie("/dashboard/admin", &bob)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Administrators only"), "{body}");
        assert!(!body.contains("alice@example.test"), "{body}");

        // Alice lists both accounts and disables Bob, who is signed out.
        let (parts, body) = call(AdminListAccounts::PATH, String::new(), &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains("bob@example.test"), "{body}");
        assert!(!body.contains("argon2"), "{body}");
        let (_, body) = call(
            AdminSetAccountDisabled::PATH,
            format!("account_id={alice_id}&disabled=true"),
            &alice,
        )
        .await;
        assert!(body.contains("your own account"), "{body}");
        let (parts, body) = call(
            AdminSetAccountDisabled::PATH,
            format!("account_id={bob_id}&disabled=true"),
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert_eq!(body, "true");
        let (parts, _) = call(ListSessions::PATH, String::new(), &bob).await;
        assert_eq!(parts.status, StatusCode::UNAUTHORIZED);

        db.close().await;
        scratch.drop().await;
    }

    /// Percent-encodes every byte but ASCII letters and digits, for a form
    /// body.
    fn form_value(raw: &str) -> String {
        raw.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    /// Alice is the bootstrapped owner and installation administrator; Bob
    /// is a plain account. Returns their session cookies.
    async fn admin_and_member(db: &Database, router: &Router) -> (String, String) {
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
        sqlx::query(
            "INSERT INTO accounts (id, email, display_name, password_hash) \
             SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts",
        )
        .execute(db.pool())
        .await
        .unwrap();
        (
            sign_in_cookie(router, "alice%40example.test").await,
            sign_in_cookie(router, "bob%40example.test").await,
        )
    }

    fn test_cipher() -> supabase_dashboard_application::secrets::CredentialCipher {
        supabase_dashboard_application::secrets::CredentialCipher::from_base64(&SecretString::from(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn only_installation_admins_reach_the_dokploy_connection() {
        let Some(scratch) = ScratchDb::create("http_dokploy").await else {
            return;
        };
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        let router = router_with_cipher(db.clone(), Some(test_cipher())).await;
        let (alice, bob) = admin_and_member(&db, &router).await;
        let call = |path: &'static str, body: &str, cookie: &str| {
            send(&router, form_post(path, body, Some(cookie)))
        };

        // Bob is refused every call, and his page says so.
        for (path, body) in [
            (GetDokployConnection::PATH, ""),
            (
                ConnectDokploy::PATH,
                "url=https%3A%2F%2Fdokploy.example.test&key=marker-key",
            ),
            (ReplaceDokployKey::PATH, "key=marker-key"),
            (DisconnectDokploy::PATH, ""),
            (GetDokployPlacement::PATH, ""),
            (ConfirmDokployPlacement::PATH, "service=compose%3Aabc"),
            (ClearDokployPlacement::PATH, ""),
        ] {
            let (parts, response) = call(path, body, &bob).await;
            assert_eq!(parts.status, StatusCode::FORBIDDEN, "{path}: {response}");
            assert!(response.contains("Forbidden"), "{path}: {response}");
        }
        let (parts, body) = send(&router, get_with_cookie("/dashboard/admin", &bob)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(
            body.contains(
                "Only installation administrators can see or change the Dokploy connection."
            ),
            "{body}"
        );

        // Alice sees that nothing is connected, with the connect form.
        let (parts, body) = call(GetDokployConnection::PATH, "", &alice).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains(r#""connection":null"#), "{body}");
        assert!(body.contains(r#""storage_available":true"#), "{body}");
        let (parts, body) = send(&router, get_with_cookie("/dashboard/admin", &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(body.contains("Not connected"), "{body}");
        assert!(body.contains(r#"id="dokploy-key""#), "{body}");
        assert!(body.contains(r#"type="password""#), "{body}");

        // Malformed input is refused with a message; nothing is called.
        let (parts, body) = call(
            ConnectDokploy::PATH,
            "url=dokploy.example.test&key=marker-key",
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Enter Dokploy's address"), "{body}");
        // Loopback is not enrolled on this server, so the key is never sent.
        let (parts, body) = call(
            ConnectDokploy::PATH,
            "url=http%3A%2F%2F127.0.0.1%3A9&key=marker-key",
            &alice,
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Dokploy could not be reached"), "{body}");
        assert!(body.contains("does not contact"), "{body}");
        assert!(!body.contains("marker"), "{body}");
        let (parts, body) = call(ReplaceDokployKey::PATH, "key=marker-key", &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Dokploy is not connected"), "{body}");
        let (parts, body) = call(GetDokployPlacement::PATH, "", &alice).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Dokploy is not connected"), "{body}");
        let failures: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events \
             WHERE action = 'dokploy.connect' AND outcome = 'failure' AND target_id = '127.0.0.1'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(failures, 1);
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM dokploy_connection")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(stored, 0);

        db.close().await;
        scratch.drop().await;
    }

    /// Against the disposable Dokploy fixture (`tests/fixtures/dokploy`).
    /// Skipped unless `SUPABASE_DASHBOARD_TEST_DOKPLOY_URL` is set as well.
    #[tokio::test]
    async fn an_admin_connects_replaces_and_removes_dokploy() {
        let Ok(dokploy_url) = std::env::var("SUPABASE_DASHBOARD_TEST_DOKPLOY_URL") else {
            eprintln!("skipping: SUPABASE_DASHBOARD_TEST_DOKPLOY_URL is not set");
            return;
        };
        let Some(scratch) = ScratchDb::create("http_dokploy_fixture").await else {
            return;
        };
        let key_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/dokploy/api-key"
        );
        let key = std::fs::read_to_string(key_path)
            .expect("run tests/fixtures/dokploy/setup.sh first")
            .trim()
            .to_owned();
        let db = Database::connect(&scratch.settings).await.unwrap();
        db.migrate().await.unwrap();
        // The fixture listens on loopback, which this server enrolls.
        let router = router_with_dokploy_policy(
            db.clone(),
            Some(test_cipher()),
            None,
            TargetPolicy {
                allow_loopback: true,
            },
        )
        .await;
        let (alice, _bob) = admin_and_member(&db, &router).await;
        let call =
            |path: &'static str, body: String| send(&router, form_post(path, &body, Some(&alice)));
        let url = form_value(&dokploy_url);
        // Never print a response that might hold the key.
        let leaks = |body: &str| body.contains(key.as_str());

        // A key Dokploy does not know is refused and not stored.
        let (parts, body) = call(
            ConnectDokploy::PATH,
            format!("url={url}&key=not-a-dokploy-key"),
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("Dokploy refused the API key"), "{body}");

        // The fixture's key connects; the answer has the version, not the key.
        let (parts, body) = call(
            ConnectDokploy::PATH,
            format!("url={url}&key={}", form_value(&key)),
        )
        .await;
        assert!(!leaks(&body), "the connect response contains the key");
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(
            body.contains(r#""version":{"major":0,"minor":31,"patch":1}"#),
            "{body}"
        );
        assert!(body.contains(r#""by":{"Account":"Alice"}"#), "{body}");
        let (parts, page) = send(&router, get_with_cookie("/dashboard/admin", &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(!leaks(&page), "the admin page contains the key");
        assert!(page.contains("v0.31.1"), "{page}");
        assert!(page.contains("Remove connection"), "{page}");
        let audit: String =
            sqlx::query_scalar("SELECT string_agg(row_to_json(a)::text, ' ') FROM audit_events a")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(!leaks(&audit), "the audit log contains the key");

        // Replacing: a refused key keeps the stored one; the same key again
        // is accepted and records who replaced it.
        let (parts, body) = call(ReplaceDokployKey::PATH, "key=not-a-dokploy-key".to_owned()).await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (parts, body) =
            call(ReplaceDokployKey::PATH, format!("key={}", form_value(&key))).await;
        assert!(!leaks(&body), "the replace response contains the key");
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains(r#""key_replaced":{"#), "{body}");

        // Placement: Dokploy's services are read with the stored key and
        // looked through for the dashboard's public host. Nothing is
        // confirmed until an admin picks a service the key can see.
        let (parts, body) = call(GetDokployPlacement::PATH, String::new()).await;
        assert!(!leaks(&body), "the placement response contains the key");
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        assert!(body.contains(r#""Found":{"#), "{body}");
        assert!(body.contains(TEST_PUBLIC_HOST), "{body}");
        assert!(body.contains(r#""confirmed":null"#), "{body}");
        let (parts, body) = call(
            ConfirmDokployPlacement::PATH,
            "service=compose%3Anot-a-visible-service".to_owned(),
        )
        .await;
        assert_eq!(parts.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body.contains("does not show that service"), "{body}");
        let (parts, page) = send(&router, get_with_cookie("/dashboard/admin", &alice)).await;
        assert_eq!(parts.status, StatusCode::OK);
        assert!(page.contains("Where the dashboard runs"), "{page}");

        // Removing forgets it; Dokploy itself is not called.
        let (parts, body) = call(DisconnectDokploy::PATH, String::new()).await;
        assert_eq!(parts.status, StatusCode::OK, "{body}");
        let (_, body) = call(GetDokployConnection::PATH, String::new()).await;
        assert!(body.contains(r#""connection":null"#), "{body}");
        let outcomes: Vec<(String, String)> = sqlx::query_as(
            "SELECT action, outcome FROM audit_events WHERE action LIKE 'dokploy.%' \
             ORDER BY occurred_at, id",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        let outcomes: Vec<(&str, &str)> = outcomes
            .iter()
            .map(|(a, o)| (a.as_str(), o.as_str()))
            .collect();
        assert_eq!(
            outcomes,
            [
                ("dokploy.connect", "failure"),
                ("dokploy.connect", "success"),
                ("dokploy.key_replace", "failure"),
                ("dokploy.key_replace", "success"),
                ("dokploy.placement_confirm", "failure"),
                ("dokploy.disconnect", "success"),
            ]
        );

        db.close().await;
        scratch.drop().await;
    }
}
