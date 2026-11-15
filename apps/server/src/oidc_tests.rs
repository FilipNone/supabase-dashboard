//! Single sign-on over HTTP against an in-process mock OpenID Connect
//! provider: discovery, keys, and a token endpoint that signs real RS256 ID
//! tokens. The dashboard side is the real router, the real adapter, and a
//! scratch metadata database. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration as StdDuration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    net::TargetPolicy,
    oidc::{OidcClient, OidcSettings},
    tls::ExtraRoots,
};
use supabase_dashboard_application::auth::{AuthConfig, AuthService, oidc::OidcSignIn};
use supabase_dashboard_persistence::Database;
use supabase_dashboard_web::app::{ACCOUNT_SECURITY_PATH, SIGN_IN_PATH};

use crate::{
    app::tests::{form_post, get_with_cookie, location, router_with_auth, send},
    scratch_db::ScratchDb,
};

const CLIENT_ID: &str = "dashboard-test-client";
const CLIENT_SECRET: &str = "mock-client-secret";
const PASSWORD: &str = "correct+horse+battery+staple";
const NEXT: &str = "/dashboard/account/me";

/// One RSA key for the whole test binary: generating it is the slow part.
fn signing_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    })
}

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(
        signing_pem(),
        Some(openidconnect::JsonWebKeyId::new("mock-key".to_owned())),
    )
    .unwrap()
}

/// What the token endpoint puts in the ID token for one code.
#[derive(Clone)]
struct Grant {
    subject: String,
    nonce: String,
    audience: String,
    expired: bool,
    code_challenge: String,
}

#[derive(Clone)]
struct Mock {
    issuer: String,
    grants: Arc<Mutex<HashMap<String, Grant>>>,
    /// Codes the token endpoint has seen, to show each is redeemed once.
    redeemed: Arc<Mutex<Vec<String>>>,
}

async fn discovery(State(mock): State<Mock>) -> Json<serde_json::Value> {
    let issuer = &mock.issuer;
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks() -> Json<CoreJsonWebKeySet> {
    Json(CoreJsonWebKeySet::new(vec![
        signing_key().as_verification_key(),
    ]))
}

async fn token(State(mock): State<Mock>, headers: HeaderMap, body: Bytes) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Basic "));
    let code = form.get("code").cloned().unwrap_or_default();
    mock.redeemed.lock().unwrap().push(code.clone());
    let grant = mock.grants.lock().unwrap().remove(&code);
    let (Some(grant), true) = (grant, authorized) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    };
    // PKCE: the verifier must hash to the challenge sent at authorization.
    let verifier = PkceCodeVerifier::new(form.get("code_verifier").cloned().unwrap_or_default());
    if PkceCodeChallenge::from_code_verifier_sha256(&verifier).as_str() != grant.code_challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }
    let now = chrono::Utc::now();
    let (issued, expires) = if grant.expired {
        (
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
        )
    } else {
        (now, now + chrono::Duration::minutes(5))
    };
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(mock.issuer.clone()).unwrap(),
        vec![Audience::new(grant.audience)],
        expires,
        issued,
        StandardClaims::new(SubjectIdentifier::new(grant.subject.clone())).set_email(Some(
            EndUserEmail::new(format!("{}@idp.example.test", grant.subject)),
        )),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(grant.nonce)));
    let id_token = CoreIdToken::new(
        claims,
        &signing_key(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    Json(serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    }))
    .into_response()
}

/// Starts the mock provider on a loopback port.
async fn start_mock() -> Mock {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let mock = Mock {
        issuer,
        grants: Arc::default(),
        redeemed: Arc::default(),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    mock
}

struct Harness {
    scratch: ScratchDb,
    db: Database,
    router: Router,
    mock: Mock,
}

async fn harness(name: &str) -> Option<Harness> {
    let scratch = ScratchDb::create(name).await?;
    // Generate the key before the router's request timeout starts.
    tokio::task::spawn_blocking(signing_pem).await.unwrap();
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let mock = start_mock().await;
    let provider = OidcClient::shared(OidcSettings {
        issuer: mock.issuer.clone(),
        client_id: CLIENT_ID.to_owned(),
        client_secret: SecretString::from(CLIENT_SECRET),
        redirect_url: "http://dash.localhost:3000/auth/oidc/callback".to_owned(),
        connect_timeout: StdDuration::from_secs(2),
        request_timeout: StdDuration::from_secs(5),
        extra_roots: ExtraRoots::default(),
    })
    .unwrap();
    let auth = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap()
        .with_oidc(OidcSignIn::new(provider, "Mock IdP"));
    auth.bootstrap_owner(
        "owner@example.test",
        "Owner",
        &SecretString::from("correct horse battery staple"),
    )
    .await
    .unwrap();
    let router = router_with_auth(db.clone(), None, None, TargetPolicy::default(), auth);
    Some(Harness {
        scratch,
        db,
        router,
        mock,
    })
}

/// The `name=value` part of the response's cookie called `name`.
fn cookie(parts: &http::response::Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(|value| value.split(';').next().unwrap_or_default().to_owned())
}

fn query_param(url: &str, name: &str) -> String {
    let url = url::Url::parse(url).unwrap();
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("{name} missing from {url}"))
}

/// A flow the dashboard started: the provider URL and the flow cookie.
struct Started {
    authorize_url: String,
    flow_cookie: String,
}

impl Started {
    fn state(&self) -> String {
        query_param(&self.authorize_url, "state")
    }

    /// The callback request, as the browser would send it.
    fn callback(&self, code: &str, session: Option<&str>) -> Request<Body> {
        let cookies = match session {
            Some(session) => format!("{}; {session}", self.flow_cookie),
            None => self.flow_cookie.clone(),
        };
        get_with_cookie(
            &format!("/auth/oidc/callback?state={}&code={code}", self.state()),
            &cookies,
        )
    }
}

impl Harness {
    async fn start(&self, path: &str, body: &str, session: Option<&str>) -> Started {
        let (parts, _) = send(&self.router, form_post(path, body, session)).await;
        assert_eq!(parts.status, StatusCode::SEE_OTHER);
        let authorize_url = location(&parts).to_owned();
        assert!(
            authorize_url.starts_with(&format!("{}/authorize?", self.mock.issuer)),
            "{authorize_url}"
        );
        let set_cookie = parts.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.starts_with("sd-oidc="), "{set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        assert!(set_cookie.contains("Max-Age=600"), "{set_cookie}");
        let flow_cookie = cookie(&parts, "sd-oidc").unwrap();
        Started {
            authorize_url,
            flow_cookie,
        }
    }

    async fn start_sign_in(&self) -> Started {
        self.start("/auth/oidc/sign-in", &format!("next={NEXT}"), None)
            .await
    }

    /// The provider authorizes `started` for `subject` and returns a code.
    fn grant(&self, started: &Started, code: &str, subject: &str, tweak: impl FnOnce(&mut Grant)) {
        let mut grant = Grant {
            subject: subject.to_owned(),
            nonce: query_param(&started.authorize_url, "nonce"),
            audience: CLIENT_ID.to_owned(),
            expired: false,
            code_challenge: query_param(&started.authorize_url, "code_challenge"),
        };
        tweak(&mut grant);
        self.mock
            .grants
            .lock()
            .unwrap()
            .insert(code.to_owned(), grant);
    }

    async fn password_session(&self, email: &str) -> String {
        let (parts, _) = send(
            &self.router,
            form_post(
                "/auth/sign-in",
                &format!("email={email}&password={PASSWORD}"),
                None,
            ),
        )
        .await;
        cookie(&parts, "sd-session").unwrap()
    }

    async fn audited(&self, action: &str, outcome: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
            .bind(action)
            .bind(outcome)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
}

fn sign_in_error(code: &str) -> String {
    format!("{SIGN_IN_PATH}?error={code}")
}

#[tokio::test]
async fn single_sign_on_against_a_mock_provider() {
    let Some(h) = harness("http_oidc").await else {
        return;
    };

    // The authorization request uses PKCE (S256), state, nonce, and the
    // three scopes.
    let started = h.start_sign_in().await;
    assert_eq!(query_param(&started.authorize_url, "response_type"), "code");
    assert_eq!(query_param(&started.authorize_url, "client_id"), CLIENT_ID);
    assert_eq!(
        query_param(&started.authorize_url, "code_challenge_method"),
        "S256"
    );
    assert_eq!(
        query_param(&started.authorize_url, "scope"),
        "openid email profile"
    );
    assert_eq!(
        query_param(&started.authorize_url, "redirect_uri"),
        "http://dash.localhost:3000/auth/oidc/callback"
    );

    // Not linked yet: refused, without signing in.
    h.grant(&started, "code-unlinked", "alice", |_| {});
    let (parts, _) = send(&h.router, started.callback("code-unlinked", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc_unlinked"));
    assert!(cookie(&parts, "sd-session").is_none());
    // The flow cookie is cleared whatever the outcome.
    assert_eq!(cookie(&parts, "sd-oidc").as_deref(), Some("sd-oidc="));

    // Link from the account security page.
    let owner = h.password_session("owner%40example.test").await;
    let linking = h.start("/auth/oidc/link", "", Some(&owner)).await;
    h.grant(&linking, "code-link", "alice", |_| {});
    let (parts, _) = send(&h.router, linking.callback("code-link", Some(&owner))).await;
    assert_eq!(
        location(&parts),
        format!("{ACCOUNT_SECURITY_PATH}?oidc=linked")
    );
    assert_eq!(h.audited("account.oidc_link", "success").await, 1);

    // Sign in with it, and land on `next`.
    let started = h.start_sign_in().await;
    h.grant(&started, "code-ok", "alice", |_| {});
    let (parts, body) = send(&h.router, started.callback("code-ok", None)).await;
    assert_eq!(parts.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&parts), NEXT);
    assert!(!body.contains("code-ok"));
    let session = cookie(&parts, "sd-session").unwrap();
    let (parts, body) = send(&h.router, get_with_cookie(NEXT, &session)).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert!(body.contains("Account settings"), "{body}");
    assert_eq!(h.audited("session.sign_in_oidc", "success").await, 1);

    // Replaying the callback fails, and the provider never sees the code
    // again.
    let (parts, _) = send(&h.router, started.callback("code-ok", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc"));
    assert!(cookie(&parts, "sd-session").is_none());
    let redeemed = h.mock.redeemed.lock().unwrap().clone();
    assert_eq!(redeemed.iter().filter(|code| *code == "code-ok").count(), 1);

    // From another browser (no flow cookie), the callback fails.
    let started = h.start_sign_in().await;
    h.grant(&started, "code-elsewhere", "alice", |_| {});
    let request = get_with_cookie(
        &format!(
            "/auth/oidc/callback?state={}&code=code-elsewhere",
            started.state()
        ),
        "sd-oidc=0000000000000000000000000000000000000000000000000000000000000000",
    );
    let (parts, _) = send(&h.router, request).await;
    assert_eq!(location(&parts), sign_in_error("oidc"));
    // ...and the flow is used up for the browser that started it too.
    let (parts, _) = send(&h.router, started.callback("code-elsewhere", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc"));

    // ID tokens that fail verification.
    for (code, tweak) in [
        (
            "code-nonce",
            Box::new(|g: &mut Grant| g.nonce = "another-nonce".to_owned())
                as Box<dyn FnOnce(&mut Grant)>,
        ),
        (
            "code-audience",
            Box::new(|g: &mut Grant| g.audience = "another-client".to_owned()),
        ),
        ("code-expired", Box::new(|g: &mut Grant| g.expired = true)),
        (
            "code-pkce",
            Box::new(|g: &mut Grant| g.code_challenge = "not-the-challenge".to_owned()),
        ),
    ] {
        let started = h.start_sign_in().await;
        h.grant(&started, code, "alice", tweak);
        let (parts, _) = send(&h.router, started.callback(code, None)).await;
        assert_eq!(location(&parts), sign_in_error("oidc"), "{code}");
        assert!(cookie(&parts, "sd-session").is_none(), "{code}");
    }
    assert_eq!(h.audited("session.sign_in_oidc", "success").await, 1);
    assert!(h.audited("session.sign_in_oidc", "denied").await >= 4);

    // The operator cancelled at the provider.
    let started = h.start_sign_in().await;
    let request = get_with_cookie(
        &format!(
            "/auth/oidc/callback?state={}&error=access_denied",
            started.state()
        ),
        &started.flow_cookie,
    );
    let (parts, _) = send(&h.router, request).await;
    assert_eq!(location(&parts), sign_in_error("oidc_cancelled"));

    // A disabled account cannot sign in through its identity.
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts LIMIT 1",
    )
    .execute(h.db.pool())
    .await
    .unwrap();
    let bob = h.password_session("bob%40example.test").await;
    let linking = h.start("/auth/oidc/link", "", Some(&bob)).await;
    h.grant(&linking, "code-link-bob", "bob", |_| {});
    let (parts, _) = send(&h.router, linking.callback("code-link-bob", Some(&bob))).await;
    assert_eq!(
        location(&parts),
        format!("{ACCOUNT_SECURITY_PATH}?oidc=linked")
    );
    sqlx::query("UPDATE accounts SET disabled_at = now() WHERE email = 'bob@example.test'")
        .execute(h.db.pool())
        .await
        .unwrap();
    let started = h.start_sign_in().await;
    h.grant(&started, "code-disabled", "bob", |_| {});
    let (parts, _) = send(&h.router, started.callback("code-disabled", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc_unlinked"));
    assert!(cookie(&parts, "sd-session").is_none());

    // Nothing from the protocol reaches the audit log.
    let audit_text: Vec<String> = sqlx::query_scalar(
        "SELECT concat_ws(' ', action, target_type, target_id, outcome) FROM audit_events",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    for row in &audit_text {
        assert!(!row.contains("code-"), "{row}");
        assert!(!row.contains("mock-access-token"), "{row}");
        assert!(!row.contains("alice"), "{row}");
        assert!(!row.contains("eyJ"), "{row}");
    }

    h.db.close().await;
    h.scratch.drop().await;
}

#[tokio::test]
async fn sign_in_page_offers_single_sign_on_only_when_configured() {
    let Some(h) = harness("http_oidc_page").await else {
        return;
    };
    let (parts, body) = send(&h.router, crate::app::tests::get(SIGN_IN_PATH)).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert!(body.contains("Sign in with Mock IdP"), "{body}");
    assert!(body.contains(r#"action="/auth/oidc/sign-in""#), "{body}");
    h.db.close().await;
    h.scratch.drop().await;

    let Some(scratch) = ScratchDb::create("http_oidc_page_off").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let auth = AuthService::new(db.clone(), AuthConfig::default())
        .await
        .unwrap();
    let router = router_with_auth(db.clone(), None, None, TargetPolicy::default(), auth);
    let (_, body) = send(&router, crate::app::tests::get(SIGN_IN_PATH)).await;
    assert!(!body.contains("Sign in with"), "{body}");
    // Starting a flow without a provider goes back to the sign-in page.
    let (parts, _) = send(&router, form_post("/auth/oidc/sign-in", "", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc"));
    db.close().await;
    scratch.drop().await;
}
