//! Single sign-on over HTTP against an in-process mock OpenID Connect
//! provider: discovery, keys, and a token endpoint that signs real RS256 ID
//! tokens, plus back-channel logout tokens signed with the same key. The dashboard side is the real router, the real adapter, and a
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
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AdditionalClaims, Audience, EndUserEmail, IdToken, IdTokenClaims, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreGenderClaim, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
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
use uuid::Uuid;

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

/// The provider's session ID, which back-channel logout tokens name.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SessionClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
}

impl AdditionalClaims for SessionClaims {}

type MockIdToken = IdToken<
    SessionClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// What the token endpoint puts in the ID token for one code.
#[derive(Clone)]
struct Grant {
    subject: String,
    sid: Option<String>,
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
    let claims = IdTokenClaims::<SessionClaims, CoreGenderClaim>::new(
        IssuerUrl::new(mock.issuer.clone()).unwrap(),
        vec![Audience::new(grant.audience)],
        expires,
        issued,
        StandardClaims::new(SubjectIdentifier::new(grant.subject.clone())).set_email(Some(
            EndUserEmail::new(format!("{}@idp.example.test", grant.subject)),
        )),
        SessionClaims { sid: grant.sid },
    )
    .set_nonce(Some(Nonce::new(grant.nonce)));
    let id_token = MockIdToken::new(
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
            sid: None,
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

const LOGOUT_PATH: &str = "/auth/oidc/backchannel-logout";
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

fn b64_json(value: &serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
}

/// A logout token signed with the mock provider's key.
fn logout_token(claims: &serde_json::Value) -> String {
    let header = serde_json::json!({ "alg": "RS256", "kid": "mock-key", "typ": "logout+jwt" });
    let input = format!("{}.{}", b64_json(&header), b64_json(claims));
    let signature = signing_key()
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// The provider's back-channel request: no cookie, and from another site.
fn logout_request(body: String) -> Request<Body> {
    Request::post(LOGOUT_PATH)
        .header(header::HOST, crate::app::tests::HOST)
        .header(header::ORIGIN, "http://idp.example.test")
        .header("sec-fetch-site", "cross-site")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn logout_form(token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("logout_token", token)
        .finish()
}

impl Harness {
    fn logout_claims(&self, jti: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": self.mock.issuer,
            "aud": CLIENT_ID,
            "iat": chrono::Utc::now().timestamp(),
            "jti": jti,
            "events": { LOGOUT_EVENT: {} },
        })
    }

    /// Signs in as `subject` with the provider session `sid`.
    async fn oidc_session(&self, code: &str, subject: &str, sid: &str) -> String {
        let started = self.start_sign_in().await;
        self.grant(&started, code, subject, |grant| {
            grant.sid = Some(sid.to_owned());
        });
        let (parts, _) = send(&self.router, started.callback(code, None)).await;
        assert_eq!(location(&parts), NEXT, "{code}");
        cookie(&parts, "sd-session").unwrap()
    }

    async fn logout(&self, token: &str) -> (http::response::Parts, String) {
        send(&self.router, logout_request(logout_form(token))).await
    }

    async fn signed_in(&self, session: &str) -> bool {
        let (parts, _) = send(&self.router, get_with_cookie(NEXT, session)).await;
        parts.status == StatusCode::OK
    }

    /// A Studio session on a project of the owner's, started from the
    /// dashboard session that has provider session `sid`.
    async fn studio_session(&self, sid: &str) -> (Uuid, [u8; 32]) {
        let org = Uuid::now_v7();
        let project = Uuid::now_v7();
        let token_hash = [7u8; 32];
        let pool = self.db.pool();
        sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, 'Org')")
            .bind(org)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organization_members (organization_id, account_id, role) \
             SELECT $1, id, 'owner' FROM accounts WHERE email = 'owner@example.test'",
        )
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO projects (id, organization_id, name, api_url) \
             VALUES ($1, $2, 'Project', 'http://stack.example.test')",
        )
        .bind(project)
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO project_credentials (project_id, kind, key_id, nonce, ciphertext) \
             VALUES ($1, 'studio_login', 'k1', $2, $3)",
        )
        .bind(project)
        .bind([0u8; 12].as_slice())
        .bind([0u8; 32].as_slice())
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO studio_sessions (token_hash, session_id, project_id, expires_at) \
             SELECT $1, id, $2, now() + interval '1 hour' FROM sessions WHERE oidc_sid = $3",
        )
        .bind(token_hash.as_slice())
        .bind(project)
        .bind(sid)
        .execute(pool)
        .await
        .unwrap();
        (project, token_hash)
    }

    async fn studio_open(&self, (project, token_hash): (Uuid, [u8; 32])) -> bool {
        self.db
            .find_studio_grant(&token_hash, project, StdDuration::from_secs(3600))
            .await
            .unwrap()
            .is_some()
    }
}

#[tokio::test]
async fn back_channel_logout_from_a_mock_provider() {
    let Some(h) = harness("http_oidc_logout").await else {
        return;
    };
    // The owner links `alice` and signs in through it twice (two provider
    // sessions), and once with a password.
    let password = h.password_session("owner%40example.test").await;
    let linking = h.start("/auth/oidc/link", "", Some(&password)).await;
    h.grant(&linking, "code-link", "alice", |_| {});
    let (parts, _) = send(&h.router, linking.callback("code-link", Some(&password))).await;
    assert_eq!(
        location(&parts),
        format!("{ACCOUNT_SECURITY_PATH}?oidc=linked")
    );
    let first = h.oidc_session("code-1", "alice", "sid-1").await;
    let second = h.oidc_session("code-2", "alice", "sid-2").await;
    let studio = h.studio_session("sid-1").await;
    assert!(h.studio_open(studio).await);

    // Tokens the dashboard refuses, each with a generic answer and
    // nothing revoked.
    let claims = |jti: &str, edit: &dyn Fn(&mut serde_json::Value)| {
        let mut claims = h.logout_claims(jti);
        claims["sid"] = serde_json::json!("sid-1");
        edit(&mut claims);
        claims
    };
    // The first logouts arrive together, as Authentik sends one per token
    // of a session: both wait for one key fetch and succeed.
    let together = [
        logout_token(&claims("first-1", &|c| c["sid"] = "sid-x".into())),
        logout_token(&claims("first-2", &|c| c["sid"] = "sid-x".into())),
    ];
    let (one, two) = tokio::join!(h.logout(&together[0]), h.logout(&together[1]));
    assert_eq!(
        (one.0.status, two.0.status),
        (StatusCode::OK, StatusCode::OK)
    );
    let tampered = {
        // Another token's claims under this token's signature.
        let signed = logout_token(&claims("bad-signature", &|_| {}));
        let other = b64_json(&claims("bad-signature", &|c| c["sid"] = "sid-2".into()));
        let mut parts = signed.split('.');
        let header = parts.next().unwrap();
        let _ = parts.next();
        format!("{header}.{other}.{}", parts.next().unwrap())
    };
    for (name, token) in [
        (
            "audience",
            logout_token(&claims("aud", &|c| c["aud"] = "another-client".into())),
        ),
        (
            "issuer",
            logout_token(&claims("iss", &|c| {
                c["iss"] = "http://idp.example.test".into();
            })),
        ),
        (
            "nonce",
            logout_token(&claims("nonce", &|c| c["nonce"] = "n-1".into())),
        ),
        (
            "events",
            logout_token(&claims("events", &|c| {
                c.as_object_mut().unwrap().remove("events");
            })),
        ),
        (
            "issued long ago",
            logout_token(&claims("iat", &|c| {
                c["iat"] = (chrono::Utc::now().timestamp() - 3600).into();
            })),
        ),
        (
            "neither sub nor sid",
            logout_token(&claims("nothing", &|c| {
                c.as_object_mut().unwrap().remove("sid");
            })),
        ),
        ("signature", tampered),
        ("garbage", "not-a-jwt".to_owned()),
    ] {
        let (parts, body) = h.logout(&token).await;
        assert_eq!(parts.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store", "{name}");
        assert_eq!(body, r#"{"error":"invalid_request"}"#, "{name}");
    }
    assert!(h.signed_in(&first).await);
    assert!(h.studio_open(studio).await);

    // Malformed requests: not a form, no token, two tokens, too large.
    let valid = logout_token(&claims("valid-1", &|_| {}));
    let mut not_a_form = logout_request(logout_form(&valid));
    not_a_form
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    for request in [
        not_a_form,
        logout_request(String::new()),
        logout_request(format!("{0}&{0}", logout_form(&valid))),
    ] {
        let (parts, _) = send(&h.router, request).await;
        assert_eq!(parts.status, StatusCode::BAD_REQUEST);
    }
    // Too large, whether announced or not: a valid token padded past the
    // limit is refused unread.
    let padded = format!(
        "{}&pad={}",
        logout_form(&logout_token(&claims("padded", &|_| {}))),
        "a".repeat(17 * 1024)
    );
    let mut announced = logout_request(padded.clone());
    announced
        .headers_mut()
        .insert(header::CONTENT_LENGTH, padded.len().into());
    let (parts, _) = send(&h.router, announced).await;
    assert_eq!(parts.status, StatusCode::PAYLOAD_TOO_LARGE);
    let (parts, _) = send(&h.router, logout_request(padded)).await;
    assert!(parts.status.is_client_error(), "{}", parts.status);
    assert!(h.signed_in(&first).await);

    // A provider session the dashboard never saw: accepted, nothing ends.
    let (parts, body) = h
        .logout(&logout_token(&claims("unknown", &|c| {
            c["sid"] = "sid-unknown".into();
        })))
        .await;
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(body, "");
    assert!(h.signed_in(&first).await && h.signed_in(&second).await);

    // By sid: only that dashboard session ends, with its Studio session.
    // The cross-site Origin is no obstacle on this one path.
    let (parts, body) = h.logout(&valid).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(parts.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(body, "");
    assert!(!h.signed_in(&first).await);
    assert!(!h.studio_open(studio).await);
    assert!(h.signed_in(&second).await);
    assert!(h.signed_in(&password).await);
    assert_eq!(
        h.audited("session.oidc_backchannel_logout", "success")
            .await,
        1
    );

    // The same token again is a replay.
    let (parts, _) = h.logout(&valid).await;
    assert_eq!(parts.status, StatusCode::BAD_REQUEST);

    // A subject of another identity ends nothing.
    let mut other = h.logout_claims("other-subject");
    other["sub"] = "mallory".into();
    let (parts, _) = h.logout(&logout_token(&other)).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert!(h.signed_in(&second).await);

    // By sub alone: every session from that identity ends, and the
    // password session stays.
    let third = h.oidc_session("code-3", "alice", "sid-3").await;
    let mut by_subject = h.logout_claims("by-subject");
    by_subject["sub"] = "alice".into();
    let (parts, _) = h.logout(&logout_token(&by_subject)).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert!(!h.signed_in(&second).await);
    assert!(!h.signed_in(&third).await);
    assert!(h.signed_in(&password).await);
    assert_eq!(
        h.audited("session.oidc_backchannel_logout", "success")
            .await,
        3
    );

    // The same route is only for POST; elsewhere a cross-site POST is
    // still refused.
    let (parts, _) = send(&h.router, crate::app::tests::get(LOGOUT_PATH)).await;
    assert_eq!(parts.status, StatusCode::METHOD_NOT_ALLOWED);
    let mut cross_site = logout_request(String::new());
    *cross_site.uri_mut() = "/auth/oidc/sign-in".parse().unwrap();
    let (parts, _) = send(&h.router, cross_site).await;
    assert_eq!(parts.status, StatusCode::FORBIDDEN);

    // Nothing from the tokens reaches the audit log.
    let audit_text: Vec<String> = sqlx::query_scalar(
        "SELECT concat_ws(' ', action, target_type, target_id, outcome, request_id) \
         FROM audit_events",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    for row in &audit_text {
        for secret in ["eyJ", "sid-", "valid-1", "by-subject", "alice"] {
            assert!(!row.contains(secret), "{row}");
        }
    }

    h.db.close().await;
    h.scratch.drop().await;
}

#[tokio::test]
async fn administrators_unlink_other_operators_identities() {
    use leptos::server_fn::ServerFn;
    use supabase_dashboard_web::server_fns::AdminUnlinkOidcIdentity;

    let Some(h) = harness("http_oidc_admin_unlink").await else {
        return;
    };
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         SELECT gen_random_uuid(), 'bob@example.test', 'Bob', password_hash FROM accounts LIMIT 1",
    )
    .execute(h.db.pool())
    .await
    .unwrap();
    let owner = h.password_session("owner%40example.test").await;
    let bob = h.password_session("bob%40example.test").await;
    for (session, subject, code) in [
        (&owner, "alice", "code-link-a"),
        (&bob, "bob", "code-link-b"),
    ] {
        let linking = h.start("/auth/oidc/link", "", Some(session)).await;
        h.grant(&linking, code, subject, |_| {});
        let (parts, _) = send(&h.router, linking.callback(code, Some(session))).await;
        assert_eq!(
            location(&parts),
            format!("{ACCOUNT_SECURITY_PATH}?oidc=linked")
        );
    }
    let bob_sso = h.oidc_session("code-bob", "bob", "sid-bob").await;
    let pool = h.db.pool().clone();
    let ids = |email: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Uuid, Uuid)>(
                "SELECT a.id, i.id FROM accounts a JOIN oidc_identities i ON i.account_id = a.id \
             WHERE a.email = $1",
            )
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let (owner_id, owner_identity) = ids("owner@example.test").await;
    let (bob_id, bob_identity) = ids("bob@example.test").await;
    let unlink = |account: Uuid, identity: Uuid, session: &str| {
        send(
            &h.router,
            form_post(
                AdminUnlinkOidcIdentity::PATH,
                &format!("account_id={account}&identity_id={identity}"),
                Some(session),
            ),
        )
    };

    // Bob is not an administrator: refused on the server.
    let (parts, body) = unlink(owner_id, owner_identity, &bob).await;
    assert!(!parts.status.is_success());
    assert!(body.contains("Forbidden"), "{body}");
    // The owner's own identity is unlinked under Account settings instead,
    // and an identity is only found under its own account.
    let (_, body) = unlink(owner_id, owner_identity, &owner).await;
    assert!(body.contains("Account settings"), "{body}");
    let (parts, _) = unlink(bob_id, owner_identity, &owner).await;
    assert!(!parts.status.is_success());
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_identities")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(linked, 2);
    assert!(h.signed_in(&bob_sso).await);

    // The account list names the identity and the account in the dialog.
    let (parts, body) = send(&h.router, get_with_cookie("/dashboard/admin", &owner)).await;
    assert_eq!(parts.status, StatusCode::OK);
    assert!(
        body.contains("Unlink bob@idp.example.test from Bob?"),
        "{body}"
    );
    assert!(
        !body.contains(&format!("value=\"{owner_identity}\"")),
        "{body}"
    );

    // The owner unlinks Bob's: his single sign-on session ends, his
    // password session stays, and the identity no longer signs in.
    let (parts, body) = unlink(bob_id, bob_identity, &owner).await;
    assert_eq!(parts.status, StatusCode::OK, "{body}");
    assert_eq!(body, "1");
    assert!(!h.signed_in(&bob_sso).await);
    assert!(h.signed_in(&bob).await);
    let started = h.start_sign_in().await;
    h.grant(&started, "code-after", "bob", |_| {});
    let (parts, _) = send(&h.router, started.callback("code-after", None)).await;
    assert_eq!(location(&parts), sign_in_error("oidc_unlinked"));
    let (parts, _) = unlink(bob_id, bob_identity, &owner).await;
    assert!(!parts.status.is_success());

    assert_eq!(h.audited("admin.account_oidc_unlink", "success").await, 1);
    assert_eq!(h.audited("admin.account_oidc_unlink", "denied").await, 2);
    assert_eq!(h.audited("admin.account_oidc_unlink", "failure").await, 2);

    h.db.close().await;
    h.scratch.drop().await;
}
