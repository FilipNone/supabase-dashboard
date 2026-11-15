//! The deployment's OpenID Connect provider, for dashboard sign-in.
//!
//! The protocol is the `openidconnect` crate's: discovery, the
//! authorization code flow with PKCE (S256), `state`, and `nonce`, and the
//! ID token checks (issuer, audience, signature, expiry, nonce). Only
//! asymmetric signatures are accepted, so the client secret never doubles
//! as a token signing key.
//!
//! The issuer URL is an enrolled destination, like the deployment's
//! Dokploy URL. The server talks to the provider only through [`OidcHttp`]:
//!
//! - every request must go to the issuer's origin (scheme, host, port);
//!   discovery cannot point the server anywhere else
//! - each resolved address is checked against the target policy at
//!   connection time; loopback is allowed because the deployment named
//!   this origin, but metadata, link-local and similar addresses never are
//! - redirects are not followed, proxies from the environment are ignored
//! - connect and total timeouts, and a bound on each response body
//!
//! The browser is sent to the authorization endpoint the provider's
//! discovery document names; the server never fetches it.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreJwsSigningAlgorithm, CoreProviderMetadata},
};
use reqwest::{Client, redirect};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::auth::oidc::{
    AuthorizeFuture, ExchangeFuture, OidcAuthorization, OidcIdentityClaims, OidcPending,
    OidcProvider, OidcProviderError,
};
use supabase_dashboard_domain::connection::UnreachableReason;

use crate::{
    gateway::{GatewayError, classify, refused_literal},
    net::{PolicyResolver, TargetPolicy},
    tls::{Clients, ExtraRoots},
};

/// Largest response read from the provider: discovery, keys, or tokens.
pub const MAX_OIDC_BODY_BYTES: usize = 256 * 1024;

/// The scopes asked for, besides `openid`. The email and name are only
/// shown to the operator next to a linked identity.
const SCOPES: [&str; 2] = ["email", "profile"];

/// Signature algorithms accepted for ID tokens: asymmetric only.
const ALLOWED_ALGS: [CoreJwsSigningAlgorithm; 8] = [
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
    CoreJwsSigningAlgorithm::RsaSsaPssSha256,
    CoreJwsSigningAlgorithm::RsaSsaPssSha384,
    CoreJwsSigningAlgorithm::RsaSsaPssSha512,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EcdsaP384Sha384,
];

#[derive(Debug, Clone)]
pub struct OidcSettings {
    /// The issuer exactly as the provider names itself in ID tokens. The
    /// deployment checks its scheme; this adapter takes it as given.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretString,
    /// The dashboard's callback URL registered at the provider.
    pub redirect_url: String,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Authorities trusted in addition to the bundled roots.
    pub extra_roots: ExtraRoots,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcSetupError {
    #[error("the issuer URL is not a valid URL")]
    Issuer,
    #[error("the redirect URL is not a valid URL")]
    RedirectUrl,
    #[error(transparent)]
    Client(#[from] GatewayError),
    #[error("could not configure TLS for the provider")]
    Tls,
}

/// Why a request to the provider was not made or did not complete. The
/// message never holds a URL, header, or body.
#[derive(Debug, thiserror::Error)]
pub enum OidcHttpError {
    #[error("the request was not for the issuer's origin")]
    OffOrigin,
    #[error("the request could not be built")]
    Build,
    #[error("the provider could not be reached: {0:?}")]
    Unreachable(UnreachableReason),
    #[error("the provider's answer is larger than {MAX_OIDC_BODY_BYTES} bytes")]
    TooLarge,
}

/// The only HTTP client the provider protocol gets.
pub struct OidcHttp {
    client: Client,
    origin: url::Origin,
    policy: TargetPolicy,
}

impl OidcHttp {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, OidcHttpError> {
        let url =
            reqwest::Url::parse(&request.uri().to_string()).map_err(|_| OidcHttpError::Build)?;
        if url.origin() != self.origin {
            return Err(OidcHttpError::OffOrigin);
        }
        if refused_literal(&url, self.policy) {
            return Err(OidcHttpError::Unreachable(
                UnreachableReason::DestinationNotAllowed,
            ));
        }
        let request = reqwest::Request::try_from(request).map_err(|_| OidcHttpError::Build)?;
        let mut response = self
            .client
            .execute(request)
            .await
            .map_err(|err| OidcHttpError::Unreachable(classify(&err)))?;
        let mut answer = http::Response::builder().status(response.status());
        if let Some(content_type) = response.headers().get(http::header::CONTENT_TYPE) {
            answer = answer.header(http::header::CONTENT_TYPE, content_type);
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > MAX_OIDC_BODY_BYTES {
                        return Err(OidcHttpError::TooLarge);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(err) => return Err(OidcHttpError::Unreachable(classify(&err))),
            }
        }
        answer.body(body).map_err(|_| OidcHttpError::Build)
    }
}

impl<'c> AsyncHttpClient<'c> for OidcHttp {
    type Error = OidcHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, OidcHttpError>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(self.send(request))
    }
}

/// The provider adapter.
pub struct OidcClient {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: SecretString,
    redirect_url: RedirectUrl,
    http: OidcHttp,
}

impl OidcClient {
    pub fn new(settings: OidcSettings) -> Result<Self, OidcSetupError> {
        let issuer_url = url::Url::parse(&settings.issuer).map_err(|_| OidcSetupError::Issuer)?;
        if issuer_url.cannot_be_a_base() || !matches!(issuer_url.scheme(), "https" | "http") {
            return Err(OidcSetupError::Issuer);
        }
        let issuer = IssuerUrl::new(settings.issuer.clone()).map_err(|_| OidcSetupError::Issuer)?;
        let redirect_url = RedirectUrl::new(settings.redirect_url.clone())
            .map_err(|_| OidcSetupError::RedirectUrl)?;
        // The issuer is enrolled by the deployment, so it may be on
        // loopback (a provider on the same host). Nothing else changes.
        let policy = TargetPolicy {
            allow_loopback: true,
        };
        let connect_timeout = settings.connect_timeout;
        let request_timeout = settings.request_timeout;
        let clients = Clients::new(settings.extra_roots, move |config| {
            Client::builder()
                .tls_backend_preconfigured(config)
                .dns_resolver(PolicyResolver { policy })
                .redirect(redirect::Policy::none())
                .no_proxy()
                .connect_timeout(connect_timeout)
                .timeout(request_timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
                .build()
        })?;
        let client = clients.get(None).map_err(|_| OidcSetupError::Tls)?;
        Ok(Self {
            issuer,
            client_id: ClientId::new(settings.client_id),
            client_secret: settings.client_secret,
            redirect_url,
            http: OidcHttp {
                client,
                origin: issuer_url.origin(),
                policy,
            },
        })
    }

    /// The adapter as the application's [`OidcProvider`].
    pub fn shared(settings: OidcSettings) -> Result<Arc<dyn OidcProvider>, OidcSetupError> {
        Ok(Arc::new(Self::new(settings)?))
    }

    /// Discovery and the provider's keys, fetched fresh for each step so
    /// rotated keys are picked up.
    async fn discover(&self) -> Result<CoreProviderMetadata, OidcProviderError> {
        let metadata = CoreProviderMetadata::discover_async(self.issuer.clone(), &self.http)
            .await
            .map_err(|err| {
                OidcProviderError::Unavailable(match err {
                    openidconnect::DiscoveryError::Request(err) => format!("discovery: {err}"),
                    openidconnect::DiscoveryError::Response(status, ..) => {
                        format!("discovery answered HTTP {}", status.as_u16())
                    }
                    openidconnect::DiscoveryError::Validation(_) => {
                        "the discovery document does not name the configured issuer".to_owned()
                    }
                    _ => "the discovery document or key set could not be read".to_owned(),
                })
            })?;
        let token_on_origin = metadata
            .token_endpoint()
            .is_some_and(|url| url.url().origin() == self.http.origin);
        if !token_on_origin || metadata.jwks_uri().url().origin() != self.http.origin {
            return Err(OidcProviderError::Unavailable(
                "the token endpoint or key set is not on the issuer's origin".to_owned(),
            ));
        }
        Ok(metadata)
    }

    fn client(
        &self,
        metadata: CoreProviderMetadata,
    ) -> openidconnect::core::CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    > {
        CoreClient::from_provider_metadata(
            metadata,
            self.client_id.clone(),
            Some(ClientSecret::new(
                self.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(self.redirect_url.clone())
    }

    pub async fn authorize(&self) -> Result<OidcAuthorization, OidcProviderError> {
        let client = self.client(self.discover().await?);
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in SCOPES {
            request = request.add_scope(Scope::new(scope.to_owned()));
        }
        let (url, state, nonce) = request.set_pkce_challenge(challenge).url();
        Ok(OidcAuthorization {
            url: url.into(),
            state: state.secret().clone(),
            pending: OidcPending {
                pkce_verifier: SecretString::from(verifier.into_secret()),
                nonce: SecretString::from(nonce.secret().clone()),
            },
        })
    }

    pub async fn exchange(
        &self,
        code: &str,
        pending: &OidcPending,
    ) -> Result<OidcIdentityClaims, OidcProviderError> {
        let client = self.client(self.discover().await?);
        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| {
                OidcProviderError::Unavailable("the provider names no token endpoint".to_owned())
            })?
            .set_pkce_verifier(PkceCodeVerifier::new(
                pending.pkce_verifier.expose_secret().to_owned(),
            ))
            .request_async(&self.http)
            .await
            .map_err(|err| match err {
                openidconnect::RequestTokenError::ServerResponse(answer) => {
                    OidcProviderError::Rejected(format!(
                        "the token endpoint refused the code: {}",
                        answer.error().as_ref()
                    ))
                }
                openidconnect::RequestTokenError::Request(err) => {
                    OidcProviderError::Unavailable(format!("token request: {err}"))
                }
                _ => OidcProviderError::Unavailable(
                    "the token endpoint's answer could not be read".to_owned(),
                ),
            })?;
        let id_token = response.id_token().ok_or_else(|| {
            OidcProviderError::Rejected("the token response has no ID token".to_owned())
        })?;
        let verifier = client.id_token_verifier().set_allowed_algs(ALLOWED_ALGS);
        let nonce = Nonce::new(pending.nonce.expose_secret().to_owned());
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|err| OidcProviderError::Rejected(claims_error(&err).to_owned()))?;
        let label = claims
            .email()
            .map(|email| email.as_str().to_owned())
            .or_else(|| {
                claims
                    .preferred_username()
                    .map(|name| name.as_str().to_owned())
            });
        Ok(OidcIdentityClaims {
            subject: claims.subject().as_str().to_owned(),
            label,
        })
    }
}

/// A fixed description of a failed ID token check. The library's messages
/// can quote claim values, which do not belong in the log.
fn claims_error(err: &openidconnect::ClaimsVerificationError) -> &'static str {
    use openidconnect::{ClaimsVerificationError as E, SignatureVerificationError as S};
    match err {
        E::Expired(_) => "the ID token has expired",
        E::InvalidAudience(_) => "the ID token is for another client",
        E::InvalidIssuer(_) => "the ID token names another issuer",
        E::InvalidNonce(_) => "the ID token's nonce does not match",
        E::InvalidSubject(_) => "the ID token's subject is invalid",
        E::SignatureVerification(S::DisallowedAlg(_)) => {
            "the ID token is signed with an algorithm that is not accepted"
        }
        E::SignatureVerification(S::NoMatchingKey) => {
            "no key of the provider matches the ID token's signature"
        }
        E::SignatureVerification(_) => "the ID token's signature is not valid",
        _ => "the ID token failed verification",
    }
}

impl OidcProvider for OidcClient {
    fn issuer(&self) -> &str {
        self.issuer.as_str()
    }

    fn authorize(&self) -> AuthorizeFuture<'_> {
        Box::pin(OidcClient::authorize(self))
    }

    fn exchange<'a>(&'a self, code: &'a str, pending: &'a OidcPending) -> ExchangeFuture<'a> {
        Box::pin(OidcClient::exchange(self, code, pending))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};

    use super::*;

    fn settings(issuer: &str) -> OidcSettings {
        OidcSettings {
            issuer: issuer.to_owned(),
            client_id: "client".to_owned(),
            client_secret: SecretString::from("secret"),
            redirect_url: "https://dash.example.test/auth/oidc/callback".to_owned(),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
            extra_roots: ExtraRoots::default(),
        }
    }

    fn request(url: &str) -> HttpRequest {
        http::Request::get(url).body(Vec::new()).unwrap()
    }

    /// Serves the router `make` builds for its own origin, on loopback.
    async fn serve(make: impl FnOnce(String) -> Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = make(origin.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        origin
    }

    fn metadata(issuer: &str, token_origin: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{token_origin}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        })
    }

    #[tokio::test]
    async fn requests_leave_only_for_the_issuer_origin() {
        let client = OidcClient::new(settings("http://127.0.0.1:9/realms/test")).unwrap();
        for url in [
            "http://evil.example.test/token",
            "https://127.0.0.1:9/token",
            "http://127.0.0.1:10/token",
        ] {
            assert!(
                matches!(
                    client.http.send(request(url)).await,
                    Err(OidcHttpError::OffOrigin)
                ),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn metadata_addresses_are_refused_even_as_the_issuer() {
        for issuer in ["http://169.254.169.254", "http://[fd00:ec2::254]"] {
            let client = OidcClient::new(settings(issuer)).unwrap();
            let url = format!("{issuer}/.well-known/openid-configuration");
            assert!(
                matches!(
                    client.http.send(request(&url)).await,
                    Err(OidcHttpError::Unreachable(
                        UnreachableReason::DestinationNotAllowed
                    ))
                ),
                "{issuer}"
            );
            assert!(matches!(
                client.authorize().await,
                Err(OidcProviderError::Unavailable(_))
            ));
        }
    }

    #[tokio::test]
    async fn discovery_must_keep_the_token_endpoint_on_the_issuer_origin() {
        let issuer =
            serve(|origin| {
                Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(move || async move { Json(metadata(&origin, "https://elsewhere.test")) }),
                )
                .route("/jwks", get(|| async { Json(serde_json::json!({ "keys": [] })) }))
            })
            .await;
        let client = OidcClient::new(settings(&issuer)).unwrap();
        let Err(OidcProviderError::Unavailable(reason)) = client.authorize().await else {
            panic!("an off-origin token endpoint was accepted");
        };
        assert!(reason.contains("origin"), "{reason}");
    }

    #[tokio::test]
    async fn discovery_names_the_issuer_and_starts_a_pkce_flow() {
        let issuer = serve(|origin| {
            Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(move || async move { Json(metadata(&origin, &origin)) }),
                )
                .route(
                    "/jwks",
                    get(|| async { Json(serde_json::json!({ "keys": [] })) }),
                )
        })
        .await;
        let client = OidcClient::new(settings(&issuer)).unwrap();
        let authorization = client.authorize().await.unwrap();
        let url = url::Url::parse(&authorization.url).unwrap();
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(param("scope").as_deref(), Some("openid email profile"));
        assert_eq!(
            param("state").as_deref(),
            Some(authorization.state.as_str())
        );
        assert_eq!(
            param("nonce").as_deref(),
            Some(authorization.pending.nonce.expose_secret())
        );
        assert!(param("code_challenge").is_some());

        // Another issuer in the document is refused.
        let wrong = serve(|origin| {
            Router::new().route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    Json(metadata("https://other-issuer.example.test", &origin))
                }),
            )
        })
        .await;
        let client = OidcClient::new(settings(&wrong)).unwrap();
        assert!(matches!(
            client.authorize().await,
            Err(OidcProviderError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn redirects_are_not_followed_and_bodies_are_bounded() {
        let followed = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&followed);
        let issuer = serve(move |origin| {
            let target = format!("{origin}/elsewhere");
            Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(move || async move {
                        (StatusCode::FOUND, [(http::header::LOCATION, target)]).into_response()
                    }),
                )
                .route(
                    "/elsewhere",
                    get(move || async move {
                        hits.fetch_add(1, Ordering::Relaxed);
                        StatusCode::OK
                    }),
                )
                .route(
                    "/large",
                    get(|| async { "x".repeat(MAX_OIDC_BODY_BYTES + 1) }),
                )
        })
        .await;
        let client = OidcClient::new(settings(&issuer)).unwrap();
        let Err(OidcProviderError::Unavailable(reason)) = client.authorize().await else {
            panic!("a redirected discovery was accepted");
        };
        assert!(reason.contains("302"), "{reason}");
        assert_eq!(followed.load(Ordering::Relaxed), 0);
        assert!(matches!(
            client.http.send(request(&format!("{issuer}/large"))).await,
            Err(OidcHttpError::TooLarge)
        ));
    }
}
