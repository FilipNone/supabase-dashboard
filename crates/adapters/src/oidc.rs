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
//!
//! Back-channel logout tokens: `openidconnect` 4.1 verifies ID and user
//! info tokens but has no type for logout tokens, whose `sub` is optional
//! and which carry no `nonce`. They are checked here with the crate's key
//! set and its key types' own signature verification; no signature code is
//! written here. The claims are checked before any key is fetched, the key
//! set is cached for [`LOGOUT_KEYS_TTL`], and it is fetched again at most
//! once per [`LOGOUT_KEYS_MIN_REFETCH`] (when no key matches), so a flood of
//! forged tokens cannot make the server call the provider for each one.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, IssuerUrl, JsonWebKey, JsonWebKeyAlgorithm, JsonWebKeyId, JsonWebKeyUse,
    JwsSigningAlgorithm, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreJsonWebKey, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
};
use reqwest::{Client, redirect};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use supabase_dashboard_application::auth::oidc::{
    AuthorizeFuture, ExchangeFuture, LOGOUT_TOKEN_CLOCK_SKEW, LOGOUT_TOKEN_MAX_AGE,
    LogoutTokenFuture, MAX_LOGOUT_TOKEN_LEN, OidcAuthorization, OidcIdentityClaims,
    OidcLogoutClaims, OidcPending, OidcProvider, OidcProviderError,
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

/// The event a back-channel logout token must carry.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// How long the provider's key set is reused for logout tokens.
pub const LOGOUT_KEYS_TTL: Duration = Duration::from_secs(300);

/// The key set is fetched for logout tokens at most this often, even when a
/// token names a key it does not have.
pub const LOGOUT_KEYS_MIN_REFETCH: Duration = Duration::from_secs(10);

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

/// The provider's key set as last fetched for logout tokens.
#[derive(Default)]
struct LogoutKeys {
    keys: Option<(Instant, CoreJsonWebKeySet)>,
    last_fetch: Option<Instant>,
}

/// The provider adapter.
pub struct OidcClient {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: SecretString,
    redirect_url: RedirectUrl,
    http: OidcHttp,
    /// Held across a fetch, so concurrent logouts wait for one fetch
    /// instead of each starting their own or failing.
    logout_keys: tokio::sync::Mutex<LogoutKeys>,
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
            logout_keys: tokio::sync::Mutex::new(LogoutKeys::default()),
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
            session_id: verified_sid(&id_token.to_string()),
        })
    }

    /// Verifies a back-channel logout token (OpenID Connect Back-Channel
    /// Logout 1.0, section 2.6).
    pub async fn verify_logout_token(
        &self,
        token: &str,
    ) -> Result<OidcLogoutClaims, OidcProviderError> {
        let parsed = LogoutToken::parse(token)?;
        let claims = parsed.check_claims(self.issuer.as_str(), &self.client_id, unix_now())?;
        let keys = self.logout_keys(false).await?;
        match parsed.verify_signature(&keys) {
            Err(KeyCheck::NoMatchingKey) => {
                // The provider may have rotated its keys.
                let keys = self.logout_keys(true).await?;
                parsed
                    .verify_signature(&keys)
                    .map_err(|err| OidcProviderError::Rejected(err.reason().to_owned()))?;
            }
            Err(err) => return Err(OidcProviderError::Rejected(err.reason().to_owned())),
            Ok(()) => {}
        }
        Ok(claims)
    }

    /// The key set for logout tokens: cached for [`LOGOUT_KEYS_TTL`], or
    /// fetched again when `refresh` and the last fetch is at least
    /// [`LOGOUT_KEYS_MIN_REFETCH`] old.
    async fn logout_keys(&self, refresh: bool) -> Result<CoreJsonWebKeySet, OidcProviderError> {
        let mut cache = self.logout_keys.lock().await;
        let now = Instant::now();
        let fresh = cache
            .keys
            .as_ref()
            .filter(|(fetched, _)| now.duration_since(*fetched) < LOGOUT_KEYS_TTL);
        if let (Some((_, keys)), false) = (fresh, refresh) {
            return Ok(keys.clone());
        }
        let recently = cache
            .last_fetch
            .is_some_and(|last| now.duration_since(last) < LOGOUT_KEYS_MIN_REFETCH);
        if recently {
            return match &cache.keys {
                Some((_, keys)) => Ok(keys.clone()),
                None => Err(OidcProviderError::Unavailable(
                    "the provider's key set was not available moments ago".to_owned(),
                )),
            };
        }
        cache.last_fetch = Some(now);
        let keys = self.discover().await?.jwks().clone();
        cache.keys = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The `sid` claim of an ID token whose signature and claims were already
/// verified. `None` when absent or not a string.
fn verified_sid(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sid")?.as_str().map(str::to_owned)
}

/// The JOSE header of a logout token.
#[derive(Deserialize)]
struct LogoutTokenHeader {
    alg: CoreJwsSigningAlgorithm,
    #[serde(default)]
    kid: Option<JsonWebKeyId>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    cty: Option<serde_json::Value>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audiences {
    One(String),
    Many(Vec<String>),
}

/// The claims of a logout token, unverified until the signature is.
#[derive(Deserialize)]
struct LogoutTokenClaims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<Audiences>,
    #[serde(default)]
    iat: Option<f64>,
    #[serde(default)]
    exp: Option<f64>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    events: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    nonce: Option<serde_json::Value>,
}

/// A logout token split into its parts. Nothing in it is trusted until
/// [`LogoutToken::verify_signature`] succeeds.
struct LogoutToken {
    header: LogoutTokenHeader,
    claims: LogoutTokenClaims,
    signing_input: Vec<u8>,
    signature: Vec<u8>,
}

fn rejected(reason: &str) -> OidcProviderError {
    OidcProviderError::Rejected(reason.to_owned())
}

#[derive(Debug, PartialEq, Eq)]
enum KeyCheck {
    NoMatchingKey,
    AmbiguousKey,
    BadSignature,
}

impl KeyCheck {
    fn reason(&self) -> &'static str {
        match self {
            Self::NoMatchingKey => "no key of the provider matches the logout token",
            Self::AmbiguousKey => "several keys of the provider match the logout token",
            Self::BadSignature => "the logout token's signature is not valid",
        }
    }
}

impl LogoutToken {
    /// Splits a compact JWS and reads its header and claims. Refuses
    /// encrypted or nested tokens, critical header parameters, other `typ`
    /// values than `JWT` or `logout+jwt`, and algorithms other than the
    /// asymmetric ones accepted for ID tokens.
    fn parse(token: &str) -> Result<Self, OidcProviderError> {
        if token.len() > MAX_LOGOUT_TOKEN_LEN {
            return Err(rejected("the logout token is too long"));
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(rejected("the logout token is not a signed JWT"));
        };
        let decode = |part: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| rejected("the logout token is not valid base64url"))
        };
        let parsed_header: LogoutTokenHeader = serde_json::from_slice(&decode(header)?)
            .map_err(|_| rejected("the logout token's header is not valid"))?;
        if parsed_header.cty.is_some() || parsed_header.crit.is_some() {
            return Err(rejected("the logout token's header is not supported"));
        }
        if let Some(typ) = &parsed_header.typ {
            let typ = typ.to_ascii_lowercase();
            let typ = typ.strip_prefix("application/").unwrap_or(&typ);
            if typ != "jwt" && typ != "logout+jwt" {
                return Err(rejected("the logout token's type is not supported"));
            }
        }
        if !ALLOWED_ALGS.contains(&parsed_header.alg) {
            return Err(rejected(
                "the logout token is signed with an algorithm that is not accepted",
            ));
        }
        let claims: LogoutTokenClaims = serde_json::from_slice(&decode(payload)?)
            .map_err(|_| rejected("the logout token's claims are not valid"))?;
        Ok(Self {
            header: parsed_header,
            claims,
            signing_input: format!("{header}.{payload}").into_bytes(),
            signature: decode(signature)?,
        })
    }

    /// Section 2.6, steps 3 to 6, at `now` (seconds since the epoch).
    fn check_claims(
        &self,
        issuer: &str,
        client_id: &ClientId,
        now: i64,
    ) -> Result<OidcLogoutClaims, OidcProviderError> {
        let claims = &self.claims;
        if claims.iss.as_deref() != Some(issuer) {
            return Err(rejected("the logout token names another issuer"));
        }
        let for_us = match &claims.aud {
            Some(Audiences::One(aud)) => aud == client_id.as_str(),
            // Every audience must be this client, as for ID tokens.
            Some(Audiences::Many(auds)) => {
                !auds.is_empty() && auds.iter().all(|aud| aud == client_id.as_str())
            }
            None => false,
        };
        if !for_us {
            return Err(rejected("the logout token is for another client"));
        }
        let max_age = i64::try_from(LOGOUT_TOKEN_MAX_AGE.as_secs()).unwrap_or(i64::MAX);
        let skew = i64::try_from(LOGOUT_TOKEN_CLOCK_SKEW.as_secs()).unwrap_or(i64::MAX);
        let Some(iat) = claims.iat.filter(|iat| iat.is_finite()) else {
            return Err(rejected("the logout token has no issue time"));
        };
        #[allow(clippy::cast_precision_loss)]
        let (earliest, latest) = (
            now.saturating_sub(max_age) as f64,
            now.saturating_add(skew) as f64,
        );
        if iat < earliest || iat > latest {
            return Err(rejected(
                "the logout token was issued too long ago or in the future",
            ));
        }
        if let Some(exp) = claims.exp {
            #[allow(clippy::cast_precision_loss)]
            let oldest = now.saturating_sub(skew) as f64;
            if !exp.is_finite() || exp < oldest {
                return Err(rejected("the logout token has expired"));
            }
        }
        let is_logout_event = claims
            .events
            .as_ref()
            .and_then(|events| events.get(BACKCHANNEL_LOGOUT_EVENT))
            .is_some_and(serde_json::Value::is_object);
        if !is_logout_event {
            return Err(rejected(
                "the logout token has no back-channel logout event",
            ));
        }
        if claims.nonce.is_some() {
            return Err(rejected("the logout token has a nonce"));
        }
        if claims.sub.is_none() && claims.sid.is_none() {
            return Err(rejected("the logout token names neither sub nor sid"));
        }
        let Some(jti) = claims.jti.as_ref().filter(|jti| !jti.is_empty()) else {
            return Err(rejected("the logout token has no jti"));
        };
        Ok(OidcLogoutClaims {
            subject: claims.sub.clone(),
            session_id: claims.sid.clone(),
            token_id: jti.clone(),
        })
    }

    /// Picks the one key of `keys` that fits the header (`kid` when given,
    /// signing use, key type, and algorithm), as the crate does for ID
    /// tokens, and lets it check the signature.
    fn verify_signature(&self, keys: &CoreJsonWebKeySet) -> Result<(), KeyCheck> {
        let alg = &self.header.alg;
        let mut candidates = keys.keys().iter().filter(|key: &&CoreJsonWebKey| {
            self.header
                .kid
                .as_ref()
                .is_none_or(|kid| key.key_id() == Some(kid))
                && key.key_use().is_none_or(JsonWebKeyUse::allows_signature)
                && alg.key_type().as_ref() == Some(key.key_type())
                && match key.signing_alg() {
                    JsonWebKeyAlgorithm::Unspecified => true,
                    JsonWebKeyAlgorithm::Algorithm(key_alg) => key_alg == alg,
                    JsonWebKeyAlgorithm::Unsupported => false,
                }
        });
        let key = match (candidates.next(), candidates.next()) {
            (Some(key), None) => key,
            (None, _) => return Err(KeyCheck::NoMatchingKey),
            (Some(_), Some(_)) => return Err(KeyCheck::AmbiguousKey),
        };
        key.verify_signature(alg, &self.signing_input, &self.signature)
            .map_err(|_| KeyCheck::BadSignature)
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

    fn verify_logout_token<'a>(&'a self, token: &'a str) -> LogoutTokenFuture<'a> {
        Box::pin(OidcClient::verify_logout_token(self, token))
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

    fn b64(value: &serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }

    fn unsigned(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        format!("{}.{}.c2ln", b64(header), b64(claims))
    }

    const NOW: i64 = 1_800_000_000;
    const ISSUER: &str = "https://idp.example.test/";

    fn logout_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": "client",
            "iat": NOW - 10,
            "jti": "token-1",
            "sub": "alice",
            "sid": "session-1",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        })
    }

    fn check(claims: &serde_json::Value) -> Result<OidcLogoutClaims, OidcProviderError> {
        let header = serde_json::json!({ "alg": "RS256", "typ": "logout+jwt" });
        LogoutToken::parse(&unsigned(&header, claims))?.check_claims(
            ISSUER,
            &ClientId::new("client".to_owned()),
            NOW,
        )
    }

    fn refused(claims: &serde_json::Value) -> String {
        match check(claims) {
            Err(OidcProviderError::Rejected(reason)) => reason,
            other => panic!(
                "accepted or failed otherwise: {:?}",
                other.map(|c| c.token_id)
            ),
        }
    }

    #[test]
    fn logout_token_claims_follow_the_specification() {
        let accepted = check(&logout_claims()).unwrap();
        assert_eq!(accepted.subject.as_deref(), Some("alice"));
        assert_eq!(accepted.session_id.as_deref(), Some("session-1"));
        assert_eq!(accepted.token_id, "token-1");

        let with = |name: &str, value: serde_json::Value| {
            let mut claims = logout_claims();
            claims[name] = value;
            claims
        };
        let without = |names: &[&str]| {
            let mut claims = logout_claims();
            for name in names {
                claims.as_object_mut().unwrap().remove(*name);
            }
            claims
        };
        // Either sub or sid is enough; an audience list of only this client
        // is accepted; an exp in the future is fine.
        assert!(check(&without(&["sub"])).is_ok());
        assert!(check(&without(&["sid"])).is_ok());
        assert!(check(&with("aud", serde_json::json!(["client"]))).is_ok());
        assert!(check(&with("exp", serde_json::json!(NOW + 60))).is_ok());
        assert!(check(&with("iat", serde_json::json!(NOW + 30))).is_ok());

        for (claims, reason) in [
            (
                with("iss", serde_json::json!("https://other.example.test/")),
                "another issuer",
            ),
            (without(&["iss"]), "another issuer"),
            (
                with("aud", serde_json::json!("other-client")),
                "another client",
            ),
            (
                with("aud", serde_json::json!(["client", "other-client"])),
                "another client",
            ),
            (without(&["aud"]), "another client"),
            (without(&["iat"]), "no issue time"),
            (with("iat", serde_json::json!(NOW - 301)), "too long ago"),
            (with("iat", serde_json::json!(NOW + 61)), "in the future"),
            (with("exp", serde_json::json!(NOW - 61)), "expired"),
            (without(&["events"]), "no back-channel logout event"),
            (
                with(
                    "events",
                    serde_json::json!({ "http://example.test/other": {} }),
                ),
                "no back-channel logout event",
            ),
            (
                with(
                    "events",
                    serde_json::json!({ BACKCHANNEL_LOGOUT_EVENT: "yes" }),
                ),
                "no back-channel logout event",
            ),
            (with("nonce", serde_json::json!("n-1")), "has a nonce"),
            (without(&["sub", "sid"]), "neither sub nor sid"),
            (without(&["jti"]), "no jti"),
            (with("jti", serde_json::json!("")), "no jti"),
            (with("sub", serde_json::json!(42)), "claims are not valid"),
        ] {
            let reason_given = refused(&claims);
            assert!(reason_given.contains(reason), "{reason_given} / {reason}");
        }
    }

    #[test]
    fn logout_token_headers_are_checked_before_anything_else() {
        let claims = logout_claims();
        let parse = |header: serde_json::Value| LogoutToken::parse(&unsigned(&header, &claims));
        assert!(parse(serde_json::json!({ "alg": "RS256" })).is_ok());
        assert!(parse(serde_json::json!({ "alg": "ES256", "typ": "JWT" })).is_ok());
        assert!(
            parse(serde_json::json!({ "alg": "RS256", "typ": "application/logout+jwt" })).is_ok()
        );
        for header in [
            serde_json::json!({ "alg": "none" }),
            serde_json::json!({ "alg": "HS256" }),
            serde_json::json!({ "alg": "RS257" }),
            serde_json::json!({}),
            serde_json::json!({ "alg": "RS256", "typ": "at+jwt" }),
            serde_json::json!({ "alg": "RS256", "cty": "JWT" }),
            serde_json::json!({ "alg": "RS256", "crit": ["exp"] }),
        ] {
            assert!(parse(header.clone()).is_err(), "{header}");
        }
        let header = b64(&serde_json::json!({ "alg": "RS256" }));
        let payload = b64(&claims);
        for token in [
            format!("{header}.{payload}"),
            format!("{header}.{payload}.c2ln.extra"),
            format!("{header}.{payload}.not base64"),
            format!("{header}.e30=.c2ln"),
            "x".repeat(MAX_LOGOUT_TOKEN_LEN + 1),
        ] {
            assert!(LogoutToken::parse(&token).is_err(), "{token}");
        }
    }

    #[test]
    fn logout_tokens_need_exactly_one_fitting_key() {
        let token = LogoutToken::parse(&unsigned(
            &serde_json::json!({ "alg": "RS256", "kid": "k1" }),
            &logout_claims(),
        ))
        .unwrap();
        let rsa = |kid: &str| {
            CoreJsonWebKey::new_rsa(
                vec![1; 256],
                vec![1, 0, 1],
                Some(JsonWebKeyId::new(kid.to_owned())),
            )
        };
        let set = |keys: Vec<CoreJsonWebKey>| CoreJsonWebKeySet::new(keys);
        assert_eq!(
            token.verify_signature(&set(vec![])),
            Err(KeyCheck::NoMatchingKey)
        );
        assert_eq!(
            token.verify_signature(&set(vec![rsa("k2")])),
            Err(KeyCheck::NoMatchingKey)
        );
        assert_eq!(
            token.verify_signature(&set(vec![rsa("k1"), rsa("k1")])),
            Err(KeyCheck::AmbiguousKey)
        );
        // The right key, but the signature is not its own.
        assert_eq!(
            token.verify_signature(&set(vec![rsa("k1"), rsa("k2")])),
            Err(KeyCheck::BadSignature)
        );
    }
}
