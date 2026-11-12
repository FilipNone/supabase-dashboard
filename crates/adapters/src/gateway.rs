//! Service checks through a stack's API gateway (Kong or Envoy in the
//! standard self-hosted setup).
//!
//! Requests go only to paths built here under the registered API URL. The
//! key travels in the `apikey` header, marked sensitive, and never in the
//! URL. Redirects are not followed, proxies from the environment are
//! ignored (they would bypass the address checks), and every request has a
//! connect timeout, a total timeout, and a bound on the body it reads.

use std::{sync::Arc, time::Duration};

use reqwest::{
    Client, Response, StatusCode,
    header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, SERVER, WWW_AUTHENTICATE},
    redirect,
};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::connections::{ProbeFuture, StackProbe};
use supabase_dashboard_domain::{
    authority::{AuthorityError, AuthorityInfo, ProjectAuthorities},
    connection::{
        ServiceCheck, ServiceStatus, StackService, UnreachableReason, sanitize_version,
        split_studio_login,
    },
    project::ProjectUrl,
};
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::{
    net::{DestinationNotAllowed, NameNotResolved, PolicyResolver, TargetPolicy, chain_has},
    tls::{self, Clients, ExtraRoots},
};

/// Largest response body read from a health endpoint.
const MAX_HEALTH_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct GatewaySettings {
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Authorities trusted in addition to the bundled roots.
    pub extra_roots: ExtraRoots,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            policy: TargetPolicy::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            extra_roots: ExtraRoots::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("could not build the HTTP client: {0}")]
    Client(#[source] reqwest::Error),
    #[error("could not configure TLS: {0}")]
    Tls(#[source] rustls::Error),
}

/// Checks services behind a stack's API gateway.
#[derive(Clone)]
pub struct GatewayProbe {
    clients: Arc<Clients>,
    policy: TargetPolicy,
}

impl GatewayProbe {
    pub fn new(settings: GatewaySettings) -> Result<Self, GatewayError> {
        let policy = settings.policy;
        let clients = Clients::new(settings.extra_roots, move |config| {
            Client::builder()
                .tls_backend_preconfigured(config)
                .dns_resolver(PolicyResolver { policy })
                .redirect(redirect::Policy::none())
                // Gives each response the server's certificate, for its expiry.
                .tls_info(true)
                .no_proxy()
                .connect_timeout(settings.connect_timeout)
                .timeout(settings.request_timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
                .build()
        })?;
        Ok(Self {
            clients: Arc::new(clients),
            policy,
        })
    }

    pub fn shared(settings: GatewaySettings) -> Result<Arc<dyn StackProbe>, GatewayError> {
        Ok(Arc::new(Self::new(settings)?))
    }

    async fn check_service(
        &self,
        api_url: &ProjectUrl,
        service: StackService,
        key: &SecretString,
        authorities: Option<&ProjectAuthorities>,
    ) -> ServiceCheck {
        let unreachable = |reason| ServiceCheck {
            service,
            status: ServiceStatus::Unreachable { reason },
            version: None,
            latency_ms: None,
            certificate_expires_at: None,
        };
        let Ok(url) = reqwest::Url::parse(&format!("{}{}", api_url.as_str(), path(service))) else {
            return unreachable(UnreachableReason::InvalidResponse);
        };
        if refused_literal(&url, self.policy) {
            return unreachable(UnreachableReason::DestinationNotAllowed);
        }
        // A stored bundle that no longer parses trusts nothing extra, so
        // the connection fails as a TLS problem rather than half-trusted.
        let Ok(client) = self.clients.get(authorities) else {
            return unreachable(UnreachableReason::Tls);
        };
        if service == StackService::Studio {
            return check_studio(&client, url, key).await;
        }
        let mut headers = HeaderMap::new();
        let Ok(mut apikey) = HeaderValue::from_str(key.expose_secret()) else {
            // Stored keys are validated as printable ASCII, so this means
            // the stored value is not a usable key.
            return unreachable(UnreachableReason::InvalidResponse);
        };
        apikey.set_sensitive(true);
        if service == StackService::Functions {
            // The functions router reads the JWT from `Authorization` only.
            let Ok(mut bearer) = HeaderValue::from_str(&format!("Bearer {}", key.expose_secret()))
            else {
                return unreachable(UnreachableReason::InvalidResponse);
            };
            bearer.set_sensitive(true);
            headers.insert(AUTHORIZATION, bearer);
        }
        headers.insert("apikey", apikey);
        headers.insert(ACCEPT, HeaderValue::from_static(accept(service)));

        let started = Instant::now();
        let response = match client.get(url).headers(headers).send().await {
            Ok(response) => response,
            Err(err) => return unreachable(classify(&err)),
        };
        let latency_ms = u32::try_from(started.elapsed().as_millis()).ok();
        let certificate_expires_at = certificate_expiry(&response);
        let status = response.status();
        if service == StackService::Functions {
            return ServiceCheck {
                service,
                status: functions_status(response).await,
                version: None,
                latency_ms,
                certificate_expires_at,
            };
        }
        let (status, version) = if status.is_success() {
            match service {
                StackService::Auth => match read_bounded(response).await {
                    Ok(body) => (ServiceStatus::Healthy, auth_version(&body)),
                    Err(reason) => (ServiceStatus::Unreachable { reason }, None),
                },
                StackService::Storage => match read_bounded(response).await {
                    Ok(body) => (ServiceStatus::Healthy, storage_version(&body)),
                    Err(reason) => (ServiceStatus::Unreachable { reason }, None),
                },
                // The REST root is the OpenAPI description, which can be
                // large, so its version comes from the `Server` header
                // instead. Realtime's ping says only "Success". The body is
                // not read.
                StackService::Rest => (
                    ServiceStatus::Healthy,
                    rest_version(response.headers().get(SERVER)),
                ),
                StackService::Realtime | StackService::Functions | StackService::Studio => {
                    (ServiceStatus::Healthy, None)
                }
            }
        } else {
            (failure(&response), None)
        };
        ServiceCheck {
            service,
            status,
            version,
            latency_ms,
            certificate_expires_at,
        }
    }
}

/// Studio's route must refuse a request without the login and accept
/// one with it. Studio answers `/` with a redirect to its project page,
/// so a redirect counts as success; it is not followed.
async fn check_studio(client: &Client, url: reqwest::Url, login: &SecretString) -> ServiceCheck {
    let service = StackService::Studio;
    let done = |status, latency_ms, certificate_expires_at| ServiceCheck {
        service,
        status,
        version: None,
        latency_ms,
        certificate_expires_at,
    };
    let Some((username, password)) = split_studio_login(login.expose_secret()) else {
        return done(
            ServiceStatus::Unreachable {
                reason: UnreachableReason::InvalidResponse,
            },
            None,
            None,
        );
    };
    let open = match client.get(url.clone()).send().await {
        Ok(response) => response.status(),
        Err(err) => {
            return done(
                ServiceStatus::Unreachable {
                    reason: classify(&err),
                },
                None,
                None,
            );
        }
    };
    if open.is_success() || open.is_redirection() {
        return done(
            ServiceStatus::Unprotected {
                http_status: open.as_u16(),
            },
            None,
            None,
        );
    }
    let started = Instant::now();
    let response = match client
        .get(url)
        .basic_auth(username, Some(password))
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return done(
                ServiceStatus::Unreachable {
                    reason: classify(&err),
                },
                None,
                None,
            );
        }
    };
    let latency_ms = u32::try_from(started.elapsed().as_millis()).ok();
    let expires_at = certificate_expiry(&response);
    let status = response.status();
    if status.is_success() || status.is_redirection() {
        done(ServiceStatus::Healthy, latency_ms, expires_at)
    } else {
        done(status_failure(status), latency_ms, expires_at)
    }
}

impl StackProbe for GatewayProbe {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
        authorities: Option<&'a ProjectAuthorities>,
    ) -> ProbeFuture<'a> {
        Box::pin(self.check_service(api_url, service, key, authorities))
    }

    fn read_authorities(&self, pem: &str) -> Result<Vec<AuthorityInfo>, AuthorityError> {
        tls::read_authorities(pem).map(|(_, infos)| infos)
    }
}

/// Whether `url` names an IP address the policy refuses. The resolver only
/// sees host names, so address literals are checked before anything is
/// sent.
pub(crate) fn refused_literal(url: &reqwest::Url, policy: TargetPolicy) -> bool {
    let literal = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
        _ => None,
    };
    literal.is_some_and(|ip| !policy.allows(ip))
}

const fn path(service: StackService) -> &'static str {
    match service {
        StackService::Auth => "/auth/v1/health",
        StackService::Rest => "/rest/v1/",
        StackService::Storage => "/storage/v1/version",
        StackService::Realtime => "/realtime/v1/api/ping",
        StackService::Functions => "/functions/v1/",
        StackService::Studio => "/",
    }
}

const fn accept(service: StackService) -> &'static str {
    match service {
        StackService::Auth => "application/json",
        StackService::Rest => "application/openapi+json",
        StackService::Storage => "text/plain",
        StackService::Realtime | StackService::Functions => "application/json",
        StackService::Studio => "text/html",
    }
}

/// A failed service response. A 401 with a basic-auth challenge comes from
/// the gateway's Studio route, which upstream's Kong and Envoy setups use
/// for every path without another route; the services themselves and
/// Kong's key check never ask for basic auth.
fn failure(response: &Response) -> ServiceStatus {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED && asks_for_basic_auth(response.headers()) {
        return ServiceStatus::NotRouted {
            http_status: status.as_u16(),
        };
    }
    status_failure(status)
}

fn asks_for_basic_auth(headers: &HeaderMap) -> bool {
    headers.get_all(WWW_AUTHENTICATE).iter().any(|value| {
        value
            .as_bytes()
            .get(..6)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"basic "))
            || value.as_bytes().eq_ignore_ascii_case(b"basic")
    })
}

fn status_failure(status: StatusCode) -> ServiceStatus {
    let http_status = status.as_u16();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        ServiceStatus::KeyRejected { http_status }
    } else {
        ServiceStatus::Unhealthy { http_status }
    }
}

/// The expiry of the leaf certificate the gateway presented, from the TLS
/// details reqwest attaches to each response. Only the validity period is
/// read; trust was already decided by the handshake.
fn certificate_expiry(response: &Response) -> Option<OffsetDateTime> {
    let der = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()?
        .peer_certificate()?;
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(certificate.validity().not_after.to_datetime())
}

/// The Edge Functions router answers a request without a function name
/// with a 404 and `sb-error-code: NOT_FOUND`; routers from before 2025
/// answered it with a 400 and `{"msg": "missing function name in
/// request"}`. Either means the router runs and accepted the key. A 404
/// without the header comes from the gateway, which has no route for
/// functions.
async fn functions_status(response: Response) -> ServiceStatus {
    let status = response.status();
    if status.is_success() {
        return ServiceStatus::Healthy;
    }
    if status == StatusCode::NOT_FOUND {
        let routed = response
            .headers()
            .get("sb-error-code")
            .is_some_and(|code| code.as_bytes() == b"NOT_FOUND");
        return if routed {
            ServiceStatus::Healthy
        } else {
            failure(&response)
        };
    }
    if status == StatusCode::BAD_REQUEST {
        return match read_bounded(response).await {
            Ok(body) if missing_function_name(&body) => ServiceStatus::Healthy,
            Ok(_) => status_failure(status),
            Err(reason) => ServiceStatus::Unreachable { reason },
        };
    }
    failure(&response)
}

fn missing_function_name(body: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Refusal {
        msg: Option<String>,
    }
    serde_json::from_slice::<Refusal>(body)
        .ok()
        .and_then(|r| r.msg)
        .is_some_and(|msg| msg == "missing function name in request")
}

/// Maps a request error to a fixed reason. The error itself may name
/// addresses, so it is logged at debug level only and never returned.
fn classify(err: &reqwest::Error) -> UnreachableReason {
    tracing::debug!(error = %err, "service check request failed");
    if chain_has::<DestinationNotAllowed>(err) {
        UnreachableReason::DestinationNotAllowed
    } else if chain_has::<NameNotResolved>(err) {
        UnreachableReason::Dns
    } else if err.is_timeout() {
        UnreachableReason::Timeout
    } else if chain_has::<rustls::Error>(err) {
        UnreachableReason::Tls
    } else if err.is_connect() {
        UnreachableReason::Connect
    } else {
        UnreachableReason::InvalidResponse
    }
}

async fn read_bounded(mut response: Response) -> Result<Vec<u8>, UnreachableReason> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_HEALTH_BODY_BYTES {
                    return Err(UnreachableReason::InvalidResponse);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(err) => return Err(classify(&err)),
        }
    }
}

/// GoTrue's health endpoint answers `{"version": "...", "name": "GoTrue",
/// ...}`. A body without a usable version still counts as healthy.
fn auth_version(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Health {
        version: Option<String>,
    }
    serde_json::from_slice::<Health>(body)
        .ok()
        .and_then(|h| h.version)
        .and_then(|v| sanitize_version(&v))
}

/// PostgREST names itself in the `Server` header, such as
/// `postgrest/14.18`. Kong passes the header through; a gateway that
/// replaces it with its own name leaves the version unknown.
fn rest_version(server: Option<&HeaderValue>) -> Option<String> {
    let server = server?.to_str().ok()?;
    let (name, version) = server.split_once('/')?;
    name.trim()
        .eq_ignore_ascii_case("postgrest")
        .then(|| sanitize_version(version))
        .flatten()
}

/// Storage's version path answers with the bare version, such as
/// `1.89.12`. Anything longer or unprintable is dropped.
fn storage_version(body: &[u8]) -> Option<String> {
    std::str::from_utf8(body).ok().and_then(sanitize_version)
}

/// rustls with the ring provider (the one SQLx already uses) and the
/// Mozilla root store from `webpki-roots`. Stacks behind a private CA are
/// not supported yet.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_mapped() {
        assert_eq!(
            status_failure(StatusCode::UNAUTHORIZED),
            ServiceStatus::KeyRejected { http_status: 401 }
        );
        assert_eq!(
            status_failure(StatusCode::FORBIDDEN),
            ServiceStatus::KeyRejected { http_status: 403 }
        );
        assert_eq!(
            status_failure(StatusCode::FOUND),
            ServiceStatus::Unhealthy { http_status: 302 }
        );
        assert_eq!(
            status_failure(StatusCode::BAD_GATEWAY),
            ServiceStatus::Unhealthy { http_status: 502 }
        );
    }

    #[test]
    fn basic_auth_challenges_are_told_from_key_checks() {
        let challenge = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(WWW_AUTHENTICATE, HeaderValue::from_str(value).unwrap());
            }
            asks_for_basic_auth(&headers)
        };
        assert!(challenge(&[r#"Basic realm="service""#]));
        assert!(challenge(&["basic"]));
        assert!(challenge(&["Key", r#"BASIC realm="x""#]));
        assert!(!challenge(&["Key"]));
        assert!(!challenge(&[r#"Bearer realm="x""#]));
        assert!(!challenge(&["Basicish"]));
        assert!(!challenge(&[]));
    }

    #[test]
    fn auth_version_is_read_when_present() {
        assert_eq!(
            auth_version(br#"{"version":"v2.197.0","name":"GoTrue"}"#),
            Some("v2.197.0".into())
        );
        assert_eq!(auth_version(br#"{"name":"GoTrue"}"#), None);
        assert_eq!(auth_version(b"not json"), None);
        assert_eq!(auth_version(br#"{"version":"v1\u0000"}"#), None);
    }

    #[test]
    fn rest_version_is_read_from_the_server_header() {
        let read = |raw: &str| rest_version(Some(&HeaderValue::from_str(raw).unwrap()));
        assert_eq!(read("postgrest/14.18"), Some("14.18".into()));
        assert_eq!(read("PostgREST/12.2.3"), Some("12.2.3".into()));
        assert_eq!(read("envoy"), None);
        assert_eq!(read("kong/3.9.3"), None);
        assert_eq!(read("postgrest/"), None);
        assert_eq!(read(&format!("postgrest/{}", "1".repeat(100))), None);
        assert_eq!(rest_version(None), None);
    }

    #[test]
    fn the_old_functions_router_refusal_is_recognized() {
        assert!(missing_function_name(
            br#"{"msg":"missing function name in request"}"#
        ));
        assert!(!missing_function_name(br#"{"msg":"Invalid JWT"}"#));
        assert!(!missing_function_name(b"missing function name in request"));
    }

    #[test]
    fn storage_version_is_the_body() {
        assert_eq!(storage_version(b"1.89.12"), Some("1.89.12".into()));
        assert_eq!(storage_version(b"1.89.12\n"), Some("1.89.12".into()));
        assert_eq!(storage_version(b""), None);
        assert_eq!(storage_version(&[0xff, 0xfe]), None);
        assert_eq!(storage_version("v".repeat(100).as_bytes()), None);
    }
}
