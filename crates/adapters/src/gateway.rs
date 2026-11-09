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
    header::{ACCEPT, HeaderMap, HeaderValue},
    redirect,
};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::connections::{ProbeFuture, StackProbe};
use supabase_dashboard_domain::{
    connection::{ServiceCheck, ServiceStatus, StackService, UnreachableReason, sanitize_version},
    project::ProjectUrl,
};
use tokio::time::Instant;

use crate::net::{DestinationNotAllowed, NameNotResolved, PolicyResolver, TargetPolicy, chain_has};

/// Largest response body read from a health endpoint.
const MAX_HEALTH_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct GatewaySettings {
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            policy: TargetPolicy::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
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
    client: Client,
    policy: TargetPolicy,
}

impl GatewayProbe {
    pub fn new(settings: GatewaySettings) -> Result<Self, GatewayError> {
        let client = Client::builder()
            .tls_backend_preconfigured(tls_config()?)
            .dns_resolver(PolicyResolver {
                policy: settings.policy,
            })
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(GatewayError::Client)?;
        Ok(Self {
            client,
            policy: settings.policy,
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
    ) -> ServiceCheck {
        let unreachable = |reason| ServiceCheck {
            service,
            status: ServiceStatus::Unreachable { reason },
            version: None,
            latency_ms: None,
        };
        let Ok(url) = reqwest::Url::parse(&format!("{}{}", api_url.as_str(), path(service))) else {
            return unreachable(UnreachableReason::InvalidResponse);
        };
        // The resolver only sees host names; address literals are checked
        // here, before anything is sent.
        let literal = match url.host() {
            Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
            _ => None,
        };
        if literal.is_some_and(|ip| !self.policy.allows(ip)) {
            return unreachable(UnreachableReason::DestinationNotAllowed);
        }
        let mut headers = HeaderMap::new();
        let Ok(mut apikey) = HeaderValue::from_str(key.expose_secret()) else {
            // Stored keys are validated as printable ASCII, so this means
            // the stored value is not a usable key.
            return unreachable(UnreachableReason::InvalidResponse);
        };
        apikey.set_sensitive(true);
        headers.insert("apikey", apikey);
        headers.insert(ACCEPT, HeaderValue::from_static(accept(service)));

        let started = Instant::now();
        let response = match self.client.get(url).headers(headers).send().await {
            Ok(response) => response,
            Err(err) => return unreachable(classify(&err)),
        };
        let latency_ms = u32::try_from(started.elapsed().as_millis()).ok();
        let status = response.status();
        let (status, version) = if status.is_success() {
            match service {
                StackService::Auth => match read_bounded(response).await {
                    Ok(body) => (ServiceStatus::Healthy, auth_version(&body)),
                    Err(reason) => (ServiceStatus::Unreachable { reason }, None),
                },
                // The REST root is the OpenAPI description, which can be
                // large. The status is enough; the body is not read.
                StackService::Rest => (ServiceStatus::Healthy, None),
            }
        } else {
            (status_failure(status), None)
        };
        ServiceCheck {
            service,
            status,
            version,
            latency_ms,
        }
    }
}

impl StackProbe for GatewayProbe {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
    ) -> ProbeFuture<'a> {
        Box::pin(self.check_service(api_url, service, key))
    }
}

const fn path(service: StackService) -> &'static str {
    match service {
        StackService::Auth => "/auth/v1/health",
        StackService::Rest => "/rest/v1/",
    }
}

const fn accept(service: StackService) -> &'static str {
    match service {
        StackService::Auth => "application/json",
        StackService::Rest => "application/openapi+json",
    }
}

fn status_failure(status: StatusCode) -> ServiceStatus {
    let http_status = status.as_u16();
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        ServiceStatus::KeyRejected { http_status }
    } else {
        ServiceStatus::Unhealthy { http_status }
    }
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

/// rustls with the ring provider (the one SQLx already uses) and the
/// Mozilla root store from `webpki-roots`. Stacks behind a private CA are
/// not supported yet.
fn tls_config() -> Result<rustls::ClientConfig, GatewayError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(GatewayError::Tls)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(config)
}

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
    fn auth_version_is_read_when_present() {
        assert_eq!(
            auth_version(br#"{"version":"v2.197.0","name":"GoTrue"}"#),
            Some("v2.197.0".into())
        );
        assert_eq!(auth_version(br#"{"name":"GoTrue"}"#), None);
        assert_eq!(auth_version(b"not json"), None);
        assert_eq!(auth_version(br#"{"version":"v1\u0000"}"#), None);
    }
}
