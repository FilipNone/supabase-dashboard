//! Forwarding a project's Studio traffic to its gateway
//! (docs/adr/0002-studio-access.md, "Forwarding").
//!
//! The destination is always the project's registered API URL; the browser
//! chooses only the path. The gateway's Studio login is added here, on the
//! server, and whatever `Authorization` the browser sent is dropped, as is
//! the dashboard's own Studio cookie. Bodies are streamed in both
//! directions, redirects are passed back to the browser instead of being
//! followed, and the connection goes through the same address policy as
//! the service checks.

use std::{error::Error as StdError, time::Duration};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode,
    header::{self, AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE},
};
use reqwest::{Client, redirect};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_domain::{connection::split_studio_login, project::ProjectUrl};

use crate::{
    gateway::{GatewayError, refused_literal, tls_config},
    net::{DestinationNotAllowed, NameNotResolved, PolicyResolver, TargetPolicy, chain_has},
};

/// The body of a response from Studio, streamed to the browser.
pub type UpstreamBody = reqwest::Body;

#[derive(Debug, Clone, Copy)]
pub struct StudioProxySettings {
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
    /// Longest wait for the next piece of a response. The total time is
    /// bounded by the caller, because Studio's SQL editor can run long.
    pub read_timeout: Duration,
}

impl Default for StudioProxySettings {
    fn default() -> Self {
        Self {
            policy: TargetPolicy::default(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(300),
        }
    }
}

/// Why a request could not be forwarded. None of these carry the upstream
/// address or the underlying error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    #[error("the gateway address is not allowed")]
    DestinationNotAllowed,
    #[error("the gateway host name did not resolve")]
    Dns,
    #[error("the gateway did not answer in time")]
    Timeout,
    #[error("TLS with the gateway failed")]
    Tls,
    #[error("could not connect to the gateway")]
    Connect,
    /// The stored login or the request path cannot be used.
    #[error("the request cannot be forwarded")]
    InvalidRequest,
    #[error("the gateway connection failed")]
    Upstream,
}

/// A request body for Studio, streamed from the browser.
pub struct ProxyBody(reqwest::Body);

impl ProxyBody {
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: futures_core::TryStream + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        Bytes: From<S::Ok>,
    {
        Self(reqwest::Body::wrap_stream(stream))
    }

    pub fn empty() -> Self {
        Self(reqwest::Body::from(Bytes::new()))
    }
}

/// One browser request on a Studio host.
pub struct ProxyRequest {
    pub method: Method,
    /// Path and query as the browser sent them; must start with `/`.
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: ProxyBody,
}

/// Facts about the Studio host the request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct StudioSite<'a> {
    /// `host[:port]` of the Studio host, sent as `X-Forwarded-Host`.
    pub host: &'a str,
    /// `https` or `http`, sent as `X-Forwarded-Proto`.
    pub proto: &'a str,
    /// The dashboard's Studio session cookie, which never reaches Studio.
    pub session_cookie: &'a str,
}

#[derive(Clone)]
pub struct StudioProxy {
    client: Client,
    policy: TargetPolicy,
}

impl StudioProxy {
    pub fn new(settings: StudioProxySettings) -> Result<Self, GatewayError> {
        let client = Client::builder()
            .tls_backend_preconfigured(tls_config()?)
            .dns_resolver(PolicyResolver {
                policy: settings.policy,
            })
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(settings.connect_timeout)
            .read_timeout(settings.read_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(GatewayError::Client)?;
        Ok(Self {
            client,
            policy: settings.policy,
        })
    }

    /// Sends `request` to the Studio route of the gateway at `api_url`,
    /// signed in with `login` (`username:password`).
    pub async fn forward(
        &self,
        api_url: &ProjectUrl,
        login: &SecretString,
        site: StudioSite<'_>,
        request: ProxyRequest,
    ) -> Result<Response<UpstreamBody>, ProxyError> {
        let base = reqwest::Url::parse(api_url.as_str()).map_err(|_| ProxyError::InvalidRequest)?;
        let url = upstream_url(&base, &request.path_and_query)?;
        if refused_literal(&url, self.policy) {
            return Err(ProxyError::DestinationNotAllowed);
        }
        let (username, password) =
            split_studio_login(login.expose_secret()).ok_or(ProxyError::InvalidRequest)?;
        let headers = request_headers(&request.headers, site);
        let response = self
            .client
            .request(request.method, url)
            .headers(headers)
            .basic_auth(username, Some(password))
            .body(request.body.0)
            .send()
            .await
            .map_err(|err| classify(&err))?;
        let mut response: Response<UpstreamBody> = response.into();
        response_headers(response.headers_mut(), &base, site);
        Ok(response)
    }
}

/// Builds the upstream URL from the registered API URL and the browser's
/// path. Fails unless the result is still on the gateway's origin, under
/// its path.
fn upstream_url(base: &reqwest::Url, path_and_query: &str) -> Result<reqwest::Url, ProxyError> {
    if !path_and_query.starts_with('/') || path_and_query.contains(['#', '\\']) {
        return Err(ProxyError::InvalidRequest);
    }
    let joined = format!("{}{path_and_query}", base.as_str().trim_end_matches('/'));
    let url = reqwest::Url::parse(&joined).map_err(|_| ProxyError::InvalidRequest)?;
    let same_origin = url.origin() == base.origin();
    let prefix = format!("{}/", base.path().trim_end_matches('/'));
    if !same_origin || !url.path().starts_with(&prefix) {
        return Err(ProxyError::InvalidRequest);
    }
    Ok(url)
}

/// Hop-by-hop headers (RFC 9110, section 7.6.1) and headers that describe
/// the connection to the dashboard rather than the request.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forwarding headers a browser could forge; the proxy sets its own.
const CLIENT_FORWARDING: [&str; 6] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// The headers sent to the gateway: the browser's, minus credentials,
/// hop-by-hop headers, `Host` (taken from the upstream URL), forged
/// forwarding headers, and the dashboard's Studio cookie.
fn request_headers(incoming: &HeaderMap, site: StudioSite<'_>) -> HeaderMap {
    let mut headers = incoming.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(header::HOST);
    headers.remove(AUTHORIZATION);
    for name in CLIENT_FORWARDING {
        headers.remove(name);
    }
    let cookies: Vec<String> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|pair| {
            !pair.is_empty() && pair.split('=').next().map(str::trim) != Some(site.session_cookie)
        })
        .map(str::to_owned)
        .collect();
    headers.remove(COOKIE);
    if !cookies.is_empty()
        && let Ok(mut value) = HeaderValue::from_str(&cookies.join("; "))
    {
        value.set_sensitive(true);
        headers.insert(COOKIE, value);
    }
    if let Ok(value) = HeaderValue::from_str(site.host) {
        headers.insert("x-forwarded-host", value);
    }
    if let Ok(value) = HeaderValue::from_str(site.proto) {
        headers.insert("x-forwarded-proto", value);
    }
    headers
}

/// Cleans Studio's response headers: hop-by-hop headers go, a cookie with
/// the dashboard's Studio cookie name is dropped, other cookies lose any
/// `Domain` attribute so they stay on this project's host, and a redirect
/// to the gateway's own address becomes a path on the Studio host.
fn response_headers(headers: &mut HeaderMap, base: &reqwest::Url, site: StudioSite<'_>) {
    strip_hop_by_hop(headers);
    let cookies: Vec<HeaderValue> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| host_only_cookie(value, site.session_cookie))
        .collect();
    headers.remove(SET_COOKIE);
    for cookie in cookies {
        headers.append(SET_COOKIE, cookie);
    }
    let rewritten = headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|location| reqwest::Url::parse(location).ok())
        .filter(|target| target.origin() == base.origin())
        .map(|target| {
            let mut path = target.path().to_owned();
            if let Some(query) = target.query() {
                path.push('?');
                path.push_str(query);
            }
            path
        });
    if let Some(path) = rewritten {
        match HeaderValue::from_str(&path) {
            Ok(value) => {
                headers.insert(LOCATION, value);
            }
            Err(_) => {
                headers.remove(LOCATION);
            }
        }
    }
}

fn host_only_cookie(value: &HeaderValue, reserved: &str) -> Option<HeaderValue> {
    let raw = value.to_str().ok()?;
    let mut parts = raw.split(';');
    let pair = parts.next()?.trim();
    let name = pair.split('=').next()?.trim();
    if name.is_empty() || name == reserved {
        return None;
    }
    let mut cookie = pair.to_owned();
    for attribute in parts {
        let attribute = attribute.trim();
        let key = attribute.split('=').next().unwrap_or("").trim();
        if attribute.is_empty() || key.eq_ignore_ascii_case("domain") {
            continue;
        }
        cookie.push_str("; ");
        cookie.push_str(attribute);
    }
    HeaderValue::from_str(&cookie).ok()
}

/// Maps a request error to a fixed reason. The error text may name
/// addresses, so it is only logged at debug level.
fn classify(err: &reqwest::Error) -> ProxyError {
    tracing::debug!(error = %err, "Studio request failed");
    if chain_has::<DestinationNotAllowed>(err) {
        ProxyError::DestinationNotAllowed
    } else if chain_has::<NameNotResolved>(err) {
        ProxyError::Dns
    } else if err.is_timeout() {
        ProxyError::Timeout
    } else if chain_has::<rustls::Error>(err) {
        ProxyError::Tls
    } else if err.is_connect() {
        ProxyError::Connect
    } else {
        ProxyError::Upstream
    }
}

impl ProxyError {
    /// The status the browser gets.
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SITE: StudioSite<'static> = StudioSite {
        host: "abc.studio.example.test",
        proto: "https",
        session_cookie: "__Host-sd-studio",
    };

    fn base() -> reqwest::Url {
        reqwest::Url::parse("https://gw.example.test").unwrap()
    }

    #[test]
    fn upstream_urls_stay_on_the_gateway() {
        let url = upstream_url(&base(), "/project/default/editor?schema=public").unwrap();
        assert_eq!(
            url.as_str(),
            "https://gw.example.test/project/default/editor?schema=public"
        );
        // A double slash is a path here, not a new host.
        let url = upstream_url(&base(), "//evil.example/x").unwrap();
        assert_eq!(url.host_str(), Some("gw.example.test"));
        for bad in ["", "project", "@evil.example/", "/a#b", "/\\evil.example"] {
            assert_eq!(
                upstream_url(&base(), bad).unwrap_err(),
                ProxyError::InvalidRequest,
                "{bad}"
            );
        }
        let prefixed = reqwest::Url::parse("https://gw.example.test/stack").unwrap();
        let url = upstream_url(&prefixed, "/api/profile").unwrap();
        assert_eq!(url.path(), "/stack/api/profile");
        assert!(upstream_url(&prefixed, "/../other").is_err());
    }

    #[test]
    fn request_headers_lose_credentials_and_the_dashboard_cookie() {
        let mut incoming = HeaderMap::new();
        incoming.insert(header::HOST, HeaderValue::from_static(SITE.host));
        incoming.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        incoming.insert(
            "proxy-authorization",
            HeaderValue::from_static("Basic eDp5"),
        );
        incoming.insert(header::CONNECTION, HeaderValue::from_static("x-secret"));
        incoming.insert("x-secret", HeaderValue::from_static("1"));
        incoming.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        incoming.insert("x-forwarded-host", HeaderValue::from_static("evil.example"));
        incoming.append(
            COOKIE,
            HeaderValue::from_static("__Host-sd-studio=token; theme=dark"),
        );
        incoming.append(COOKIE, HeaderValue::from_static("other=1"));
        incoming.insert(header::ACCEPT, HeaderValue::from_static("text/html"));

        let headers = request_headers(&incoming, SITE);
        for gone in [
            "host",
            "authorization",
            "proxy-authorization",
            "connection",
            "x-secret",
            "x-forwarded-for",
        ] {
            assert!(!headers.contains_key(gone), "{gone}");
        }
        assert_eq!(headers["x-forwarded-host"], SITE.host);
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers[COOKIE], "theme=dark; other=1");
        assert!(headers[COOKIE].is_sensitive());
        assert_eq!(headers[header::ACCEPT], "text/html");

        let mut only_ours = HeaderMap::new();
        only_ours.insert(COOKIE, HeaderValue::from_static("__Host-sd-studio=token"));
        assert!(!request_headers(&only_ours, SITE).contains_key(COOKIE));
    }

    #[test]
    fn response_cookies_stay_on_the_studio_host() {
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("__Host-sd-studio=forged; Path=/"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("sb-session=abc; Domain=.example.test; Path=/; HttpOnly"),
        );
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        response_headers(&mut headers, &base(), SITE);
        let cookies: Vec<_> = headers.get_all(SET_COOKIE).iter().collect();
        assert_eq!(cookies, ["sb-session=abc; Path=/; HttpOnly"]);
        assert!(!headers.contains_key(header::TRANSFER_ENCODING));
    }

    #[test]
    fn redirects_to_the_gateway_become_paths() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://gw.example.test/project/default?x=1"),
        );
        response_headers(&mut headers, &base(), SITE);
        assert_eq!(headers[LOCATION], "/project/default?x=1");

        for kept in ["/project/default", "https://elsewhere.example/"] {
            let mut headers = HeaderMap::new();
            headers.insert(LOCATION, HeaderValue::from_str(kept).unwrap());
            response_headers(&mut headers, &base(), SITE);
            assert_eq!(headers[LOCATION], kept);
        }
    }

    #[test]
    fn errors_map_to_gateway_statuses() {
        assert_eq!(ProxyError::Timeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(ProxyError::Connect.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(ProxyError::InvalidRequest.status(), StatusCode::BAD_REQUEST);
    }
}
