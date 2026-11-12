//! Browser sessions over HTTP: the session cookie, the sign-in and sign-out
//! form handlers, the access guard, and the Origin check that protects
//! cookie-authenticated mutations from cross-site requests.

use axum::{
    Form,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use secrecy::SecretString;
use serde::Deserialize;
use supabase_dashboard_application::auth::{RequestContext, SignInError};
use supabase_dashboard_web::app::{
    HOME_PATH, INVITE_PATH, INVITE_PREVIEW_PATH, INVITE_SIGN_UP_PATH, SIGN_IN_PATH,
    sign_in_return_path,
};

use crate::{error::ApiError, state::AppState};

/// How the session cookie is written.
#[derive(Debug, Clone)]
pub struct CookieSettings {
    /// `__Host-` prefixed when `secure`, which pins the cookie to this exact
    /// host and path `/` and requires HTTPS.
    pub name: &'static str,
    pub secure: bool,
    pub max_age_secs: u64,
}

impl CookieSettings {
    /// The Studio session cookie on a project's Studio host. It has its own
    /// name, so the dashboard never mistakes one for the other.
    pub fn studio(secure: bool, max_age_secs: u64) -> Self {
        Self {
            name: if secure {
                "__Host-sd-studio"
            } else {
                "sd-studio"
            },
            secure,
            max_age_secs,
        }
    }

    pub fn new(secure: bool, max_age_secs: u64) -> Self {
        Self {
            name: if secure {
                "__Host-sd-session"
            } else {
                "sd-session"
            },
            secure,
            max_age_secs,
        }
    }

    pub(crate) fn set(&self, value: &str) -> Option<HeaderValue> {
        self.header(value, self.max_age_secs)
    }

    pub(crate) fn clear(&self) -> Option<HeaderValue> {
        self.header("", 0)
    }

    fn header(&self, value: &str, max_age_secs: u64) -> Option<HeaderValue> {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}{secure}",
            self.name
        ))
        .ok()
    }

    /// The session cookie value from the request, if present.
    pub(crate) fn read<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == self.name)
            .map(|(_, value)| value)
    }
}

/// Who may reach a path without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Health probes, static assets, and the sign-in flow.
    Public,
    /// The sign-in page: public, but signed-in operators are sent home.
    SignInPage,
    /// The invitation page and its two server functions: public, with the
    /// session attached when there is one. The invitation code is the
    /// credential there.
    Optional,
    /// JSON API and server functions: 401 without a session.
    Api,
    /// Everything else, including unknown paths: redirect to sign-in.
    Page,
}

fn classify(path: &str) -> Access {
    match path {
        "/healthz"
        | "/readyz"
        | "/favicon.svg"
        | "/auth/sign-in"
        | "/auth/sign-out"
        | crate::studio::TLS_ASK_PATH => Access::Public,
        SIGN_IN_PATH => Access::SignInPage,
        INVITE_PATH | INVITE_PREVIEW_PATH | INVITE_SIGN_UP_PATH => Access::Optional,
        _ if path.starts_with("/pkg/") => Access::Public,
        _ if path.starts_with("/api/") || path.starts_with("/auth/") => Access::Api,
        _ => Access::Page,
    }
}

/// Resolves the session cookie and denies by default: every path that is not
/// explicitly public needs a valid session. The signed-in account summary is
/// added to request extensions for server functions and SSR.
pub async fn guard(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let access = classify(request.uri().path());
    let session = match state.cookie.read(request.headers()) {
        None => None,
        Some(value) => match state.auth.authenticate(value).await {
            Ok(session) => session,
            Err(err) => {
                tracing::error!(error = %err, "session lookup failed");
                return match access {
                    Access::Public | Access::SignInPage | Access::Optional => {
                        next.run(request).await
                    }
                    Access::Api => ApiError::Unavailable.into_response(),
                    Access::Page => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "The dashboard's metadata database is unavailable. Try again shortly.",
                    )
                        .into_response(),
                };
            }
        },
    };

    match (access, session) {
        (Access::SignInPage, Some(_)) => {
            let next = query_value(request.uri().query(), "next");
            Redirect::to(after_sign_in(next.as_deref())).into_response()
        }
        (Access::Api, None) => ApiError::Unauthenticated.into_response(),
        (Access::Page, None) => {
            let target = request
                .uri()
                .path_and_query()
                .map_or(request.uri().path(), |p| p.as_str());
            Redirect::to(&sign_in_url(Some(target), None)).into_response()
        }
        (Access::Public | Access::SignInPage, None) => next.run(request).await,
        (Access::Optional, None) => no_store(next.run(request).await),
        (_, Some(session)) => {
            request.extensions_mut().insert(session.summary());
            request.extensions_mut().insert(session);
            // Authenticated pages must not be stored by shared caches or the
            // browser's back-forward cache after sign-out.
            no_store(next.run(request).await)
        }
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// Rejects state-changing requests that a browser marks as cross-site.
///
/// Browsers send `Sec-Fetch-Site` and/or `Origin` on every POST. A request
/// with neither is refused as well: cookie-authenticated mutations only come
/// from this dashboard's own pages. Together with `SameSite=Lax` this is the
/// CSRF defense; there is no token to leak.
pub async fn verify_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if is_safe_method(request.method()) || origin_allowed(&state, request.headers()) {
        next.run(request).await
    } else {
        tracing::warn!(path = %request.uri().path(), "cross-origin state change refused");
        ApiError::CrossOriginRequest.into_response()
    }
}

pub(crate) fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let header_str = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    if let Some(site) = header_str(header::HeaderName::from_static("sec-fetch-site")) {
        return site == "same-origin";
    }
    let Some(origin) = header_str(header::ORIGIN) else {
        return false;
    };
    match &state.expected_origin {
        Some(expected) => origin == expected,
        // Development without a public URL: the origin must name the host
        // the request was sent to.
        None => header_str(header::HOST).is_some_and(|host| {
            origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                == Some(host)
        }),
    }
}

/// Fields of the sign-in form. No `Debug`: it holds a password.
#[derive(Deserialize)]
pub struct SignInForm {
    email: String,
    password: String,
    /// The page to return to, checked again before use.
    #[serde(default)]
    next: Option<String>,
}

/// The first value of `name` in a query string.
fn query_value(query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// The page to open after signing in: `next` when it is a safe dashboard
/// page, home otherwise.
fn after_sign_in(next: Option<&str>) -> &str {
    next.and_then(sign_in_return_path).unwrap_or(HOME_PATH)
}

/// The sign-in page, carrying a safe `next` page and an error code.
fn sign_in_url(next: Option<&str>, error: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if let Some(code) = error {
        query.append_pair("error", code);
    }
    if let Some(next) = next.and_then(sign_in_return_path) {
        query.append_pair("next", next);
    }
    let query = query.finish();
    if query.is_empty() {
        SIGN_IN_PATH.to_owned()
    } else {
        format!("{SIGN_IN_PATH}?{query}")
    }
}

/// `POST /auth/sign-in`. Always answers with a redirect so the form works
/// without JavaScript. Failure reasons travel as a fixed code in the query
/// string; the submitted email and password are never echoed.
pub async fn sign_in(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SignInForm>,
) -> Response {
    let password = SecretString::from(form.password);
    let next = form.next.as_deref();
    let ctx = request_context(&headers);
    match state.auth.sign_in(&form.email, &password, ctx).await {
        Ok(signed_in) => {
            let mut response = Redirect::to(after_sign_in(next)).into_response();
            if let Some(cookie) = state.cookie.set(signed_in.token.expose_cookie_value()) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            response
        }
        Err(SignInError::InvalidCredentials) => {
            let code = match state.auth.is_initialized().await {
                Ok(false) => "setup",
                _ => "invalid",
            };
            sign_in_error(code, next)
        }
        Err(SignInError::Throttled { retry_after }) => {
            tracing::warn!(
                retry_after_secs = retry_after.as_secs(),
                "sign-in throttled"
            );
            sign_in_error("throttled", next)
        }
        Err(SignInError::Internal(err)) => {
            tracing::error!(error = %err, "sign-in failed");
            sign_in_error("unavailable", next)
        }
    }
}

/// `POST /auth/sign-out`. Revokes the server-side session and clears the
/// cookie. Succeeds even without a valid session.
pub async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(value) = state.cookie.read(&headers)
        && let Err(err) = state.auth.sign_out(value, request_context(&headers)).await
    {
        tracing::error!(error = %err, "sign-out could not revoke the session");
    }
    let mut response = Redirect::to(SIGN_IN_PATH).into_response();
    if let Some(cookie) = state.cookie.clear() {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

fn sign_in_error(code: &str, next: Option<&str>) -> Response {
    Redirect::to(&sign_in_url(next, Some(code))).into_response()
}

pub(crate) fn request_context(headers: &HeaderMap) -> RequestContext<'_> {
    RequestContext {
        request_id: headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_denies_by_default() {
        assert_eq!(classify("/healthz"), Access::Public);
        assert_eq!(classify(crate::studio::TLS_ASK_PATH), Access::Public);
        assert_eq!(classify("/tls/ask/other"), Access::Page);
        assert_eq!(classify("/pkg/supabase-dashboard.wasm"), Access::Public);
        assert_eq!(classify(SIGN_IN_PATH), Access::SignInPage);
        assert_eq!(classify("/api/get_installation_health"), Access::Api);
        assert_eq!(classify("/auth/other"), Access::Api);
        assert_eq!(classify("/dashboard/organizations"), Access::Page);
        assert_eq!(classify("/dashboard/sign-in/extra"), Access::Page);
        assert_eq!(classify(INVITE_PATH), Access::Optional);
        assert_eq!(classify("/auth/invitation/preview"), Access::Optional);
        assert_eq!(classify("/auth/invitation/sign-up"), Access::Optional);
        assert_eq!(classify("/auth/invitation/other"), Access::Api);
        assert_eq!(classify("/dashboard/invite/extra"), Access::Page);
        assert_eq!(classify("/anything-else"), Access::Page);
    }

    #[test]
    fn cookie_attributes() {
        let secure = CookieSettings::new(true, 60);
        let value = secure.set("abc").unwrap();
        assert_eq!(
            value,
            "__Host-sd-session=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure"
        );
        let clear = CookieSettings::new(false, 60).clear().unwrap();
        assert_eq!(
            clear,
            "sd-session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }

    #[test]
    fn cookie_is_read_from_any_cookie_header() {
        let settings = CookieSettings::new(false, 60);
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("sd-theme=dark"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("other=1; sd-session=tok"),
        );
        assert_eq!(settings.read(&headers), Some("tok"));
        // A lookalike name does not match.
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("xsd-session=tok"));
        assert_eq!(settings.read(&headers), None);
    }
}
