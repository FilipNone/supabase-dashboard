//! Single sign-on through the deployment's OpenID Connect provider: the
//! form handlers that start a sign-in or a link, the callback the provider
//! sends the browser back to, and the back-channel logout endpoint the
//! provider posts to.
//!
//! The browser only ever sees a fixed error code. What went wrong is in
//! the server log and the audit log, without codes, tokens, or claims.

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use supabase_dashboard_application::auth::{
    CurrentSession,
    oidc::{OidcCallback, OidcError, OidcFinished, OidcLogoutError},
};
use supabase_dashboard_web::app::{
    ACCOUNT_SECURITY_PATH, OIDC_LINK_PATH, OIDC_SIGN_IN_PATH, sign_in_return_path,
};

use crate::{
    session::{
        CookieSettings, after_sign_in, form_value, query_value, request_context, sign_in_url,
    },
    state::AppState,
};

/// `POST`: starts a sign-in. Form field `next` names the page to open
/// afterwards.
pub const SIGN_IN_PATH: &str = OIDC_SIGN_IN_PATH;
/// `POST`: starts linking an identity to the signed-in account.
pub const LINK_PATH: &str = OIDC_LINK_PATH;
/// `GET`: where the provider sends the browser back.
pub const CALLBACK_PATH: &str = crate::config::OIDC_CALLBACK_PATH;
/// `POST`: where the provider posts back-channel logout tokens, server to
/// server. No session, and exempt from the Origin check.
pub const BACKCHANNEL_LOGOUT_PATH: &str = crate::config::OIDC_BACKCHANNEL_LOGOUT_PATH;

/// Largest back-channel logout request body read.
pub const MAX_BACKCHANNEL_LOGOUT_BODY: usize = 16 * 1024;

/// Longest callback parameter read. Real codes and states are far shorter.
const MAX_PARAM_LEN: usize = 2048;

fn flow_cookie(state: &AppState) -> CookieSettings {
    CookieSettings::oidc_flow(state.cookie.secure)
}

/// Sends the browser to the provider, with the flow cookie.
fn to_provider(state: &AppState, url: &str, browser_cookie: &str) -> Response {
    let mut response = Redirect::to(url).into_response();
    if let Some(cookie) = flow_cookie(state).set(browser_cookie) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn security_page(code: &str) -> Response {
    Redirect::to(&format!("{ACCOUNT_SECURITY_PATH}?oidc={code}")).into_response()
}

/// `POST /auth/oidc/sign-in`.
pub async fn sign_in(State(state): State<AppState>, body: Bytes) -> Response {
    let next = form_value(&body, "next");
    let next = next.as_deref().and_then(sign_in_return_path);
    match state.auth.begin_oidc_sign_in(next).await {
        Ok(redirect) => to_provider(&state, &redirect.url, redirect.browser_cookie_value()),
        Err(err) => {
            log_start_failure(&err);
            Redirect::to(&sign_in_url(next, Some("oidc"))).into_response()
        }
    }
}

/// `POST /auth/oidc/link`. Needs a session; without one the browser signs
/// in first and comes back to the security page.
pub async fn link(State(state): State<AppState>, request: Request) -> Response {
    let Some(current) = request.extensions().get::<CurrentSession>().cloned() else {
        return Redirect::to(&sign_in_url(Some(ACCOUNT_SECURITY_PATH), None)).into_response();
    };
    match state.auth.begin_oidc_link(&current).await {
        Ok(redirect) => to_provider(&state, &redirect.url, redirect.browser_cookie_value()),
        Err(err) => {
            log_start_failure(&err);
            security_page("unavailable")
        }
    }
}

fn log_start_failure(err: &OidcError) {
    match err {
        OidcError::NotConfigured => tracing::info!("single sign-on is not configured"),
        OidcError::Busy => tracing::warn!("too many single sign-on flows are in progress"),
        err => tracing::error!(error = %err, "could not start single sign-on"),
    }
}

/// `GET /auth/oidc/callback`. The flow cookie is cleared whatever the
/// outcome.
pub async fn callback(State(state): State<AppState>, request: Request) -> Response {
    let headers: &HeaderMap = request.headers();
    let current = request.extensions().get::<CurrentSession>();
    let query = request.uri().query();
    let param = |name| query_value(query, name).filter(|value| value.len() <= MAX_PARAM_LEN);
    let state_param = param("state").unwrap_or_default();
    // A provider error (`error=access_denied`) means no code, even if one
    // is present as well.
    let code = if param("error").is_some() {
        None
    } else {
        param("code")
    };
    let flow_cookie_settings = flow_cookie(&state);
    let result = state
        .auth
        .finish_oidc(
            OidcCallback {
                state: &state_param,
                code: code.as_deref(),
            },
            flow_cookie_settings.read(headers),
            current,
            request_context(headers),
        )
        .await;
    let mut response = match result {
        Ok(OidcFinished::SignedIn { signed_in, next }) => {
            let mut response = Redirect::to(after_sign_in(next.as_deref())).into_response();
            if let Some(cookie) = state.cookie.set(signed_in.token.expose_cookie_value()) {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            response
        }
        Ok(OidcFinished::Linked) => security_page("linked"),
        Err(err) => failure(&err, current.is_some()),
    };
    if let Some(cookie) = flow_cookie_settings.clear() {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// Where a failed flow lands: the security page for an operator who is
/// signed in (they were linking), the sign-in page otherwise.
fn failure(err: &OidcError, signed_in: bool) -> Response {
    let code = match err {
        OidcError::LinkedToOther => "taken",
        OidcError::IssuerTaken => "has_identity",
        OidcError::SessionChanged => "session",
        OidcError::NotLinked => "oidc_unlinked",
        OidcError::ProviderDenied => "oidc_cancelled",
        OidcError::Internal(err) => {
            tracing::error!(error = %err, "single sign-on failed");
            "unavailable"
        }
        // Logged and audited where they happened.
        _ => "oidc",
    };
    match (signed_in, code) {
        (_, "taken" | "has_identity" | "session") => security_page(code),
        (true, "unavailable") => security_page("unavailable"),
        (true, _) => security_page("failed"),
        (false, code) => Redirect::to(&sign_in_url(None, Some(code))).into_response(),
    }
}

/// `POST /auth/oidc/backchannel-logout` (OpenID Connect Back-Channel Logout
/// 1.0, section 2.5): a form with one `logout_token`. Answers 200 when the
/// token is valid, whether or not it named a live session; 400 with a
/// generic body when the request or token is not valid; 503 when the
/// provider's keys or the metadata database are unavailable or too many
/// logouts are in progress. Never cached.
pub async fn backchannel_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    let mut tokens = url::form_urlencoded::parse(&body)
        .filter(|(key, _)| key == "logout_token")
        .map(|(_, value)| value);
    let token = match (is_form, tokens.next(), tokens.next()) {
        (true, Some(token), None) => token,
        _ => {
            tracing::warn!(
                "back-channel logout request without exactly one logout_token form field"
            );
            return logout_answer(StatusCode::BAD_REQUEST);
        }
    };
    let status = match state
        .auth
        .oidc_backchannel_logout(&token, request_context(&headers))
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(OidcLogoutError::NotConfigured) => StatusCode::NOT_FOUND,
        Err(err @ (OidcLogoutError::Invalid(_) | OidcLogoutError::Replayed)) => {
            tracing::warn!(error = %err, "back-channel logout refused");
            StatusCode::BAD_REQUEST
        }
        Err(err @ OidcLogoutError::Busy) => {
            tracing::warn!(error = %err, "back-channel logout refused");
            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(err @ (OidcLogoutError::Unavailable(_) | OidcLogoutError::Internal(_))) => {
            tracing::error!(error = %err, "back-channel logout failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    logout_answer(status)
}

/// The answer to a back-channel logout: empty on success, a fixed error
/// code otherwise, and never stored.
fn logout_answer(status: StatusCode) -> Response {
    let mut response = if status == StatusCode::OK {
        status.into_response()
    } else {
        let error = if status == StatusCode::BAD_REQUEST {
            "invalid_request"
        } else {
            "temporarily_unavailable"
        };
        (status, axum::Json(serde_json::json!({ "error": error }))).into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
