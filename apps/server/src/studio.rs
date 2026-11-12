//! Opening a project's Studio over HTTP (docs/adr/0002-studio-access.md).
//!
//! - [`launch`] runs on the dashboard host at `/dashboard/project/:id` for
//!   a signed-in member and redirects to the project's Studio host with a
//!   one-time code.
//! - [`dispatch`] sends every request whose `Host` is a Studio host to
//!   [`router`] instead of the dashboard's routes.
//! - On the Studio host, [`handoff`] trades the code for a Studio session
//!   cookie, and [`forward`] checks that session on every request before
//!   passing it to the project's gateway.

use std::sync::Arc;

use axum::{
    Extension, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;
use supabase_dashboard_adapters::studio_proxy::{ProxyBody, ProxyRequest, StudioProxy, StudioSite};
use supabase_dashboard_application::{
    auth::CurrentSession,
    studio::{STUDIO_SESSION_LIFETIME, StudioError, StudioService},
    studio_access::StudioAccessRecorder,
};
use supabase_dashboard_domain::studio_access::{NewStudioAccess, loggable_path};
use uuid::Uuid;

use crate::{
    session::{CookieSettings, is_safe_method, request_context},
    state::AppState,
    studio_host::{HostRoute, StudioHosts},
};

/// The one path the dashboard keeps on a Studio host.
pub const HANDOFF_PATH: &str = "/__dashboard/handoff";

/// Everything a Studio host needs.
pub struct StudioGateway {
    pub hosts: StudioHosts,
    pub service: Arc<StudioService>,
    pub proxy: StudioProxy,
    pub cookie: CookieSettings,
    /// The dashboard's public origin, where members are sent to sign in.
    pub dashboard_origin: String,
    /// Where forwarded requests are recorded, when the access log is on.
    pub access_log: Option<Arc<StudioAccessRecorder>>,
}

impl StudioGateway {
    pub fn new(
        hosts: StudioHosts,
        service: Arc<StudioService>,
        proxy: StudioProxy,
        dashboard_origin: String,
    ) -> Self {
        let cookie = CookieSettings::studio(hosts.is_https(), STUDIO_SESSION_LIFETIME.as_secs());
        Self {
            hosts,
            service,
            proxy,
            cookie,
            dashboard_origin,
            access_log: None,
        }
    }

    /// Records every request that passes the Studio session check.
    #[must_use]
    pub fn with_access_log(mut self, recorder: Arc<StudioAccessRecorder>) -> Self {
        self.access_log = Some(recorder);
        self
    }

    fn launch_url(&self, project_id: Uuid, path: Option<&str>) -> String {
        let mut url = format!("{}{}", self.dashboard_origin, launch_path(project_id));
        if let Some(path) = path {
            url.push_str("?path=");
            url.push_str(
                &url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>(),
            );
        }
        url
    }
}

/// `/dashboard/project/:id` on the dashboard host.
pub fn launch_path(project_id: Uuid) -> String {
    supabase_dashboard_web::pages::project::studio_launch_path(project_id)
}

/// The project a Studio host request belongs to, set by [`dispatch`].
#[derive(Debug, Clone, Copy)]
struct StudioProject(Uuid);

/// Sends Studio host requests to `studio` and everything else on to the
/// dashboard. Runs before the dashboard's session guard and Origin check,
/// which do not apply on Studio hosts.
pub async fn dispatch(
    gateway: Option<(StudioHosts, Router)>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some((hosts, studio)) = gateway else {
        return next.run(request).await;
    };
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| request.uri().authority().map(|a| a.as_str()))
        .unwrap_or("");
    match hosts.route(host) {
        HostRoute::Dashboard => next.run(request).await,
        HostRoute::UnknownStudio => plain(StatusCode::NOT_FOUND, "Not found."),
        HostRoute::Studio(id) => {
            request.extensions_mut().insert(StudioProject(id));
            match tower::ServiceExt::oneshot(studio, request).await {
                Ok(response) => response,
                Err(never) => match never {},
            }
        }
    }
}

/// Routes on a Studio host. Body limit and timeout are added by the caller.
pub fn router(gateway: Arc<StudioGateway>) -> Router {
    Router::new()
        .route(HANDOFF_PATH, get(handoff))
        .fallback(forward)
        .with_state(gateway)
}

#[derive(Deserialize)]
pub struct LaunchQuery {
    path: Option<String>,
}

/// `GET /dashboard/project/:project_id`: starts opening Studio. Refusals
/// that the member can act on go back to the project's page with a fixed
/// reason; an unknown project and one in another organization look the
/// same.
pub async fn launch(
    State(state): State<AppState>,
    Path(raw_id): Path<String>,
    Query(query): Query<LaunchQuery>,
    Extension(current): Extension<CurrentSession>,
    headers: HeaderMap,
) -> Response {
    let Ok(project_id) = raw_id.parse::<Uuid>() else {
        return not_found_page();
    };
    let Some(gateway) = &state.studio else {
        return back_to_project(&state, &current, project_id, "disabled").await;
    };
    let ctx = request_context(&headers);
    match gateway
        .service
        .begin(&current, project_id, query.path.as_deref(), ctx)
        .await
    {
        Ok(handoff) => {
            let target = format!(
                "{}{HANDOFF_PATH}?code={}",
                gateway.hosts.origin(handoff.project_id),
                handoff.code.expose_code()
            );
            private(Redirect::to(&target).into_response())
        }
        Err(StudioError::NotFound) => not_found_page(),
        Err(StudioError::Forbidden) => {
            back_to_project(&state, &current, project_id, "forbidden").await
        }
        Err(StudioError::NotConfigured) => {
            back_to_project(&state, &current, project_id, "not_configured").await
        }
        Err(err) => {
            tracing::error!(error = %err, "could not start opening Studio");
            unavailable_page()
        }
    }
}

async fn back_to_project(
    state: &AppState,
    current: &CurrentSession,
    project_id: Uuid,
    reason: &str,
) -> Response {
    match state.projects.get(current, project_id).await {
        Ok(project) => Redirect::to(&format!(
            "/dashboard/org/{}/projects/{}?studio={reason}",
            project.organization_id, project.id
        ))
        .into_response(),
        Err(_) => not_found_page(),
    }
}

#[derive(Deserialize)]
pub struct HandoffQuery {
    code: Option<String>,
}

/// `GET /__dashboard/handoff?code=…` on a Studio host: uses up the code
/// and sets the Studio session cookie.
async fn handoff(
    State(gateway): State<Arc<StudioGateway>>,
    Extension(StudioProject(project_id)): Extension<StudioProject>,
    Query(query): Query<HandoffQuery>,
) -> Response {
    let code = query.code.unwrap_or_default();
    match gateway.service.redeem(project_id, &code).await {
        Ok((token, path)) => {
            let mut response = Redirect::to(&path).into_response();
            if let Some(cookie) = gateway.cookie.set(token.expose_cookie_value()) {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            private(response)
        }
        Err(StudioError::Expired) => private(expired_page(&gateway, project_id)),
        Err(err) => {
            tracing::error!(error = %err, "could not redeem a Studio handoff code");
            unavailable_page()
        }
    }
}

/// Every other request on a Studio host.
async fn forward(
    State(gateway): State<Arc<StudioGateway>>,
    Extension(StudioProject(project_id)): Extension<StudioProject>,
    request: Request,
) -> Response {
    let origin = gateway.hosts.origin(project_id);
    let headers = request.headers();
    if !is_safe_method(request.method()) && !same_origin(headers, &origin) {
        tracing::warn!("cross-origin request to a Studio host refused");
        return plain(StatusCode::FORBIDDEN, "Cross-origin request refused.");
    }
    let Some(token) = gateway.cookie.read(headers).map(str::to_owned) else {
        return sign_in_again(&gateway, project_id, &request, false);
    };
    let upstream = match gateway.service.authorize(project_id, &token).await {
        Ok(upstream) => upstream,
        Err(StudioError::Expired) => return sign_in_again(&gateway, project_id, &request, true),
        Err(StudioError::Forbidden) => {
            return plain(
                StatusCode::FORBIDDEN,
                "Your role in this organization no longer allows opening Studio.",
            );
        }
        Err(StudioError::NotConfigured | StudioError::NotFound) => {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Studio access is not set up for this project. Save the gateway's Studio login \
                 on the project's settings page in the dashboard.",
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "Studio session check failed");
            return unavailable_page();
        }
    };

    let host = gateway.hosts.host(project_id);
    let site = StudioSite {
        host: &host,
        proto: gateway.hosts.scheme(),
        session_cookie: gateway.cookie.name,
    };
    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned());
    // Kept before the request moves on: the method and the path without
    // its query, nothing else.
    let logged = gateway.access_log.as_ref().map(|recorder| {
        (
            Arc::clone(recorder),
            parts.method.as_str().chars().take(16).collect::<String>(),
            loggable_path(&path_and_query),
        )
    });
    let body = if matches!(parts.method, Method::GET | Method::HEAD) {
        ProxyBody::empty()
    } else {
        ProxyBody::from_stream(body.into_data_stream())
    };
    let proxied = ProxyRequest {
        method: parts.method,
        path_and_query,
        headers: parts.headers,
        body,
    };
    let response = match gateway
        .proxy
        .forward(
            &upstream.api_url,
            &upstream.login,
            upstream.authorities.as_ref(),
            site,
            proxied,
        )
        .await
    {
        Ok(response) => response.map(Body::new),
        Err(err) => {
            tracing::warn!(error = %err, "Studio request could not be forwarded");
            plain(
                err.status(),
                "The project's Studio did not answer. Check the project's health in the dashboard.",
            )
        }
    };
    if let Some((recorder, method, path)) = logged {
        recorder.record(NewStudioAccess {
            project_id,
            account_id: upstream.account_id,
            at: time::OffsetDateTime::now_utc(),
            method,
            path,
            status: response.status().as_u16(),
        });
    }
    response
}

/// Without a usable Studio session: page loads go back through the
/// dashboard, which signs the member in if needed; anything else gets 401.
fn sign_in_again(
    gateway: &StudioGateway,
    project_id: Uuid,
    request: &Request,
    clear: bool,
) -> Response {
    let navigation = matches!(*request.method(), Method::GET | Method::HEAD)
        && request
            .headers()
            .get("sec-fetch-mode")
            .is_none_or(|mode| mode == "navigate");
    let mut response = if navigation {
        let path = request.uri().path_and_query().map(|pq| pq.as_str());
        Redirect::to(&gateway.launch_url(project_id, path)).into_response()
    } else {
        plain(
            StatusCode::UNAUTHORIZED,
            "Open Studio again from the dashboard.",
        )
    };
    if clear && let Some(cookie) = gateway.cookie.clear() {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    private(response)
}

/// `Sec-Fetch-Site: same-origin`, or an `Origin` equal to this Studio
/// host's origin when the browser sends no fetch metadata.
fn same_origin(headers: &HeaderMap, expected: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site == "same-origin";
    }
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| origin == expected)
}

fn private(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn plain(status: StatusCode, message: &'static str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], message).into_response()
}

pub(crate) fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light dark\"><title>{title}</title></head>\
         <body style=\"font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; \
         padding: 0 1rem; line-height: 1.5\"><h1 style=\"font-size: 1.25rem\">{title}</h1>{body}\
         </body></html>"
    );
    (status, [(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

pub(crate) fn not_found_page() -> Response {
    page(
        StatusCode::NOT_FOUND,
        "Project unavailable",
        "<p>This project was not found, or you do not have access to it.</p>\
         <p><a href=\"/dashboard/organizations\">Back to organizations</a></p>",
    )
}

fn unavailable_page() -> Response {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Studio is unavailable",
        "<p>The dashboard could not open Studio right now. Try again shortly.</p>",
    )
}

fn expired_page(gateway: &StudioGateway, project_id: Uuid) -> Response {
    let again = gateway.launch_url(project_id, None);
    page(
        StatusCode::BAD_REQUEST,
        "This link has expired",
        &format!(
            "<p>Links that open Studio work once and only for a minute.</p>\
             <p><a href=\"{again}\">Open Studio again</a></p>"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_prefers_fetch_metadata() {
        let expected = "https://abc.studio.example.test";
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, HeaderValue::from_static(expected));
        assert!(same_origin(&headers, expected));
        // A sibling project's Studio is same-site, not same-origin.
        headers.insert("sec-fetch-site", HeaderValue::from_static("same-site"));
        assert!(!same_origin(&headers, expected));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://def.studio.example.test"),
        );
        assert!(!same_origin(&headers, expected));
        assert!(!same_origin(&HeaderMap::new(), expected));
    }
}
