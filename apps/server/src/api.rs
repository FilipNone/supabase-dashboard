//! The read-only JSON API under `/api/v1`, for dashboard API tokens.
//!
//! These routes accept only `Authorization: Bearer <token>`. They never read
//! the session cookie, so a browser cannot be made to call them with the
//! operator's session, and they answer only `GET`.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use supabase_dashboard_application::api_tokens::{ApiAccessError, ApiProject, TokenPrincipal};
use supabase_dashboard_domain::{
    api_token::ApiTokenScope, connection::StackService, organization::OrganizationSummary,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::state::AppState;

/// Paths under this prefix are the token API; the session guard leaves
/// them alone.
pub const API_V1_PREFIX: &str = "/api/v1/";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/organizations", get(list_organizations))
        .route(
            "/api/v1/organizations/{organization_id}/projects",
            get(list_projects),
        )
        .route("/api/v1/projects/{project_id}", get(get_project))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiV1Error {
    /// Missing, malformed, unknown, revoked, or expired token, or a token
    /// of a disabled account. One answer for all of them.
    #[error("send a valid dashboard API token as `Authorization: Bearer <token>`")]
    InvalidToken,
    #[error("this token does not have the {} scope", .0.as_str())]
    InsufficientScope(ApiTokenScope),
    #[error("your role in this organization does not allow this")]
    Forbidden,
    /// Also for objects in organizations the account does not belong to.
    #[error("not found")]
    NotFound,
    #[error("the dashboard is temporarily unavailable")]
    Unavailable,
}

impl ApiV1Error {
    const fn status(&self) -> StatusCode {
        match self {
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope(_) | Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    const fn code(&self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope(_) => "insufficient_scope",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiV1Error {
    fn into_response(self) -> Response {
        // RFC 6750, section 3.
        let challenge = match &self {
            Self::InvalidToken => Some("Bearer realm=\"supabase-dashboard\"".to_owned()),
            Self::InsufficientScope(scope) => Some(format!(
                "Bearer realm=\"supabase-dashboard\", error=\"insufficient_scope\", scope=\"{}\"",
                scope.as_str()
            )),
            _ => None,
        };
        let body = ErrorEnvelope {
            error: ErrorBody {
                code: self.code(),
                message: self.to_string(),
            },
        };
        let mut response = (self.status(), Json(body)).into_response();
        if let Some(value) = challenge.and_then(|value| HeaderValue::from_str(&value).ok()) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

impl From<ApiAccessError> for ApiV1Error {
    fn from(err: ApiAccessError) -> Self {
        match err {
            ApiAccessError::MissingScope(scope) => Self::InsufficientScope(scope),
            ApiAccessError::Forbidden => Self::Forbidden,
            ApiAccessError::NotFound => Self::NotFound,
            ApiAccessError::Internal(message) => {
                tracing::error!(error = %message, "token API read failed");
                Self::Unavailable
            }
        }
    }
}

/// The principal behind the request's bearer token.
async fn principal(state: &AppState, headers: &HeaderMap) -> Result<TokenPrincipal, ApiV1Error> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
        })
        .ok_or(ApiV1Error::InvalidToken)?;
    match state.api_tokens.authenticate(token).await {
        Ok(Some(principal)) => Ok(principal),
        Ok(None) => Err(ApiV1Error::InvalidToken),
        Err(err) => {
            tracing::error!(error = %err, "API token lookup failed");
            Err(ApiV1Error::Unavailable)
        }
    }
}

/// A path ID. Anything that is not a UUID is answered like an ID that does
/// not exist.
fn path_id(raw: &str) -> Result<Uuid, ApiV1Error> {
    Uuid::parse_str(raw).map_err(|_| ApiV1Error::NotFound)
}

fn timestamp(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

#[derive(Serialize)]
struct OrganizationJson {
    id: Uuid,
    name: String,
    role: &'static str,
}

impl From<OrganizationSummary> for OrganizationJson {
    fn from(org: OrganizationSummary) -> Self {
        Self {
            id: org.id,
            name: org.name.as_str().to_owned(),
            role: org.role.as_str(),
        }
    }
}

#[derive(Serialize)]
struct LastCheckJson {
    checked_at: String,
    /// Older than a day when read.
    stale: bool,
    failing: Vec<StackService>,
    not_checked: Vec<StackService>,
}

#[derive(Serialize)]
struct ProjectJson {
    id: Uuid,
    organization_id: Uuid,
    name: String,
    api_url: String,
    created_at: String,
    role: &'static str,
    last_check: Option<LastCheckJson>,
}

impl From<ApiProject> for ProjectJson {
    fn from(entry: ApiProject) -> Self {
        let project = entry.project;
        Self {
            id: project.id,
            organization_id: project.organization_id,
            name: project.name.as_str().to_owned(),
            api_url: project.api_url.as_str().to_owned(),
            created_at: timestamp(project.created_at),
            role: project.role.as_str(),
            last_check: entry.last_check.map(|digest| LastCheckJson {
                checked_at: timestamp(digest.checked_at),
                stale: digest.stale,
                failing: digest.failing,
                not_checked: digest.not_checked,
            }),
        }
    }
}

#[derive(Serialize)]
struct OrganizationList {
    organizations: Vec<OrganizationJson>,
}

#[derive(Serialize)]
struct ProjectList {
    projects: Vec<ProjectJson>,
}

#[derive(Serialize)]
struct ProjectEnvelope {
    project: ProjectJson,
}

fn no_store<T: Serialize>(body: T) -> Response {
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn list_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiV1Error> {
    let principal = principal(&state, &headers).await?;
    let organizations = state.token_api.organizations(&principal).await?;
    Ok(no_store(OrganizationList {
        organizations: organizations.into_iter().map(Into::into).collect(),
    }))
}

async fn list_projects(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiV1Error> {
    let principal = principal(&state, &headers).await?;
    let organization_id = path_id(&organization_id)?;
    let projects = state
        .token_api
        .projects(&principal, organization_id)
        .await?;
    Ok(no_store(ProjectList {
        projects: projects.into_iter().map(Into::into).collect(),
    }))
}

async fn get_project(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiV1Error> {
    let principal = principal(&state, &headers).await?;
    let project_id = path_id(&project_id)?;
    let project = state.token_api.project(&principal, project_id).await?;
    Ok(no_store(ProjectEnvelope {
        project: project.into(),
    }))
}
