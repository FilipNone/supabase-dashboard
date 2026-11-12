//! `GET /dashboard/project/:project_id/studio-access.csv`: a download of a
//! project's Studio access log for its owners and admins.

use axum::{
    Extension,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use supabase_dashboard_application::{auth::CurrentSession, studio_access::StudioAccessError};
use supabase_dashboard_domain::studio_access::studio_access_csv;
use uuid::Uuid;

use crate::{
    session::request_context,
    state::AppState,
    studio::{not_found_page, page},
};

#[derive(Deserialize)]
pub struct ExportQuery {
    /// An account ID; empty or absent exports every member's requests.
    member: Option<String>,
}

pub async fn studio_access_csv_download(
    State(state): State<AppState>,
    Path(raw_id): Path<String>,
    Query(query): Query<ExportQuery>,
    Extension(current): Extension<CurrentSession>,
    headers: HeaderMap,
) -> Response {
    let Ok(project_id) = raw_id.parse::<Uuid>() else {
        return not_found_page();
    };
    let member = match query.member.as_deref().filter(|m| !m.is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<Uuid>() {
            Ok(id) => Some(id),
            Err(_) => {
                return page(
                    StatusCode::BAD_REQUEST,
                    "Export unavailable",
                    "<p>The member in this link is not valid.</p>",
                );
            }
        },
    };
    let ctx = request_context(&headers);
    match state
        .studio_access
        .export(&current, project_id, member, ctx)
        .await
    {
        Ok(Some(export)) => {
            if export.truncated {
                tracing::info!(%project_id, "Studio access log export cut to its row limit");
            }
            let disposition = format!("attachment; filename=\"studio-access-{project_id}.csv\"");
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
                studio_access_csv(&export.entries),
            )
                .into_response();
            let headers = response.headers_mut();
            if let Ok(value) = HeaderValue::from_str(&disposition) {
                headers.insert(header::CONTENT_DISPOSITION, value);
            }
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(None) => page(
            StatusCode::NOT_FOUND,
            "Export unavailable",
            "<p>This installation does not record Studio requests.</p>",
        ),
        Err(StudioAccessError::NotFound) => not_found_page(),
        Err(StudioAccessError::Forbidden) => page(
            StatusCode::FORBIDDEN,
            "Export unavailable",
            "<p>Your role in this organization does not allow reading the Studio access log.</p>",
        ),
        Err(StudioAccessError::Internal(err)) => {
            tracing::error!(error = %err, "could not export the Studio access log");
            page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Export unavailable",
                "<p>The dashboard could not read the access log right now. Try again shortly.</p>",
            )
        }
    }
}
