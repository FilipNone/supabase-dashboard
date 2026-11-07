//! Typed errors for JSON API responses.
//!
//! Every API error has a stable machine-readable `code` and a short message
//! that never includes credentials, SQL, or internal error text. Details
//! belong in the server log, correlated by the `x-request-id` header.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("the requested API endpoint does not exist")]
    NotFound,
}

impl ApiError {
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
        }
    }

    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
        }
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    error: Body<'a>,
}

#[derive(Serialize)]
struct Body<'a> {
    code: &'a str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Envelope {
            error: Body {
                code: self.code(),
                message: self.to_string(),
            },
        };
        (self.status(), Json(body)).into_response()
    }
}

/// Fallback for unknown paths under `/api`, so API clients get JSON instead
/// of the HTML not-found page.
pub async fn api_not_found() -> ApiError {
    ApiError::NotFound
}
