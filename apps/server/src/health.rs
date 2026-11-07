//! Liveness and readiness endpoints for the dashboard installation.

use std::time::Duration;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;
use supabase_dashboard_domain::health::{ComponentHealth, ComponentStatus, InstallationHealth};
use supabase_dashboard_persistence::{Database, PersistenceError};

use crate::state::AppState;

/// Liveness: the process is running and serving HTTP. Does not touch the
/// database so that a database outage does not cause restarts.
pub async fn live() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Readiness: every dashboard component is available.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let report = check(state.db.clone(), state.readiness_timeout).await;
    let status = if report.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report))
}

pub async fn check(db: Database, timeout: Duration) -> InstallationHealth {
    let database = match db.ping(timeout).await {
        Ok(()) => ComponentHealth {
            component: "metadata_database".into(),
            status: ComponentStatus::Available,
            detail: None,
        },
        Err(err) => {
            // Full error goes to the server log only; the response carries a
            // fixed, credential-free description.
            tracing::warn!(error = %err, "metadata database readiness check failed");
            let detail = match err {
                PersistenceError::Timeout(_) => "did not respond in time",
                _ => "query failed",
            };
            ComponentHealth {
                component: "metadata_database".into(),
                status: ComponentStatus::Unavailable,
                detail: Some(detail.into()),
            }
        }
    };
    InstallationHealth {
        components: vec![database],
    }
}
