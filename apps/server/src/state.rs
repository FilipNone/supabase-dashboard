use std::time::Duration;

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use supabase_dashboard_persistence::Database;

#[derive(Clone)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub db: Database,
    pub readiness_timeout: Duration,
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
