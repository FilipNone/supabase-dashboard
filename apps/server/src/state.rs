use std::{sync::Arc, time::Duration};

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use supabase_dashboard_application::auth::AuthService;
use supabase_dashboard_persistence::Database;

use crate::session::CookieSettings;

#[derive(Clone)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub db: Database,
    pub readiness_timeout: Duration,
    pub auth: Arc<AuthService>,
    pub cookie: CookieSettings,
    /// `scheme://host[:port]` of the public URL. `None` only in development
    /// without a public URL, where the Host header is compared instead.
    pub expected_origin: Option<String>,
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
