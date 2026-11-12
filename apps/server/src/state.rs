use std::{sync::Arc, time::Duration};

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use supabase_dashboard_application::{
    auth::AuthService, connections::ConnectionService, dokploy::DokployService,
    organizations::OrganizationService, projects::ProjectService,
    studio_access::StudioAccessService,
};
use supabase_dashboard_persistence::Database;

use crate::{session::CookieSettings, studio::StudioGateway};

#[derive(Clone)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub db: Database,
    pub readiness_timeout: Duration,
    pub auth: Arc<AuthService>,
    pub organizations: Arc<OrganizationService>,
    pub projects: Arc<ProjectService>,
    pub connections: Arc<ConnectionService>,
    pub studio_access: Arc<StudioAccessService>,
    /// The installation's Dokploy connection.
    pub dokploy: Arc<DokployService>,
    pub cookie: CookieSettings,
    /// `scheme://host[:port]` of the public URL. `None` only in development
    /// without a public URL, where the Host header is compared instead.
    pub expected_origin: Option<String>,
    /// Studio hosts and the gateway behind them, when
    /// `SUPABASE_DASHBOARD_STUDIO_DOMAIN` is set.
    pub studio: Option<Arc<StudioGateway>>,
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
