use std::{sync::Arc, time::Duration};

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use supabase_dashboard_application::{
    api_tokens::{ApiTokenService, TokenApi},
    auth::AuthService,
    connections::ConnectionService,
    dokploy::DokployService,
    organizations::OrganizationService,
    projects::ProjectService,
    provisioning::ProvisioningService,
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
    /// Creates, lists, and revokes API tokens, and resolves bearer tokens.
    pub api_tokens: Arc<ApiTokenService>,
    /// The reads the token API offers.
    pub token_api: Arc<TokenApi>,
    pub organizations: Arc<OrganizationService>,
    pub projects: Arc<ProjectService>,
    pub connections: Arc<ConnectionService>,
    pub studio_access: Arc<StudioAccessService>,
    /// The installation's Dokploy connection.
    pub dokploy: Arc<DokployService>,
    /// Queues new stacks and reports their progress.
    pub provisioning: Arc<ProvisioningService>,
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
