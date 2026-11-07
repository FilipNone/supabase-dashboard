//! Server functions called from the UI.
//!
//! Each function runs on the server. Inputs and outputs are serialized, so
//! they must never contain credentials.

use leptos::prelude::*;
use supabase_dashboard_domain::{account::AccountSummary, health::InstallationHealth};

#[cfg(feature = "ssr")]
pub use probe::HealthProbe;

#[cfg(feature = "ssr")]
mod probe {
    use std::{future::Future, pin::Pin, sync::Arc};

    use supabase_dashboard_domain::health::InstallationHealth;

    type ProbeFn =
        dyn Fn() -> Pin<Box<dyn Future<Output = InstallationHealth> + Send>> + Send + Sync;

    /// Server-provided health check, injected as Leptos context so this
    /// crate does not depend on the persistence layer.
    #[derive(Clone)]
    pub struct HealthProbe(Arc<ProbeFn>);

    impl HealthProbe {
        pub fn new<F, Fut>(probe: F) -> Self
        where
            F: Fn() -> Fut + Send + Sync + 'static,
            Fut: Future<Output = InstallationHealth> + Send + 'static,
        {
            Self(Arc::new(move || Box::pin(probe())))
        }

        pub async fn check(&self) -> InstallationHealth {
            (self.0)().await
        }
    }
}

/// The signed-in operator. The server's session guard attaches the summary
/// to the request; it holds no credentials or session identifiers. Every
/// server function requires a session, so this is `None` only during SSR of
/// a public page.
#[server]
pub async fn get_current_account() -> Result<Option<AccountSummary>, ServerFnError> {
    Ok(use_context::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AccountSummary>().cloned()))
}

/// Health of the dashboard's own components. Requires a signed-in operator
/// (enforced by the server's session guard for every server function).
#[server]
pub async fn get_installation_health() -> Result<InstallationHealth, ServerFnError> {
    let probe = use_context::<HealthProbe>()
        .ok_or_else(|| ServerFnError::new("health probe is not configured"))?;
    Ok(probe.check().await)
}
