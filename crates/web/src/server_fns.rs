//! Server functions called from the UI.
//!
//! Each function runs on the server. Inputs and outputs are serialized, so
//! they must never contain credentials.

use leptos::prelude::*;
use supabase_dashboard_domain::{
    account::AccountSummary,
    authz::OrgRole,
    health::InstallationHealth,
    organization::{MemberSummary, OrganizationSummary},
};
use uuid::Uuid;

use crate::error::AppError;

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

#[cfg(feature = "ssr")]
mod org_context {
    use std::sync::Arc;

    use leptos::prelude::use_context;
    use supabase_dashboard_application::{
        auth::{CurrentSession, RequestContext},
        organizations::OrganizationService,
    };

    use crate::error::AppError;

    /// The signed-in session attached by the server's session guard.
    pub fn session() -> Result<CurrentSession, AppError> {
        use_context::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CurrentSession>().cloned())
            .ok_or(AppError::Unauthenticated)
    }

    pub fn organizations() -> Result<Arc<OrganizationService>, AppError> {
        use_context::<Arc<OrganizationService>>().ok_or_else(|| {
            tracing::error!("organization service is not configured");
            AppError::Unavailable
        })
    }

    /// Request ID and user agent for audit events, owned so they outlive
    /// the borrowed request parts.
    pub struct AuditContext {
        request_id: Option<String>,
        user_agent: Option<String>,
    }

    impl AuditContext {
        pub fn current() -> Self {
            let header = |name: &str| {
                use_context::<http::request::Parts>().and_then(|parts| {
                    parts
                        .headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                })
            };
            Self {
                request_id: header("x-request-id"),
                user_agent: header("user-agent"),
            }
        }

        pub fn get(&self) -> RequestContext<'_> {
            RequestContext {
                request_id: self.request_id.as_deref(),
                user_agent: self.user_agent.as_deref(),
            }
        }
    }
}

/// Organizations the signed-in operator belongs to.
#[server]
pub async fn list_organizations() -> Result<Vec<OrganizationSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::organizations()?.list(&session).await?)
}

#[server]
pub async fn get_organization(id: Uuid) -> Result<OrganizationSummary, AppError> {
    let session = org_context::session()?;
    Ok(org_context::organizations()?.get(&session, id).await?)
}

#[server]
pub async fn create_organization(name: String) -> Result<OrganizationSummary, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .create(&session, &name, audit.get())
        .await?)
}

#[server]
pub async fn rename_organization(id: Uuid, name: String) -> Result<OrganizationSummary, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .rename(&session, id, &name, audit.get())
        .await?)
}

#[server]
pub async fn list_members(organization_id: Uuid) -> Result<Vec<MemberSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::organizations()?
        .members(&session, organization_id)
        .await?)
}

#[server]
pub async fn change_member_role(
    organization_id: Uuid,
    account_id: Uuid,
    role: OrgRole,
) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .change_role(&session, organization_id, account_id, role, audit.get())
        .await?)
}

/// Removes a member, or leaves the organization when `account_id` is the
/// signed-in operator.
#[server]
pub async fn remove_member(organization_id: Uuid, account_id: Uuid) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .remove_member(&session, organization_id, account_id, audit.get())
        .await?)
}
