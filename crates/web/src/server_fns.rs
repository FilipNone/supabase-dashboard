//! Server functions called from the UI.
//!
//! Each function runs on the server. Inputs and outputs are serialized, so
//! they must never contain credentials.

use std::fmt;

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use supabase_dashboard_domain::{
    account::{AccountSummary, AdminAccountSummary, SessionSummary},
    admin::RegisteredResources,
    authz::OrgRole,
    connection::{CredentialKind, CredentialOverview, HealthReport},
    health::InstallationHealth,
    invitation::{InvitationCode, InvitationPreview, InvitationSummary, IssuedInvitation},
    organization::{MemberSummary, OrganizationSummary},
    project::ProjectSummary,
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
        auth::{AuthService, CurrentSession, RequestContext},
        connections::ConnectionService,
        organizations::OrganizationService,
        projects::ProjectService,
    };

    use crate::error::AppError;

    /// The signed-in session attached by the server's session guard.
    pub fn session() -> Result<CurrentSession, AppError> {
        optional_session().ok_or(AppError::Unauthenticated)
    }

    /// The session on paths the guard lets through without one.
    pub fn optional_session() -> Option<CurrentSession> {
        use_context::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<CurrentSession>().cloned())
    }

    pub fn auth() -> Result<Arc<AuthService>, AppError> {
        use_context::<Arc<AuthService>>().ok_or_else(|| {
            tracing::error!("auth service is not configured");
            AppError::Unavailable
        })
    }

    pub fn organizations() -> Result<Arc<OrganizationService>, AppError> {
        use_context::<Arc<OrganizationService>>().ok_or_else(|| {
            tracing::error!("organization service is not configured");
            AppError::Unavailable
        })
    }

    pub fn projects() -> Result<Arc<ProjectService>, AppError> {
        use_context::<Arc<ProjectService>>().ok_or_else(|| {
            tracing::error!("project service is not configured");
            AppError::Unavailable
        })
    }

    pub fn connections() -> Result<Arc<ConnectionService>, AppError> {
        use_context::<Arc<ConnectionService>>().ok_or_else(|| {
            tracing::error!("connection service is not configured");
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

/// Which API keys are stored for a project, without their values.
#[server]
pub async fn get_project_credentials(id: Uuid) -> Result<CredentialOverview, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?
        .credentials(&session, id)
        .await?)
}

/// An API key typed into a form. Never printed, never sent back.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretInput(String);

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput([REDACTED])")
    }
}

/// Stores or replaces one of a project's API keys.
#[server]
pub async fn replace_project_credential(
    id: Uuid,
    kind: CredentialKind,
    value: SecretInput,
) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let value = secrecy::SecretString::from(value.0);
    Ok(org_context::connections()?
        .replace_credential(&session, id, kind, &value, audit.get())
        .await?)
}

#[server]
pub async fn remove_project_credential(id: Uuid, kind: CredentialKind) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::connections()?
        .remove_credential(&session, id, kind, audit.get())
        .await?)
}

/// The last saved service check of a project, if any.
#[server]
pub async fn get_project_health(id: Uuid) -> Result<Option<HealthReport>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?
        .last_report(&session, id)
        .await?)
}

/// Checks the project's services now and saves the result.
#[server]
pub async fn check_project_health(id: Uuid) -> Result<HealthReport, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?.check_now(&session, id).await?)
}

/// Projects registered in an organization.
#[server]
pub async fn list_projects(organization_id: Uuid) -> Result<Vec<ProjectSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::projects()?
        .list(&session, organization_id)
        .await?)
}

#[server]
pub async fn get_project(id: Uuid) -> Result<ProjectSummary, AppError> {
    let session = org_context::session()?;
    Ok(org_context::projects()?.get(&session, id).await?)
}

/// Registers an existing stack. Nothing is sent to it.
#[server]
pub async fn register_project(
    organization_id: Uuid,
    name: String,
    api_url: String,
    // Set by a checkbox, so it is absent when unchecked.
    #[server(default)] allow_unencrypted: bool,
) -> Result<ProjectSummary, AppError> {
    use supabase_dashboard_application::projects::Registration;
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let input = Registration {
        name: &name,
        api_url: &api_url,
        allow_unencrypted,
    };
    Ok(org_context::projects()?
        .register(&session, organization_id, input, audit.get())
        .await?)
}

#[server]
pub async fn rename_project(id: Uuid, name: String) -> Result<ProjectSummary, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::projects()?
        .rename(&session, id, &name, audit.get())
        .await?)
}

/// Points a project at a different API URL. Nothing is sent to it.
#[server]
pub async fn change_project_url(
    id: Uuid,
    api_url: String,
    // Set by a checkbox, so it is absent when unchecked.
    #[server(default)] allow_unencrypted: bool,
) -> Result<ProjectSummary, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::projects()?
        .change_url(&session, id, &api_url, allow_unencrypted, audit.get())
        .await?)
}

/// Removes the registry entry. `confirmation` must be the project's name.
#[server]
pub async fn unregister_project(id: Uuid, confirmation: String) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::projects()?
        .unregister(&session, id, &confirmation, audit.get())
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

/// Open invitations of an organization.
#[server]
pub async fn list_invitations(organization_id: Uuid) -> Result<Vec<InvitationSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::organizations()?
        .invitations(&session, organization_id)
        .await?)
}

/// Creates an invitation. The response carries the invitation code, once.
#[server]
pub async fn create_invitation(
    organization_id: Uuid,
    email: String,
    role: OrgRole,
) -> Result<IssuedInvitation, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .invite(&session, organization_id, &email, role, audit.get())
        .await?)
}

#[server]
pub async fn revoke_invitation(organization_id: Uuid, invitation_id: Uuid) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .revoke_invitation(&session, organization_id, invitation_id, audit.get())
        .await?)
}

/// Accepts an invitation as the signed-in operator. Returns the
/// organization joined.
#[server]
pub async fn accept_invitation(code: InvitationCode) -> Result<Uuid, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::organizations()?
        .accept_invitation(&session, code.expose(), audit.get())
        .await?)
}

/// What the invitation page shows for a code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationPageData {
    /// `None` when the code is not an open invitation.
    pub invitation: Option<InvitationPreview>,
    pub signed_in_as: Option<AccountSummary>,
}

/// Public: the code is the credential. The server's session guard lets this
/// exact path through without a session and attaches one when present.
#[server(prefix = "/auth/invitation", endpoint = "preview")]
pub async fn preview_invitation(code: InvitationCode) -> Result<InvitationPageData, AppError> {
    let invitation = org_context::auth()?
        .preview_invitation(code.expose())
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "invitation lookup failed");
            AppError::Unavailable
        })?;
    Ok(InvitationPageData {
        invitation,
        signed_in_as: org_context::optional_session().map(|session| session.summary()),
    })
}

/// A password typed into a form. Never printed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasswordInput(String);

impl fmt::Debug for PasswordInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordInput([REDACTED])")
    }
}

/// Public: creates an account for the invited email and joins the
/// organization. The invitee signs in afterwards.
#[server(prefix = "/auth/invitation", endpoint = "sign-up")]
pub async fn sign_up_with_invitation(
    code: InvitationCode,
    display_name: String,
    password: PasswordInput,
    password_confirmation: PasswordInput,
) -> Result<Uuid, AppError> {
    if password.0 != password_confirmation.0 {
        return Err(AppError::Rejected(
            "The passwords do not match.".to_string(),
        ));
    }
    let password = secrecy::SecretString::from(password.0);
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .accept_invitation_with_new_account(code.expose(), &display_name, &password, audit.get())
        .await?)
}

/// Changes the signed-in operator's display name.
#[server]
pub async fn update_profile(display_name: String) -> Result<AccountSummary, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .update_display_name(&session, &display_name, audit.get())
        .await?)
}

/// Changes the signed-in operator's password and signs out their other
/// sessions. Returns how many were signed out.
#[server]
pub async fn change_password(
    current_password: PasswordInput,
    new_password: PasswordInput,
    new_password_confirmation: PasswordInput,
) -> Result<u64, AppError> {
    let session = org_context::session()?;
    if new_password.0 != new_password_confirmation.0 {
        return Err(AppError::Rejected(
            "The new passwords do not match.".to_string(),
        ));
    }
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .change_password(
            &session,
            &secrecy::SecretString::from(current_password.0),
            &secrecy::SecretString::from(new_password.0),
            audit.get(),
        )
        .await?)
}

/// The signed-in operator's live sessions.
#[server]
pub async fn list_sessions() -> Result<Vec<SessionSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::auth()?.list_sessions(&session).await?)
}

/// Signs out one of the operator's other sessions. The current session
/// ends through the regular sign-out form instead.
#[server]
pub async fn revoke_session(session_id: Uuid) -> Result<(), AppError> {
    let session = org_context::session()?;
    if session_id == session.session_id {
        return Err(AppError::Rejected(
            "Use Sign out to end the session you are using.".to_string(),
        ));
    }
    let audit = org_context::AuditContext::current();
    if org_context::auth()?
        .revoke_own_session(&session, session_id, audit.get())
        .await?
    {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Signs out every session of the operator except this one.
#[server]
pub async fn revoke_other_sessions() -> Result<u64, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .revoke_other_sessions(&session, audit.get())
        .await?)
}

/// Every account of the installation. Installation administrators only.
#[server]
pub async fn admin_list_accounts() -> Result<Vec<AdminAccountSummary>, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .admin_list_accounts(&session, audit.get())
        .await?)
}

/// Every organization and registered project. Installation administrators
/// only; the list grants no access to the projects themselves.
#[server]
pub async fn admin_list_resources() -> Result<RegisteredResources, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .admin_list_resources(&session, audit.get())
        .await?)
}

/// Disables or re-enables another account. Installation administrators
/// only.
#[server]
pub async fn admin_set_account_disabled(
    account_id: Uuid,
    disabled: bool,
) -> Result<bool, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::auth()?
        .admin_set_account_disabled(&session, account_id, disabled, audit.get())
        .await?)
}
