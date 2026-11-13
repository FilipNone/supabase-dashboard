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
    authority::ProjectTrust,
    authz::OrgRole,
    connection::{
        CredentialKind, CredentialOverview, HealthDigest, HealthHistory, HealthReport,
        SavedCredential,
    },
    dokploy::DokployOverview,
    dokploy_placement::PlacementOverview,
    dokploy_target::StackTargetsOverview,
    health::InstallationHealth,
    invitation::{InvitationCode, InvitationPreview, InvitationSummary, IssuedInvitation},
    organization::{MemberSummary, OrganizationSummary},
    project::ProjectSummary,
    provisioning::{ProvisionJobSummary, ProvisionTargets, StackAction, StackDeploymentView},
    stack_settings::{StackConfigPreview, StackSettingsView},
    studio_access::StudioAccessLog,
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
        dokploy::DokployService,
        organizations::OrganizationService,
        projects::ProjectService,
        provisioning::ProvisioningService,
        studio_access::StudioAccessService,
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

    pub fn studio_access() -> Result<Arc<StudioAccessService>, AppError> {
        use_context::<Arc<StudioAccessService>>().ok_or_else(|| {
            tracing::error!("Studio access log service is not configured");
            AppError::Unavailable
        })
    }

    pub fn connections() -> Result<Arc<ConnectionService>, AppError> {
        use_context::<Arc<ConnectionService>>().ok_or_else(|| {
            tracing::error!("connection service is not configured");
            AppError::Unavailable
        })
    }

    pub fn dokploy() -> Result<Arc<DokployService>, AppError> {
        use_context::<Arc<DokployService>>().ok_or_else(|| {
            tracing::error!("Dokploy service is not configured");
            AppError::Unavailable
        })
    }

    pub fn provisioning() -> Result<Arc<ProvisioningService>, AppError> {
        use_context::<Arc<ProvisioningService>>().ok_or_else(|| {
            tracing::error!("provisioning service is not configured");
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
) -> Result<SavedCredential, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let value = secrecy::SecretString::from(value.0);
    Ok(org_context::connections()?
        .replace_credential(&session, id, kind, &value, audit.get())
        .await?)
}

/// Stores or replaces the gateway's Studio login for a project, after
/// trying it against the gateway's Studio route.
#[server]
pub async fn replace_studio_login(
    id: Uuid,
    username: String,
    password: SecretInput,
) -> Result<SavedCredential, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let login = supabase_dashboard_domain::connection::check_studio_login(&username, &password.0)
        .map_err(supabase_dashboard_application::connections::ConnectionError::from)?;
    let value = secrecy::SecretString::from(login);
    Ok(org_context::connections()?
        .replace_credential(
            &session,
            id,
            CredentialKind::StudioLogin,
            &value,
            audit.get(),
        )
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

/// The private certificate authorities stored for a project, summarized.
#[server]
pub async fn get_project_authorities(id: Uuid) -> Result<Option<ProjectTrust>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?
        .authorities(&session, id)
        .await?)
}

/// Stores or replaces the PEM certificates a project's gateway is checked
/// against, in addition to the shared roots.
#[server]
pub async fn replace_project_authorities(id: Uuid, pem: String) -> Result<ProjectTrust, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::connections()?
        .replace_authorities(&session, id, &pem, audit.get())
        .await?)
}

/// Deletes a project's stored certificate authorities.
#[server]
pub async fn remove_project_authorities(id: Uuid) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::connections()?
        .remove_authorities(&session, id, audit.get())
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

/// A project's kept checks: the newest in short, and counts over the
/// retention period.
#[server]
pub async fn get_project_health_history(id: Uuid) -> Result<HealthHistory, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?
        .health_history(&session, id)
        .await?)
}

/// Requests members sent through the project's Studio host, for owners and
/// admins: the newest page, or the page older than entry `before`; only
/// `member`'s requests when given.
#[server]
pub async fn get_studio_access_log(
    id: Uuid,
    member: Option<Uuid>,
    before: Option<i64>,
) -> Result<StudioAccessLog, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::studio_access()?
        .read(&session, id, member, before, audit.get())
        .await?)
}

/// The last check of each project in an organization, in short. Projects
/// never checked are left out.
#[server]
pub async fn list_project_health(organization_id: Uuid) -> Result<Vec<HealthDigest>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::connections()?
        .health_digests(&session, organization_id)
        .await?)
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

/// Where the operator may create a new stack in an organization. Owners
/// and admins only.
#[server]
pub async fn get_provision_targets(organization_id: Uuid) -> Result<ProvisionTargets, AppError> {
    let session = org_context::session()?;
    Ok(org_context::provisioning()?
        .targets(&session, organization_id)
        .await?)
}

/// Queues a new stack through Dokploy and returns the job's ID. The
/// server checks the role, the name, the host, and that the organization
/// may use `target`. Owners and admins only.
#[server]
pub async fn start_provisioning(
    organization_id: Uuid,
    name: String,
    target: String,
    host: String,
    // Set by a checkbox, so it is absent when unchecked.
    #[server(default)] https: bool,
) -> Result<Uuid, AppError> {
    use supabase_dashboard_application::provisioning::ProvisionRequest;
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let request = ProvisionRequest {
        name: &name,
        target: &target,
        host: &host,
        https,
    };
    Ok(org_context::provisioning()?
        .start(&session, organization_id, request, audit.get())
        .await?)
}

/// One provisioning job, for members of its organization.
#[server]
pub async fn get_provision_job(id: Uuid) -> Result<ProvisionJobSummary, AppError> {
    let session = org_context::session()?;
    Ok(org_context::provisioning()?.job(&session, id).await?)
}

/// The Dokploy service behind a provisioned project, as Dokploy reports
/// it now. Members of the project's organization; only owners and admins
/// see where it runs.
#[server]
pub async fn get_project_deployment(id: Uuid) -> Result<StackDeploymentView, AppError> {
    let session = org_context::session()?;
    Ok(org_context::provisioning()?
        .deployment(&session, id)
        .await?)
}

/// Queues a stop, start, or redeploy of a provisioned project's Dokploy
/// service and returns the job's ID. Owners and admins. Stopping takes the
/// stack offline, so it must be confirmed.
#[server]
pub async fn queue_stack_action(
    id: Uuid,
    action: StackAction,
    // Set by a checkbox, so it is absent when unchecked.
    #[server(default)] confirm: bool,
) -> Result<Uuid, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::provisioning()?
        .queue_action(&session, id, action, confirm, audit.get())
        .await?)
}

/// Queues removing a provisioned project's Dokploy service: `remove`
/// keeps the data volumes on the server, `destroy` deletes them. `name`
/// must be the project's name. Owners and admins remove; only owners
/// destroy. The project stays registered.
#[server]
pub async fn queue_stack_removal(
    id: Uuid,
    action: StackAction,
    name: String,
) -> Result<Uuid, AppError> {
    if !action.deletes_service() {
        return Err(AppError::Rejected(
            "Only removing or destroying a stack is asked for here.".to_string(),
        ));
    }
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::provisioning()?
        .queue_removal(&session, id, action, &name, audit.get())
        .await?)
}

/// A provisioned stack's settings, read from Dokploy, or `None` for a
/// project the dashboard did not provision or whose service it removed.
/// Owners and admins.
#[server]
pub async fn get_stack_settings(id: Uuid) -> Result<Option<StackSettingsView>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::provisioning()?
        .stack_settings(&session, id)
        .await?)
}

/// The settings a form submitted, one optional field per setting, named
/// after its variable in lowercase. A field the form left out (a disabled
/// input) is not changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SettingsFields {
    pub site_url: Option<String>,
    pub additional_redirect_urls: Option<String>,
    pub disable_signup: Option<String>,
    pub enable_email_autoconfirm: Option<String>,
    pub enable_anonymous_users: Option<String>,
    pub jwt_expiry: Option<String>,
    pub pgrst_db_schemas: Option<String>,
}

impl SettingsFields {
    #[cfg(feature = "ssr")]
    fn submitted(&self) -> Vec<(&'static str, &str)> {
        [
            ("SITE_URL", &self.site_url),
            ("ADDITIONAL_REDIRECT_URLS", &self.additional_redirect_urls),
            ("DISABLE_SIGNUP", &self.disable_signup),
            ("ENABLE_EMAIL_AUTOCONFIRM", &self.enable_email_autoconfirm),
            ("ENABLE_ANONYMOUS_USERS", &self.enable_anonymous_users),
            ("JWT_EXPIRY", &self.jwt_expiry),
            ("PGRST_DB_SCHEMAS", &self.pgrst_db_schemas),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.as_deref().map(|value| (name, value)))
        .collect()
    }
}

/// What applying the submitted settings would change. Nothing is
/// written. Owners and admins.
#[server]
pub async fn preview_stack_settings(
    id: Uuid,
    #[server(flatten)] fields: SettingsFields,
) -> Result<(SettingsFields, StackConfigPreview), AppError> {
    let session = org_context::session()?;
    let preview = org_context::provisioning()?
        .preview_settings(&session, id, &fields.submitted())
        .await?;
    Ok((fields, preview))
}

/// Queues writing the submitted settings and redeploying, and returns
/// the job's ID. `base` is the preview's digest of the settings it saw;
/// the server refuses when any of them changed since.
/// Owners and admins.
#[server]
pub async fn queue_stack_settings(
    id: Uuid,
    #[server(flatten)] fields: SettingsFields,
    base: String,
) -> Result<Uuid, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::provisioning()?
        .queue_settings(&session, id, &fields.submitted(), &base, audit.get())
        .await?)
}

/// An organization's latest provisioning jobs, newest first.
#[server]
pub async fn list_provision_jobs(
    organization_id: Uuid,
) -> Result<Vec<ProvisionJobSummary>, AppError> {
    let session = org_context::session()?;
    Ok(org_context::provisioning()?
        .jobs(&session, organization_id)
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

/// The installation's Dokploy connection, without its key. Installation
/// administrators only.
#[server]
pub async fn get_dokploy_connection() -> Result<DokployOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .overview(&session, audit.get())
        .await?)
}

/// Connects the installation to Dokploy. The key is stored only after
/// Dokploy accepts it and reports a supported version. Installation
/// administrators only.
#[server]
pub async fn connect_dokploy(url: String, key: SecretInput) -> Result<DokployOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let key = secrecy::SecretString::from(key.0);
    Ok(org_context::dokploy()?
        .connect(&session, &url, &key, audit.get())
        .await?)
}

/// Replaces the stored Dokploy key with one Dokploy accepts. Installation
/// administrators only.
#[server]
pub async fn replace_dokploy_key(key: SecretInput) -> Result<DokployOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let key = secrecy::SecretString::from(key.0);
    Ok(org_context::dokploy()?
        .replace_key(&session, &key, audit.get())
        .await?)
}

/// Deletes the dashboard's record of the Dokploy connection. Nothing in
/// Dokploy changes. Installation administrators only.
#[server]
pub async fn disconnect_dokploy() -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .remove(&session, audit.get())
        .await?)
}

/// Where the dashboard runs in Dokploy: the confirmed service, if any, and
/// the services Dokploy reports now, with those whose domain is the
/// dashboard's public host first. Installation administrators only.
#[server]
pub async fn get_dokploy_placement() -> Result<PlacementOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .placement(&session, audit.get())
        .await?)
}

/// Confirms a service the stored key can see as the dashboard's own.
/// `service` is the kind and ID as `compose:<id>` or `application:<id>`.
/// Installation administrators only.
#[server]
pub async fn confirm_dokploy_placement(service: String) -> Result<PlacementOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let (kind, id) = service.split_once(':').unwrap_or((service.as_str(), ""));
    Ok(org_context::dokploy()?
        .confirm_placement(&session, kind, id, audit.get())
        .await?)
}

/// Forgets the confirmed placement. Nothing in Dokploy changes.
/// Installation administrators only.
#[server]
pub async fn clear_dokploy_placement() -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .clear_placement(&session, audit.get())
        .await?)
}

/// Where organizations' new stacks may go: the default target, each
/// organization's allowed targets, and the environments and servers the
/// stored key can see. Installation administrators only.
#[server]
pub async fn get_dokploy_targets() -> Result<StackTargetsOverview, AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .stack_targets(&session, audit.get())
        .await?)
}

/// Allows `organization` a Dokploy environment, on Dokploy's own server
/// when `server` is empty or missing. Installation administrators only.
#[server]
pub async fn allow_dokploy_target(
    organization: Uuid,
    environment: String,
    server: Option<String>,
) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    let value = match server.as_deref().map(str::trim) {
        Some(server) if !server.is_empty() => format!("{}@{server}", environment.trim()),
        _ => environment.trim().to_owned(),
    };
    Ok(org_context::dokploy()?
        .allow_stack_target(&session, organization, &value, audit.get())
        .await?)
}

/// Removes target `id` from `organization`. Nothing in Dokploy changes.
/// Installation administrators only.
#[server]
pub async fn remove_dokploy_target(organization: Uuid, id: Uuid) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    Ok(org_context::dokploy()?
        .remove_stack_target(&session, organization, id, audit.get())
        .await?)
}

/// Creates an environment called `name` in Dokploy project `project`.
/// Installation administrators only.
#[server]
pub async fn create_dokploy_environment(project: String, name: String) -> Result<(), AppError> {
    let session = org_context::session()?;
    let audit = org_context::AuditContext::current();
    org_context::dokploy()?
        .create_environment(&session, &project, &name, audit.get())
        .await?;
    Ok(())
}
