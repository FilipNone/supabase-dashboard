//! Adopting a Supabase stack that already runs as a Dokploy compose
//! service, for example one made from Dokploy's Supabase template.
//!
//! Owners and admins of an organization list the compose services in the
//! Dokploy environments an installation administrator allowed for it
//! explicitly. The default environment, which every organization without
//! targets of its own shares, is never searched. A service's compose file
//! and variables are read only once a member picks it, and only after
//! the service is found in an allowed environment and on an allowed
//! server. The preview names the keys it found, never their values.
//!
//! Adopting registers the project with the service's gateway URL and its
//! Dokploy service, and records the variables as they are, so later edits
//! in Dokploy are listed. The keys and the Studio login are copied only
//! when the member confirms it. Nothing is written to Dokploy.

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_domain::{
    adoption::{
        ANON_KEY_VARIABLE, AdoptableService, AdoptableServices, AdoptionPreview, AdoptionRefusal,
        KeyCheck, KeyState, MAX_ADOPTABLE_LISTED, SERVICE_ROLE_KEY_VARIABLE,
        STUDIO_PASSWORD_VARIABLE, STUDIO_USERNAME_VARIABLE, gateway_urls, looks_like_supabase,
        read_value,
    },
    authz::Permission,
    connection::{CredentialKind, check_api_key, check_studio_login},
    dokploy_compose::ComposeDetails,
    dokploy_placement::DokployId,
    dokploy_target::{StackTarget, StackTargetNames},
    project::{MAX_PROJECTS_PER_ORGANIZATION, ProjectName, ProjectUrl},
    stack_settings::EnvFile,
};
use supabase_dashboard_persistence::{
    audit::AuditOutcome,
    connections::NewCredential,
    projects::NewProject,
    provisioning::{NewDokployService, RegisterProvisionedOutcome},
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ComposeConfig, ProvisionError, ProvisioningService, env_record::EnvRecord};
use crate::{
    auth::{CurrentSession, RequestContext},
    dokploy::{DokployCredentials, DokployServiceError, EffectiveTargets},
    key_claims,
    organizations::event,
    secrets::CipherError,
};

const ACTION: &str = "project.adopt";
const COPY_ACTION: &str = "project.adopt_keys";

/// What a member asked to adopt.
#[derive(Debug, Clone, Copy)]
pub struct AdoptRequest<'a> {
    pub compose_id: &'a str,
    pub name: &'a str,
    /// One of the preview's URLs.
    pub api_url: &'a str,
    /// Copy the keys and the Studio login from the service's variables.
    pub copy_keys: bool,
}

/// A chosen service, read from Dokploy and checked.
struct Candidate {
    details: ComposeDetails,
    config: ComposeConfig,
    preview: AdoptionPreview,
    /// The usable keys, with the values to store.
    keys: Vec<(CredentialKind, SecretString)>,
}

impl ProvisioningService {
    /// The compose services an owner or admin of `organization_id` may
    /// adopt: those in its explicitly allowed environments that no project
    /// runs as yet.
    pub async fn adoptable(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<AdoptableServices, ProvisionError> {
        self.require(current, organization_id, Permission::ProjectRegister)
            .await?;
        let allowed = match self.adoption_targets(organization_id).await {
            Ok(Some(allowed)) => allowed,
            Ok(None) => return Ok(AdoptableServices::NoTarget),
            Err(ProvisionError::NotConnected) => return Ok(AdoptableServices::NotConnected),
            Err(err) => return Err(err),
        };
        let Some(compose) = self.compose.clone() else {
            return Ok(AdoptableServices::Unsupported);
        };
        let Some(credentials) = self.adoption_credentials().await? else {
            return Ok(AdoptableServices::NotConnected);
        };
        let mut listed: Vec<DokployId> = Vec::new();
        let mut services = Vec::new();
        let mut unavailable = Vec::new();
        for (target, names) in &allowed {
            // Targets on several servers can share an environment.
            if listed.contains(&target.environment_id) {
                continue;
            }
            listed.push(target.environment_id.clone());
            let location = environment_label(names);
            match compose
                .list_compose(&credentials.url, &credentials.key, &target.environment_id)
                .await
            {
                Ok(found) => services.extend(found.into_iter().map(|service| AdoptableService {
                    compose_id: service.compose_id.as_str().to_owned(),
                    name: service.name,
                    location: location.clone(),
                })),
                Err(err) => {
                    tracing::warn!(error = %err, environment = %target.environment_id.as_str(), "could not list compose services to adopt");
                    unavailable.push(location);
                }
            }
        }
        let ids: Vec<String> = services.iter().map(|s| s.compose_id.clone()).collect();
        let taken = self.db.registered_compose_ids(&ids).await?;
        services.retain(|service| !taken.contains(&service.compose_id));
        services.sort_by(|a, b| a.name.cmp(&b.name).then(a.location.cmp(&b.location)));
        let truncated = services.len() > MAX_ADOPTABLE_LISTED;
        services.truncate(MAX_ADOPTABLE_LISTED);
        Ok(AdoptableServices::Found {
            services,
            truncated,
            unavailable,
        })
    }

    /// What adopting `compose_id` would register, for an owner or admin.
    pub async fn adoption_preview(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        compose_id: &str,
    ) -> Result<AdoptionPreview, ProvisionError> {
        self.require(current, organization_id, Permission::ProjectRegister)
            .await?;
        Ok(self.candidate(organization_id, compose_id).await?.preview)
    }

    /// Registers `request.compose_id` as a project of `organization_id`
    /// and returns the project's ID. Owners and admins only.
    pub async fn adopt(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        request: AdoptRequest<'_>,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if !membership.role.allows(Permission::ProjectRegister) {
            let denied = event(
                current,
                ACTION,
                ("organization", organization_id.to_string()),
                AuditOutcome::Denied,
                ctx,
            );
            if let Err(err) = self.db.record_audit_event(&denied).await {
                tracing::error!(error = %err, action = ACTION, "could not record audit event");
            }
            return Err(ProvisionError::Forbidden);
        }
        let name = ProjectName::parse(request.name)?;
        let cipher = self.cipher.as_ref().ok_or(ProvisionError::NoCipher)?;
        let candidate = self.candidate(organization_id, request.compose_id).await?;
        if let Some(refusal) = candidate.preview.refusal {
            return Err(ProvisionError::NotAdoptable(refusal));
        }
        if !candidate
            .preview
            .urls
            .iter()
            .any(|url| url == request.api_url)
        {
            return Err(ProvisionError::UrlNotOffered);
        }
        let api_url = ProjectUrl::parse(request.api_url)?;
        let project_id = Uuid::now_v7();
        let env = EnvFile::parse(candidate.config.env.expose_secret());
        let env_record = EnvRecord::of(&env).seal(cipher, project_id)?;
        let copied: &[(CredentialKind, SecretString)] = if request.copy_keys {
            &candidate.keys
        } else {
            &[]
        };
        let sealed = copied
            .iter()
            .map(|(kind, value)| Ok((*kind, cipher.seal(project_id, *kind, value)?)))
            .collect::<Result<Vec<_>, CipherError>>()?;
        let credentials: Vec<NewCredential<'_>> = sealed
            .iter()
            .map(|(kind, sealed)| NewCredential {
                project_id,
                kind: *kind,
                key_id: &sealed.key_id,
                nonce: &sealed.nonce,
                ciphertext: &sealed.ciphertext,
                updated_by: current.account.id,
            })
            .collect();
        let target = ("project", project_id.to_string());
        let mut audits = vec![event(
            current,
            ACTION,
            target.clone(),
            AuditOutcome::Success,
            ctx,
        )];
        if !credentials.is_empty() {
            audits.push(event(
                current,
                COPY_ACTION,
                target,
                AuditOutcome::Success,
                ctx,
            ));
        }
        let details = &candidate.details;
        let outcome = self
            .db
            .register_provisioned_project(
                &NewProject {
                    id: project_id,
                    organization_id,
                    name: &name,
                    api_url: &api_url,
                    created_by: current.account.id,
                },
                &NewDokployService {
                    compose_id: details.compose_id.as_str(),
                    app_name: &details.app_name,
                    environment_id: details.environment_id.as_str(),
                    server_id: details.server_id.as_ref().map(DokployId::as_str),
                    job_id: None,
                    env_record: Some(&env_record),
                },
                &credentials,
                MAX_PROJECTS_PER_ORGANIZATION,
                &audits,
            )
            .await?;
        match outcome {
            RegisterProvisionedOutcome::Created => Ok(project_id),
            RegisterProvisionedOutcome::AlreadyRegistered
            | RegisterProvisionedOutcome::ServiceTaken => Err(ProvisionError::AlreadyAdopted),
            RegisterProvisionedOutcome::OrganizationNotFound => Err(ProvisionError::NotFound),
            RegisterProvisionedOutcome::LimitReached => Err(ProvisionError::LimitReached),
        }
    }

    /// The organization's explicitly allowed targets, or `None` when it
    /// has none and the shared default would apply.
    async fn adoption_targets(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<Vec<(StackTarget, StackTargetNames)>>, ProvisionError> {
        match self.dokploy.organization_targets(organization_id).await {
            Ok(EffectiveTargets::Allowed(allowed)) => Ok(Some(allowed)),
            Ok(EffectiveTargets::Default(_)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn adoption_credentials(&self) -> Result<Option<DokployCredentials>, ProvisionError> {
        match self.dokploy.credentials().await {
            Ok(credentials) => Ok(credentials),
            Err(DokployServiceError::NotConnected) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Reads and checks `compose_id`. A service Dokploy does not have, or
    /// has outside the allowed targets, is refused the same way, before
    /// its variables are read.
    async fn candidate(
        &self,
        organization_id: Uuid,
        compose_id: &str,
    ) -> Result<Candidate, ProvisionError> {
        let compose_id =
            DokployId::parse(compose_id).map_err(|_| ProvisionError::AdoptionNotAllowed)?;
        let allowed = self
            .adoption_targets(organization_id)
            .await?
            .ok_or(ProvisionError::AdoptionNotAllowed)?;
        let compose = self.compose.clone().ok_or_else(|| {
            ProvisionError::DokployUnavailable(
                "This server does not read Dokploy services.".to_owned(),
            )
        })?;
        let credentials = self
            .adoption_credentials()
            .await?
            .ok_or(ProvisionError::NotConnected)?;
        let unavailable = |err: supabase_dashboard_domain::dokploy::DokployError| {
            ProvisionError::DokployUnavailable(err.to_string())
        };
        let details = compose
            .compose_details(&credentials.url, &credentials.key, &compose_id)
            .await
            .map_err(unavailable)?
            .ok_or(ProvisionError::AdoptionNotAllowed)?;
        let target = StackTarget {
            environment_id: details.environment_id.clone(),
            server_id: details.server_id.clone(),
        };
        if !allowed.iter().any(|(allowed, _)| *allowed == target) {
            return Err(ProvisionError::AdoptionNotAllowed);
        }
        if !self
            .db
            .registered_compose_ids(&[compose_id.as_str().to_owned()])
            .await?
            .is_empty()
        {
            return Err(ProvisionError::AlreadyAdopted);
        }
        let config = compose
            .compose_config(&credentials.url, &credentials.key, &compose_id)
            .await
            .map_err(unavailable)?
            .ok_or(ProvisionError::AdoptionNotAllowed)?;
        let domains = compose
            .compose_domains(&credentials.url, &credentials.key, &compose_id)
            .await
            .map_err(unavailable)?;
        let urls = gateway_urls(&domains);
        let refusal = if !looks_like_supabase(&config.compose_file) {
            Some(AdoptionRefusal::NotSupabase)
        } else if urls.is_empty() {
            Some(AdoptionRefusal::NoDomain)
        } else {
            None
        };
        let env = EnvFile::parse(config.env.expose_secret());
        let now = OffsetDateTime::now_utc();
        let mut checks = Vec::new();
        let mut keys = Vec::new();
        for (kind, variable) in [
            (CredentialKind::AnonKey, ANON_KEY_VARIABLE),
            (CredentialKind::ServiceRoleKey, SERVICE_ROLE_KEY_VARIABLE),
        ] {
            let state = match read_value(&env, variable) {
                Err(state) => state,
                Ok(None) => KeyState::Missing,
                Ok(Some(raw)) => match check_api_key(kind, raw)
                    .and_then(|value| key_claims::check_claims(kind, value, now).map(|()| value))
                {
                    Ok(value) => {
                        keys.push((kind, SecretString::from(value.to_owned())));
                        KeyState::Found
                    }
                    Err(err) => KeyState::Invalid(err.to_string()),
                },
            };
            checks.push(KeyCheck {
                variable: variable.to_owned(),
                state,
            });
        }
        let login_state = match (
            read_value(&env, STUDIO_USERNAME_VARIABLE),
            read_value(&env, STUDIO_PASSWORD_VARIABLE),
        ) {
            (Err(state), _) | (_, Err(state)) => state,
            (Ok(None), _) | (_, Ok(None)) => KeyState::Missing,
            (Ok(Some(username)), Ok(Some(password))) => {
                match check_studio_login(username, password) {
                    Ok(login) => {
                        keys.push((CredentialKind::StudioLogin, SecretString::from(login)));
                        KeyState::Found
                    }
                    Err(err) => KeyState::Invalid(err.to_string()),
                }
            }
        };
        checks.push(KeyCheck {
            variable: format!("{STUDIO_USERNAME_VARIABLE} and {STUDIO_PASSWORD_VARIABLE}"),
            state: login_state,
        });
        let location = StackTargetNames {
            project_name: details.project_name.clone(),
            environment_name: details.environment_name.clone(),
            server_name: details.server_name.clone(),
        }
        .label();
        let preview = AdoptionPreview {
            compose_id: details.compose_id.as_str().to_owned(),
            name: details.name.clone(),
            location,
            suggested_name: ProjectName::parse(&details.name)
                .ok()
                .map(|name| name.as_str().to_owned()),
            urls,
            keys: checks,
            refusal,
        };
        Ok(Candidate {
            details,
            config,
            preview,
            keys,
        })
    }
}

/// `Project / environment`, without the server: a listed service may run
/// on any of the environment's servers.
fn environment_label(names: &StackTargetNames) -> String {
    format!("{} / {}", names.project_name, names.environment_name)
}
