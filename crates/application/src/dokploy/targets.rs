//! Where each dashboard organization's new stacks may go in Dokploy.
//!
//! An installation administrator allows an organization a Dokploy
//! environment on a Dokploy server, picked from what the stored key can
//! see. An organization with no targets of its own may use only the
//! dashboard's own environment, on the server the dashboard runs on, and
//! only while the confirmed placement still holds. Every change and every
//! refusal is audited.

use std::collections::HashMap;

use secrecy::SecretString;
use supabase_dashboard_domain::{
    dokploy::DokployUrl,
    dokploy_placement::{DokployId, PlacementStatus},
    dokploy_target::{
        AllowedStackTarget, DefaultTarget, MAX_LISTED_ENVIRONMENTS, MAX_LISTED_SERVERS,
        MAX_TARGETS_PER_ORGANIZATION, OrganizationStackTargets, StackTarget, StackTargetNames,
        StackTargetsOverview, TargetLookup, check_environment_name,
    },
    organization::OrganizationName,
};
use supabase_dashboard_persistence::{
    PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    dokploy::StoredDokployConnection,
    dokploy_targets::{AllowOutcome, NewStackTarget, StoredStackTarget},
};
use uuid::Uuid;

use super::{
    DokployService, DokployServiceError, DokployTargetInventory, is_transient, sealed, stored_url,
};
use crate::auth::{CurrentSession, RequestContext};

/// Most organizations listed on the administrator page.
const MAX_LISTED_ORGANIZATIONS: usize = 500;

/// The targets an organization may use for a new stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveTargets {
    /// Targets an installation administrator allowed the organization.
    Allowed(Vec<(StackTarget, StackTargetNames)>),
    /// The organization has none of its own, so the default applies: the
    /// dashboard's environment, or nothing when it is not available.
    Default(DefaultTarget),
}

impl DokployService {
    /// The stack targets section of the administrator page: the default
    /// target, each organization's allowed targets, and what the key can
    /// see in Dokploy now. A failed call to Dokploy is reported in the
    /// answer, so the stored targets still show.
    pub async fn stack_targets(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<StackTargetsOverview, DokployServiceError> {
        self.require_admin(current, "dokploy.view", ctx).await?;
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        let limit = i64::try_from(MAX_LISTED_ORGANIZATIONS + 1).unwrap_or(i64::MAX);
        let mut names = self.db.list_organization_names(limit).await?;
        let organizations_truncated = names.len() > MAX_LISTED_ORGANIZATIONS;
        names.truncate(MAX_LISTED_ORGANIZATIONS);
        let mut by_organization: HashMap<Uuid, Vec<AllowedStackTarget>> = HashMap::new();
        for row in self.db.list_dokploy_stack_targets().await? {
            by_organization
                .entry(row.organization_id)
                .or_default()
                .push(allowed_from_row(&row)?);
        }
        let organizations = names
            .into_iter()
            .map(|row| {
                Ok(OrganizationStackTargets {
                    organization_id: row.id,
                    organization_name: OrganizationName::parse(&row.name)
                        .map_err(|_| PersistenceError::InvalidRow("organizations.name"))?,
                    allowed: by_organization.remove(&row.id).unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>, PersistenceError>>()?;
        let lookup = match self.read_targets(&stored).await {
            Ok(mut inventory) => {
                let truncated = inventory.environments.len() > MAX_LISTED_ENVIRONMENTS
                    || inventory
                        .servers
                        .as_ref()
                        .is_some_and(|servers| servers.len() > MAX_LISTED_SERVERS);
                inventory.environments.truncate(MAX_LISTED_ENVIRONMENTS);
                if let Some(servers) = inventory.servers.as_mut() {
                    servers.truncate(MAX_LISTED_SERVERS);
                }
                TargetLookup::Found {
                    inventory,
                    truncated,
                }
            }
            Err(err) => TargetLookup::Failed(err.to_string()),
        };
        Ok(StackTargetsOverview {
            default_target: self.default_target(&stored).await?,
            organizations,
            organizations_truncated,
            lookup,
        })
    }

    /// The targets `organization_id` may use for a new stack. No operator
    /// is involved, so nothing is checked or audited here; callers must
    /// have authorized the operation they use it for.
    pub async fn organization_targets(
        &self,
        organization_id: Uuid,
    ) -> Result<EffectiveTargets, DokployServiceError> {
        let Some(stored) = self.db.find_dokploy_connection().await? else {
            return Err(DokployServiceError::NotConnected);
        };
        let rows = self
            .db
            .list_organization_stack_targets(organization_id)
            .await?;
        if rows.is_empty() {
            return Ok(EffectiveTargets::Default(
                self.default_target(&stored).await?,
            ));
        }
        rows.iter()
            .map(|row| {
                let allowed = allowed_from_row(row)?;
                Ok((allowed.target, allowed.names))
            })
            .collect::<Result<_, PersistenceError>>()
            .map(EffectiveTargets::Allowed)
            .map_err(DokployServiceError::from)
    }

    /// Allows `organization_id` the target a form sent as `value` (see
    /// [`StackTarget::value`]). Dokploy is asked again, and the target is
    /// stored with the names Dokploy reports, only if the stored key can
    /// see the environment and, for a remote server, the server.
    pub async fn allow_stack_target(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        value: &str,
        ctx: RequestContext<'_>,
    ) -> Result<(), DokployServiceError> {
        let action = "dokploy.target_allow";
        self.require_admin(current, action, ctx).await?;
        let refuse = |err: DokployServiceError| async {
            self.audit_best_effort(&organization_event(
                current,
                action,
                organization_id,
                AuditOutcome::Failure,
                ctx,
            ))
            .await;
            Err(err)
        };
        let Some(target) = StackTarget::parse_value(value) else {
            return refuse(DokployServiceError::TargetNotVisible).await;
        };
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        let inventory = match self.read_targets(&stored).await {
            Ok(inventory) => inventory,
            Err(err) => return refuse(err).await,
        };
        let Some(environment) = inventory.environment(&target.environment_id) else {
            return refuse(DokployServiceError::TargetNotVisible).await;
        };
        let server = match &target.server_id {
            Some(id) => match inventory.server(id) {
                Some(server) => Some((server.id.as_str(), server.name.as_str())),
                None => return refuse(DokployServiceError::TargetNotVisible).await,
            },
            None => None,
        };
        let outcome = self
            .db
            .allow_dokploy_stack_target(
                &NewStackTarget {
                    url: &stored.url,
                    organization_id,
                    project_id: environment.project_id.as_str(),
                    project_name: &environment.project_name,
                    environment_id: environment.environment_id.as_str(),
                    environment_name: &environment.environment_name,
                    server,
                    added_by: current.account.id,
                    limit: MAX_TARGETS_PER_ORGANIZATION,
                },
                &organization_event(current, action, organization_id, AuditOutcome::Success, ctx),
            )
            .await?;
        let err = match outcome {
            AllowOutcome::Added(_) => {
                tracing::info!(
                    %organization_id,
                    environment_id = target.environment_id.as_str(),
                    server_id = target.server_id.as_ref().map(DokployId::as_str),
                    "Dokploy stack target allowed"
                );
                return Ok(());
            }
            AllowOutcome::AlreadyAllowed => DokployServiceError::TargetAlreadyAllowed,
            AllowOutcome::LimitReached => DokployServiceError::TooManyTargets,
            AllowOutcome::NotConnected => DokployServiceError::NotConnected,
            AllowOutcome::NoOrganization => DokployServiceError::OrganizationNotFound,
        };
        refuse(err).await
    }

    /// Removes target `target_id` from `organization_id`. Nothing in
    /// Dokploy changes, and stacks already created there stay.
    pub async fn remove_stack_target(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        target_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), DokployServiceError> {
        let action = "dokploy.target_remove";
        self.require_admin(current, action, ctx).await?;
        let removed = self
            .db
            .remove_dokploy_stack_target(
                organization_id,
                target_id,
                &organization_event(current, action, organization_id, AuditOutcome::Success, ctx),
            )
            .await?;
        if removed.is_none() {
            return Err(DokployServiceError::TargetNotFound);
        }
        tracing::info!(%organization_id, %target_id, "Dokploy stack target removed");
        Ok(())
    }

    /// Creates an environment called `name` in Dokploy project
    /// `project_id`, which the stored key must see, and returns its ID.
    /// Dokploy accepts a name that is taken, so a project that already has
    /// the name (without case) is refused first; that also keeps a second
    /// click from making a duplicate. The request is sent once: when
    /// Dokploy does not answer, the outcome is reported as unknown.
    pub async fn create_environment(
        &self,
        current: &CurrentSession,
        project_id: &str,
        name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<DokployId, DokployServiceError> {
        let action = "dokploy.environment_create";
        self.require_admin(current, action, ctx).await?;
        let name = check_environment_name(name)?;
        let project = DokployId::parse(project_id).ok();
        let refuse = |err: DokployServiceError| async {
            self.audit_best_effort(&project_event(
                current,
                action,
                project.as_ref(),
                None,
                AuditOutcome::Failure,
                ctx,
            ))
            .await;
            Err(err)
        };
        let Some(project_id) = project.clone() else {
            return refuse(DokployServiceError::ProjectNotVisible).await;
        };
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        let inventory = match self.read_targets(&stored).await {
            Ok(inventory) => inventory,
            Err(err) => return refuse(err).await,
        };
        if !inventory.projects().iter().any(|(id, _)| id == &project_id) {
            return refuse(DokployServiceError::ProjectNotVisible).await;
        }
        if inventory.has_environment_named(&project_id, name) {
            return refuse(DokployServiceError::EnvironmentExists).await;
        }
        let (url, key) = self.open_key(&stored)?;
        match self
            .connector
            .create_environment(&url, &key, &project_id, name)
            .await
        {
            Ok(environment_id) => {
                self.audit_best_effort(&project_event(
                    current,
                    action,
                    Some(&project_id),
                    Some(&environment_id),
                    AuditOutcome::Success,
                    ctx,
                ))
                .await;
                tracing::info!(
                    project_id = project_id.as_str(),
                    environment_id = environment_id.as_str(),
                    "Dokploy environment created"
                );
                Ok(environment_id)
            }
            Err(err) => {
                tracing::warn!(error = %err, project_id = project_id.as_str(), "Dokploy did not create the environment");
                let err = if is_transient(&err) {
                    DokployServiceError::EnvironmentOutcomeUnknown
                } else {
                    err.into()
                };
                refuse(err).await
            }
        }
    }

    /// The dashboard's own environment, on the server the dashboard runs
    /// on, while the confirmed placement still holds. A service whose
    /// domain changed is still in the same environment, so it counts.
    async fn default_target(
        &self,
        stored: &StoredDokployConnection,
    ) -> Result<DefaultTarget, DokployServiceError> {
        let Some(confirmed) = self.confirmed_placement().await? else {
            return Ok(DefaultTarget::NoPlacement);
        };
        let inventory = match self.read_inventory(stored).await {
            Ok(inventory) => inventory,
            Err(err) => return Ok(DefaultTarget::Unavailable(err.to_string())),
        };
        let status = PlacementStatus::check(
            &confirmed.placement,
            &inventory,
            self.public_host.as_deref(),
        );
        let service = match (&status, inventory.service(&confirmed.placement.service)) {
            (PlacementStatus::Current | PlacementStatus::DomainChanged, Some(service)) => service,
            _ => return Ok(DefaultTarget::Unavailable(status.message())),
        };
        Ok(DefaultTarget::Placement {
            target: StackTarget {
                environment_id: service.environment_id.clone(),
                server_id: service.server_id.clone(),
            },
            names: StackTargetNames {
                project_name: service.project_name.clone(),
                environment_name: service.environment_name.clone(),
                // Dokploy names a server it lists; its ID stands in otherwise.
                server_name: service.server_id.as_ref().map(|id| {
                    service
                        .server_name
                        .clone()
                        .unwrap_or_else(|| id.as_str().to_owned())
                }),
            },
        })
    }

    /// Reads the environments and servers the stored key can see.
    async fn read_targets(
        &self,
        stored: &StoredDokployConnection,
    ) -> Result<DokployTargetInventory, DokployServiceError> {
        let (url, key) = self.open_key(stored)?;
        Ok(self.connector.targets(&url, &key).await?)
    }

    /// The stored URL and the key opened with this server's credential
    /// key.
    pub(super) fn open_key(
        &self,
        stored: &StoredDokployConnection,
    ) -> Result<(DokployUrl, SecretString), DokployServiceError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(DokployServiceError::StorageUnavailable)?;
        let url = stored_url(stored)?;
        let key = cipher.open_dokploy_key(url.as_str(), &sealed(stored))?;
        Ok((url, key))
    }
}

fn allowed_from_row(row: &StoredStackTarget) -> Result<AllowedStackTarget, PersistenceError> {
    let invalid = |column| PersistenceError::InvalidRow(column);
    let id = |raw: &str, column| DokployId::parse(raw).map_err(|_| invalid(column));
    let server_id = row
        .server_id
        .as_deref()
        .map(|raw| id(raw, "dokploy_stack_targets.server_id"))
        .transpose()?;
    Ok(AllowedStackTarget {
        id: row.id,
        target: StackTarget {
            environment_id: id(&row.environment_id, "dokploy_stack_targets.environment_id")?,
            server_id,
        },
        project_id: id(&row.project_id, "dokploy_stack_targets.project_id")?,
        names: StackTargetNames {
            project_name: row.project_name.clone(),
            environment_name: row.environment_name.clone(),
            server_name: row.server_name.clone(),
        },
        added_at: row.added_at,
        added_by: row.added_by()?,
    })
}

/// An audit event naming the dashboard organization whose targets changed.
fn organization_event<'a>(
    current: &CurrentSession,
    action: &'static str,
    organization_id: Uuid,
    outcome: AuditOutcome,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some("organization"),
        target_id: Some(organization_id.to_string()),
        outcome,
        request_id: ctx.request_id,
    }
}

/// An audit event naming a Dokploy project, and the environment created in
/// it, by checked Dokploy IDs only.
fn project_event<'a>(
    current: &CurrentSession,
    action: &'static str,
    project: Option<&DokployId>,
    environment: Option<&DokployId>,
    outcome: AuditOutcome,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    let target_id = project.map(|project| match environment {
        Some(environment) => format!("{}/{}", project.as_str(), environment.as_str()),
        None => project.as_str().to_owned(),
    });
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some("dokploy_project"),
        target_id,
        outcome,
        request_id: ctx.request_id,
    }
}
