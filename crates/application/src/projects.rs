//! Project registry use cases. Every method checks the operator's role in
//! the project's organization on the server.
//!
//! A project in an organization the operator does not belong to is reported
//! as [`ProjectError::NotFound`], exactly like one that does not exist.

use supabase_dashboard_domain::{
    authz::{OrgRole, Permission},
    project::{
        MAX_PROJECTS_PER_ORGANIZATION, ProjectInputError, ProjectName, ProjectSummary,
        check_registration_url,
    },
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::AuditOutcome,
    projects::{CreateProjectOutcome, NewProject, ProjectAccess, ProjectRecord},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    organizations::event,
};

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    /// The project or organization does not exist, or the operator is not a
    /// member of it.
    #[error("project not found")]
    NotFound,
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    #[error(
        "this organization already has {MAX_PROJECTS_PER_ORGANIZATION} projects; \
         unregister one before adding another"
    )]
    LimitReached,
    #[error("type the project name exactly to confirm")]
    ConfirmationMismatch,
    #[error(transparent)]
    Input(#[from] ProjectInputError),
    /// Internal failure. The message is for server logs only.
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

/// What the operator entered to register a project.
#[derive(Debug, Clone, Copy)]
pub struct Registration<'a> {
    pub name: &'a str,
    pub api_url: &'a str,
    /// The operator confirmed that plain HTTP is acceptable for this URL.
    pub allow_unencrypted: bool,
}

pub struct ProjectService {
    db: Database,
}

impl ProjectService {
    pub const fn new(db: Database) -> Self {
        Self { db }
    }

    /// Projects of an organization the operator belongs to, by name.
    pub async fn list(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<Vec<ProjectSummary>, ProjectError> {
        let role = self
            .org_role(current, organization_id, Permission::ProjectRead)
            .await?;
        let projects = self
            .db
            .list_projects(organization_id, MAX_PROJECTS_PER_ORGANIZATION)
            .await?;
        Ok(projects
            .into_iter()
            .map(|project| summary(project, role))
            .collect())
    }

    pub async fn get(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<ProjectSummary, ProjectError> {
        let access = self
            .project_access(current, project_id, Permission::ProjectRead)
            .await?;
        Ok(summary(access.project, access.role))
    }

    /// Records an existing stack under the organization. Nothing is sent to
    /// the stack.
    pub async fn register(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        input: Registration<'_>,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectSummary, ProjectError> {
        let action = "project.register";
        let role = match self
            .org_role(current, organization_id, Permission::ProjectRegister)
            .await
        {
            Err(ProjectError::Forbidden) => {
                let target = ("organization", organization_id.to_string());
                self.deny(current, action, target, ctx).await;
                return Err(ProjectError::Forbidden);
            }
            other => other?,
        };
        let name = ProjectName::parse(input.name)?;
        let api_url = check_registration_url(input.api_url, input.allow_unencrypted)?;
        let id = Uuid::now_v7();
        let outcome = self
            .db
            .create_project(
                &NewProject {
                    id,
                    organization_id,
                    name: &name,
                    api_url: &api_url,
                    created_by: current.account.id,
                },
                MAX_PROJECTS_PER_ORGANIZATION,
                &event(
                    current,
                    action,
                    ("project", id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        match outcome {
            CreateProjectOutcome::Created => Ok(ProjectSummary {
                id,
                organization_id,
                name,
                api_url,
                // Close enough for the response; reads use the stored value.
                created_at: OffsetDateTime::now_utc(),
                role,
            }),
            CreateProjectOutcome::OrganizationNotFound => Err(ProjectError::NotFound),
            CreateProjectOutcome::LimitReached => Err(ProjectError::LimitReached),
        }
    }

    pub async fn rename(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        name: &str,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectSummary, ProjectError> {
        let action = "project.rename";
        let access = self
            .audited_access(current, project_id, Permission::ProjectUpdate, action, ctx)
            .await?;
        let name = ProjectName::parse(name)?;
        let target = ("project", project_id.to_string());
        let renamed = self
            .db
            .rename_project(
                project_id,
                &name,
                &event(current, action, target, AuditOutcome::Success, ctx),
            )
            .await?;
        if !renamed {
            return Err(ProjectError::NotFound);
        }
        Ok(summary(
            ProjectRecord {
                name,
                ..access.project
            },
            access.role,
        ))
    }

    /// Removes the registry entry after the operator typed the project's
    /// name. The stack, its services, and its data are left as they are.
    pub async fn unregister(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        confirmation: &str,
        ctx: RequestContext<'_>,
    ) -> Result<(), ProjectError> {
        let action = "project.unregister";
        let access = self
            .audited_access(
                current,
                project_id,
                Permission::ProjectUnregister,
                action,
                ctx,
            )
            .await?;
        if confirmation.trim() != access.project.name.as_str() {
            return Err(ProjectError::ConfirmationMismatch);
        }
        let target = ("project", project_id.to_string());
        let deleted = self
            .db
            .delete_project(
                project_id,
                &event(current, action, target, AuditOutcome::Success, ctx),
            )
            .await?;
        if deleted {
            Ok(())
        } else {
            Err(ProjectError::NotFound)
        }
    }

    /// The operator's role in an organization, if it grants `permission`.
    async fn org_role(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
        permission: Permission,
    ) -> Result<OrgRole, ProjectError> {
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(ProjectError::NotFound)?;
        if membership.role.allows(permission) {
            Ok(membership.role)
        } else {
            Err(ProjectError::Forbidden)
        }
    }

    /// The project and the operator's role, if it grants `permission`.
    async fn project_access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        permission: Permission,
    ) -> Result<ProjectAccess, ProjectError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ProjectError::NotFound)?;
        if access.role.allows(permission) {
            Ok(access)
        } else {
            Err(ProjectError::Forbidden)
        }
    }

    /// [`Self::project_access`] for mutations: a refusal is audited.
    async fn audited_access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        permission: Permission,
        action: &'static str,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectAccess, ProjectError> {
        match self.project_access(current, project_id, permission).await {
            Err(ProjectError::Forbidden) => {
                let target = ("project", project_id.to_string());
                self.deny(current, action, target, ctx).await;
                Err(ProjectError::Forbidden)
            }
            other => other,
        }
    }

    /// Records a refused mutation. Best effort: a failure is logged and the
    /// caller still gets the refusal.
    async fn deny(
        &self,
        current: &CurrentSession,
        action: &'static str,
        target: (&'static str, String),
        ctx: RequestContext<'_>,
    ) {
        let event = event(current, action, target, AuditOutcome::Denied, ctx);
        if let Err(err) = self.db.record_audit_event(&event).await {
            tracing::error!(error = %err, action, "could not record audit event");
        }
    }
}

fn summary(project: ProjectRecord, role: OrgRole) -> ProjectSummary {
    ProjectSummary {
        id: project.id,
        organization_id: project.organization_id,
        name: project.name,
        api_url: project.api_url,
        created_at: project.created_at,
        role,
    }
}
