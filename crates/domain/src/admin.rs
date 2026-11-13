//! What the installation administrator view lists about registered
//! resources. These rows carry names, addresses, and counts only. They hold
//! no credentials and give the administrator no access to the resources
//! themselves: an administrator who is not a member of an organization still
//! cannot open its projects.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    connection::HealthDigest,
    job::JobKind,
    organization::OrganizationName,
    project::{ProjectName, ProjectUrl},
    provisioning::StackAction,
};

/// Upper bound on rows of each kind returned to the administrator view.
pub const ADMIN_RESOURCE_LIST_LIMIT: usize = 500;

/// Most failed jobs listed on the administrator view.
pub const ADMIN_FAILED_JOB_LIMIT: usize = 50;

/// How far back the administrator view lists failed jobs, in days.
pub const ADMIN_FAILED_JOB_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminOrganizationSummary {
    pub id: Uuid,
    pub name: OrganizationName,
    pub member_count: i64,
    pub project_count: i64,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminProjectSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: OrganizationName,
    pub name: ProjectName,
    pub api_url: ProjectUrl,
    pub created_at: OffsetDateTime,
    /// The last saved check in short; `None` when never checked.
    pub health: Option<HealthDigest>,
}

/// Every organization and project of the installation, oldest first, each
/// list cut at [`ADMIN_RESOURCE_LIST_LIMIT`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredResources {
    pub organizations: Vec<AdminOrganizationSummary>,
    /// More organizations exist than were returned.
    pub organizations_truncated: bool,
    pub projects: Vec<AdminProjectSummary>,
    /// More projects exist than were returned.
    pub projects_truncated: bool,
    /// Jobs that failed in the last [`ADMIN_FAILED_JOB_DAYS`] days, newest
    /// first, at most [`ADMIN_FAILED_JOB_LIMIT`].
    pub failed_jobs: Vec<AdminFailedJob>,
    /// More failed jobs exist in that period than were returned.
    pub failed_jobs_truncated: bool,
}

/// A background job that failed. Its message says why and holds no
/// secret; members of its organization see the same message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminFailedJob {
    pub id: Uuid,
    pub kind: JobKind,
    /// Which action, for a stack action.
    pub action: Option<StackAction>,
    pub organization_id: Uuid,
    pub organization_name: OrganizationName,
    /// The project the job was for, while it is still registered.
    pub project_id: Option<Uuid>,
    /// The project's current name, or the name a provisioning job was
    /// given when it registered no project.
    pub project_name: Option<String>,
    pub message: Option<String>,
    pub failed_at: OffsetDateTime,
}
