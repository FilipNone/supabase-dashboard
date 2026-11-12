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
    organization::OrganizationName,
    project::{ProjectName, ProjectUrl},
};

/// Upper bound on rows of each kind returned to the administrator view.
pub const ADMIN_RESOURCE_LIST_LIMIT: usize = 500;

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
}
