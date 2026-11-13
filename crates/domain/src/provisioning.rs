//! What members see of stacks the dashboard provisions: the targets they
//! may choose and the progress of each provisioning job.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    dokploy_compose::{ComposeStatus, DeploymentStatus},
    job::JobState,
};

/// A step of the provisioning job, in the order it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionStep {
    Check,
    CreateService,
    Configure,
    Mounts,
    Domain,
    Deploy,
    WaitDeploy,
    Register,
    Health,
}

impl ProvisionStep {
    pub const ALL: [Self; 9] = [
        Self::Check,
        Self::CreateService,
        Self::Configure,
        Self::Mounts,
        Self::Domain,
        Self::Deploy,
        Self::WaitDeploy,
        Self::Register,
        Self::Health,
    ];

    /// The name the job saves.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::CreateService => "create_service",
            Self::Configure => "configure",
            Self::Mounts => "mounts",
            Self::Domain => "domain",
            Self::Deploy => "deploy",
            Self::WaitDeploy => "wait_deploy",
            Self::Register => "register",
            Self::Health => "health",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.as_str() == raw)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Check => "Check permissions and target",
            Self::CreateService => "Create the Dokploy service",
            Self::Configure => "Set the compose file and variables",
            Self::Mounts => "Write the configuration files",
            Self::Domain => "Add the domain",
            Self::Deploy => "Start the deployment",
            Self::WaitDeploy => "Deploy the stack",
            Self::Register => "Register the project",
            Self::Health => "Check that the stack answers",
        }
    }
}

/// A place a member may create a stack in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetChoice {
    /// The form value (see [`crate::dokploy_target::StackTarget::value`]).
    pub value: String,
    /// `Project / environment, on server`, as Dokploy names them.
    pub label: String,
}

/// Where an organization may create stacks, as a form shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvisionTargets {
    Choices(Vec<TargetChoice>),
    /// No Dokploy connection.
    NotConnected,
    /// No target allowed and no default: an installation administrator
    /// has not confirmed where the dashboard runs.
    NoTarget,
    /// The default target could not be read from Dokploy now.
    Unavailable,
}

/// A provisioning job, as members of its organization see it. Holds no
/// secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionJobSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub host: String,
    pub https: bool,
    pub state: JobState,
    /// `None` for a step this version does not know.
    pub step: Option<ProvisionStep>,
    pub message: Option<String>,
    /// The project, once the job registered it.
    pub project_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub finished_at: Option<OffsetDateTime>,
}

impl ProvisionJobSummary {
    /// `https://host` or `http://host`.
    pub fn public_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}", self.host)
    }
}

/// What members see of the Dokploy service behind a project, read from
/// Dokploy when asked. Never the service's variables or compose file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StackDeploymentView {
    /// The project was registered, not provisioned by the dashboard.
    NotProvisioned,
    /// The project was provisioned, but Dokploy is no longer connected.
    NotConnected,
    /// Dokploy did not answer or refused the key. `reason` names no
    /// address, key, or response text.
    Unavailable {
        reason: String,
    },
    /// Dokploy has no service with the recorded ID: it was deleted in
    /// Dokploy, or the key's member can no longer see it.
    Missing {
        compose_name: Option<String>,
    },
    Found(Box<StackDeployment>),
}

/// The provisioned project's service as Dokploy reports it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDeployment {
    pub name: String,
    /// `None` for a status this version does not know.
    pub status: Option<ComposeStatus>,
    /// The service is in another environment or on another server than
    /// when the dashboard created it.
    pub moved: bool,
    /// Where the service is, for owners and admins only, who also choose
    /// where new stacks go. `None` for other roles.
    pub location: Option<StackLocation>,
    /// Newest first.
    pub deployments: Vec<StackDeploymentRun>,
    /// More deployments exist than are listed.
    pub more_deployments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackLocation {
    pub project_name: String,
    pub environment_name: String,
    /// `None` for Dokploy's own server.
    pub server_name: Option<String>,
    pub compose_id: String,
    pub app_name: String,
    /// The service's page in Dokploy's UI, or `None` when the dashboard
    /// reaches Dokploy at an address a browser cannot use.
    pub dokploy_link: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackDeploymentRun {
    pub title: Option<String>,
    pub status: DeploymentStatus,
    /// Started by the dashboard rather than in Dokploy.
    pub from_dashboard: bool,
    pub created_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_round_trip_and_are_job_step_names() {
        for step in ProvisionStep::ALL {
            assert_eq!(ProvisionStep::parse(step.as_str()), Some(step));
            assert!(crate::job::is_step_name(step.as_str()));
        }
        assert_eq!(ProvisionStep::parse("unknown"), None);
    }
}
