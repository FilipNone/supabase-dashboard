//! What members see of stacks the dashboard provisions: the targets they
//! may choose and the progress of each provisioning job.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::job::JobState;

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
