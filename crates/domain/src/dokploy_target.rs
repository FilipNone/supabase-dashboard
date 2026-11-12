//! Where an organization's new stacks may go in Dokploy: a Dokploy
//! environment, and the Dokploy server the stack runs on.
//!
//! Dashboard organizations and Dokploy organizations are separate. An
//! installation administrator decides which targets each dashboard
//! organization may use. An organization with no targets of its own may use
//! only the dashboard's own environment, on the server the dashboard runs
//! on, and only while the confirmed placement is current.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{account::DisplayName, dokploy_placement::DokployId, organization::OrganizationName};

/// Most targets one organization may be allowed.
pub const MAX_TARGETS_PER_ORGANIZATION: usize = 50;

/// Most environments offered to choose from on the administrator page.
pub const MAX_LISTED_ENVIRONMENTS: usize = 500;

/// Most servers offered to choose from on the administrator page.
pub const MAX_LISTED_SERVERS: usize = 200;

/// Longest name accepted for a new Dokploy environment.
pub const ENVIRONMENT_NAME_MAX_CHARS: usize = 64;

/// An environment the key can see, with its project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployEnvironmentInfo {
    pub project_id: DokployId,
    pub project_name: String,
    pub environment_id: DokployId,
    pub environment_name: String,
    /// The environment Dokploy created with the project.
    pub is_default: bool,
}

/// A remote server Dokploy deploys to. Build servers and inactive servers
/// are never listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployServerInfo {
    pub id: DokployId,
    pub name: String,
}

/// What the key can use for new stacks: the environments it can see, and
/// the servers Dokploy deploys to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployTargetInventory {
    pub environments: Vec<DokployEnvironmentInfo>,
    /// `None` when the key may not list servers. Only Dokploy's own server
    /// can be chosen then, and a target on another server is not checked.
    pub servers: Option<Vec<DokployServerInfo>>,
}

impl DokployTargetInventory {
    pub fn environment(&self, id: &DokployId) -> Option<&DokployEnvironmentInfo> {
        self.environments
            .iter()
            .find(|env| &env.environment_id == id)
    }

    pub fn server(&self, id: &DokployId) -> Option<&DokployServerInfo> {
        self.servers
            .as_ref()?
            .iter()
            .find(|server| &server.id == id)
    }

    /// Each project once, in the order Dokploy listed them.
    pub fn projects(&self) -> Vec<(DokployId, String)> {
        let mut projects: Vec<(DokployId, String)> = Vec::new();
        for env in &self.environments {
            if !projects.iter().any(|(id, _)| id == &env.project_id) {
                projects.push((env.project_id.clone(), env.project_name.clone()));
            }
        }
        projects
    }

    /// Whether `project` already has an environment called `name`,
    /// compared without case.
    pub fn has_environment_named(&self, project: &DokployId, name: &str) -> bool {
        self.environments.iter().any(|env| {
            &env.project_id == project && env.environment_name.eq_ignore_ascii_case(name)
        })
    }
}

/// Where a stack goes: a Dokploy environment, and the server it runs on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StackTarget {
    pub environment_id: DokployId,
    /// `None` for Dokploy's own server.
    pub server_id: Option<DokployId>,
}

impl StackTarget {
    /// The value a form sends: the environment ID, then `@` and the server
    /// ID for a remote server. Dokploy IDs never contain `@`.
    pub fn value(&self) -> String {
        match &self.server_id {
            Some(server) => format!("{}@{}", self.environment_id.as_str(), server.as_str()),
            None => self.environment_id.as_str().to_owned(),
        }
    }

    pub fn parse_value(raw: &str) -> Option<Self> {
        let (environment, server) = match raw.split_once('@') {
            Some((environment, server)) => (environment, Some(DokployId::parse(server).ok()?)),
            None => (raw, None),
        };
        Some(Self {
            environment_id: DokployId::parse(environment).ok()?,
            server_id: server,
        })
    }
}

/// The Dokploy names of a target, kept for display while Dokploy cannot be
/// reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackTargetNames {
    pub project_name: String,
    pub environment_name: String,
    /// `None` for Dokploy's own server.
    pub server_name: Option<String>,
}

impl StackTargetNames {
    /// `Project / environment, on server`.
    pub fn label(&self) -> String {
        let server = match &self.server_name {
            Some(name) => format!("on server {name}"),
            None => "on Dokploy's own server".to_owned(),
        };
        format!(
            "{} / {}, {server}",
            self.project_name, self.environment_name
        )
    }
}

/// How an allowed target compares with what Dokploy reports now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetStatus {
    Available,
    /// The key no longer sees the environment: it was deleted, or the key's
    /// member lost access to it.
    EnvironmentMissing,
    /// Dokploy no longer lists the server as an active deploy server.
    ServerMissing,
    /// The key may not list servers, so the server was not checked.
    ServerUnchecked,
}

impl TargetStatus {
    pub fn check(target: &StackTarget, inventory: &DokployTargetInventory) -> Self {
        if inventory.environment(&target.environment_id).is_none() {
            return Self::EnvironmentMissing;
        }
        match (&target.server_id, &inventory.servers) {
            (None, _) => Self::Available,
            (Some(_), None) => Self::ServerUnchecked,
            (Some(id), Some(_)) if inventory.server(id).is_some() => Self::Available,
            (Some(_), Some(_)) => Self::ServerMissing,
        }
    }
}

/// A target an installation administrator allowed an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedStackTarget {
    pub id: Uuid,
    pub target: StackTarget,
    pub project_id: DokployId,
    pub names: StackTargetNames,
    pub added_at: OffsetDateTime,
    /// `None` once that account has been deleted.
    pub added_by: Option<DisplayName>,
}

/// One organization's allowed targets. Empty means the default: the
/// dashboard's own environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationStackTargets {
    pub organization_id: Uuid,
    pub organization_name: OrganizationName,
    pub allowed: Vec<AllowedStackTarget>,
}

/// The target every organization without targets of its own may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultTarget {
    /// The dashboard's environment, on the server the dashboard runs on.
    Placement {
        target: StackTarget,
        names: StackTargetNames,
    },
    /// No placement is confirmed, so there is no default.
    NoPlacement,
    /// A placement is confirmed but is not current in Dokploy, or Dokploy
    /// could not be asked. The message says which.
    Unavailable(String),
}

/// What Dokploy reported when the page asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetLookup {
    Found {
        /// Up to [`MAX_LISTED_ENVIRONMENTS`] environments and
        /// [`MAX_LISTED_SERVERS`] servers.
        inventory: DokployTargetInventory,
        /// Whether the key can see more than is listed.
        truncated: bool,
    },
    /// Dokploy could not be asked; the message names no address or key.
    Failed(String),
}

/// The stack targets part of the administrator page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackTargetsOverview {
    pub default_target: DefaultTarget,
    pub organizations: Vec<OrganizationStackTargets>,
    /// Whether there are more organizations than are listed.
    pub organizations_truncated: bool,
    pub lookup: TargetLookup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentNameError {
    #[error("enter a name for the environment")]
    Empty,
    #[error("environment names are at most {ENVIRONMENT_NAME_MAX_CHARS} characters")]
    TooLong,
    #[error(
        "environment names start with a letter or digit and use only letters, digits, spaces, \
         '.', '_', and '-'"
    )]
    InvalidCharacters,
}

/// Checks a name for a new Dokploy environment and returns it trimmed.
pub fn check_environment_name(raw: &str) -> Result<&str, EnvironmentNameError> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(EnvironmentNameError::Empty);
    }
    if name.chars().count() > ENVIRONMENT_NAME_MAX_CHARS {
        return Err(EnvironmentNameError::TooLong);
    }
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok =
        chars.all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '.' || c == '_' || c == '-');
    if first_ok && rest_ok {
        Ok(name)
    } else {
        Err(EnvironmentNameError::InvalidCharacters)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn id(raw: &str) -> DokployId {
        DokployId::parse(raw).unwrap()
    }

    fn inventory(servers: Option<Vec<DokployServerInfo>>) -> DokployTargetInventory {
        DokployTargetInventory {
            environments: vec![
                DokployEnvironmentInfo {
                    project_id: id("p1"),
                    project_name: "Infra".to_owned(),
                    environment_id: id("e1"),
                    environment_name: "production".to_owned(),
                    is_default: true,
                },
                DokployEnvironmentInfo {
                    project_id: id("p1"),
                    project_name: "Infra".to_owned(),
                    environment_id: id("e2"),
                    environment_name: "Stacks".to_owned(),
                    is_default: false,
                },
            ],
            servers,
        }
    }

    #[test]
    fn a_target_is_sent_as_its_environment_and_server() {
        let own = StackTarget {
            environment_id: id("e1"),
            server_id: None,
        };
        let remote = StackTarget {
            environment_id: id("e1"),
            server_id: Some(id("s1")),
        };
        assert_eq!(own.value(), "e1");
        assert_eq!(remote.value(), "e1@s1");
        assert_eq!(StackTarget::parse_value("e1"), Some(own));
        assert_eq!(StackTarget::parse_value("e1@s1"), Some(remote));
        for bad in ["", "@s1", "e1@", "e1@s1@s2", "e 1", "e1@s/1"] {
            assert_eq!(StackTarget::parse_value(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_target_is_checked_against_what_dokploy_reports() {
        let servers = Some(vec![DokployServerInfo {
            id: id("s1"),
            name: "edge-1".to_owned(),
        }]);
        let listed = inventory(servers);
        let target = |env: &str, server: Option<&str>| StackTarget {
            environment_id: id(env),
            server_id: server.map(id),
        };
        assert_eq!(
            TargetStatus::check(&target("e1", None), &listed),
            TargetStatus::Available
        );
        assert_eq!(
            TargetStatus::check(&target("e2", Some("s1")), &listed),
            TargetStatus::Available
        );
        assert_eq!(
            TargetStatus::check(&target("e9", None), &listed),
            TargetStatus::EnvironmentMissing
        );
        assert_eq!(
            TargetStatus::check(&target("e1", Some("s9")), &listed),
            TargetStatus::ServerMissing
        );
        let unlisted = inventory(None);
        assert_eq!(
            TargetStatus::check(&target("e1", Some("s1")), &unlisted),
            TargetStatus::ServerUnchecked
        );
        assert_eq!(
            TargetStatus::check(&target("e1", None), &unlisted),
            TargetStatus::Available
        );
    }

    #[test]
    fn projects_are_listed_once_and_names_compare_without_case() {
        let listed = inventory(None);
        assert_eq!(listed.projects(), vec![(id("p1"), "Infra".to_owned())]);
        assert!(listed.has_environment_named(&id("p1"), "stacks"));
        assert!(!listed.has_environment_named(&id("p2"), "stacks"));
        assert!(!listed.has_environment_named(&id("p1"), "staging"));
    }

    #[test]
    fn environment_names_are_checked() {
        assert_eq!(check_environment_name("  staging 2 "), Ok("staging 2"));
        assert_eq!(check_environment_name("a.b_c-d"), Ok("a.b_c-d"));
        assert_eq!(
            check_environment_name("   "),
            Err(EnvironmentNameError::Empty)
        );
        assert_eq!(
            check_environment_name(&"a".repeat(65)),
            Err(EnvironmentNameError::TooLong)
        );
        for bad in ["-x", "x/y", "x\ny", "ünï", "<b>"] {
            assert_eq!(
                check_environment_name(bad),
                Err(EnvironmentNameError::InvalidCharacters),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn labels_name_the_server() {
        let mut names = StackTargetNames {
            project_name: "Infra".to_owned(),
            environment_name: "production".to_owned(),
            server_name: None,
        };
        assert_eq!(names.label(), "Infra / production, on Dokploy's own server");
        names.server_name = Some("edge-1".to_owned());
        assert_eq!(names.label(), "Infra / production, on server edge-1");
    }
}
