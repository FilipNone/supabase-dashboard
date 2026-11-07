//! Health reporting for the dashboard's own components.

use serde::{Deserialize, Serialize};

/// The observed state of one component.
///
/// `Unknown` means the check could not be made or has not run; it is not
/// the same as `Unavailable`, which means a check ran and failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Available,
    Unavailable,
    Unknown,
}

impl ComponentStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "Available",
            Self::Unavailable => "Unavailable",
            Self::Unknown => "Unknown",
        }
    }
}

/// Result of checking one component of the dashboard installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Stable machine name, for example `metadata_database`.
    pub component: String,
    pub status: ComponentStatus,
    /// Short, credential-free explanation suitable for operators.
    pub detail: Option<String>,
}

/// Health of the dashboard installation itself (not of managed projects).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationHealth {
    pub components: Vec<ComponentHealth>,
}

impl InstallationHealth {
    /// The installation is ready only when every component is available.
    pub fn is_ready(&self) -> bool {
        self.components
            .iter()
            .all(|c| c.status == ComponentStatus::Available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(status: ComponentStatus) -> ComponentHealth {
        ComponentHealth {
            component: "metadata_database".into(),
            status,
            detail: None,
        }
    }

    #[test]
    fn ready_requires_every_component_available() {
        let mut health = InstallationHealth {
            components: vec![component(ComponentStatus::Available)],
        };
        assert!(health.is_ready());

        health.components.push(component(ComponentStatus::Unknown));
        assert!(!health.is_ready(), "unknown must not count as ready");
    }

    #[test]
    fn status_serializes_as_snake_case() {
        let json = serde_json::to_string(&ComponentStatus::Unavailable).unwrap();
        assert_eq!(json, "\"unavailable\"");
    }
}
