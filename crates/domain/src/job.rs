//! Durable background jobs: their kinds and states.

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// Provision a new stack through the deployment provider.
    ProvisionStack,
}

impl JobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProvisionStack => "provision_stack",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "provision_stack" => Some(Self::ProvisionStack),
            _ => None,
        }
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Waiting for a worker, either new or between steps that wait.
    Queued,
    /// A worker holds it.
    Running,
    Succeeded,
    Failed,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_finished(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// Whether `raw` is a valid step name: lowercase letters and underscores,
/// starting with a letter, at most 64 characters. The database checks the
/// same.
pub fn is_step_name(raw: &str) -> bool {
    let mut bytes = raw.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && raw.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_states_round_trip() {
        assert_eq!(
            JobKind::parse(JobKind::ProvisionStack.as_str()),
            Some(JobKind::ProvisionStack)
        );
        for state in [
            JobState::Queued,
            JobState::Running,
            JobState::Succeeded,
            JobState::Failed,
        ] {
            assert_eq!(JobState::parse(state.as_str()), Some(state));
        }
        assert_eq!(JobKind::parse("other"), None);
    }

    #[test]
    fn step_names() {
        assert!(is_step_name("create_service"));
        assert!(!is_step_name("_start"));
        assert!(!is_step_name("Create"));
        assert!(!is_step_name(""));
        assert!(!is_step_name(&"a".repeat(65)));
    }
}
