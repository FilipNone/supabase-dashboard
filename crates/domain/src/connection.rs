//! Connection data for a registered project: which API keys the dashboard
//! holds for it, and what the last service check found.
//!
//! None of these types carry a key value. Keys go from the browser to the
//! server once, as form input, and are never sent back.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Upper bound on a stored API key. Legacy keys are JWTs of a few hundred
/// bytes; the newer `sb_` keys are shorter.
pub const API_KEY_MAX_LEN: usize = 4096;

/// Minimum seconds between two checks of the same project, so the check
/// button cannot be used to flood a stack with requests.
pub const HEALTH_CHECK_COOLDOWN_SECS: i64 = 10;

/// An API key the dashboard can store for a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// The anon or publishable key. Clients embed it, but it still grants
    /// whatever the `anon` role may do, so it is stored like a secret.
    AnonKey,
    /// The service_role or secret key. It bypasses row-level security.
    ServiceRoleKey,
}

impl CredentialKind {
    pub const ALL: [Self; 2] = [Self::AnonKey, Self::ServiceRoleKey];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnonKey => "anon_key",
            Self::ServiceRoleKey => "service_role_key",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == raw)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::AnonKey => "Anon (publishable) key",
            Self::ServiceRoleKey => "Service role (secret) key",
        }
    }

    /// Name of the variable that holds this key in the stack's `.env`.
    pub const fn env_name(self) -> &'static str {
        match self {
            Self::AnonKey => "ANON_KEY",
            Self::ServiceRoleKey => "SERVICE_ROLE_KEY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyError {
    #[error("enter the key")]
    Empty,
    #[error("the key must be at most {API_KEY_MAX_LEN} characters")]
    TooLong,
    #[error("the key must not contain spaces or control characters")]
    InvalidCharacters,
    #[error("this looks like a secret key; paste it into the service role field instead")]
    SecretInAnonSlot,
    #[error("this looks like a publishable key; paste it into the anon field instead")]
    PublishableInSecretSlot,
}

/// Checks the shape of a pasted key and returns it trimmed. It catches
/// typos and keys pasted into the wrong field. Whether the stack accepts the
/// key is only known after a check.
pub fn check_api_key(kind: CredentialKind, raw: &str) -> Result<&str, ApiKeyError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ApiKeyError::Empty);
    }
    if value.len() > API_KEY_MAX_LEN {
        return Err(ApiKeyError::TooLong);
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(ApiKeyError::InvalidCharacters);
    }
    match kind {
        CredentialKind::AnonKey if value.starts_with("sb_secret_") => {
            Err(ApiKeyError::SecretInAnonSlot)
        }
        CredentialKind::ServiceRoleKey if value.starts_with("sb_publishable_") => {
            Err(ApiKeyError::PublishableInSecretSlot)
        }
        _ => Ok(value),
    }
}

/// Whether the dashboard holds a usable key of one kind for a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub kind: CredentialKind,
    pub state: CredentialState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CredentialState {
    NotSet,
    Set {
        updated_at: OffsetDateTime,
    },
    /// Stored, but encrypted with a key this server does not have, for
    /// example after the encryption key was replaced. Enter it again.
    Unreadable {
        updated_at: OffsetDateTime,
    },
}

/// What the project's settings page shows about stored keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialOverview {
    /// `false` when the server has no encryption key configured, in which
    /// case keys can be neither stored nor read.
    pub storage_available: bool,
    pub credentials: Vec<CredentialStatus>,
}

/// A service behind the stack's API gateway that the dashboard checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StackService {
    /// Supabase Auth (GoTrue), checked at `/auth/v1/health`.
    Auth,
    /// PostgREST, checked at `/rest/v1/`.
    Rest,
}

impl StackService {
    pub const ALL: [Self; 2] = [Self::Auth, Self::Rest];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Auth => "Auth",
            Self::Rest => "REST API (PostgREST)",
        }
    }
}

/// Why a service could not be reached. Each variant maps to a fixed message,
/// so no internal error text reaches the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableReason {
    /// The host name did not resolve.
    Dns,
    /// The address resolved to a destination the dashboard refuses to
    /// contact, such as a cloud metadata endpoint or loopback.
    DestinationNotAllowed,
    Connect,
    /// TLS handshake or certificate verification failed.
    Tls,
    Timeout,
    /// The service answered with something that is not a valid response.
    InvalidResponse,
}

impl UnreachableReason {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Dns => "The host name could not be resolved.",
            Self::DestinationNotAllowed => {
                "The address resolves to a destination the dashboard does not contact, such as \
                 loopback, link-local, or a cloud metadata service."
            }
            Self::Connect => "The connection was refused or could not be opened.",
            Self::Tls => "The TLS handshake failed or the certificate is not trusted.",
            Self::Timeout => "The service did not answer in time.",
            Self::InvalidResponse => "The service sent a response the dashboard could not read.",
        }
    }
}

/// Why a service was not checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The check needs a key the dashboard does not hold.
    MissingKey,
    /// A key is stored but could not be decrypted.
    UnreadableKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServiceStatus {
    /// The service answered with a success status.
    Healthy,
    /// The gateway or service refused the key (HTTP 401 or 403).
    KeyRejected {
        http_status: u16,
    },
    /// The service answered with another non-success status. Redirects are
    /// never followed and land here too.
    Unhealthy {
        http_status: u16,
    },
    Unreachable {
        reason: UnreachableReason,
    },
    NotChecked {
        reason: SkipReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCheck {
    pub service: StackService,
    pub status: ServiceStatus,
    /// Version the service reported about itself, if it does.
    pub version: Option<String>,
    /// Time to the response headers, when there was a response.
    pub latency_ms: Option<u32>,
}

/// Upper bound on a reported version string, so a misbehaving service
/// cannot fill the report.
pub const SERVICE_VERSION_MAX_LEN: usize = 64;

/// Keeps a version string a service reported only if it is short and
/// printable.
pub fn sanitize_version(raw: &str) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty()
        && value.len() <= SERVICE_VERSION_MAX_LEN
        && value.chars().all(|c| c.is_ascii_graphic() || c == ' '))
    .then(|| value.to_owned())
}

/// The result of checking every service of one project at one time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub checked_at: OffsetDateTime,
    pub checks: Vec<ServiceCheck>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_kinds_round_trip() {
        for kind in CredentialKind::ALL {
            assert_eq!(CredentialKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(CredentialKind::parse("password"), None);
    }

    #[test]
    fn api_keys_are_trimmed_and_checked() {
        use ApiKeyError as E;
        use CredentialKind as K;
        assert_eq!(check_api_key(K::AnonKey, "  eyJ.a.b \n"), Ok("eyJ.a.b"));
        assert_eq!(check_api_key(K::AnonKey, "   "), Err(E::Empty));
        assert_eq!(
            check_api_key(K::AnonKey, "ab cd"),
            Err(E::InvalidCharacters)
        );
        assert_eq!(check_api_key(K::AnonKey, "abé"), Err(E::InvalidCharacters));
        assert_eq!(
            check_api_key(K::AnonKey, &"a".repeat(API_KEY_MAX_LEN + 1)),
            Err(E::TooLong)
        );
        assert_eq!(
            check_api_key(K::AnonKey, "sb_secret_abc"),
            Err(E::SecretInAnonSlot)
        );
        assert_eq!(
            check_api_key(K::ServiceRoleKey, "sb_publishable_abc"),
            Err(E::PublishableInSecretSlot)
        );
        assert!(check_api_key(K::ServiceRoleKey, "sb_secret_abc").is_ok());
    }

    #[test]
    fn versions_are_bounded_and_printable() {
        assert_eq!(sanitize_version(" v2.197.0 "), Some("v2.197.0".into()));
        assert_eq!(sanitize_version(""), None);
        assert_eq!(sanitize_version("v1\n<script>"), None);
        assert_eq!(sanitize_version(&"9".repeat(65)), None);
    }

    #[test]
    fn report_serializes_without_values() {
        let report = HealthReport {
            checked_at: OffsetDateTime::UNIX_EPOCH,
            checks: vec![ServiceCheck {
                service: StackService::Auth,
                status: ServiceStatus::KeyRejected { http_status: 401 },
                version: None,
                latency_ms: Some(12),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""status":"key_rejected""#), "{json}");
        let back: HealthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }
}
