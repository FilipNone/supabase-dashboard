//! Connection data for a registered project: which API keys the dashboard
//! holds for it, and what the last service check found.
//!
//! None of these types carry a key value. Keys go from the browser to the
//! server once, as form input, and are never sent back.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Upper bound on a stored API key. Legacy keys are JWTs of a few hundred
/// bytes; the newer `sb_` keys are shorter.
pub const API_KEY_MAX_LEN: usize = 4096;

/// Minimum seconds between two checks of the same project, so the check
/// button cannot be used to flood a stack with requests.
pub const HEALTH_CHECK_COOLDOWN_SECS: i64 = 10;

/// Age after which a saved check is shown as stale. The server checks
/// projects on its own unless that is turned off, so a check this old
/// usually means scheduled checks are off or keep failing to run.
pub const HEALTH_STALE_AFTER_SECS: i64 = 24 * 60 * 60;

/// How long a project's past checks are kept. Older entries are deleted
/// when a new check is saved.
pub const HEALTH_HISTORY_RETENTION_DAYS: u16 = 7;

/// The most past checks kept for one project, whatever their age. Checks
/// every 15 minutes come to 672 a week, which leaves room for manual ones.
pub const HEALTH_HISTORY_MAX_ENTRIES: u16 = 1000;

/// How many past checks the project overview lists, newest first.
pub const HEALTH_HISTORY_PAGE: u16 = 20;

/// An API key the dashboard can store for a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// The anon or publishable key. Clients embed it, but it still grants
    /// whatever the `anon` role may do, so it is stored like a secret.
    AnonKey,
    /// The service_role or secret key. It bypasses row-level security.
    ServiceRoleKey,
    /// The gateway's basic-auth login for Studio (`DASHBOARD_USERNAME` and
    /// `DASHBOARD_PASSWORD`), stored as `username:password`. Whoever holds
    /// it has full control of the project through Studio.
    StudioLogin,
}

impl CredentialKind {
    pub const ALL: [Self; 3] = [Self::AnonKey, Self::ServiceRoleKey, Self::StudioLogin];
    /// The kinds shown in the API keys section.
    pub const API_KEYS: [Self; 2] = [Self::AnonKey, Self::ServiceRoleKey];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnonKey => "anon_key",
            Self::ServiceRoleKey => "service_role_key",
            Self::StudioLogin => "studio_login",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == raw)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::AnonKey => "Anon (publishable) key",
            Self::ServiceRoleKey => "Service role (secret) key",
            Self::StudioLogin => "Studio login",
        }
    }

    /// Name of the variable that holds this key in the stack's `.env`.
    pub const fn env_name(self) -> &'static str {
        match self {
            Self::AnonKey => "ANON_KEY",
            Self::ServiceRoleKey => "SERVICE_ROLE_KEY",
            Self::StudioLogin => "DASHBOARD_USERNAME and DASHBOARD_PASSWORD",
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
    #[error("this key has expired; generate a new one from the stack's JWT secret")]
    Expired,
    #[error(
        "the Studio user name must be 1 to {STUDIO_USERNAME_MAX_LEN} characters without spaces or colons"
    )]
    StudioUsername,
    #[error(
        "the Studio password must be {STUDIO_PASSWORD_MIN_LEN} to {STUDIO_PASSWORD_MAX_LEN} characters without control characters"
    )]
    StudioPasswordLength,
    #[error(
        "this is the example password from the upstream .env file; set a new one on the stack first"
    )]
    StudioDefaultPassword,
}

pub const STUDIO_USERNAME_MAX_LEN: usize = 64;
/// Anyone who guesses it controls the project, so short passwords are
/// refused even though the gateway would accept them.
pub const STUDIO_PASSWORD_MIN_LEN: usize = 16;
pub const STUDIO_PASSWORD_MAX_LEN: usize = 256;
/// `DASHBOARD_PASSWORD` in upstream's `.env.example`.
const UPSTREAM_EXAMPLE_PASSWORD: &str = "this_password_is_insecure_and_should_be_updated";

/// Checks a Studio login and returns it as `username:password`, the form
/// it is stored and sent in. The user name is trimmed; the password is
/// taken as typed.
pub fn check_studio_login(username: &str, password: &str) -> Result<String, ApiKeyError> {
    let username = username.trim();
    if username.is_empty()
        || username.len() > STUDIO_USERNAME_MAX_LEN
        || username
            .chars()
            .any(|c| c == ':' || c.is_whitespace() || c.is_control() || !c.is_ascii())
    {
        return Err(ApiKeyError::StudioUsername);
    }
    let length = password.chars().count();
    if !(STUDIO_PASSWORD_MIN_LEN..=STUDIO_PASSWORD_MAX_LEN).contains(&length)
        || password.chars().any(char::is_control)
    {
        return Err(ApiKeyError::StudioPasswordLength);
    }
    if password == UPSTREAM_EXAMPLE_PASSWORD {
        return Err(ApiKeyError::StudioDefaultPassword);
    }
    Ok(format!("{username}:{password}"))
}

/// Splits a stored Studio login back into user name and password. The
/// user name cannot contain a colon, so the first one separates them.
pub fn split_studio_login(stored: &str) -> Option<(&str, &str)> {
    stored.split_once(':')
}

/// Checks the shape of a pasted key and returns it trimmed. It catches
/// typos and keys pasted into the wrong field. Whether the stack accepts the
/// key is only known after a check.
pub fn check_api_key(kind: CredentialKind, raw: &str) -> Result<&str, ApiKeyError> {
    if kind == CredentialKind::StudioLogin {
        // The stored form comes from [`check_studio_login`]; checking it
        // again here keeps one entry point for every credential.
        let (username, password) = split_studio_login(raw).ok_or(ApiKeyError::StudioUsername)?;
        check_studio_login(username, password)?;
        return Ok(raw);
    }
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
        /// From the key's own `exp` claim, read on the server without
        /// verifying the key. `None` for keys without one, including keys
        /// in the `sb_` format and Studio logins.
        expires: Option<KeyExpiry>,
    },
    /// Stored, but encrypted with a key this server does not have, for
    /// example after the encryption key was replaced. Enter it again.
    Unreadable {
        updated_at: OffsetDateTime,
    },
}

/// When a stored key expires, as of the moment the server read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyExpiry {
    pub at: OffsetDateTime,
    pub expired: bool,
    /// UTC calendar days from today to the expiry date, so it matches the
    /// date shown: 0 when it expires later today, 1 when tomorrow. Zero
    /// once expired.
    pub days_left: i64,
}

impl KeyExpiry {
    /// Keys expiring within this many days are flagged.
    pub const WARN_DAYS: i64 = 30;

    pub fn new(at: OffsetDateTime, now: OffsetDateTime) -> Self {
        let expired = at <= now;
        let utc = time::UtcOffset::UTC;
        let days = (at.to_offset(utc).date() - now.to_offset(utc).date()).whole_days();
        Self {
            at,
            expired,
            days_left: if expired { 0 } else { days.max(0) },
        }
    }

    pub fn expires_soon(self) -> bool {
        !self.expired && self.days_left < Self::WARN_DAYS
    }
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
    /// Supabase Storage, checked at `/storage/v1/version`, which also
    /// gives its version.
    Storage,
    /// Supabase Realtime, checked at `/realtime/v1/api/ping`. This shows
    /// the service answers; it does not open a WebSocket or check the
    /// tenant's database connection.
    Realtime,
    /// Edge Functions, checked at `/functions/v1/` with no function name.
    /// Upstream's main router answers that with a 404 carrying
    /// `sb-error-code: NOT_FOUND`, after checking the caller's JWT when
    /// `VERIFY_JWT` is on. No function is run.
    Functions,
    /// Studio, behind the gateway's basic-auth route at `/`.
    Studio,
}

impl StackService {
    pub const ALL: [Self; 6] = [
        Self::Auth,
        Self::Rest,
        Self::Storage,
        Self::Realtime,
        Self::Functions,
        Self::Studio,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Auth => "Auth",
            Self::Rest => "REST API (PostgREST)",
            Self::Storage => "Storage",
            Self::Realtime => "Realtime",
            Self::Functions => "Edge Functions",
            Self::Studio => "Studio",
        }
    }
}

impl StackService {
    /// The version the dashboard is tested against, for services that
    /// report their version. It matches the image in the Supabase fixture
    /// and the baseline in `docs/supabase-compatibility.md`.
    pub const fn tested_version(self) -> Option<&'static str> {
        match self {
            Self::Auth => Some("2.197.0"),
            Self::Rest => Some("14.18"),
            Self::Storage => Some("1.89.12"),
            Self::Realtime | Self::Functions | Self::Studio => None,
        }
    }

    /// How a version this service reported compares with the tested one.
    /// `None` when there is no tested version to compare with.
    pub fn version_support(self, reported: &str) -> Option<VersionSupport> {
        let tested = self.tested_version()?;
        let (Some(have), Some(want)) = (parse_version(reported), parse_version(tested)) else {
            return Some(VersionSupport::Unrecognized);
        };
        Some(match have.cmp(&want) {
            std::cmp::Ordering::Equal => VersionSupport::Tested,
            std::cmp::Ordering::Less => VersionSupport::Older { tested },
            std::cmp::Ordering::Greater => VersionSupport::Newer { tested },
        })
    }
}

/// A reported version against the tested one. Only the release number is
/// compared; a pre-release or build suffix is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSupport {
    Tested,
    /// Older than the tested version. Studio pages may call APIs this
    /// version lacks.
    Older {
        tested: &'static str,
    },
    /// Newer than the tested version, so not covered by the tests yet.
    Newer {
        tested: &'static str,
    },
    /// Not a version number the dashboard can compare.
    Unrecognized,
}

/// Reads `v2.197.0`, `1.89.12`, or `v2.197.0-rc.1` as (major, minor,
/// patch). A missing patch counts as 0.
fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let raw = raw.trim();
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let release = raw.split(['-', '+']).next()?;
    let mut parts = release.split('.');
    let mut next = |required: bool| match parts.next() {
        Some(part) if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) => {
            part.parse::<u64>().ok()
        }
        None if !required => Some(0),
        _ => None,
    };
    let version = (next(true)?, next(true)?, next(false)?);
    parts.next().is_none().then_some(version)
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
    /// The gateway serves Studio without asking for a password, so anyone
    /// who can reach the API URL can open it without the dashboard.
    Unprotected {
        http_status: u16,
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

impl HealthReport {
    /// Services that refused the key, answered with an error, could not be
    /// reached, or serve Studio without a password.
    pub fn failing(&self) -> Vec<StackService> {
        self.services(|status| {
            matches!(
                status,
                ServiceStatus::KeyRejected { .. }
                    | ServiceStatus::Unhealthy { .. }
                    | ServiceStatus::Unreachable { .. }
                    | ServiceStatus::Unprotected { .. }
            )
        })
    }

    /// Services skipped because a key or login is missing or unreadable.
    pub fn not_checked(&self) -> Vec<StackService> {
        self.services(|status| matches!(status, ServiceStatus::NotChecked { .. }))
    }

    fn services(&self, pick: impl Fn(&ServiceStatus) -> bool) -> Vec<StackService> {
        self.checks
            .iter()
            .filter(|check| pick(&check.status))
            .map(|check| check.service)
            .collect()
    }
}

/// One past check in short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthHistoryEntry {
    pub checked_at: OffsetDateTime,
    pub failing: Vec<StackService>,
    pub not_checked: Vec<StackService>,
}

impl From<&HealthReport> for HealthHistoryEntry {
    fn from(report: &HealthReport) -> Self {
        Self {
            checked_at: report.checked_at,
            failing: report.failing(),
            not_checked: report.not_checked(),
        }
    }
}

/// A project's kept checks: the newest few, and counts over everything
/// kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthHistory {
    /// Newest first, at most [`HEALTH_HISTORY_PAGE`].
    pub recent: Vec<HealthHistoryEntry>,
    /// Every kept check, at most [`HEALTH_HISTORY_MAX_ENTRIES`].
    pub total: u32,
    /// Kept checks that found at least one failing service.
    pub with_failures: u32,
    /// The oldest kept check, if any.
    pub since: Option<OffsetDateTime>,
    /// Kept checks counted per UTC hour, oldest first. Hours without a
    /// check are left out.
    pub hours: Vec<HealthHour>,
    /// When the history was read, so the view can tell hours with no check
    /// from hours that have not happened yet.
    pub read_at: OffsetDateTime,
}

/// The checks saved within one UTC hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthHour {
    /// The start of the hour.
    pub hour: OffsetDateTime,
    pub checks: u32,
    /// Checks that found at least one failing service.
    pub failing: u32,
}

/// A project's last check in short, for its card on the organization
/// page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthDigest {
    pub project_id: Uuid,
    pub checked_at: OffsetDateTime,
    /// Services that refused the key, answered with an error, could not be
    /// reached, or serve Studio without a password.
    pub failing: Vec<StackService>,
    /// Services skipped because a key or login is missing or unreadable.
    pub not_checked: Vec<StackService>,
    /// Whether the check was older than [`HEALTH_STALE_AFTER_SECS`] when
    /// the digest was made.
    pub stale: bool,
}

impl HealthDigest {
    pub fn new(project_id: Uuid, report: &HealthReport, now: OffsetDateTime) -> Self {
        Self {
            project_id,
            checked_at: report.checked_at,
            failing: report.failing(),
            not_checked: report.not_checked(),
            stale: (now - report.checked_at).whole_seconds() > HEALTH_STALE_AFTER_SECS,
        }
    }
}

/// What the dashboard learned about a key when it saved it.
///
/// API keys are stored without contacting the stack; the next health check
/// tells whether they work. A Studio login is tried against the gateway's
/// Studio route first. A login the gateway refuses is never stored, so
/// only the outcomes that still lead to a stored login appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SavedCredential {
    /// Stored without a check.
    NotChecked,
    /// The gateway refused Studio without the login and accepted it with
    /// the login.
    Confirmed,
    /// Stored, but the gateway did not confirm the login, for example
    /// because it was unreachable or serves Studio without a password.
    Unconfirmed { status: ServiceStatus },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_sort_services_by_outcome_and_age() {
        let checked_at = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let check = |service, status| ServiceCheck {
            service,
            status,
            version: None,
            latency_ms: None,
        };
        let report = HealthReport {
            checked_at,
            checks: vec![
                check(StackService::Auth, ServiceStatus::Healthy),
                check(
                    StackService::Rest,
                    ServiceStatus::KeyRejected { http_status: 401 },
                ),
                check(
                    StackService::Storage,
                    ServiceStatus::Unhealthy { http_status: 404 },
                ),
                check(
                    StackService::Realtime,
                    ServiceStatus::NotChecked {
                        reason: SkipReason::MissingKey,
                    },
                ),
                check(
                    StackService::Studio,
                    ServiceStatus::Unprotected { http_status: 200 },
                ),
            ],
        };
        let id = Uuid::nil();
        let fresh = HealthDigest::new(id, &report, checked_at + time::Duration::hours(24));
        assert_eq!(
            fresh.failing,
            vec![
                StackService::Rest,
                StackService::Storage,
                StackService::Studio
            ]
        );
        assert_eq!(fresh.not_checked, vec![StackService::Realtime]);
        assert!(!fresh.stale);
        let old = HealthDigest::new(
            id,
            &report,
            checked_at + time::Duration::hours(24) + time::Duration::seconds(1),
        );
        assert!(old.stale);
    }

    #[test]
    fn credential_kinds_round_trip() {
        for kind in CredentialKind::ALL {
            assert_eq!(CredentialKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(CredentialKind::parse("password"), None);
    }

    #[test]
    fn studio_logins_are_checked() {
        use ApiKeyError as E;
        let password = "a-long-random-password";
        assert_eq!(
            check_studio_login(" supabase ", password).as_deref(),
            Ok("supabase:a-long-random-password")
        );
        assert_eq!(check_studio_login("", password), Err(E::StudioUsername));
        assert_eq!(check_studio_login("a:b", password), Err(E::StudioUsername));
        assert_eq!(check_studio_login("a b", password), Err(E::StudioUsername));
        assert_eq!(
            check_studio_login("supabase", "short"),
            Err(E::StudioPasswordLength)
        );
        assert_eq!(
            check_studio_login("supabase", &"a".repeat(STUDIO_PASSWORD_MAX_LEN + 1)),
            Err(E::StudioPasswordLength)
        );
        assert_eq!(
            check_studio_login("supabase", "line\nbreak-password-long"),
            Err(E::StudioPasswordLength)
        );
        assert_eq!(
            check_studio_login("supabase", UPSTREAM_EXAMPLE_PASSWORD),
            Err(E::StudioDefaultPassword)
        );
        // A colon in the password survives the round trip.
        let stored = check_studio_login("u", "pass:word-long-enough").unwrap();
        assert_eq!(
            split_studio_login(&stored),
            Some(("u", "pass:word-long-enough"))
        );
        assert_eq!(
            check_api_key(CredentialKind::StudioLogin, &stored),
            Ok(stored.as_str())
        );
        assert_eq!(
            check_api_key(CredentialKind::StudioLogin, "nocolon"),
            Err(E::StudioUsername)
        );
    }

    #[test]
    fn key_expiry_counts_calendar_days() {
        // 2027-01-15 08:00 UTC.
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000 - 1_800_000_000 % 86_400)
            .unwrap()
            + time::Duration::hours(8);
        let later = |hours: i64| KeyExpiry::new(now + time::Duration::hours(hours), now);
        assert!(later(0).expired);
        assert!(later(-1).expired);
        assert_eq!(later(-48).days_left, 0);
        // Later today, then tomorrow even when under 24 hours away.
        let today = later(15);
        assert!(!today.expired && today.expires_soon());
        assert_eq!(today.days_left, 0);
        assert_eq!(later(17).days_left, 1);
        // Ten days from now is ten days, whatever the hour.
        assert_eq!(later(24 * 10).days_left, 10);
        assert_eq!(later(24 * 10 - 1).days_left, 10);
        assert!(later(24 * 29).expires_soon());
        assert!(!later(24 * 30).expires_soon());
        assert!(!later(-1).expires_soon());
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
    fn reported_versions_are_compared_with_the_tested_ones() {
        use VersionSupport::*;
        let auth = StackService::Auth;
        assert_eq!(auth.version_support("v2.197.0"), Some(Tested));
        assert_eq!(auth.version_support("2.197.0"), Some(Tested));
        assert_eq!(auth.version_support("v2.197.0-rc.2"), Some(Tested));
        assert_eq!(
            auth.version_support("v2.180.3"),
            Some(Older { tested: "2.197.0" })
        );
        assert_eq!(auth.version_support("v2.197"), Some(Tested));
        assert_eq!(
            auth.version_support("v2.196"),
            Some(Older { tested: "2.197.0" })
        );
        assert_eq!(
            auth.version_support("v2.198.0"),
            Some(Newer { tested: "2.197.0" })
        );
        assert_eq!(
            auth.version_support("v3.0.0"),
            Some(Newer { tested: "2.197.0" })
        );
        for odd in [
            "",
            "latest",
            "v2",
            "v2.x.0",
            "2.197.0.1",
            "v2..0",
            "v-2.1.0",
        ] {
            assert_eq!(auth.version_support(odd), Some(Unrecognized), "{odd}");
        }
        assert_eq!(
            StackService::Storage.version_support("1.89.12"),
            Some(Tested)
        );
        let rest = StackService::Rest;
        assert_eq!(rest.version_support("14.18"), Some(Tested));
        assert_eq!(rest.version_support("14.18.0"), Some(Tested));
        assert_eq!(
            rest.version_support("12.2.3"),
            Some(Older { tested: "14.18" })
        );
        assert_eq!(
            rest.version_support("14.19"),
            Some(Newer { tested: "14.18" })
        );
        assert_eq!(StackService::Realtime.version_support("v2.148.3"), None);
    }

    #[test]
    fn tested_versions_match_the_fixture_and_the_baseline() {
        let fixture = include_str!("../../../tests/fixtures/supabase/docker-compose.yml");
        let baseline = include_str!("../../../docs/supabase-compatibility.md");
        for (service, image) in [
            (StackService::Auth, "supabase/gotrue"),
            (StackService::Storage, "supabase/storage-api"),
            (StackService::Rest, "postgrest/postgrest"),
        ] {
            let tag = format!("{image}:v{}", service.tested_version().unwrap());
            assert!(fixture.contains(&tag), "fixture does not use {tag}");
            assert!(baseline.contains(&tag), "baseline does not list {tag}");
        }
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
