//! Stored API keys and service checks for registered projects.
//!
//! Keys are written once and never returned. Members see only whether a key
//! is set. The check uses the keys on the server, through a [`StackProbe`]
//! that the server wires to the network adapter.

use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    authority::{
        AuthorityError, AuthorityInfo, ProjectAuthorities, ProjectTrust, check_bundle_size,
    },
    authz::Permission,
    connection::{
        ApiKeyError, CredentialKind, CredentialOverview, CredentialState, CredentialStatus,
        HEALTH_CHECK_COOLDOWN_SECS, HEALTH_HISTORY_MAX_ENTRIES, HEALTH_HISTORY_PAGE,
        HEALTH_HISTORY_RETENTION_DAYS, HealthDigest, HealthHistory, HealthHistoryEntry, HealthHour,
        HealthReport, KeyExpiry, SavedCredential, ServiceCheck, ServiceStatus, SkipReason,
        StackService, check_api_key,
    },
    project::{MAX_PROJECTS_PER_ORGANIZATION, ProjectUrl},
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::AuditOutcome,
    connections::{HistoryRetention, NewCredential, StoredCredential},
    projects::{ProjectAccess, ProjectRecord},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    key_claims,
    organizations::event,
    secrets::{CipherError, CredentialCipher, Sealed},
};

/// When an API key says it expires. Studio logins are not JWTs.
fn expiry(kind: CredentialKind, value: &SecretString) -> Option<OffsetDateTime> {
    use secrecy::ExposeSecret;
    if kind == CredentialKind::StudioLogin {
        return None;
    }
    key_claims::read_claims(value.expose_secret()).and_then(|claims| claims.expires_at)
}

/// How long past checks are kept, as the server applies it.
const RETENTION: HistoryRetention = HistoryRetention {
    max_age_days: HEALTH_HISTORY_RETENTION_DAYS,
    max_entries: HEALTH_HISTORY_MAX_ENTRIES,
};

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("project not found")]
    NotFound,
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    #[error(
        "this dashboard has no encryption key configured, so it cannot store API keys; \
         set SUPABASE_DASHBOARD_SECRET_KEY_FILE on the server"
    )]
    StorageUnavailable,
    #[error("no key of this kind is stored for the project")]
    NotStored,
    #[error("this project was checked moments ago; try again in {retry_after_secs} seconds")]
    CheckTooSoon { retry_after_secs: i64 },
    #[error("a check of this project is already running")]
    CheckInProgress,
    #[error(
        "the stack's gateway refused this Studio login (HTTP {http_status}), so it was not \
         saved; check DASHBOARD_USERNAME and DASHBOARD_PASSWORD on the stack"
    )]
    StudioLoginRejected { http_status: u16 },
    #[error("no certificate authorities are stored for the project")]
    NoAuthorities,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Input(#[from] ApiKeyError),
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = ServiceCheck> + Send + 'a>>;

/// Checks one service of a stack. Implementations must enforce the
/// outbound network policy, never follow redirects, and bound time and
/// response size. They report failures as statuses, never as error text.
///
/// `authorities` is the project's own certificate bundle, trusted for this
/// check only, in addition to the roots every project trusts.
pub trait StackProbe: Send + Sync {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
        authorities: Option<&'a ProjectAuthorities>,
    ) -> ProbeFuture<'a>;

    /// Reads a pasted certificate bundle the way [`Self::check`] would use
    /// it, and summarizes each certificate. Refuses anything that is not a
    /// usable CA certificate, so nothing is stored that checks would
    /// later ignore or trust in part.
    fn read_authorities(&self, pem: &str) -> Result<Vec<AuthorityInfo>, AuthorityError>;
}

/// Which stored key a service check uses. The least privileged key that
/// works is preferred: Auth's health endpoint accepts the anon key, while
/// PostgREST's root (its OpenAPI description) is limited to the service role
/// in current upstream gateway configurations. Storage's version path and
/// Realtime's ping answer the anon key, and so does the Edge Functions
/// router.
pub const fn key_preference(service: StackService) -> &'static [CredentialKind] {
    match service {
        StackService::Auth
        | StackService::Storage
        | StackService::Realtime
        | StackService::Functions => &[CredentialKind::AnonKey, CredentialKind::ServiceRoleKey],
        StackService::Rest => &[CredentialKind::ServiceRoleKey, CredentialKind::AnonKey],
        StackService::Studio => &[CredentialKind::StudioLogin],
    }
}

/// How the dashboard checks projects on its own schedule.
#[derive(Debug, Clone, Copy)]
pub struct ScheduledChecks {
    /// Check a project again once its last check is older than this.
    pub older_than: std::time::Duration,
    /// Most projects checked in one pass.
    pub batch: usize,
    /// Most checks running at once.
    pub concurrency: usize,
    /// How long a pass holds the projects it picked. Other passes, in this
    /// process or another one sharing the database, leave them alone until
    /// then. Longer than a check can take.
    pub lease: std::time::Duration,
}

/// What one scheduled pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRun {
    pub checked: usize,
    /// Skipped because a check of the project was already running.
    pub skipped: usize,
    /// The check could not be run or saved. Problems at the stack are not
    /// failures here; they are recorded in the saved report.
    pub failed: usize,
}

impl ScheduledRun {
    fn count(&mut self, joined: Result<Result<bool, ConnectionError>, tokio::task::JoinError>) {
        match joined {
            Ok(Ok(true)) => self.checked += 1,
            Ok(Ok(false)) => self.skipped += 1,
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "scheduled project check failed");
                self.failed += 1;
            }
            Err(err) => {
                tracing::error!(error = %err, "scheduled project check stopped");
                self.failed += 1;
            }
        }
    }
}

pub struct ConnectionService {
    db: Database,
    cipher: Option<CredentialCipher>,
    probe: Arc<dyn StackProbe>,
    /// Projects with a check in progress in this process.
    running: Arc<Mutex<HashSet<Uuid>>>,
}

/// Marks a project's check as running until dropped, including when the
/// request is cancelled halfway through.
struct RunningGuard {
    running: Arc<Mutex<HashSet<Uuid>>>,
    project_id: Uuid,
}

impl RunningGuard {
    fn acquire(running: &Arc<Mutex<HashSet<Uuid>>>, project_id: Uuid) -> Option<Self> {
        let inserted = running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(project_id);
        inserted.then(|| Self {
            running: Arc::clone(running),
            project_id,
        })
    }
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.project_id);
    }
}

impl ConnectionService {
    pub fn new(db: Database, cipher: Option<CredentialCipher>, probe: Arc<dyn StackProbe>) -> Self {
        Self {
            db,
            cipher,
            probe,
            running: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Whether each key is stored, without its value.
    pub async fn credentials(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<CredentialOverview, ConnectionError> {
        self.access(current, project_id, Permission::ProjectRead)
            .await?;
        let stored = self.db.list_credentials(project_id).await?;
        let now = OffsetDateTime::now_utc();
        let credentials = CredentialKind::ALL
            .into_iter()
            .map(|kind| CredentialStatus {
                kind,
                state: match stored.iter().find(|c| c.kind == kind) {
                    None => CredentialState::NotSet,
                    Some(c) => match self.open_stored(project_id, c) {
                        Some(value) => CredentialState::Set {
                            updated_at: c.updated_at,
                            expires: expiry(kind, &value).map(|at| KeyExpiry::new(at, now)),
                        },
                        None => CredentialState::Unreadable {
                            updated_at: c.updated_at,
                        },
                    },
                },
            })
            .collect();
        Ok(CredentialOverview {
            storage_available: self.cipher.is_some(),
            credentials,
        })
    }

    /// Stores a key, replacing any previous value without reading it.
    ///
    /// A Studio login is tried against the gateway first. When the gateway
    /// refuses it, nothing is stored, the attempt is audited as a failure,
    /// and the previous login stays in place. Other outcomes of the check
    /// (unreachable, no password asked) are returned with the stored login,
    /// so an operator can save it before the stack is up.
    pub async fn replace_credential(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        kind: CredentialKind,
        value: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<SavedCredential, ConnectionError> {
        let action = "project.credential.replace";
        let access = self
            .audited_access(current, project_id, action, ctx)
            .await?;
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(ConnectionError::StorageUnavailable)?;
        let value = {
            use secrecy::ExposeSecret;
            let value = check_api_key(kind, value.expose_secret())?;
            if kind != CredentialKind::StudioLogin {
                key_claims::check_claims(kind, value, OffsetDateTime::now_utc())?;
            }
            SecretString::from(value)
        };
        let saved = if kind == CredentialKind::StudioLogin {
            let authorities = self.stored_authorities(project_id).await?;
            let check = self
                .probe
                .check(
                    &access.project.api_url,
                    StackService::Studio,
                    &value,
                    authorities.as_ref(),
                )
                .await;
            match check.status {
                ServiceStatus::Healthy => SavedCredential::Confirmed,
                ServiceStatus::KeyRejected { http_status } => {
                    let event = event(
                        current,
                        action,
                        credential_target(project_id, kind),
                        AuditOutcome::Failure,
                        ctx,
                    );
                    if let Err(err) = self.db.record_audit_event(&event).await {
                        tracing::error!(error = %err, action, "could not record audit event");
                    }
                    return Err(ConnectionError::StudioLoginRejected { http_status });
                }
                status => SavedCredential::Unconfirmed { status },
            }
        } else {
            SavedCredential::NotChecked
        };
        let sealed = cipher.seal(project_id, kind, &value)?;
        let stored = self
            .db
            .upsert_credential(
                &NewCredential {
                    project_id,
                    kind,
                    key_id: &sealed.key_id,
                    nonce: &sealed.nonce,
                    ciphertext: &sealed.ciphertext,
                    updated_by: current.account.id,
                },
                &event(
                    current,
                    action,
                    credential_target(project_id, kind),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        if stored {
            Ok(saved)
        } else {
            Err(ConnectionError::NotFound)
        }
    }

    /// Deletes a stored key. Works without the encryption key, so a key
    /// that became unreadable can still be removed.
    pub async fn remove_credential(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        kind: CredentialKind,
        ctx: RequestContext<'_>,
    ) -> Result<(), ConnectionError> {
        let action = "project.credential.remove";
        self.audited_access(current, project_id, action, ctx)
            .await?;
        let deleted = self
            .db
            .delete_credential(
                project_id,
                kind,
                &event(
                    current,
                    action,
                    credential_target(project_id, kind),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        if deleted {
            Ok(())
        } else {
            Err(ConnectionError::NotStored)
        }
    }

    /// The project's own certificate authorities, summarized. Any member
    /// may read them: certificates are public. `None` when none are
    /// stored. A stored bundle the adapter can no longer read comes back
    /// with no authorities listed.
    pub async fn authorities(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<Option<ProjectTrust>, ConnectionError> {
        self.access(current, project_id, Permission::ProjectRead)
            .await?;
        let Some((pem, updated_at)) = self.db.find_project_authorities(project_id).await? else {
            return Ok(None);
        };
        let authorities = self.probe.read_authorities(&pem).unwrap_or_else(|err| {
            tracing::warn!(project_id = %project_id, error = %err, "stored certificate authorities cannot be read");
            Vec::new()
        });
        Ok(Some(ProjectTrust {
            authorities,
            updated_at,
            read_at: OffsetDateTime::now_utc(),
        }))
    }

    /// Stores the project's certificate bundle, replacing any previous
    /// one. Limited to the roles that replace keys, and audited. Nothing is
    /// sent to the stack; the next check uses the new bundle.
    pub async fn replace_authorities(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        pem: &str,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectTrust, ConnectionError> {
        let action = "project.authorities.replace";
        self.audited_access(current, project_id, action, ctx)
            .await?;
        let pem = check_bundle_size(pem)?;
        let authorities = self.probe.read_authorities(pem)?;
        let updated_at = self
            .db
            .upsert_project_authorities(
                project_id,
                pem,
                current.account.id,
                &event(
                    current,
                    action,
                    ("project", project_id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?
            .ok_or(ConnectionError::NotFound)?;
        Ok(ProjectTrust {
            authorities,
            updated_at,
            read_at: OffsetDateTime::now_utc(),
        })
    }

    /// Deletes the project's certificate bundle. Later checks trust only
    /// the roots every project trusts.
    pub async fn remove_authorities(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), ConnectionError> {
        let action = "project.authorities.remove";
        self.audited_access(current, project_id, action, ctx)
            .await?;
        let deleted = self
            .db
            .delete_project_authorities(
                project_id,
                &event(
                    current,
                    action,
                    ("project", project_id.to_string()),
                    AuditOutcome::Success,
                    ctx,
                ),
            )
            .await?;
        if deleted {
            Ok(())
        } else {
            Err(ConnectionError::NoAuthorities)
        }
    }

    async fn stored_authorities(
        &self,
        project_id: Uuid,
    ) -> Result<Option<ProjectAuthorities>, ConnectionError> {
        Ok(self
            .db
            .find_project_authorities(project_id)
            .await?
            .map(|(pem, _)| ProjectAuthorities::from_stored(&pem)))
    }

    /// The last saved check, if any. It may be old; the caller shows when
    /// it was taken.
    pub async fn last_report(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<Option<HealthReport>, ConnectionError> {
        self.access(current, project_id, Permission::ProjectRead)
            .await?;
        Ok(self.db.find_health_report(project_id).await?)
    }

    /// The project's kept checks: the newest few in short and counts over
    /// the retention period. Any member may read them.
    pub async fn health_history(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<HealthHistory, ConnectionError> {
        self.access(current, project_id, Permission::ProjectRead)
            .await?;
        let stored = self
            .db
            .health_history(project_id, RETENTION, HEALTH_HISTORY_PAGE)
            .await?;
        Ok(HealthHistory {
            recent: stored.recent.iter().map(HealthHistoryEntry::from).collect(),
            total: u32::try_from(stored.total).unwrap_or(u32::MAX),
            with_failures: u32::try_from(stored.with_failures).unwrap_or(u32::MAX),
            since: stored.since,
            hours: stored
                .hours
                .into_iter()
                .map(|(hour, checks, failing)| HealthHour {
                    hour,
                    checks: u32::try_from(checks).unwrap_or(u32::MAX),
                    failing: u32::try_from(failing).unwrap_or(u32::MAX),
                })
                .collect(),
            read_at: stored.read_at,
        })
    }

    /// The last saved check of each project in an organization, in short,
    /// for the project cards. Any member may read them; projects never
    /// checked are left out.
    pub async fn health_digests(
        &self,
        current: &CurrentSession,
        organization_id: Uuid,
    ) -> Result<Vec<HealthDigest>, ConnectionError> {
        let membership = self
            .db
            .find_membership(organization_id, current.account.id)
            .await?
            .ok_or(ConnectionError::NotFound)?;
        if !membership.role.allows(Permission::ProjectRead) {
            return Err(ConnectionError::Forbidden);
        }
        let now = OffsetDateTime::now_utc();
        Ok(self
            .db
            .list_health_reports(organization_id, MAX_PROJECTS_PER_ORGANIZATION)
            .await?
            .into_iter()
            .map(|(project_id, report)| HealthDigest::new(project_id, &report, now))
            .collect())
    }

    /// Checks every service now, saves the result, and returns it. Any
    /// member may run a check; the cooldown and the in-progress guard keep
    /// it from being used to flood the stack.
    pub async fn check_now(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<HealthReport, ConnectionError> {
        let access = self
            .access(current, project_id, Permission::ProjectRead)
            .await?;
        if let Some(last) = self.db.last_health_check(project_id).await? {
            let elapsed = (OffsetDateTime::now_utc() - last).whole_seconds();
            if (0..HEALTH_CHECK_COOLDOWN_SECS).contains(&elapsed) {
                return Err(ConnectionError::CheckTooSoon {
                    retry_after_secs: HEALTH_CHECK_COOLDOWN_SECS - elapsed,
                });
            }
        }
        let Some(_guard) = RunningGuard::acquire(&self.running, project_id) else {
            return Err(ConnectionError::CheckInProgress);
        };
        let report = self.run_check(&access.project).await?;
        self.db
            .save_health_report(project_id, &report, RETENTION)
            .await?;
        tracing::info!(project_id = %project_id, "project services checked");
        Ok(report)
    }

    /// One pass of the dashboard's own checks: projects never checked or
    /// last checked longer ago than `schedule.older_than`, oldest first,
    /// at most `schedule.batch` of them and `schedule.concurrency` at a
    /// time. Each pass claims its projects for `schedule.lease` first, so
    /// server processes sharing the database split the work instead of
    /// repeating it. A project with a check already running in this
    /// process is skipped. No member
    /// is involved, so nothing is audited; results are saved like a check
    /// a member asked for.
    pub async fn check_due(
        self: &Arc<Self>,
        schedule: ScheduledChecks,
    ) -> Result<ScheduledRun, ConnectionError> {
        let older_than = i64::try_from(schedule.older_than.as_secs()).unwrap_or(i64::MAX);
        let lease = i64::try_from(schedule.lease.as_secs()).unwrap_or(i64::MAX);
        let due = self
            .db
            .claim_projects_due_for_check(older_than, lease, schedule.batch)
            .await?;
        let mut run = ScheduledRun::default();
        let mut tasks = tokio::task::JoinSet::new();
        let concurrency = schedule.concurrency.max(1);
        for project in due {
            while tasks.len() >= concurrency {
                if let Some(joined) = tasks.join_next().await {
                    run.count(joined);
                }
            }
            let service = Arc::clone(self);
            tasks.spawn(async move { service.scheduled_check(&project).await });
        }
        while let Some(joined) = tasks.join_next().await {
            run.count(joined);
        }
        Ok(run)
    }

    /// Checks one project for [`Self::check_due`]. `Ok(false)` means a
    /// check of it was already running.
    async fn scheduled_check(&self, project: &ProjectRecord) -> Result<bool, ConnectionError> {
        let Some(_guard) = RunningGuard::acquire(&self.running, project.id) else {
            return Ok(false);
        };
        let report = self.run_check(project).await?;
        self.db
            .save_health_report(project.id, &report, RETENTION)
            .await?;
        Ok(true)
    }

    async fn run_check(&self, project: &ProjectRecord) -> Result<HealthReport, ConnectionError> {
        let stored = self.db.list_credentials(project.id).await?;
        let authorities = self.stored_authorities(project.id).await?;
        let mut checks = Vec::with_capacity(StackService::ALL.len());
        for service in StackService::ALL {
            let check = match self.pick_key(project.id, service, &stored) {
                Ok(key) => {
                    self.probe
                        .check(&project.api_url, service, &key, authorities.as_ref())
                        .await
                }
                Err(reason) => ServiceCheck {
                    service,
                    status: ServiceStatus::NotChecked { reason },
                    version: None,
                    latency_ms: None,
                    certificate_expires_at: None,
                },
            };
            checks.push(check);
        }
        // PostgreSQL keeps microseconds; truncating here makes the returned
        // report identical to the one read back later.
        let now = OffsetDateTime::now_utc();
        let checked_at = now
            .replace_nanosecond(now.nanosecond() / 1_000 * 1_000)
            .unwrap_or(now);
        Ok(HealthReport { checked_at, checks })
    }

    /// The preferred readable key for a service, or why there is none.
    fn pick_key(
        &self,
        project_id: Uuid,
        service: StackService,
        stored: &[StoredCredential],
    ) -> Result<SecretString, SkipReason> {
        let mut unreadable = false;
        for &kind in key_preference(service) {
            let Some(credential) = stored.iter().find(|c| c.kind == kind) else {
                continue;
            };
            match self.open_stored(project_id, credential) {
                Some(key) => return Ok(key),
                None => unreadable = true,
            }
        }
        Err(if unreadable {
            SkipReason::UnreadableKey
        } else {
            SkipReason::MissingKey
        })
    }

    /// A stored key's value, or `None` when this server cannot decrypt it.
    fn open_stored(&self, project_id: Uuid, credential: &StoredCredential) -> Option<SecretString> {
        self.cipher.as_ref().and_then(|cipher| {
            cipher
                .open(
                    project_id,
                    credential.kind,
                    &Sealed {
                        key_id: credential.key_id.clone(),
                        nonce: credential.nonce.clone(),
                        ciphertext: credential.ciphertext.clone(),
                    },
                )
                .ok()
        })
    }

    async fn access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        permission: Permission,
    ) -> Result<ProjectAccess, ConnectionError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ConnectionError::NotFound)?;
        if access.role.allows(permission) {
            Ok(access)
        } else {
            Err(ConnectionError::Forbidden)
        }
    }

    /// Access check for key changes. A refusal is audited, best effort.
    async fn audited_access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        action: &'static str,
        ctx: RequestContext<'_>,
    ) -> Result<ProjectAccess, ConnectionError> {
        match self
            .access(current, project_id, Permission::ProjectCredentialsReplace)
            .await
        {
            Err(ConnectionError::Forbidden) => {
                let event = event(
                    current,
                    action,
                    ("project", project_id.to_string()),
                    AuditOutcome::Denied,
                    ctx,
                );
                if let Err(err) = self.db.record_audit_event(&event).await {
                    tracing::error!(error = %err, action, "could not record audit event");
                }
                Err(ConnectionError::Forbidden)
            }
            other => other,
        }
    }
}

/// Audit target for a key change: the project and the kind, never the value.
fn credential_target(project_id: Uuid, kind: CredentialKind) -> (&'static str, String) {
    ("project", format!("{project_id}:{}", kind.as_str()))
}
