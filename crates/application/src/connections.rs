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
    authz::Permission,
    connection::{
        ApiKeyError, CredentialKind, CredentialOverview, CredentialState, CredentialStatus,
        HEALTH_CHECK_COOLDOWN_SECS, HealthDigest, HealthReport, SavedCredential, ServiceCheck,
        ServiceStatus, SkipReason, StackService, check_api_key,
    },
    project::{MAX_PROJECTS_PER_ORGANIZATION, ProjectUrl},
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::AuditOutcome,
    connections::{NewCredential, StoredCredential},
    projects::ProjectAccess,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    organizations::event,
    secrets::{CipherError, CredentialCipher, Sealed},
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
pub trait StackProbe: Send + Sync {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
    ) -> ProbeFuture<'a>;
}

/// Which stored key a service check uses. The least privileged key that
/// works is preferred: Auth's health endpoint accepts the anon key, while
/// PostgREST's root (its OpenAPI description) is limited to the service role
/// in current upstream gateway configurations. Storage's version path and
/// Realtime's ping answer the anon key.
pub const fn key_preference(service: StackService) -> &'static [CredentialKind] {
    match service {
        StackService::Auth | StackService::Storage | StackService::Realtime => {
            &[CredentialKind::AnonKey, CredentialKind::ServiceRoleKey]
        }
        StackService::Rest => &[CredentialKind::ServiceRoleKey, CredentialKind::AnonKey],
        StackService::Studio => &[CredentialKind::StudioLogin],
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
        let credentials = CredentialKind::ALL
            .into_iter()
            .map(|kind| CredentialStatus {
                kind,
                state: match stored.iter().find(|c| c.kind == kind) {
                    None => CredentialState::NotSet,
                    Some(c) if self.cipher.as_ref().is_some_and(|k| k.can_open(&c.key_id)) => {
                        CredentialState::Set {
                            updated_at: c.updated_at,
                        }
                    }
                    Some(c) => CredentialState::Unreadable {
                        updated_at: c.updated_at,
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
            SecretString::from(check_api_key(kind, value.expose_secret())?)
        };
        let saved = if kind == CredentialKind::StudioLogin {
            let check = self
                .probe
                .check(&access.project.api_url, StackService::Studio, &value)
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
        let report = self.run_check(&access).await?;
        self.db.save_health_report(project_id, &report).await?;
        tracing::info!(project_id = %project_id, "project services checked");
        Ok(report)
    }

    async fn run_check(&self, access: &ProjectAccess) -> Result<HealthReport, ConnectionError> {
        let project = &access.project;
        let stored = self.db.list_credentials(project.id).await?;
        let mut checks = Vec::with_capacity(StackService::ALL.len());
        for service in StackService::ALL {
            let check = match self.pick_key(project.id, service, &stored) {
                Ok(key) => self.probe.check(&project.api_url, service, &key).await,
                Err(reason) => ServiceCheck {
                    service,
                    status: ServiceStatus::NotChecked { reason },
                    version: None,
                    latency_ms: None,
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
            let opened = self.cipher.as_ref().map(|cipher| {
                cipher.open(
                    project_id,
                    kind,
                    &Sealed {
                        key_id: credential.key_id.clone(),
                        nonce: credential.nonce.clone(),
                        ciphertext: credential.ciphertext.clone(),
                    },
                )
            });
            match opened {
                Some(Ok(key)) => return Ok(key),
                Some(Err(_)) | None => unreadable = true,
            }
        }
        Err(if unreadable {
            SkipReason::UnreadableKey
        } else {
            SkipReason::MissingKey
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
