//! Reading and changing the settings of a provisioned stack (see
//! [`supabase_dashboard_domain::stack_settings`]). Owners and admins read
//! them from the service's variables in Dokploy, preview a change, and
//! queue it as a `stack_action` job that writes the variables and
//! redeploys.
//!
//! Secret settings are write-only: the page learns whether one is set,
//! never its value. A new value travels in the job's sealed secrets, not
//! in its data or audit event, and is not compared with the current one,
//! so a preview never tells whether a guess matches it.

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_domain::{
    authz::Permission,
    dokploy_placement::DokployId,
    provisioning::StackAction,
    stack_settings::{
        ChangedSecret, ENV_SEEN_MAX_LEN, EnvFile, EnvValue, SECRET_SETTINGS, STACK_SETTINGS,
        SecretSetting, SecretSettingView, SettingState, StackConfigPreview, StackSetting,
        StackSettingView, StackSettingsView, secret_setting, stack_setting,
    },
};
use supabase_dashboard_persistence::audit::AuditOutcome;
use uuid::Uuid;

use super::{
    ComposeConfig, ProvisionError, ProvisioningService,
    env_record::{self, EnvRecord},
    stack_action::{SecretChange, SettingChange},
};
use crate::{
    auth::{CurrentSession, RequestContext},
    dokploy::DokployServiceError,
    organizations::event,
};

/// What the operator submitted: a setting's variable name and its value.
pub type SubmittedSetting<'a> = (&'a str, &'a str);

/// A new value for a secret setting. Keeping the current one is not
/// submitting it.
pub enum SecretEdit {
    Replace(SecretString),
    /// Removes the value, so the compose file's empty default applies.
    Remove,
}

// Never print the value.
impl std::fmt::Debug for SecretEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Replace(_) => f.write_str("Replace(..)"),
            Self::Remove => f.write_str("Remove"),
        }
    }
}

/// What the operator submitted for a secret setting: its variable name and
/// the edit.
pub type SubmittedSecret<'a> = (&'a str, SecretEdit);

/// A secret setting as the service has it now.
struct CurrentSecret {
    setting: &'static SecretSetting,
    state: SettingState,
    /// The variable's value, `None` when it is not set or cannot be read.
    raw: Option<SecretString>,
    /// The variable has a value other than empty, or one the dashboard
    /// cannot read.
    set: bool,
}

fn read_secrets(config: &ComposeConfig) -> Vec<CurrentSecret> {
    let env = EnvFile::parse(config.env.expose_secret());
    SECRET_SETTINGS
        .iter()
        .map(|setting| {
            let (state, raw, set) = match env.get(setting.name) {
                EnvValue::Unreadable => (SettingState::Unreadable, None, true),
                EnvValue::Missing => (SettingState::Editable, None, false),
                EnvValue::Set(value) => (
                    SettingState::Editable,
                    Some(SecretString::from(value.to_owned())),
                    !value.is_empty(),
                ),
            };
            let state = if state == SettingState::Editable && !setting.read_by(&config.compose_file)
            {
                SettingState::NotInComposeFile
            } else {
                state
            };
            CurrentSecret {
                setting,
                state,
                raw,
                set,
            }
        })
        .collect()
}

/// Checks the submitted secrets' names and values, without reading the
/// stack.
fn check_secrets(submitted: &[SubmittedSecret<'_>]) -> Result<(), ProvisionError> {
    for (i, (name, edit)) in submitted.iter().enumerate() {
        let Some(setting) = secret_setting(name) else {
            return Err(ProvisionError::SettingUnavailable(format!(
                "{name} is not a setting the dashboard changes"
            )));
        };
        if submitted[..i].iter().any(|(other, _)| other == name) {
            return Err(ProvisionError::SettingUnavailable(format!(
                "{}: submitted more than once",
                setting.label
            )));
        }
        if let SecretEdit::Replace(value) = edit {
            setting.check(value.expose_secret())?;
        }
    }
    Ok(())
}

/// The changes `submitted` makes to the secret settings, in display order.
/// A new value always counts as a change: comparing it with the current
/// one would tell the operator whether they guessed it.
fn plan_secrets(
    current: &[CurrentSecret],
    submitted: &[SubmittedSecret<'_>],
) -> Result<Vec<(&'static SecretSetting, SecretChange)>, ProvisionError> {
    check_secrets(submitted)?;
    let mut changes = Vec::new();
    for now in current {
        let Some((_, edit)) = submitted.iter().find(|(name, _)| *name == now.setting.name) else {
            continue;
        };
        if matches!(edit, SecretEdit::Remove) && !now.set {
            continue;
        }
        match now.state {
            SettingState::Editable => {}
            SettingState::NotInComposeFile => {
                return Err(ProvisionError::SettingUnavailable(format!(
                    "{}: this stack's compose file does not read {}, so the dashboard cannot change it",
                    now.setting.label, now.setting.name
                )));
            }
            SettingState::Unreadable => {
                return Err(ProvisionError::SettingUnavailable(format!(
                    "{}: {} is set in a form the dashboard does not rewrite; change it in Dokploy",
                    now.setting.label, now.setting.name
                )));
            }
        }
        let value = match edit {
            SecretEdit::Replace(value) => value.clone(),
            SecretEdit::Remove => SecretString::from(String::new()),
        };
        changes.push((
            now.setting,
            SecretChange {
                name: now.setting.name.to_owned(),
                value,
                previous: now.raw.clone(),
            },
        ));
    }
    Ok(changes)
}

/// A setting as the service has it now.
struct Current {
    setting: &'static StackSetting,
    state: SettingState,
    /// The variable's value, `None` when it is not set.
    raw: Option<String>,
    /// The value in effect.
    effective: Option<String>,
}

fn read_settings(config: &ComposeConfig) -> Vec<Current> {
    let env = EnvFile::parse(config.env.expose_secret());
    STACK_SETTINGS
        .iter()
        .map(|setting| {
            let (state, raw) = match env.get(setting.name) {
                EnvValue::Unreadable => (SettingState::Unreadable, None),
                value => {
                    let raw = match value {
                        EnvValue::Set(value) => Some(value.to_owned()),
                        _ => None,
                    };
                    if setting.read_by(&config.compose_file) {
                        (SettingState::Editable, raw)
                    } else {
                        (SettingState::NotInComposeFile, raw)
                    }
                }
            };
            let effective = match state {
                SettingState::Unreadable | SettingState::NotInComposeFile => None,
                _ => raw.clone().or_else(|| setting.default.map(str::to_owned)),
            };
            Current {
                setting,
                state,
                raw,
                effective,
            }
        })
        .collect()
}

/// The changes `submitted` makes to `current`, in display order.
fn plan(
    current: &[Current],
    submitted: &[SubmittedSetting<'_>],
) -> Result<Vec<(&'static StackSetting, SettingChange)>, ProvisionError> {
    for (name, _) in submitted {
        if stack_setting(name).is_none() {
            return Err(ProvisionError::SettingUnavailable(format!(
                "{name} is not a setting the dashboard changes"
            )));
        }
    }
    let mut changes = Vec::new();
    for now in current {
        let Some((_, raw)) = submitted
            .iter()
            .rev()
            .find(|(name, _)| *name == now.setting.name)
        else {
            continue;
        };
        let value = now.setting.normalize(raw)?;
        let unchanged = now.effective.as_deref().is_some_and(|effective| {
            now.setting
                .normalize(effective)
                .map_or(effective == value, |normalized| normalized == value)
        });
        if unchanged {
            continue;
        }
        match now.state {
            SettingState::Editable => {}
            SettingState::NotInComposeFile => {
                return Err(ProvisionError::SettingUnavailable(format!(
                    "{}: this stack's compose file does not read {}, so the dashboard cannot change it",
                    now.setting.label, now.setting.name
                )));
            }
            SettingState::Unreadable => {
                return Err(ProvisionError::SettingUnavailable(format!(
                    "{}: {} is set in a form the dashboard does not rewrite; change it in Dokploy",
                    now.setting.label, now.setting.name
                )));
            }
        }
        changes.push((
            now.setting,
            SettingChange {
                name: now.setting.name.to_owned(),
                value,
                previous: now.raw.clone(),
            },
        ));
    }
    Ok(changes)
}

/// A digest of every setting's state and raw value, so a review can be
/// checked against the stack when it is applied. Secret settings count
/// only by state and whether they are set: the digest goes to the page.
fn base_of(current: &[Current], secrets: &[CurrentSecret]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for now in secrets {
        let state = match now.state {
            SettingState::Editable => "e",
            SettingState::NotInComposeFile => "n",
            SettingState::Unreadable => "u",
        };
        hash.update(b"secret\0");
        hash.update(now.setting.name.as_bytes());
        hash.update([0]);
        hash.update(state.as_bytes());
        hash.update([u8::from(now.set), 0]);
    }
    for now in current {
        let state = match now.state {
            SettingState::Editable => "e",
            SettingState::NotInComposeFile => "n",
            SettingState::Unreadable => "u",
        };
        hash.update(now.setting.name.as_bytes());
        hash.update([0]);
        hash.update(state.as_bytes());
        match &now.raw {
            Some(raw) => {
                hash.update([1]);
                hash.update(raw.as_bytes());
            }
            None => hash.update([2]),
        }
        hash.update([0]);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn preview_of(
    current: &[Current],
    secrets: &[CurrentSecret],
    changes: &[(&'static StackSetting, SettingChange)],
    secret_changes: &[(&'static SecretSetting, SecretChange)],
) -> StackConfigPreview {
    let mut restarts: Vec<String> = changes
        .iter()
        .flat_map(|(setting, _)| setting.services.iter())
        .chain(
            secret_changes
                .iter()
                .flat_map(|(setting, _)| setting.services.iter()),
        )
        .map(|s| (*s).to_owned())
        .collect();
    restarts.sort_unstable();
    restarts.dedup();
    StackConfigPreview {
        changed: changes
            .iter()
            .map(|(setting, _)| setting.name)
            .chain(secret_changes.iter().map(|(setting, _)| setting.name))
            .map(str::to_owned)
            .collect(),
        secrets: secret_changes
            .iter()
            .map(|(setting, change)| ChangedSecret {
                name: setting.name.to_owned(),
                removed: change.value.expose_secret().is_empty(),
            })
            .collect(),
        restarts,
        base: base_of(current, secrets),
    }
}

impl ProvisioningService {
    /// The stack's settings as Dokploy has them, or `None` when the
    /// dashboard did not provision the project or removed its service.
    /// Owners and admins.
    pub async fn stack_settings(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<Option<StackSettingsView>, ProvisionError> {
        let config = match self.read_config(current, project_id).await {
            Err(ProvisionError::NotProvisioned | ProvisionError::AlreadyRemoved) => {
                return Ok(None);
            }
            other => other?,
        };
        let busy = self
            .last_action(project_id)
            .await?
            .is_some_and(|last| !last.state.is_finished());
        let env = EnvFile::parse(config.env.expose_secret());
        let tracking =
            env_record::tracking(&self.db, self.cipher.as_ref(), project_id, &env).await?;
        Ok(Some(StackSettingsView {
            settings: read_settings(&config)
                .into_iter()
                .map(|now| StackSettingView {
                    name: now.setting.name.to_owned(),
                    label: now.setting.label.to_owned(),
                    help: now.setting.help.to_owned(),
                    kind: now.setting.kind,
                    value: now.effective,
                    state: now.state,
                })
                .collect(),
            secrets: read_secrets(&config)
                .into_iter()
                .map(|now| SecretSettingView {
                    name: now.setting.name.to_owned(),
                    label: now.setting.label.to_owned(),
                    help: now.setting.help.to_owned(),
                    set: now.set,
                    state: now.state,
                })
                .collect(),
            busy,
            tracking,
        }))
    }

    /// What applying `submitted` and `secrets` would change. Nothing is
    /// written.
    pub async fn preview_settings(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        submitted: &[SubmittedSetting<'_>],
        secrets: &[SubmittedSecret<'_>],
    ) -> Result<StackConfigPreview, ProvisionError> {
        self.check_operator(current, project_id).await?;
        check_secrets(secrets)?;
        let config = self.read_config(current, project_id).await?;
        let now = read_settings(&config);
        let now_secrets = read_secrets(&config);
        let changes = plan(&now, submitted)?;
        let secret_changes = plan_secrets(&now_secrets, secrets)?;
        if changes.is_empty() && secret_changes.is_empty() {
            return Err(ProvisionError::NoChanges);
        }
        Ok(preview_of(&now, &now_secrets, &changes, &secret_changes))
    }

    /// Queues writing `submitted` and `secrets` and redeploying, and
    /// returns the job's ID. `base` is the preview's
    /// [`StackConfigPreview::base`]; when any setting changed since the
    /// preview, nothing is queued. New secret values are sealed with the
    /// job, apart from its data, and go when it finishes.
    pub async fn queue_settings(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        submitted: &[SubmittedSetting<'_>],
        secrets: &[SubmittedSecret<'_>],
        base: &str,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        let checked = match self.check_operator(current, project_id).await {
            Ok(()) => {
                check_secrets(secrets)?;
                self.read_config(current, project_id).await
            }
            Err(err) => Err(err),
        };
        let config = match checked {
            Err(ProvisionError::Forbidden) => {
                let denied = event(
                    current,
                    StackAction::Configure.audit_action(),
                    ("project", project_id.to_string()),
                    AuditOutcome::Denied,
                    ctx,
                );
                if let Err(err) = self.db.record_audit_event(&denied).await {
                    tracing::error!(error = %err, "could not record audit event");
                }
                return Err(ProvisionError::Forbidden);
            }
            other => other?,
        };
        let now = read_settings(&config);
        let now_secrets = read_secrets(&config);
        if base_of(&now, &now_secrets) != base {
            return Err(ProvisionError::PreviewOutdated);
        }
        let changes = plan(&now, submitted)?;
        let secret_changes = plan_secrets(&now_secrets, secrets)?;
        if changes.is_empty() && secret_changes.is_empty() {
            return Err(ProvisionError::NoChanges);
        }
        let settings = changes.into_iter().map(|(_, change)| change).collect();
        let secret_changes = secret_changes
            .into_iter()
            .map(|(_, change)| change)
            .collect();
        self.queue_settings_job(current, project_id, settings, secret_changes, ctx)
            .await
    }

    /// Takes the stack's variables as Dokploy has them now as the ones the
    /// dashboard wrote, so edits made in Dokploy stop being listed.
    /// Nothing is written to Dokploy. `seen` is what the page showed, from
    /// [`EnvTracking::seen`](supabase_dashboard_domain::stack_settings::EnvTracking::seen);
    /// when the comparison changed since, nothing is accepted. A record
    /// sealed under a key this server lacks is replaced. Owners and admins.
    pub async fn accept_variables(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        seen: &str,
        ctx: RequestContext<'_>,
    ) -> Result<(), ProvisionError> {
        const ACTION: &str = "stack.variables_accept";
        let audit = |outcome| {
            event(
                current,
                ACTION,
                ("project", project_id.to_string()),
                outcome,
                ctx,
            )
        };
        let config = match self.read_config(current, project_id).await {
            Err(ProvisionError::Forbidden) => {
                if let Err(err) = self
                    .db
                    .record_audit_event(&audit(AuditOutcome::Denied))
                    .await
                {
                    tracing::error!(error = %err, action = ACTION, "could not record audit event");
                }
                return Err(ProvisionError::Forbidden);
            }
            other => other?,
        };
        let cipher = self.cipher.as_ref().ok_or(ProvisionError::NoCipher)?;
        if seen.len() > ENV_SEEN_MAX_LEN {
            return Err(ProvisionError::EditsOutdated);
        }
        if self
            .last_action(project_id)
            .await?
            .is_some_and(|last| !last.state.is_finished())
        {
            return Err(ProvisionError::Busy);
        }
        let env = EnvFile::parse(config.env.expose_secret());
        let stored = env_record::load(&self.db, Some(cipher), project_id).await?;
        let tracking = stored.tracking(&env);
        if !tracking.has_edits() {
            return Err(ProvisionError::NoEdits);
        }
        if tracking.seen() != seen {
            return Err(ProvisionError::EditsOutdated);
        }
        let sealed = EnvRecord::of(&env).seal(cipher, project_id)?;
        // Another accept, a settings job, or a key rotation replaced the
        // record meanwhile.
        if !self
            .db
            .replace_env_record(project_id, stored.nonce(), &sealed)
            .await?
        {
            return Err(ProvisionError::EditsOutdated);
        }
        if let Err(err) = self
            .db
            .record_audit_event(&audit(AuditOutcome::Success))
            .await
        {
            tracing::error!(error = %err, action = ACTION, "could not record audit event");
        }
        Ok(())
    }

    /// The operator is an owner or admin of the project.
    async fn check_operator(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<(), ProvisionError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if access.role.allows(Permission::StackOperate) {
            Ok(())
        } else {
            Err(ProvisionError::Forbidden)
        }
    }

    /// The service's variables and compose file, for an owner or admin of
    /// a project whose stack the dashboard provisioned and still has.
    async fn read_config(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<ComposeConfig, ProvisionError> {
        self.check_operator(current, project_id).await?;
        let stored = self
            .db
            .find_project_dokploy_service(project_id)
            .await?
            .ok_or(ProvisionError::NotProvisioned)?;
        if stored.removed_at.is_some() {
            return Err(ProvisionError::AlreadyRemoved);
        }
        let credentials = match self.dokploy.credentials().await {
            Ok(Some(credentials)) => credentials,
            Ok(None) | Err(DokployServiceError::NotConnected) => {
                return Err(ProvisionError::NotConnected);
            }
            Err(err) => return Err(err.into()),
        };
        let compose = self.compose.as_ref().ok_or_else(|| {
            ProvisionError::DokployUnavailable(
                "This server does not read Dokploy services.".to_owned(),
            )
        })?;
        let compose_id = DokployId::parse(&stored.compose_id)
            .map_err(|_| ProvisionError::Internal("unreadable Dokploy service ID".to_owned()))?;
        compose
            .compose_config(&credentials.url, &credentials.key, &compose_id)
            .await
            .map_err(|err| ProvisionError::DokployUnavailable(err.to_string()))?
            .ok_or(ProvisionError::ServiceMissing)
    }
}
