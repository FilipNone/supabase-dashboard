//! Reading and changing the settings of a provisioned stack (see
//! [`supabase_dashboard_domain::stack_settings`]). Owners and admins read
//! them from the service's variables in Dokploy, preview a change, and
//! queue it as a `stack_action` job that writes the variables and
//! redeploys.

use secrecy::ExposeSecret;
use supabase_dashboard_domain::{
    authz::Permission,
    dokploy_placement::DokployId,
    provisioning::StackAction,
    stack_settings::{
        EnvFile, EnvValue, STACK_SETTINGS, SettingState, StackConfigPreview, StackSetting,
        StackSettingView, StackSettingsView, stack_setting,
    },
};
use supabase_dashboard_persistence::audit::AuditOutcome;
use uuid::Uuid;

use super::{ComposeConfig, ProvisionError, ProvisioningService, stack_action::SettingChange};
use crate::{
    auth::{CurrentSession, RequestContext},
    dokploy::DokployServiceError,
    organizations::event,
};

/// What the operator submitted: a setting's variable name and its value.
pub type SubmittedSetting<'a> = (&'a str, &'a str);

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
/// checked against the stack when it is applied.
fn base_of(current: &[Current]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
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
    changes: &[(&'static StackSetting, SettingChange)],
) -> StackConfigPreview {
    let mut restarts: Vec<String> = changes
        .iter()
        .flat_map(|(setting, _)| setting.services.iter().map(|s| (*s).to_owned()))
        .collect();
    restarts.sort_unstable();
    restarts.dedup();
    StackConfigPreview {
        changed: changes
            .iter()
            .map(|(setting, _)| setting.name.to_owned())
            .collect(),
        restarts,
        base: base_of(current),
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
            busy,
        }))
    }

    /// What applying `submitted` would change. Nothing is written.
    pub async fn preview_settings(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        submitted: &[SubmittedSetting<'_>],
    ) -> Result<StackConfigPreview, ProvisionError> {
        let config = self.read_config(current, project_id).await?;
        let now = read_settings(&config);
        let changes = plan(&now, submitted)?;
        if changes.is_empty() {
            return Err(ProvisionError::NoChanges);
        }
        Ok(preview_of(&now, &changes))
    }

    /// Queues writing `submitted` and redeploying, and returns the job's
    /// ID. `base` is the preview's [`StackConfigPreview::base`]; when any
    /// setting changed since the preview, nothing is queued.
    pub async fn queue_settings(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        submitted: &[SubmittedSetting<'_>],
        base: &str,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, ProvisionError> {
        let config = match self.read_config(current, project_id).await {
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
        if base_of(&now) != base {
            return Err(ProvisionError::PreviewOutdated);
        }
        let changes = plan(&now, submitted)?;
        if changes.is_empty() {
            return Err(ProvisionError::NoChanges);
        }
        let settings = changes.into_iter().map(|(_, change)| change).collect();
        self.queue_settings_job(current, project_id, settings, ctx)
            .await
    }

    /// The service's variables and compose file, for an owner or admin of
    /// a project whose stack the dashboard provisioned and still has.
    async fn read_config(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<ComposeConfig, ProvisionError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(ProvisionError::NotFound)?;
        if !access.role.allows(Permission::StackOperate) {
            return Err(ProvisionError::Forbidden);
        }
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
