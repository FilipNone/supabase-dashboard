//! The installation's Dokploy connection: connecting, replacing the API
//! key, and removing the connection.
//!
//! The Dokploy key is an infrastructure credential: whoever holds it can
//! deploy any compose file on Dokploy's servers. Only installation
//! administrators may see or change the connection, every change and every
//! refusal is audited with the Dokploy host but never the key, and the key
//! is stored only after Dokploy accepted it and reported a supported
//! version. It is encrypted under the deployment's credential key and never
//! returned to a browser.
//!
//! Dokploy is called through a [`DokployConnector`] that the server wires
//! to the network adapter, which applies the outbound address policy at
//! connection time.

use std::{future::Future, pin::Pin, sync::Arc};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    dokploy::{
        ChangedBy, DokployChange, DokployConnectionSummary, DokployError, DokployKeyError,
        DokployOverview, DokployUrl, DokployVersion, InvalidDokployUrl, check_dokploy_key,
    },
    dokploy_placement::{
        ConfirmedPlacement, DokployId, DokployInventory, DokployPlacement, DokployServiceKind,
        DokployServiceRef, MAX_LISTED_SERVICES, PlacementLookup, PlacementOverview,
        PlacementStatus, normalize_host,
    },
    dokploy_target::{DokployTargetInventory, EnvironmentNameError, MAX_TARGETS_PER_ORGANIZATION},
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    dokploy::{
        NewDokployConnection, NewDokployPlacement, ReplacedDokployKey, StoredDokployConnection,
        StoredDokployPlacement,
    },
};

use crate::{
    auth::{CurrentSession, RequestContext},
    secrets::{CipherError, CredentialCipher, Sealed},
};

mod targets;

pub use targets::EffectiveTargets;

/// Longest audit target ID the audit log accepts.
const AUDIT_TARGET_MAX_CHARS: usize = 128;

pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DokployVersion, DokployError>> + Send + 'a>>;

pub type InventoryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DokployInventory, DokployError>> + Send + 'a>>;

pub type TargetsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DokployTargetInventory, DokployError>> + Send + 'a>>;

pub type CreateEnvironmentFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DokployId, DokployError>> + Send + 'a>>;

/// Calls Dokploy with a key. Implementations must enforce the outbound
/// address policy at connection time, never follow redirects, bound time
/// and response size, and never put the key anywhere but the request
/// header.
pub trait DokployConnector: Send + Sync {
    /// Reads Dokploy's version with `key` and refuses a release the
    /// dashboard does not support. Returns the supported version found.
    fn connect<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> ConnectFuture<'a>;

    /// The application and compose services `key` can see, with the
    /// domains routed to them.
    fn inventory<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> InventoryFuture<'a>;

    /// The environments `key` can see and the servers Dokploy deploys to.
    fn targets<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> TargetsFuture<'a>;

    /// Creates environment `name` in project `project_id` and returns its
    /// ID. Sent once, never retried.
    fn create_environment<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        project_id: &'a DokployId,
        name: &'a str,
    ) -> CreateEnvironmentFuture<'a>;
}

#[derive(Debug, thiserror::Error)]
pub enum DokployServiceError {
    #[error("only installation administrators can do this")]
    Forbidden,
    #[error(
        "this dashboard has no encryption key configured, so it cannot store the Dokploy key; \
         set SUPABASE_DASHBOARD_SECRET_KEY_FILE on the server"
    )]
    StorageUnavailable,
    #[error("Dokploy is already connected; remove the connection before connecting another")]
    AlreadyConnected,
    #[error("Dokploy is not connected")]
    NotConnected,
    #[error(
        "this Dokploy connection comes from the server's configuration \
         (SUPABASE_DASHBOARD_DOKPLOY_URL and SUPABASE_DASHBOARD_DOKPLOY_API_KEY_FILE); change it \
         there and restart the dashboard"
    )]
    FromDeployment,
    /// The deployment supplies a URL other than the one an administrator
    /// connected. Neither is changed.
    #[error(
        "Dokploy is already connected to {stored_host} from the administrator page; remove that \
         connection to use the one in SUPABASE_DASHBOARD_DOKPLOY_URL"
    )]
    DeploymentConflict { stored_host: String },
    #[error(
        "Dokploy does not show that service to the stored key; it may have been deleted, or the \
         key's member cannot access it"
    )]
    ServiceNotVisible,
    #[error(
        "Dokploy does not show that environment or server to the stored key; it may have been \
         deleted, or the key's member cannot access it"
    )]
    TargetNotVisible,
    #[error(
        "Dokploy does not show that project to the stored key; it may have been deleted, or the \
         key's member cannot access it"
    )]
    ProjectNotVisible,
    #[error("that organization may already use this environment and server")]
    TargetAlreadyAllowed,
    #[error("an organization may use at most {MAX_TARGETS_PER_ORGANIZATION} targets")]
    TooManyTargets,
    #[error("that organization does not exist")]
    OrganizationNotFound,
    #[error("that organization has no such target")]
    TargetNotFound,
    #[error("that project already has an environment with this name")]
    EnvironmentExists,
    /// Dokploy did not answer the request to create an environment, so it
    /// may or may not exist now. Never retried on its own.
    #[error(
        "Dokploy did not answer, so the environment may or may not have been created; reload the \
         page to check before trying again"
    )]
    EnvironmentOutcomeUnknown,
    #[error(transparent)]
    EnvironmentName(#[from] EnvironmentNameError),
    #[error(transparent)]
    Url(#[from] InvalidDokployUrl),
    #[error(transparent)]
    Key(#[from] DokployKeyError),
    /// Dokploy refused the key, could not be reached, or runs an
    /// unsupported version. Nothing was stored.
    #[error(transparent)]
    Dokploy(#[from] DokployError),
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

/// The stored connection with its key, for server-side calls to Dokploy.
pub struct DokployCredentials {
    pub url: DokployUrl,
    pub key: SecretString,
}

// Never print the key.
impl std::fmt::Debug for DokployCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DokployCredentials")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

pub struct DokployService {
    db: Database,
    cipher: Option<CredentialCipher>,
    connector: Arc<dyn DokployConnector>,
    /// The host of the dashboard's public URL, normalized, which finds the
    /// dashboard's own service among Dokploy's domains.
    public_host: Option<String>,
}

impl DokployService {
    pub fn new(
        db: Database,
        cipher: Option<CredentialCipher>,
        connector: Arc<dyn DokployConnector>,
    ) -> Self {
        Self {
            db,
            cipher,
            connector,
            public_host: None,
        }
    }

    /// Sets the host of the dashboard's public URL, without which the
    /// dashboard's own service cannot be found by its domain and has to be
    /// chosen by hand.
    #[must_use]
    pub fn with_public_host(mut self, host: Option<&str>) -> Self {
        self.public_host = host.map(normalize_host).filter(|host| !host.is_empty());
        self
    }

    /// The connection as the administrator page shows it, without the key.
    pub async fn overview(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<DokployOverview, DokployServiceError> {
        self.require_admin(current, "dokploy.view", ctx).await?;
        self.current_overview().await
    }

    /// Connects Dokploy: reads its version with `key`, and only when
    /// Dokploy accepts the key and runs a supported version, stores the URL,
    /// the encrypted key, and the version. A failed attempt is audited and
    /// stores nothing.
    pub async fn connect(
        &self,
        current: &CurrentSession,
        url: &str,
        key: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<DokployOverview, DokployServiceError> {
        let action = "dokploy.connect";
        self.require_admin(current, action, ctx).await?;
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(DokployServiceError::StorageUnavailable)?;
        let url = DokployUrl::parse(url)?;
        let key = checked_key(key)?;
        // Checked before Dokploy is called, so a second connection does not
        // send a key anywhere. The insert below checks again.
        if self.db.find_dokploy_connection().await?.is_some() {
            return Err(DokployServiceError::AlreadyConnected);
        }
        let version = self.try_key(current, action, &url, &key, ctx).await?;
        let sealed = cipher.seal_dokploy_key(url.as_str(), &key)?;
        let version_text = version.to_string();
        let inserted = self
            .db
            .insert_dokploy_connection(
                &NewDokployConnection {
                    url: url.as_str(),
                    key_id: &sealed.key_id,
                    nonce: &sealed.nonce,
                    ciphertext: &sealed.ciphertext,
                    version: &version_text,
                    connected_by: Some(current.account.id),
                },
                &event(current, action, Some(&url), AuditOutcome::Success, ctx),
            )
            .await?;
        if !inserted {
            return Err(DokployServiceError::AlreadyConnected);
        }
        tracing::info!(dokploy_host = %url.host(), version = %version, "Dokploy connected");
        self.current_overview().await
    }

    /// Replaces the stored key. The new key must connect to the stored URL
    /// first; otherwise the attempt is audited and the old key stays.
    pub async fn replace_key(
        &self,
        current: &CurrentSession,
        key: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<DokployOverview, DokployServiceError> {
        let action = "dokploy.key_replace";
        self.require_admin(current, action, ctx).await?;
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(DokployServiceError::StorageUnavailable)?;
        let key = checked_key(key)?;
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        if stored.from_deployment {
            return Err(DokployServiceError::FromDeployment);
        }
        let url = stored_url(&stored)?;
        let version = self.try_key(current, action, &url, &key, ctx).await?;
        let sealed = cipher.seal_dokploy_key(url.as_str(), &key)?;
        let version_text = version.to_string();
        let replaced = self
            .db
            .replace_dokploy_key(
                &ReplacedDokployKey {
                    url: url.as_str(),
                    key_id: &sealed.key_id,
                    nonce: &sealed.nonce,
                    ciphertext: &sealed.ciphertext,
                    version: &version_text,
                    replaced_by: Some(current.account.id),
                },
                &event(current, action, Some(&url), AuditOutcome::Success, ctx),
            )
            .await?;
        // Removed, connected elsewhere, or taken over by the deployment
        // while Dokploy was being called.
        if !replaced {
            return Err(match self.db.find_dokploy_connection().await? {
                Some(stored) if stored.from_deployment => DokployServiceError::FromDeployment,
                _ => DokployServiceError::NotConnected,
            });
        }
        tracing::info!(dokploy_host = %url.host(), version = %version, "Dokploy key replaced");
        self.current_overview().await
    }

    /// Deletes the stored connection and its key. Nothing is sent to
    /// Dokploy, and the key stays valid there until it is revoked in
    /// Dokploy. Works without the encryption key, so an unreadable key can
    /// still be removed.
    pub async fn remove(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<(), DokployServiceError> {
        let action = "dokploy.disconnect";
        self.require_admin(current, action, ctx).await?;
        let Some(stored) = self.db.find_dokploy_connection().await? else {
            return Err(DokployServiceError::NotConnected);
        };
        if stored.from_deployment {
            return Err(DokployServiceError::FromDeployment);
        }
        let url = DokployUrl::parse(&stored.url).ok();
        let removed = self
            .db
            .delete_dokploy_connection(&event(
                current,
                action,
                url.as_ref(),
                AuditOutcome::Success,
                ctx,
            ))
            .await?;
        if removed.is_none() {
            return Err(match self.db.find_dokploy_connection().await? {
                Some(stored) if stored.from_deployment => DokployServiceError::FromDeployment,
                _ => DokployServiceError::NotConnected,
            });
        }
        tracing::info!("Dokploy connection removed");
        Ok(())
    }

    /// Applies the connection the deployment supplies, or releases one it
    /// no longer supplies, when the server starts. There is no operator, so
    /// changes are audited without an actor.
    ///
    /// - Nothing stored: the key is checked with Dokploy and stored.
    /// - The same URL stored: a different key is checked and replaces the
    ///   stored one. A connection an administrator made is taken over.
    /// - Another URL, supplied by the deployment before: the new URL and key
    ///   are checked and replace the connection, and the placement with it.
    /// - Another URL an administrator connected: refused, nothing changes.
    ///
    /// Only a refused key or an unsupported version is audited as a
    /// failure. An unreachable Dokploy is not, since the caller retries.
    pub async fn apply_deployment_connection(
        &self,
        supplied: Option<&DokployCredentials>,
    ) -> Result<DeploymentConnection, DokployServiceError> {
        let stored = self.db.find_dokploy_connection().await?;
        let Some(supplied) = supplied else {
            return match stored {
                Some(stored) if stored.from_deployment => {
                    self.db
                        .set_dokploy_from_deployment(&stored.url, false)
                        .await?;
                    tracing::info!(
                        "the deployment no longer supplies the Dokploy connection; \
                         administrators can now replace or remove it"
                    );
                    Ok(DeploymentConnection::Released)
                }
                _ => Ok(DeploymentConnection::NotSupplied),
            };
        };
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(DokployServiceError::StorageUnavailable)?;
        let key = checked_key(&supplied.key)?;
        let url = &supplied.url;
        let Some(stored) = stored else {
            let version = self
                .try_deployment_key("dokploy.connect", url, &key)
                .await?;
            let sealed = cipher.seal_dokploy_key(url.as_str(), &key)?;
            let version_text = version.to_string();
            let inserted = self
                .db
                .insert_dokploy_connection(
                    &NewDokployConnection {
                        url: url.as_str(),
                        key_id: &sealed.key_id,
                        nonce: &sealed.nonce,
                        ciphertext: &sealed.ciphertext,
                        version: &version_text,
                        connected_by: None,
                    },
                    &deployment_event("dokploy.connect", url, AuditOutcome::Success),
                )
                .await?;
            if !inserted {
                // An administrator connected meanwhile; the next start
                // applies the deployment's connection over it.
                return Err(DokployServiceError::AlreadyConnected);
            }
            tracing::info!(dokploy_host = %url.host(), version = %version, "Dokploy connected from the deployment's configuration");
            return Ok(DeploymentConnection::Connected);
        };
        if stored.url != url.as_str() {
            if !stored.from_deployment {
                return Err(DokployServiceError::DeploymentConflict {
                    stored_host: stored_url(&stored)?.host(),
                });
            }
            let version = self
                .try_deployment_key("dokploy.connect", url, &key)
                .await?;
            let sealed = cipher.seal_dokploy_key(url.as_str(), &key)?;
            let version_text = version.to_string();
            let replaced = self
                .db
                .replace_deployment_dokploy_connection(
                    &stored.url,
                    &NewDokployConnection {
                        url: url.as_str(),
                        key_id: &sealed.key_id,
                        nonce: &sealed.nonce,
                        ciphertext: &sealed.ciphertext,
                        version: &version_text,
                        connected_by: None,
                    },
                    &deployment_event("dokploy.connect", url, AuditOutcome::Success),
                )
                .await?;
            if !replaced {
                return Err(DokployServiceError::NotConnected);
            }
            tracing::info!(dokploy_host = %url.host(), version = %version, "Dokploy connection replaced from the deployment's configuration");
            return Ok(DeploymentConnection::Connected);
        }
        let same_key = cipher
            .open_dokploy_key(url.as_str(), &sealed(&stored))
            .is_ok_and(|current| {
                use secrecy::ExposeSecret;
                current.expose_secret() == key.expose_secret()
            });
        if same_key {
            if !stored.from_deployment {
                self.db
                    .set_dokploy_from_deployment(url.as_str(), true)
                    .await?;
                tracing::info!(
                    "the Dokploy connection now comes from the deployment's configuration"
                );
            }
            return Ok(DeploymentConnection::Unchanged);
        }
        let version = self
            .try_deployment_key("dokploy.key_replace", url, &key)
            .await?;
        let sealed = cipher.seal_dokploy_key(url.as_str(), &key)?;
        let version_text = version.to_string();
        let replaced = self
            .db
            .replace_dokploy_key(
                &ReplacedDokployKey {
                    url: url.as_str(),
                    key_id: &sealed.key_id,
                    nonce: &sealed.nonce,
                    ciphertext: &sealed.ciphertext,
                    version: &version_text,
                    replaced_by: None,
                },
                &deployment_event("dokploy.key_replace", url, AuditOutcome::Success),
            )
            .await?;
        if !replaced {
            return Err(DokployServiceError::NotConnected);
        }
        tracing::info!(dokploy_host = %url.host(), version = %version, "Dokploy key replaced from the deployment's configuration");
        Ok(DeploymentConnection::KeyReplaced)
    }

    /// Checks a key the deployment supplies. A refused key or an
    /// unsupported version is audited; an unreachable Dokploy is not.
    async fn try_deployment_key(
        &self,
        action: &'static str,
        url: &DokployUrl,
        key: &SecretString,
    ) -> Result<DokployVersion, DokployServiceError> {
        match self.connector.connect(url, key).await {
            Ok(version) => Ok(version),
            Err(err) => {
                if !is_transient(&err) {
                    self.audit_best_effort(&deployment_event(action, url, AuditOutcome::Failure))
                        .await;
                }
                Err(err.into())
            }
        }
    }

    /// The stored URL and key, for the server's own calls to Dokploy. No
    /// operator is involved, so nothing is checked or audited here; callers
    /// must have authorized the operation they use it for. `None` when
    /// Dokploy is not connected.
    pub async fn credentials(&self) -> Result<Option<DokployCredentials>, DokployServiceError> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or(DokployServiceError::StorageUnavailable)?;
        let Some(stored) = self.db.find_dokploy_connection().await? else {
            return Ok(None);
        };
        let url = stored_url(&stored)?;
        let key = cipher.open_dokploy_key(url.as_str(), &sealed(&stored))?;
        Ok(Some(DokployCredentials { url, key }))
    }

    /// Where the dashboard runs in Dokploy: the confirmed placement, if
    /// any, and what Dokploy reports now. Dokploy is asked on every call,
    /// so the page reflects moves and deletions made in Dokploy. A failed
    /// call is reported in the answer rather than as an error, so the
    /// confirmed placement still shows.
    pub async fn placement(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<PlacementOverview, DokployServiceError> {
        self.require_admin(current, "dokploy.view", ctx).await?;
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        let confirmed = self.confirmed_placement().await?;
        let lookup = match self.read_inventory(&stored).await {
            Ok(inventory) => {
                let matches = self
                    .public_host
                    .as_deref()
                    .map(|host| inventory.services_serving(host))
                    .unwrap_or_default();
                let status = confirmed.as_ref().map(|confirmed| {
                    PlacementStatus::check(
                        &confirmed.placement,
                        &inventory,
                        self.public_host.as_deref(),
                    )
                });
                let truncated = inventory.services.len() > MAX_LISTED_SERVICES;
                let mut services = inventory.services;
                services.truncate(MAX_LISTED_SERVICES);
                PlacementLookup::Found {
                    matches,
                    services,
                    truncated,
                    status,
                }
            }
            Err(err) => PlacementLookup::Failed(err.to_string()),
        };
        Ok(PlacementOverview {
            public_host: self.public_host.clone(),
            confirmed,
            lookup,
        })
    }

    /// Confirms `service` as the dashboard's own Dokploy service. Dokploy
    /// is asked again, and the service is stored with the project and
    /// environment it reports, only if the stored key can see it. Any
    /// service the key can see may be confirmed, not only one whose domain
    /// matches, because the dashboard may be reached through another proxy.
    pub async fn confirm_placement(
        &self,
        current: &CurrentSession,
        kind: &str,
        id: &str,
        ctx: RequestContext<'_>,
    ) -> Result<PlacementOverview, DokployServiceError> {
        let action = "dokploy.placement_confirm";
        self.require_admin(current, action, ctx).await?;
        // A malformed reference cannot name a service Dokploy showed.
        let service = DokployServiceKind::parse(kind)
            .zip(DokployId::parse(id).ok())
            .map(|(kind, id)| DokployServiceRef { kind, id })
            .ok_or(DokployServiceError::ServiceNotVisible)?;
        let stored = self
            .db
            .find_dokploy_connection()
            .await?
            .ok_or(DokployServiceError::NotConnected)?;
        let inventory = match self.read_inventory(&stored).await {
            Ok(inventory) => inventory,
            Err(err) => {
                self.audit_best_effort(&service_event(
                    current,
                    action,
                    Some(&service),
                    AuditOutcome::Failure,
                    ctx,
                ))
                .await;
                return Err(err);
            }
        };
        let Some(info) = inventory.service(&service) else {
            self.audit_best_effort(&service_event(
                current,
                action,
                Some(&service),
                AuditOutcome::Failure,
                ctx,
            ))
            .await;
            return Err(DokployServiceError::ServiceNotVisible);
        };
        let placement = DokployPlacement::from(info);
        let stored_placement = self
            .db
            .confirm_dokploy_placement(
                &NewDokployPlacement {
                    url: &stored.url,
                    service_kind: placement.service.kind.as_str(),
                    service_id: placement.service.id.as_str(),
                    service_name: &placement.service_name,
                    project_id: placement.project_id.as_str(),
                    project_name: &placement.project_name,
                    environment_id: placement.environment_id.as_str(),
                    environment_name: &placement.environment_name,
                    confirmed_by: current.account.id,
                },
                &service_event(current, action, Some(&service), AuditOutcome::Success, ctx),
            )
            .await?;
        if !stored_placement {
            return Err(DokployServiceError::NotConnected);
        }
        tracing::info!(
            service_kind = placement.service.kind.as_str(),
            service_id = placement.service.id.as_str(),
            "Dokploy placement confirmed"
        );
        self.placement(current, ctx).await
    }

    /// Forgets the confirmed placement. Nothing in Dokploy changes.
    pub async fn clear_placement(
        &self,
        current: &CurrentSession,
        ctx: RequestContext<'_>,
    ) -> Result<(), DokployServiceError> {
        let action = "dokploy.placement_clear";
        self.require_admin(current, action, ctx).await?;
        let Some(row) = self.db.find_dokploy_placement().await? else {
            return Ok(());
        };
        // A row this server cannot read is still cleared.
        let service = placement_from_row(&row)
            .ok()
            .map(|confirmed| confirmed.placement.service);
        self.db
            .clear_dokploy_placement(&service_event(
                current,
                action,
                service.as_ref(),
                AuditOutcome::Success,
                ctx,
            ))
            .await?;
        tracing::info!("Dokploy placement cleared");
        Ok(())
    }

    /// The confirmed placement compared with what Dokploy reports, for the
    /// startup report. No operator is involved, so nothing is audited.
    /// `None` when Dokploy is not connected or no placement is confirmed.
    pub async fn placement_status(
        &self,
    ) -> Result<Option<(DokployPlacement, PlacementStatus)>, DokployServiceError> {
        let Some(stored) = self.db.find_dokploy_connection().await? else {
            return Ok(None);
        };
        let Some(confirmed) = self.confirmed_placement().await? else {
            return Ok(None);
        };
        let inventory = self.read_inventory(&stored).await?;
        let status = PlacementStatus::check(
            &confirmed.placement,
            &inventory,
            self.public_host.as_deref(),
        );
        Ok(Some((confirmed.placement, status)))
    }

    async fn confirmed_placement(&self) -> Result<Option<ConfirmedPlacement>, DokployServiceError> {
        self.db
            .find_dokploy_placement()
            .await?
            .as_ref()
            .map(placement_from_row)
            .transpose()
            .map_err(DokployServiceError::from)
    }

    /// Reads what the stored key can see in Dokploy.
    async fn read_inventory(
        &self,
        stored: &StoredDokployConnection,
    ) -> Result<DokployInventory, DokployServiceError> {
        let (url, key) = self.open_key(stored)?;
        Ok(self.connector.inventory(&url, &key).await?)
    }

    async fn current_overview(&self) -> Result<DokployOverview, DokployServiceError> {
        let connection = match self.db.find_dokploy_connection().await? {
            Some(stored) => Some(self.summary(&stored)?),
            None => None,
        };
        Ok(DokployOverview {
            storage_available: self.cipher.is_some(),
            connection,
        })
    }

    fn summary(
        &self,
        stored: &StoredDokployConnection,
    ) -> Result<DokployConnectionSummary, DokployServiceError> {
        let url = stored_url(stored)?;
        let version = DokployVersion::parse(&stored.version)
            .ok_or(PersistenceError::InvalidRow("dokploy_connection.version"))?;
        let key_readable = self.cipher.as_ref().is_some_and(|cipher| {
            cipher
                .open_dokploy_key(url.as_str(), &sealed(stored))
                .is_ok()
        });
        Ok(DokployConnectionSummary {
            url,
            version,
            verified_at: stored.verified_at,
            connected: DokployChange {
                at: stored.connected_at,
                by: ChangedBy::from_stored(
                    stored.connected_by.clone(),
                    stored.connected_by_deployment,
                ),
            },
            key_replaced: stored.key_replaced_at.map(|at| DokployChange {
                at,
                by: ChangedBy::from_stored(
                    stored.key_replaced_by.clone(),
                    stored.key_replaced_by_deployment,
                ),
            }),
            key_readable,
            from_deployment: stored.from_deployment,
        })
    }

    /// Calls Dokploy with a key that is not stored yet. A failure is
    /// audited, best effort, with the host.
    async fn try_key(
        &self,
        current: &CurrentSession,
        action: &'static str,
        url: &DokployUrl,
        key: &SecretString,
        ctx: RequestContext<'_>,
    ) -> Result<DokployVersion, DokployServiceError> {
        match self.connector.connect(url, key).await {
            Ok(version) => Ok(version),
            Err(err) => {
                tracing::warn!(dokploy_host = %url.host(), error = %err, action, "Dokploy did not accept the connection");
                self.audit_best_effort(&event(
                    current,
                    action,
                    Some(url),
                    AuditOutcome::Failure,
                    ctx,
                ))
                .await;
                Err(err.into())
            }
        }
    }

    /// Refuses, and audits the refusal, unless the operator is an
    /// installation administrator. The flag comes from the database with
    /// the session on every request, so revoking it takes effect at once.
    async fn require_admin(
        &self,
        current: &CurrentSession,
        action: &'static str,
        ctx: RequestContext<'_>,
    ) -> Result<(), DokployServiceError> {
        if current.account.is_installation_admin {
            return Ok(());
        }
        self.audit_best_effort(&event(current, action, None, AuditOutcome::Denied, ctx))
            .await;
        Err(DokployServiceError::Forbidden)
    }

    async fn audit_best_effort(&self, event: &AuditEvent<'_>) {
        if let Err(err) = self.db.record_audit_event(event).await {
            tracing::error!(error = %err, action = event.action, "could not record audit event");
        }
    }
}

fn checked_key(raw: &SecretString) -> Result<SecretString, DokployKeyError> {
    use secrecy::ExposeSecret;
    check_dokploy_key(raw.expose_secret()).map(|key| SecretString::from(key.to_owned()))
}

fn stored_url(stored: &StoredDokployConnection) -> Result<DokployUrl, PersistenceError> {
    DokployUrl::parse(&stored.url)
        .map_err(|_| PersistenceError::InvalidRow("dokploy_connection.url"))
}

fn sealed(stored: &StoredDokployConnection) -> Sealed {
    Sealed {
        key_id: stored.key.key_id.clone(),
        nonce: stored.key.nonce.clone(),
        ciphertext: stored.key.ciphertext.clone(),
    }
}

fn placement_from_row(
    row: &StoredDokployPlacement,
) -> Result<ConfirmedPlacement, PersistenceError> {
    let invalid = |column| PersistenceError::InvalidRow(column);
    let id = |raw: &str, column| DokployId::parse(raw).map_err(|_| invalid(column));
    Ok(ConfirmedPlacement {
        placement: DokployPlacement {
            service: DokployServiceRef {
                kind: DokployServiceKind::parse(&row.service_kind)
                    .ok_or(invalid("dokploy_placement.service_kind"))?,
                id: id(&row.service_id, "dokploy_placement.service_id")?,
            },
            service_name: row.service_name.clone(),
            project_id: id(&row.project_id, "dokploy_placement.project_id")?,
            project_name: row.project_name.clone(),
            environment_id: id(&row.environment_id, "dokploy_placement.environment_id")?,
            environment_name: row.environment_name.clone(),
        },
        confirmed_at: row.confirmed_at,
        confirmed_by: row.confirmed_by()?,
    })
}

/// What applying the deployment's Dokploy connection did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentConnection {
    /// The deployment supplies no connection, and none it supplied is
    /// stored.
    NotSupplied,
    /// The stored connection was supplied by the deployment, which no longer
    /// supplies one; administrators can manage it again.
    Released,
    /// Stored as supplied, possibly replacing an earlier supplied URL.
    Connected,
    /// The stored key was replaced with the supplied one.
    KeyReplaced,
    /// The stored connection already matched.
    Unchanged,
}

/// Whether trying again later may succeed: Dokploy was unreachable or
/// answered with an error of its own. A refused key or an unsupported
/// version stays refused until the configuration changes.
#[must_use]
pub fn is_transient(err: &DokployError) -> bool {
    match err {
        DokployError::Unreachable(_) | DokployError::InvalidResponse => true,
        DokployError::Http(status) => *status >= 500 || *status == 429,
        DokployError::KeyRejected | DokployError::UnsupportedVersion { .. } => false,
    }
}

/// An audit event for a change the server made from the deployment's
/// configuration, with no actor.
fn deployment_event(
    action: &'static str,
    url: &DokployUrl,
    outcome: AuditOutcome,
) -> AuditEvent<'static> {
    AuditEvent {
        actor_account_id: None,
        action,
        target_type: Some("dokploy"),
        target_id: Some(truncate(&url.host(), AUDIT_TARGET_MAX_CHARS).to_owned()),
        outcome,
        request_id: None,
    }
}

/// An audit event naming a Dokploy service by kind and ID, such as
/// `compose:_IK3e1y1IwxNCLnlLGXEZ`. Both are checked Dokploy IDs, so the
/// target holds nothing else.
fn service_event<'a>(
    current: &CurrentSession,
    action: &'static str,
    service: Option<&DokployServiceRef>,
    outcome: AuditOutcome,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some("dokploy_service"),
        target_id: service
            .map(|service| format!("{}:{}", service.kind.as_str(), service.id.as_str())),
        outcome,
        request_id: ctx.request_id,
    }
}

/// An audit event naming Dokploy's host as the target, never the key or
/// the full URL.
fn event<'a>(
    current: &CurrentSession,
    action: &'static str,
    url: Option<&DokployUrl>,
    outcome: AuditOutcome,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some("dokploy"),
        target_id: url.map(|url| truncate(&url.host(), AUDIT_TARGET_MAX_CHARS).to_owned()),
        outcome,
        request_id: ctx.request_id,
    }
}

fn truncate(value: &str, max_chars: usize) -> &str {
    match value.char_indices().nth(max_chars) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn audit_targets_fit_the_column() {
        let long = "a".repeat(300);
        assert_eq!(truncate(&long, 128).len(), 128);
        assert_eq!(
            truncate("dokploy.example.test", 128),
            "dokploy.example.test"
        );
    }
}
