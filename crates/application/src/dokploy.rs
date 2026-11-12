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
use supabase_dashboard_domain::dokploy::{
    DokployChange, DokployConnectionSummary, DokployError, DokployKeyError, DokployOverview,
    DokployUrl, DokployVersion, InvalidDokployUrl, check_dokploy_key,
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
    dokploy::{NewDokployConnection, ReplacedDokployKey, StoredDokployConnection},
};

use crate::{
    auth::{CurrentSession, RequestContext},
    secrets::{CipherError, CredentialCipher, Sealed},
};

/// Longest audit target ID the audit log accepts.
const AUDIT_TARGET_MAX_CHARS: usize = 128;

pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DokployVersion, DokployError>> + Send + 'a>>;

/// Calls Dokploy with a key. Implementations must enforce the outbound
/// address policy at connection time, never follow redirects, bound time
/// and response size, and never put the key anywhere but the request
/// header.
pub trait DokployConnector: Send + Sync {
    /// Reads Dokploy's version with `key` and refuses a release the
    /// dashboard does not support. Returns the supported version found.
    fn connect<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> ConnectFuture<'a>;
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
        }
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
                    connected_by: current.account.id,
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
                    replaced_by: current.account.id,
                },
                &event(current, action, Some(&url), AuditOutcome::Success, ctx),
            )
            .await?;
        // Removed, or removed and connected elsewhere, while Dokploy was
        // being called.
        if !replaced {
            return Err(DokployServiceError::NotConnected);
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
            return Err(DokployServiceError::NotConnected);
        }
        tracing::info!("Dokploy connection removed");
        Ok(())
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
                by: stored.connected_by.clone(),
            },
            key_replaced: stored.key_replaced_at.map(|at| DokployChange {
                at,
                by: stored.key_replaced_by.clone(),
            }),
            key_readable,
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
