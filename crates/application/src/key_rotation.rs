//! Moving stored project credentials to the current encryption key.
//!
//! After an operator installs a new key and keeps the old one as a previous
//! key, `reseal_credentials` opens every value written under a previous key
//! and seals it again under the current one. The server keeps working
//! during the run: each row is replaced only if it still holds the value
//! that was read, so a key an operator replaces in the meantime is not
//! overwritten. Running it again is harmless.
//!
//! The run is a server command, like resetting a password, so it has no
//! dashboard actor. It is audited with the new key's ID and no values.

use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::{AuditEvent, AuditOutcome},
};

use crate::secrets::{CipherError, CredentialCipher, Sealed};

/// Rows read per query.
const PAGE: i64 = 200;

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("the system random number generator failed")]
    Randomness,
}

/// What a run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RotationSummary {
    /// Values now sealed under the current key.
    pub resealed: u64,
    /// Values under a key this server does not have, or that failed to
    /// decrypt. They stay as they are and must be entered again.
    pub unreadable: u64,
    /// Values replaced by an operator while the run was reading them.
    pub changed_meanwhile: u64,
}

/// How the stored values divide between the configured keys.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage {
    pub current: i64,
    pub previous: i64,
    pub unknown: i64,
}

/// Counts stored values by the key they are sealed under.
pub async fn key_usage(
    db: &Database,
    cipher: &CredentialCipher,
) -> Result<KeyUsage, PersistenceError> {
    let mut usage = KeyUsage::default();
    for (key_id, count) in db.count_credentials_by_key().await? {
        let slot = if key_id == cipher.key_id() {
            &mut usage.current
        } else if cipher.can_open(&key_id) {
            &mut usage.previous
        } else {
            &mut usage.unknown
        };
        *slot = slot.saturating_add(count);
    }
    Ok(usage)
}

/// Seals every stored value that is not under the current key again under
/// it, where a previous key can open it.
pub async fn reseal_credentials(
    db: &Database,
    cipher: &CredentialCipher,
) -> Result<RotationSummary, RotationError> {
    let mut summary = RotationSummary::default();
    let mut after = None;
    loop {
        let page = db
            .list_credentials_not_under(cipher.key_id(), after, PAGE)
            .await?;
        let Some((last_project, last)) = page.last() else {
            break;
        };
        after = Some((*last_project, last.kind));
        for (project_id, stored) in &page {
            let sealed = Sealed {
                key_id: stored.key_id.clone(),
                nonce: stored.nonce.clone(),
                ciphertext: stored.ciphertext.clone(),
            };
            let resealed = match cipher.reseal(*project_id, stored.kind, &sealed) {
                Ok(Some(resealed)) => resealed,
                // The query skips current-key rows, but another run may
                // have moved this one since.
                Ok(None) => continue,
                Err(CipherError::Undecryptable) => {
                    summary.unreadable += 1;
                    continue;
                }
                Err(CipherError::Randomness) => return Err(RotationError::Randomness),
            };
            let replaced = db
                .reseal_credential(
                    *project_id,
                    stored.kind,
                    &stored.nonce,
                    &resealed.key_id,
                    &resealed.nonce,
                    &resealed.ciphertext,
                )
                .await?;
            if replaced {
                summary.resealed += 1;
            } else {
                summary.changed_meanwhile += 1;
            }
        }
    }
    db.record_audit_event(&AuditEvent {
        actor_account_id: None,
        action: "credentials.reseal",
        target_type: Some("credential_key"),
        target_id: Some(cipher.key_id().to_owned()),
        outcome: AuditOutcome::Success,
        request_id: None,
    })
    .await?;
    Ok(summary)
}
