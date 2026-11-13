//! The record of the variables the dashboard wrote to a provisioned
//! stack's Dokploy service, used to show which ones were edited in
//! Dokploy since.
//!
//! The record keeps a SHA-256 digest of each variable's value by name,
//! never the value, and is stored sealed with the credential key and
//! bound to the project, because some of the values are the stack's
//! secrets. Only the variables the dashboard wrote are recorded; every
//! other variable Dokploy has counts as added there.

use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use supabase_dashboard_domain::stack_settings::{EnvChanges, EnvFile, EnvTracking};
use supabase_dashboard_persistence::{Database, PersistenceError, provisioning::SealedEnvRecord};
use uuid::Uuid;

use crate::secrets::{CipherError, CredentialCipher, Sealed};

const VERSION: u8 = 1;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct EnvRecord {
    v: u8,
    /// Variable name to the digest of its values.
    vars: BTreeMap<String, String>,
}

/// The digest of a variable's raw values, one per line it is set on.
fn digest(values: &[&str]) -> String {
    let mut hash = Sha256::new();
    for value in values {
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl EnvRecord {
    /// Every variable in `env`.
    pub(super) fn of(env: &EnvFile) -> Self {
        Self {
            v: VERSION,
            vars: env
                .raw_values()
                .into_iter()
                .map(|(name, values)| (name.to_owned(), digest(&values)))
                .collect(),
        }
    }

    /// Records `names` as `env` has them now; a name `env` does not set
    /// is dropped.
    pub(super) fn refresh<'a>(&mut self, env: &EnvFile, names: impl IntoIterator<Item = &'a str>) {
        let values = env.raw_values();
        for name in names {
            match values.get(name) {
                Some(values) => {
                    self.vars.insert(name.to_owned(), digest(values));
                }
                None => {
                    self.vars.remove(name);
                }
            }
        }
    }

    /// The variables `env` has differently from the record.
    pub(super) fn compare(&self, env: &EnvFile) -> EnvChanges {
        let values = env.raw_values();
        let mut changes = EnvChanges::default();
        for (name, values) in &values {
            match self.vars.get(*name) {
                Some(recorded) if *recorded == digest(values) => {}
                Some(_) => changes.changed.push((*name).to_owned()),
                None => changes.added.push((*name).to_owned()),
            }
        }
        changes.removed = self
            .vars
            .keys()
            .filter(|name| !values.contains_key(name.as_str()))
            .cloned()
            .collect();
        changes
    }

    fn to_secret(&self) -> SecretString {
        // Serializing a map of strings cannot fail.
        SecretString::from(serde_json::to_string(self).unwrap_or_default())
    }

    fn from_secret(text: &SecretString) -> Option<Self> {
        serde_json::from_str::<Self>(text.expose_secret())
            .ok()
            .filter(|record| record.v == VERSION)
    }

    pub(super) fn seal(
        &self,
        cipher: &CredentialCipher,
        project_id: Uuid,
    ) -> Result<SealedEnvRecord, CipherError> {
        let sealed = cipher.seal_env_record(project_id, &self.to_secret())?;
        Ok(SealedEnvRecord {
            key_id: sealed.key_id,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        })
    }
}

/// A project's stored record, opened.
pub(super) enum Stored {
    Missing,
    /// Sealed under a key this server lacks, or not a record it reads.
    Unreadable {
        nonce: Vec<u8>,
    },
    Found {
        record: EnvRecord,
        nonce: Vec<u8>,
    },
}

impl Stored {
    /// The stored record's nonce, which a replacement must name.
    pub(super) fn nonce(&self) -> Option<&[u8]> {
        match self {
            Self::Missing => None,
            Self::Unreadable { nonce } | Self::Found { nonce, .. } => Some(nonce),
        }
    }

    /// How `env` compares with this record.
    pub(super) fn tracking(&self, env: &EnvFile) -> EnvTracking {
        match self {
            Self::Missing => EnvTracking::NotRecorded,
            Self::Unreadable { .. } => EnvTracking::Unreadable,
            Self::Found { record, .. } => EnvTracking::Compared(record.compare(env)),
        }
    }
}

pub(super) async fn load(
    db: &Database,
    cipher: Option<&CredentialCipher>,
    project_id: Uuid,
) -> Result<Stored, PersistenceError> {
    let Some(stored) = db.find_env_record(project_id).await? else {
        return Ok(Stored::Missing);
    };
    let Some(cipher) = cipher else {
        return Ok(Stored::Unreadable {
            nonce: stored.nonce,
        });
    };
    let sealed = Sealed {
        key_id: stored.key_id,
        nonce: stored.nonce,
        ciphertext: stored.ciphertext,
    };
    let record = cipher
        .open_env_record(project_id, &sealed)
        .ok()
        .and_then(|text| EnvRecord::from_secret(&text));
    Ok(match record {
        Some(record) => Stored::Found {
            record,
            nonce: sealed.nonce,
        },
        None => Stored::Unreadable {
            nonce: sealed.nonce,
        },
    })
}

/// How `env` compares with the project's record.
pub(super) async fn tracking(
    db: &Database,
    cipher: Option<&CredentialCipher>,
    project_id: Uuid,
    env: &EnvFile,
) -> Result<EnvTracking, PersistenceError> {
    Ok(load(db, cipher, project_id).await?.tracking(env))
}

/// Records that the dashboard wrote `names` as `env` has them. A project
/// without a readable record keeps none: a partial one would report
/// every other variable as added in Dokploy. Failures are logged; the
/// variables are already written.
pub(super) async fn record_written(
    db: &Database,
    cipher: Option<&CredentialCipher>,
    project_id: Uuid,
    env: &EnvFile,
    names: &[&str],
) {
    // A second try covers a key rotation resealing the record meanwhile.
    for _ in 0..2 {
        let (mut record, nonce) = match load(db, cipher, project_id).await {
            Ok(Stored::Found { record, nonce }) => (record, nonce),
            Ok(Stored::Missing) => return,
            Ok(Stored::Unreadable { .. }) => {
                tracing::warn!(%project_id, "the stack's variable record cannot be opened; not updated");
                return;
            }
            Err(err) => {
                tracing::warn!(%project_id, error = %err, "could not read the stack's variable record");
                return;
            }
        };
        let Some(cipher) = cipher else { return };
        record.refresh(env, names.iter().copied());
        let sealed = match record.seal(cipher, project_id) {
            Ok(sealed) => sealed,
            Err(err) => {
                tracing::warn!(%project_id, error = %err, "could not seal the stack's variable record");
                return;
            }
        };
        match db
            .replace_env_record(project_id, Some(&nonce), &sealed)
            .await
        {
            Ok(true) => return,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(%project_id, error = %err, "could not store the stack's variable record");
                return;
            }
        }
    }
    tracing::warn!(%project_id, "the stack's variable record kept changing; not updated");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_reports_names_only() {
        let written = EnvFile::parse("A=1\nB=2\nC=3\n");
        let record = EnvRecord::of(&written);
        assert!(record.compare(&written).is_empty());
        let now = EnvFile::parse("# comment\nA=1\nB=20\nD=4\n");
        let changes = record.compare(&now);
        assert_eq!(changes.changed, ["B"]);
        assert_eq!(changes.added, ["D"]);
        assert_eq!(changes.removed, ["C"]);
    }

    #[test]
    fn a_variable_set_twice_is_changed() {
        let record = EnvRecord::of(&EnvFile::parse("A=1\n"));
        let changes = record.compare(&EnvFile::parse("A=1\nA=1\n"));
        assert_eq!(changes.changed, ["A"]);
    }

    #[test]
    fn refresh_updates_only_the_names_written() {
        let mut record = EnvRecord::of(&EnvFile::parse("A=1\nB=2\n"));
        let now = EnvFile::parse("A=9\nB=8\n");
        record.refresh(&now, ["A"]);
        assert_eq!(record.compare(&now).changed, ["B"]);
        record.refresh(&EnvFile::parse("B=8\n"), ["A"]);
        assert_eq!(
            record.compare(&EnvFile::parse("B=2\n")),
            EnvChanges::default()
        );
    }

    #[test]
    fn the_record_holds_no_value() {
        let record = EnvRecord::of(&EnvFile::parse("POSTGRES_PASSWORD=hunter2-secret\n"));
        let text = record.to_secret();
        assert!(!text.expose_secret().contains("hunter2"));
        assert_eq!(EnvRecord::from_secret(&text), Some(record));
    }
}
