//! Encryption of project credentials at rest.
//!
//! Each value is sealed with AES-256-GCM (RustCrypto `aes-gcm`) under a key
//! the deployment supplies, with a fresh random 96-bit nonce. The associated
//! data binds a ciphertext to its project and credential kind, so a row
//! copied onto another project or kind fails to decrypt instead of being
//! used there.
//!
//! The metadata database stores the key's ID next to each ciphertext. A row
//! written under a different key is reported as unreadable rather than
//! treated as corrupt.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use supabase_dashboard_domain::connection::CredentialKind;
use uuid::Uuid;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error(
        "the encryption key must be base64 for exactly 32 bytes, e.g. `openssl rand -base64 32`"
    )]
    InvalidFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    #[error("the system random number generator failed")]
    Randomness,
    /// The value was written under another key, or it was altered.
    #[error("the stored value could not be decrypted")]
    Undecryptable,
}

/// A sealed value as it is stored.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The deployment's credential encryption key.
#[derive(Clone)]
pub struct CredentialCipher {
    cipher: Aes256Gcm,
    key_id: String,
}

// Never print key material.
impl fmt::Debug for CredentialCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialCipher")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl CredentialCipher {
    /// Builds the cipher from a base64-encoded 32-byte key, as written by
    /// `openssl rand -base64 32`. Surrounding whitespace is ignored.
    pub fn from_base64(encoded: &SecretString) -> Result<Self, KeyError> {
        let bytes = STANDARD
            .decode(encoded.expose_secret().trim())
            .map_err(|_| KeyError::InvalidFormat)?;
        if bytes.len() != KEY_LEN {
            return Err(KeyError::InvalidFormat);
        }
        let cipher = Aes256Gcm::new_from_slice(&bytes).map_err(|_| KeyError::InvalidFormat)?;
        // The ID is a truncated hash of the key under a fixed label. It
        // tells keys apart without revealing anything usable about them.
        let digest = Sha256::new()
            .chain_update(b"supabase-dashboard credential key id v1\0")
            .chain_update(&bytes)
            .finalize();
        let key_id = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self { cipher, key_id })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn seal(
        &self,
        project_id: Uuid,
        kind: CredentialKind,
        value: &SecretString,
    ) -> Result<Sealed, CipherError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|_| CipherError::Randomness)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_bytes);
        let aad = associated_data(project_id, kind);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: value.expose_secret().as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            // Only possible for inputs far beyond the accepted key length.
            .map_err(|_| CipherError::Undecryptable)?;
        Ok(Sealed {
            key_id: self.key_id.clone(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Whether a stored value was written under this key.
    pub fn can_open(&self, key_id: &str) -> bool {
        key_id == self.key_id
    }

    pub fn open(
        &self,
        project_id: Uuid,
        kind: CredentialKind,
        sealed: &Sealed,
    ) -> Result<SecretString, CipherError> {
        if !self.can_open(&sealed.key_id) {
            return Err(CipherError::Undecryptable);
        }
        let nonce_bytes: [u8; NONCE_LEN] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CipherError::Undecryptable)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_bytes);
        let aad = associated_data(project_id, kind);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &sealed.ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CipherError::Undecryptable)?;
        String::from_utf8(plaintext)
            .map(SecretString::from)
            .map_err(|_| CipherError::Undecryptable)
    }
}

fn associated_data(project_id: Uuid, kind: CredentialKind) -> String {
    format!(
        "supabase-dashboard:project-credential:v1:{project_id}:{}",
        kind.as_str()
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const KEY_B: &str = "HxwdHhscGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=";

    fn cipher(key: &str) -> CredentialCipher {
        CredentialCipher::from_base64(&SecretString::from(key)).unwrap()
    }

    #[test]
    fn round_trip() {
        let c = cipher(KEY_A);
        let project = Uuid::from_u128(1);
        let value = SecretString::from("eyJhbGciOiJIUzI1NiJ9.e30.sig");
        let sealed = c.seal(project, CredentialKind::AnonKey, &value).unwrap();
        assert_eq!(sealed.nonce.len(), NONCE_LEN);
        assert!(
            !sealed.ciphertext.windows(5).any(|w| w == b"eyJhb"),
            "plaintext must not appear in the ciphertext"
        );
        let opened = c.open(project, CredentialKind::AnonKey, &sealed).unwrap();
        assert_eq!(opened.expose_secret(), value.expose_secret());
    }

    #[test]
    fn nonces_differ_between_seals() {
        let c = cipher(KEY_A);
        let value = SecretString::from("same value");
        let a = c
            .seal(Uuid::nil(), CredentialKind::AnonKey, &value)
            .unwrap();
        let b = c
            .seal(Uuid::nil(), CredentialKind::AnonKey, &value)
            .unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn values_are_bound_to_project_and_kind() {
        let c = cipher(KEY_A);
        let value = SecretString::from("secret");
        let sealed = c
            .seal(Uuid::from_u128(1), CredentialKind::ServiceRoleKey, &value)
            .unwrap();
        assert_eq!(
            c.open(Uuid::from_u128(2), CredentialKind::ServiceRoleKey, &sealed)
                .unwrap_err(),
            CipherError::Undecryptable
        );
        assert_eq!(
            c.open(Uuid::from_u128(1), CredentialKind::AnonKey, &sealed)
                .unwrap_err(),
            CipherError::Undecryptable
        );
    }

    #[test]
    fn other_keys_and_tampering_are_detected() {
        let a = cipher(KEY_A);
        let b = cipher(KEY_B);
        assert_ne!(a.key_id(), b.key_id());
        assert_eq!(a.key_id().len(), 16);
        let mut sealed = a
            .seal(
                Uuid::nil(),
                CredentialKind::AnonKey,
                &SecretString::from("x"),
            )
            .unwrap();
        assert!(!b.can_open(&sealed.key_id));
        assert!(
            b.open(Uuid::nil(), CredentialKind::AnonKey, &sealed)
                .is_err()
        );
        // Same key ID but a flipped ciphertext bit.
        sealed.ciphertext[0] ^= 1;
        assert!(
            a.open(Uuid::nil(), CredentialKind::AnonKey, &sealed)
                .is_err()
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        for bad in [
            "",
            "not base64!",
            "AAECAwQFBgcICQoLDA0ODw==",
            &format!("{KEY_A}AA"),
        ] {
            assert!(
                CredentialCipher::from_base64(&SecretString::from(bad)).is_err(),
                "{bad}"
            );
        }
        // Trailing newline from a key file is fine.
        assert!(CredentialCipher::from_base64(&SecretString::from(format!("{KEY_A}\n"))).is_ok());
    }

    #[test]
    fn debug_output_hides_the_key() {
        let printed = format!("{:?}", cipher(KEY_A));
        assert!(!printed.contains(KEY_A));
        assert!(printed.contains("key_id"));
    }
}
