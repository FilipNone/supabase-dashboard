//! Argon2id password hashing (RustCrypto `argon2`, default OWASP-recommended
//! parameters). Hashing is CPU- and memory-heavy, so it runs on the blocking
//! thread pool and a semaphore caps how many hashes run at once.

use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher as _, PasswordVerifier as _, phc::PasswordHash},
};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password hashing failed")]
    Hash,
    #[error("the stored password hash is malformed")]
    MalformedHash,
    #[error("password hashing was cancelled")]
    Cancelled,
}

#[derive(Clone)]
pub struct PasswordHashing {
    permits: Arc<Semaphore>,
}

impl PasswordHashing {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
        }
    }

    /// Returns a PHC string (`$argon2id$v=19$...`) with a random salt.
    pub async fn hash(&self, password: &SecretString) -> Result<String, PasswordError> {
        let password = password.clone();
        self.run(move || {
            Argon2::default()
                .hash_password(password.expose_secret().as_bytes())
                .map(|hash| hash.to_string())
                .map_err(|_| PasswordError::Hash)
        })
        .await
    }

    /// Checks `password` against a stored PHC string, using the parameters
    /// recorded in that string. `Ok(false)` means the password is wrong.
    pub async fn verify(
        &self,
        password: &SecretString,
        stored: &str,
    ) -> Result<bool, PasswordError> {
        let password = password.clone();
        let stored = stored.to_owned();
        self.run(move || {
            let parsed = PasswordHash::new(&stored).map_err(|_| PasswordError::MalformedHash)?;
            Ok(Argon2::default()
                .verify_password(password.expose_secret().as_bytes(), &parsed)
                .is_ok())
        })
        .await
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, PasswordError> + Send + 'static,
    ) -> Result<T, PasswordError> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| PasswordError::Cancelled)?;
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|_| PasswordError::Cancelled)?
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn hash_and_verify() {
        let hashing = PasswordHashing::new(2);
        let password = SecretString::from("correct horse battery");
        let stored = hashing.hash(&password).await.unwrap();
        assert!(stored.starts_with("$argon2id$v=19$"), "{stored}");
        assert!(!stored.contains("correct horse"));
        assert!(hashing.verify(&password, &stored).await.unwrap());
        let wrong = SecretString::from("wrong horse battery");
        assert!(!hashing.verify(&wrong, &stored).await.unwrap());
    }

    #[tokio::test]
    async fn malformed_stored_hash_is_an_error_not_a_match() {
        let hashing = PasswordHashing::new(1);
        let result = hashing
            .verify(&SecretString::from("anything at all"), "not-a-phc-string")
            .await;
        assert!(matches!(result, Err(PasswordError::MalformedHash)));
    }
}
