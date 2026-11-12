//! Private certificate authorities trusted for one project's gateway.
//!
//! A project whose gateway presents a certificate from a private authority
//! can have that authority's certificates stored with it. Health checks,
//! the Studio login check, and Studio traffic for that project then trust
//! them in addition to the bundled public roots and the deployment-wide
//! `SUPABASE_DASHBOARD_EXTRA_CA_FILE`. Other projects do not.
//!
//! Certificates are public, so the bundle is stored as PEM text and its
//! summary may be shown to any member. The network adapter parses it; this
//! module holds only the limits and the shapes passed around.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::connection::KeyExpiry;

/// Largest PEM bundle a project may store, in bytes.
pub const MAX_PROJECT_AUTHORITIES_BYTES: usize = 64 * 1024;

/// Most certificates in one project's bundle.
pub const MAX_PROJECT_AUTHORITIES: usize = 8;

/// A project's PEM bundle as stored: checked by the network adapter before
/// it was saved. Cheap to clone; equal bundles compare equal, so an adapter
/// can reuse a connection pool built for one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectAuthorities(Arc<str>);

impl ProjectAuthorities {
    /// Wraps a bundle read from storage. The adapter parses it again when
    /// it uses it, so a bundle that no longer parses fails the TLS
    /// handshake instead of being trusted partly.
    pub fn from_stored(pem: &str) -> Self {
        Self(Arc::from(pem))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One certificate of a stored bundle, as the settings page lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityInfo {
    /// The certificate's subject, as an RFC 4514 string.
    pub subject: String,
    pub not_after: OffsetDateTime,
    /// SHA-256 of the DER certificate, as colon-separated uppercase hex,
    /// to compare with the authority's own records.
    pub sha256: String,
}

impl AuthorityInfo {
    pub fn expiry(&self, now: OffsetDateTime) -> KeyExpiry {
        KeyExpiry::new(self.not_after, now)
    }
}

/// What a project's settings page shows about its stored bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectTrust {
    pub authorities: Vec<AuthorityInfo>,
    pub updated_at: OffsetDateTime,
    /// When the summary was read, to count the days to each expiry.
    pub read_at: OffsetDateTime,
}

/// Why a pasted bundle was refused. Messages are shown to the operator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum AuthorityError {
    #[error("the certificates are larger than {MAX_PROJECT_AUTHORITIES_BYTES} bytes")]
    TooLarge,
    #[error("give at most {MAX_PROJECT_AUTHORITIES} certificates")]
    TooMany,
    #[error("paste at least one certificate in PEM form (-----BEGIN CERTIFICATE-----)")]
    Empty,
    #[error("the text is not valid PEM")]
    NotPem,
    /// A private key or another block. Only certificates belong here, and
    /// a pasted private key is not stored.
    #[error("only certificates are accepted; remove any private key or other block")]
    NotACertificate,
    #[error("certificate {index} cannot be read or used as an authority")]
    Unusable { index: usize },
}

/// The size and count checks that need no parsing, applied before the
/// adapter reads the bundle.
pub fn check_bundle_size(pem: &str) -> Result<&str, AuthorityError> {
    let pem = pem.trim();
    if pem.len() > MAX_PROJECT_AUTHORITIES_BYTES {
        return Err(AuthorityError::TooLarge);
    }
    if pem.is_empty() {
        return Err(AuthorityError::Empty);
    }
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_are_trimmed_and_bounded() {
        assert_eq!(check_bundle_size("  \n-----BEGIN"), Ok("-----BEGIN"));
        assert_eq!(check_bundle_size(" \n "), Err(AuthorityError::Empty));
        let huge = "a".repeat(MAX_PROJECT_AUTHORITIES_BYTES + 1);
        assert_eq!(check_bundle_size(&huge), Err(AuthorityError::TooLarge));
    }

    #[test]
    fn equal_bundles_are_equal() {
        let a = ProjectAuthorities::from_stored("x");
        assert_eq!(a, ProjectAuthorities::from_stored("x"));
        assert_ne!(a, ProjectAuthorities::from_stored("y"));
        assert_eq!(a.as_str(), "x");
    }
}
