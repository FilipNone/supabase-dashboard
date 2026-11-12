//! Which certificate authorities outbound HTTPS trusts.
//!
//! Health checks and the Studio proxy trust the Mozilla root store bundled
//! with the binary. A deployment whose stacks use certificates from a
//! private authority can add that authority's certificates from a PEM file
//! (`SUPABASE_DASHBOARD_EXTRA_CA_FILE`). They are added to the bundled
//! roots, for every project; there is no per-project trust and no way to
//! turn certificate checks off.

use std::sync::Arc;

use rustls::pki_types::{
    CertificateDer,
    pem::{self, SectionKind},
};

/// Largest PEM file accepted, so a wrong path (a disk image, a log) fails
/// fast instead of being read into memory.
pub const MAX_EXTRA_CA_FILE_BYTES: usize = 1024 * 1024;

/// Certificates trusted in addition to the bundled roots. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct ExtraRoots(Arc<[CertificateDer<'static>]>);

#[derive(Debug, thiserror::Error)]
pub enum ExtraRootsError {
    #[error("the CA file is larger than {MAX_EXTRA_CA_FILE_BYTES} bytes")]
    TooLarge,
    #[error("the CA file is not valid PEM: {0}")]
    Pem(String),
    #[error("the CA file holds no certificate")]
    Empty,
    /// A private key or other block. Only the authority's certificates
    /// belong in the file.
    #[error("the CA file holds a {0:?} block; give only the authority's certificates")]
    NotACertificate(SectionKind),
    #[error("certificate {index} in the CA file cannot be used as a trust anchor: {source}")]
    Unusable {
        index: usize,
        #[source]
        source: rustls::Error,
    },
}

impl ExtraRoots {
    /// Reads the certificates of a PEM file and checks that each one can
    /// serve as a trust anchor. Any other block, such as a private key
    /// pasted into the same file by mistake, is refused.
    pub fn from_pem(pem: &[u8]) -> Result<Self, ExtraRootsError> {
        if pem.len() > MAX_EXTRA_CA_FILE_BYTES {
            return Err(ExtraRootsError::TooLarge);
        }
        let mut certs = Vec::new();
        let mut rest = pem;
        loop {
            match pem::from_buf(&mut rest) {
                Ok(Some((SectionKind::Certificate, der))) => certs.push(CertificateDer::from(der)),
                Ok(Some((kind, _))) => return Err(ExtraRootsError::NotACertificate(kind)),
                Ok(None) => break,
                Err(err) => return Err(ExtraRootsError::Pem(err.to_string())),
            }
        }
        if certs.is_empty() {
            return Err(ExtraRootsError::Empty);
        }
        let mut check = rustls::RootCertStore::empty();
        for (index, cert) in certs.iter().enumerate() {
            check
                .add(cert.clone())
                .map_err(|source| ExtraRootsError::Unusable {
                    index: index + 1,
                    source,
                })?;
        }
        Ok(Self(certs.into()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The TLS settings for outbound HTTPS: the bundled roots plus `extra`,
/// TLS 1.2 or later, no client certificate.
pub(crate) fn client_config(extra: &ExtraRoots) -> Result<rustls::ClientConfig, rustls::Error> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra.0.iter() {
        roots.add(cert.clone())?;
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth())
}
