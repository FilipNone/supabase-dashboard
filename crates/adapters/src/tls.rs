//! Which certificate authorities outbound HTTPS trusts.
//!
//! Health checks and the Studio proxy trust the Mozilla root store bundled
//! with the binary. A deployment whose stacks use certificates from a
//! private authority can add that authority's certificates from a PEM file
//! (`SUPABASE_DASHBOARD_EXTRA_CA_FILE`). They are added to the bundled
//! roots, for every project. A project can also have its own authorities
//! stored with it ([`ProjectAuthorities`]); those are added for that
//! project's connections only. There is no way to turn certificate checks
//! off.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use reqwest::Client;
use sha2::{Digest, Sha256};
use supabase_dashboard_domain::authority::{
    AuthorityError, AuthorityInfo, MAX_PROJECT_AUTHORITIES, MAX_PROJECT_AUTHORITIES_BYTES,
    ProjectAuthorities,
};
use time::OffsetDateTime;

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

    /// These roots followed by `other`'s.
    fn with(&self, other: &ExtraRoots) -> ExtraRoots {
        Self(self.0.iter().chain(other.0.iter()).cloned().collect())
    }
}

/// Reads a project's certificate bundle: at most
/// [`MAX_PROJECT_AUTHORITIES`] certificates, each usable as a trust anchor,
/// and nothing else. Returns the roots and a summary of each certificate.
pub fn read_authorities(pem: &str) -> Result<(ExtraRoots, Vec<AuthorityInfo>), AuthorityError> {
    if pem.len() > MAX_PROJECT_AUTHORITIES_BYTES {
        return Err(AuthorityError::TooLarge);
    }
    let roots = ExtraRoots::from_pem(pem.as_bytes()).map_err(|err| match err {
        ExtraRootsError::TooLarge => AuthorityError::TooLarge,
        ExtraRootsError::Pem(_) => AuthorityError::NotPem,
        ExtraRootsError::Empty => AuthorityError::Empty,
        ExtraRootsError::NotACertificate(_) => AuthorityError::NotACertificate,
        ExtraRootsError::Unusable { index, .. } => AuthorityError::Unusable { index },
    })?;
    if roots.len() > MAX_PROJECT_AUTHORITIES {
        return Err(AuthorityError::TooMany);
    }
    let infos = roots
        .0
        .iter()
        .enumerate()
        .map(|(index, der)| summarize(der).ok_or(AuthorityError::Unusable { index: index + 1 }))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((roots, infos))
}

fn summarize(der: &CertificateDer<'_>) -> Option<AuthorityInfo> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let not_after: OffsetDateTime = certificate.validity().not_after.to_datetime();
    let digest = Sha256::digest(der.as_ref());
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Some(AuthorityInfo {
        subject: certificate.subject().to_string(),
        not_after,
        sha256,
    })
}

/// Most HTTPS clients kept for projects with their own authorities. When
/// full, the cache is emptied and refilled as projects are checked again.
const MAX_CACHED_CLIENTS: usize = 64;

/// One HTTPS client for projects without their own authorities, and one
/// per distinct project bundle, so each bundle is trusted only for the
/// projects that store it.
pub(crate) struct Clients {
    shared: Client,
    extra: ExtraRoots,
    build: Box<dyn Fn(rustls::ClientConfig) -> Result<Client, reqwest::Error> + Send + Sync>,
    by_bundle: Mutex<HashMap<ProjectAuthorities, Client>>,
}

/// Why no client could be built for a project's bundle.
#[derive(Debug)]
pub(crate) struct UnusableBundle;

impl Clients {
    pub(crate) fn new(
        extra: ExtraRoots,
        build: impl Fn(rustls::ClientConfig) -> Result<Client, reqwest::Error> + Send + Sync + 'static,
    ) -> Result<Self, crate::gateway::GatewayError> {
        use crate::gateway::GatewayError;
        let shared = build(client_config(&extra).map_err(GatewayError::Tls)?)
            .map_err(GatewayError::Client)?;
        Ok(Self {
            shared,
            extra,
            build: Box::new(build),
            by_bundle: Mutex::new(HashMap::new()),
        })
    }

    /// The client for a project with `authorities`, built on first use.
    pub(crate) fn get(
        &self,
        authorities: Option<&ProjectAuthorities>,
    ) -> Result<Client, UnusableBundle> {
        let Some(authorities) = authorities else {
            return Ok(self.shared.clone());
        };
        if let Some(client) = self
            .by_bundle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(authorities)
        {
            return Ok(client.clone());
        }
        let (roots, _) = read_authorities(authorities.as_str()).map_err(|_| UnusableBundle)?;
        let config = client_config(&self.extra.with(&roots)).map_err(|_| UnusableBundle)?;
        let client = (self.build)(config).map_err(|_| UnusableBundle)?;
        let mut cache = self
            .by_bundle
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= MAX_CACHED_CLIENTS {
            cache.clear();
        }
        cache.insert(authorities.clone(), client.clone());
        Ok(client)
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
