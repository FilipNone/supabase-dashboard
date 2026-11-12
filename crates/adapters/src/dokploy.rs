//! Dokploy's HTTP API, the first deployment provider.
//!
//! Every call goes to a path built here under the Dokploy URL an
//! installation admin entered. The API key travels in the `x-api-key`
//! header, marked sensitive, and never in the URL. The client follows the
//! same rules as the gateway checks: resolved addresses are checked against
//! the target policy at connection time, redirects are not followed,
//! proxies from the environment are ignored, and each request has a
//! connect timeout, a total timeout, and a bound on the body it reads.

use std::{sync::Arc, time::Duration};

use reqwest::{
    Client, Response, StatusCode,
    header::{ACCEPT, HeaderValue},
    redirect,
};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::dokploy::{ConnectFuture, DokployConnector};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    dokploy::{DokployUrl, DokployVersion},
};

/// Defined with the domain types so the application layer can name it;
/// re-exported here for callers of the client.
pub use supabase_dashboard_domain::dokploy::DokployError;

use crate::{
    gateway::{GatewayError, classify, refused_literal},
    net::{PolicyResolver, TargetPolicy},
    tls::{Clients, ExtraRoots},
};

/// Largest body read from a small Dokploy answer, such as the version.
const MAX_SMALL_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone)]
pub struct DokploySettings {
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Authorities trusted in addition to the bundled roots.
    pub extra_roots: ExtraRoots,
}

impl Default for DokploySettings {
    fn default() -> Self {
        Self {
            policy: TargetPolicy::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            extra_roots: ExtraRoots::default(),
        }
    }
}

/// A Dokploy that answered with a supported version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DokployConnection {
    pub version: DokployVersion,
}

/// Calls Dokploy's API with an installation's key.
#[derive(Clone)]
pub struct DokployClient {
    clients: Arc<Clients>,
    policy: TargetPolicy,
}

impl DokployClient {
    pub fn new(settings: DokploySettings) -> Result<Self, GatewayError> {
        let policy = settings.policy;
        let clients = Clients::new(settings.extra_roots, move |config| {
            Client::builder()
                .tls_backend_preconfigured(config)
                .dns_resolver(PolicyResolver { policy })
                .redirect(redirect::Policy::none())
                .no_proxy()
                .connect_timeout(settings.connect_timeout)
                .timeout(settings.request_timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
                .build()
        })?;
        Ok(Self {
            clients: Arc::new(clients),
            policy,
        })
    }

    /// The client as the application's [`DokployConnector`].
    pub fn shared(settings: DokploySettings) -> Result<Arc<dyn DokployConnector>, GatewayError> {
        Ok(Arc::new(Self::new(settings)?))
    }

    /// Reads Dokploy's version with `key` and refuses a release the
    /// dashboard does not support. Nothing else is called before this.
    pub async fn connect(
        &self,
        url: &DokployUrl,
        key: &SecretString,
    ) -> Result<DokployConnection, DokployError> {
        let version = self.version(url, key).await?;
        if !version.is_supported() {
            return Err(DokployError::UnsupportedVersion { found: version });
        }
        Ok(DokployConnection { version })
    }

    /// `settings.getDokployVersion`, which needs a valid key and answers
    /// with a JSON string such as `"v0.31.1"`.
    pub async fn version(
        &self,
        url: &DokployUrl,
        key: &SecretString,
    ) -> Result<DokployVersion, DokployError> {
        let body = self.get(url, "settings.getDokployVersion", key).await?;
        let raw: String =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        DokployVersion::parse(&raw).ok_or(DokployError::InvalidResponse)
    }

    async fn get(
        &self,
        base: &DokployUrl,
        call: &str,
        key: &SecretString,
    ) -> Result<Vec<u8>, DokployError> {
        let unreachable = DokployError::Unreachable;
        let url = reqwest::Url::parse(&base.api(call))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        if refused_literal(&url, self.policy) {
            return Err(unreachable(UnreachableReason::DestinationNotAllowed));
        }
        let mut key_header =
            HeaderValue::from_str(key.expose_secret()).map_err(|_| DokployError::KeyRejected)?;
        key_header.set_sensitive(true);
        let client = self
            .clients
            .get(None)
            .map_err(|_| unreachable(UnreachableReason::Tls))?;
        let response = client
            .get(url)
            .header("x-api-key", key_header)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| unreachable(classify(&err)))?;
        match response.status() {
            status if status.is_success() => read_bounded(response).await,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(DokployError::KeyRejected),
            status => Err(DokployError::Http(status.as_u16())),
        }
    }
}

impl DokployConnector for DokployClient {
    fn connect<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> ConnectFuture<'a> {
        Box::pin(async move {
            DokployClient::connect(self, url, key)
                .await
                .map(|connection| connection.version)
        })
    }
}

async fn read_bounded(mut response: Response) -> Result<Vec<u8>, DokployError> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > MAX_SMALL_BODY_BYTES {
                    return Err(DokployError::InvalidResponse);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(err) => return Err(DokployError::Unreachable(classify(&err))),
        }
    }
}
