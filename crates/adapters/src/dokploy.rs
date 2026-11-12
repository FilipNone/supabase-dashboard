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
    Client, Method, Response, StatusCode,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
    redirect,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use supabase_dashboard_application::dokploy::{
    ConnectFuture, CreateEnvironmentFuture, DokployConnector, InventoryFuture, TargetsFuture,
};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    dokploy::{DokployUrl, DokployVersion},
    dokploy_placement::{
        DokployDomainInfo, DokployId, DokployInventory, DokployServiceInfo, DokployServiceKind,
        DokployServiceRef, bounded_name, normalize_host,
    },
    dokploy_target::{DokployEnvironmentInfo, DokployServerInfo, DokployTargetInventory},
};

/// Defined with the domain types so the application layer can name it;
/// re-exported here for callers of the client.
pub use supabase_dashboard_domain::dokploy::DokployError;

use crate::{
    gateway::{GatewayError, classify, refused_literal},
    net::{PolicyResolver, TargetPolicy},
    tls::{Clients, ExtraRoots},
};

mod compose;

/// What a call sends: GET input as flat query parameters, which is how
/// Dokploy reads it, or a JSON body.
#[derive(Clone, Copy)]
enum Input<'a> {
    Get(&'a [(&'a str, &'a str)]),
    Post(&'a serde_json::Value),
}

/// Largest body read from a small Dokploy answer, such as the version.
const MAX_SMALL_BODY_BYTES: usize = 4 * 1024;

/// Largest body read from a list, such as every service the key can see.
/// A service takes about 400 bytes in `overview.services`, so this covers
/// several thousand.
const MAX_LIST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Most entries read from one list; the rest are ignored.
const MAX_LIST_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct DokploySettings {
    pub policy: TargetPolicy,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Authorities trusted in addition to the bundled roots.
    pub extra_roots: ExtraRoots,
    /// The Dokploy URL the deployment supplies. Calls to exactly this URL
    /// may also reach loopback addresses, so a Dokploy on the same host
    /// works without opening loopback to project checks. Every other
    /// address rule still applies, and calls to any other URL use
    /// `policy`.
    pub enrolled_url: Option<DokployUrl>,
}

impl Default for DokploySettings {
    fn default() -> Self {
        Self {
            policy: TargetPolicy::default(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            extra_roots: ExtraRoots::default(),
            enrolled_url: None,
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
    enrolled: Option<Arc<Enrolled>>,
}

/// The clients for the enrolled URL, whose resolver allows loopback.
struct Enrolled {
    url: DokployUrl,
    clients: Clients,
    policy: TargetPolicy,
}

impl DokployClient {
    pub fn new(settings: DokploySettings) -> Result<Self, GatewayError> {
        let enrolled = match &settings.enrolled_url {
            Some(url) => {
                let policy = TargetPolicy {
                    allow_loopback: true,
                };
                Some(Arc::new(Enrolled {
                    url: url.clone(),
                    clients: Self::clients(&settings, policy)?,
                    policy,
                }))
            }
            None => None,
        };
        Ok(Self {
            clients: Arc::new(Self::clients(&settings, settings.policy)?),
            policy: settings.policy,
            enrolled,
        })
    }

    fn clients(settings: &DokploySettings, policy: TargetPolicy) -> Result<Clients, GatewayError> {
        let connect_timeout = settings.connect_timeout;
        let request_timeout = settings.request_timeout;
        Clients::new(settings.extra_roots.clone(), move |config| {
            Client::builder()
                .tls_backend_preconfigured(config)
                .dns_resolver(PolicyResolver { policy })
                .redirect(redirect::Policy::none())
                .no_proxy()
                .connect_timeout(connect_timeout)
                .timeout(request_timeout)
                .pool_idle_timeout(Duration::from_secs(30))
                .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
                .build()
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
        let body = self
            .get(url, "settings.getDokployVersion", key, MAX_SMALL_BODY_BYTES)
            .await?;
        let raw: String =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        DokployVersion::parse(&raw).ok_or(DokployError::InvalidResponse)
    }

    /// The application and compose services the key can see
    /// (`overview.services`) and the domains routed to them
    /// (`overview.domains`). Both are limited by Dokploy to the key's
    /// organization and to the services its member may access, and need
    /// the member's `service` and `domain` read permissions. Entries of
    /// other kinds, or with IDs that are not Dokploy IDs, are left out.
    pub async fn inventory(
        &self,
        url: &DokployUrl,
        key: &SecretString,
    ) -> Result<DokployInventory, DokployError> {
        let services = self
            .get(url, "overview.services", key, MAX_LIST_BODY_BYTES)
            .await?;
        let services: Vec<RawService> = parse_list(&services)?;
        let domains = self
            .get(url, "overview.domains", key, MAX_LIST_BODY_BYTES)
            .await?;
        let domains: Vec<RawDomain> = parse_list(&domains)?;
        Ok(DokployInventory {
            services: services
                .into_iter()
                .filter_map(RawService::into_info)
                .collect(),
            domains: domains
                .into_iter()
                .filter_map(RawDomain::into_info)
                .collect(),
        })
    }

    /// The environments the key can see (`project.all`, which Dokploy
    /// limits to the key's organization and the member's projects and
    /// environments), and the active deploy servers (`server.all`). A key
    /// whose member may not list servers gets `servers: None`: Dokploy
    /// accepted the same key for `project.all` a moment before, so a
    /// refusal here is about the permission, not the key.
    pub async fn targets(
        &self,
        url: &DokployUrl,
        key: &SecretString,
    ) -> Result<DokployTargetInventory, DokployError> {
        let projects = self
            .get(url, "project.all", key, MAX_LIST_BODY_BYTES)
            .await?;
        let projects: Vec<RawProject> = parse_list(&projects)?;
        let environments = projects
            .into_iter()
            .flat_map(RawProject::into_environments)
            .take(MAX_LIST_ENTRIES)
            .collect();
        let servers = match self.get(url, "server.all", key, MAX_LIST_BODY_BYTES).await {
            Ok(body) => Some(
                parse_list::<RawServer>(&body)?
                    .into_iter()
                    .filter_map(RawServer::into_info)
                    .collect(),
            ),
            Err(DokployError::KeyRejected) => None,
            Err(err) => return Err(err),
        };
        Ok(DokployTargetInventory {
            environments,
            servers,
        })
    }

    /// Creates an environment called `name` in project `project_id`
    /// (`environment.create`) and returns its ID. Dokploy accepts a name
    /// that is already taken, so callers check the name first. Not
    /// idempotent: the request is sent once and never retried.
    pub async fn create_environment(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        project_id: &DokployId,
        name: &str,
    ) -> Result<DokployId, DokployError> {
        let body = serde_json::json!({ "name": name, "projectId": project_id.as_str() });
        let answer = self
            .send(
                url,
                "environment.create",
                key,
                Input::Post(&body),
                MAX_SMALL_BODY_BYTES,
            )
            .await?;
        let created: RawCreatedEnvironment =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if created.project_id != project_id.as_str() {
            return Err(DokployError::InvalidResponse);
        }
        DokployId::parse(&created.environment_id).map_err(|_| DokployError::InvalidResponse)
    }

    async fn get(
        &self,
        base: &DokployUrl,
        call: &str,
        key: &SecretString,
        max_body_bytes: usize,
    ) -> Result<Vec<u8>, DokployError> {
        self.send(base, call, key, Input::Get(&[]), max_body_bytes)
            .await
    }

    async fn send(
        &self,
        base: &DokployUrl,
        call: &str,
        key: &SecretString,
        input: Input<'_>,
        max_body_bytes: usize,
    ) -> Result<Vec<u8>, DokployError> {
        let (method, query, body) = match input {
            Input::Get(query) => (Method::GET, query, None),
            Input::Post(body) => (Method::POST, &[][..], Some(body)),
        };
        let unreachable = DokployError::Unreachable;
        let mut url = reqwest::Url::parse(&base.api(call))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        // Dokploy reads GET input from flat query parameters.
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        // The enrolled URL's clients only ever see requests built from it.
        let (clients, policy) = match &self.enrolled {
            Some(enrolled) if enrolled.url == *base => (&enrolled.clients, enrolled.policy),
            _ => (&*self.clients, self.policy),
        };
        if refused_literal(&url, policy) {
            return Err(unreachable(UnreachableReason::DestinationNotAllowed));
        }
        let mut key_header =
            HeaderValue::from_str(key.expose_secret()).map_err(|_| DokployError::KeyRejected)?;
        key_header.set_sensitive(true);
        let client = clients
            .get(None)
            .map_err(|_| unreachable(UnreachableReason::Tls))?;
        let mut request = client
            .request(method, url)
            .header("x-api-key", key_header)
            .header(ACCEPT, "application/json");
        if let Some(body) = body {
            let body = serde_json::to_vec(body).map_err(|_| DokployError::InvalidResponse)?;
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request
            .send()
            .await
            .map_err(|err| unreachable(classify(&err)))?;
        match response.status() {
            status if status.is_success() => read_bounded(response, max_body_bytes).await,
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

    fn inventory<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> InventoryFuture<'a> {
        Box::pin(DokployClient::inventory(self, url, key))
    }

    fn targets<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> TargetsFuture<'a> {
        Box::pin(DokployClient::targets(self, url, key))
    }

    fn create_environment<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        project_id: &'a DokployId,
        name: &'a str,
    ) -> CreateEnvironmentFuture<'a> {
        Box::pin(DokployClient::create_environment(
            self, url, key, project_id, name,
        ))
    }
}

/// A list Dokploy answered with, each entry read on its own so one entry
/// of an unexpected shape is skipped rather than failing the whole list.
fn parse_list<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<Vec<T>, DokployError> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(body).map_err(|_| DokployError::InvalidResponse)?;
    Ok(entries
        .into_iter()
        .take(MAX_LIST_ENTRIES)
        .filter_map(|entry| serde_json::from_value(entry).ok())
        .collect())
}

/// One entry of `overview.services`, as of Dokploy v0.31.1. Unknown fields
/// are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawService {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    project_id: String,
    project_name: String,
    environment_id: String,
    environment_name: String,
    server_id: Option<String>,
    server_name: Option<String>,
}

impl RawService {
    fn into_info(self) -> Option<DokployServiceInfo> {
        Some(DokployServiceInfo {
            service: DokployServiceRef {
                kind: DokployServiceKind::parse(&self.kind)?,
                id: DokployId::parse(&self.id).ok()?,
            },
            name: bounded_name(&self.name),
            project_id: DokployId::parse(&self.project_id).ok()?,
            project_name: bounded_name(&self.project_name),
            environment_id: DokployId::parse(&self.environment_id).ok()?,
            environment_name: bounded_name(&self.environment_name),
            server_id: match self.server_id.as_deref() {
                Some(raw) => Some(DokployId::parse(raw).ok()?),
                None => None,
            },
            server_name: self.server_name.as_deref().map(bounded_name),
        })
    }
}

/// One entry of `overview.domains`, as of Dokploy v0.31.1.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDomain {
    host: String,
    enabled: bool,
    domain_type: Option<String>,
    service_owner_id: String,
    service_owner_type: String,
}

impl RawDomain {
    fn into_info(self) -> Option<DokployDomainInfo> {
        let host = normalize_host(&self.host);
        if host.is_empty() || host.len() > 253 {
            return None;
        }
        Some(DokployDomainInfo {
            host,
            service: DokployServiceRef {
                kind: DokployServiceKind::parse(&self.service_owner_type)?,
                id: DokployId::parse(&self.service_owner_id).ok()?,
            },
            enabled: self.enabled,
            preview: self.domain_type.as_deref() == Some("preview"),
        })
    }
}

/// One entry of `project.all`, as of Dokploy v0.31.1. The services nested
/// in each environment are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawProject {
    project_id: String,
    name: String,
    #[serde(default)]
    environments: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEnvironment {
    environment_id: String,
    name: String,
    #[serde(default)]
    is_default: bool,
}

impl RawProject {
    /// The project's environments, each read on its own so one odd entry
    /// does not hide the rest.
    fn into_environments(self) -> Vec<DokployEnvironmentInfo> {
        let Ok(project_id) = DokployId::parse(&self.project_id) else {
            return Vec::new();
        };
        let project_name = bounded_name(&self.name);
        self.environments
            .into_iter()
            .take(MAX_LIST_ENTRIES)
            .filter_map(|raw| serde_json::from_value::<RawEnvironment>(raw).ok())
            .filter_map(|env| {
                Some(DokployEnvironmentInfo {
                    project_id: project_id.clone(),
                    project_name: project_name.clone(),
                    environment_id: DokployId::parse(&env.environment_id).ok()?,
                    environment_name: bounded_name(&env.name),
                    is_default: env.is_default,
                })
            })
            .collect()
    }
}

/// One entry of `server.all`, as of Dokploy v0.31.1. Only these fields
/// are read; the rest, which includes monitoring settings, is ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawServer {
    server_id: String,
    name: String,
    server_status: Option<String>,
    server_type: Option<String>,
}

impl RawServer {
    /// Active deploy servers only; build servers never run stacks.
    fn into_info(self) -> Option<DokployServerInfo> {
        let active = self.server_status.as_deref() == Some("active");
        let deploy = self.server_type.as_deref().unwrap_or("deploy") == "deploy";
        if !(active && deploy) {
            return None;
        }
        Some(DokployServerInfo {
            id: DokployId::parse(&self.server_id).ok()?,
            name: bounded_name(&self.name),
        })
    }
}

/// The answer to `environment.create`, as of Dokploy v0.31.1.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCreatedEnvironment {
    environment_id: String,
    project_id: String,
}

async fn read_bounded(mut response: Response, max_bytes: usize) -> Result<Vec<u8>, DokployError> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(DokployError::InvalidResponse);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(err) => return Err(DokployError::Unreachable(classify(&err))),
        }
    }
}
