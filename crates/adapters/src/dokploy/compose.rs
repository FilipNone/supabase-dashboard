//! Dokploy calls for a provisioned stack's compose service, checked
//! against Dokploy v0.31.1 (see `docs/dokploy.md`).
//!
//! Creating a service, a file mount, a domain, or a deployment is not
//! idempotent in Dokploy: a repeated request makes a second one. Each is
//! sent once and never retried here; callers look the object up first.
//!
//! Several answers carry the service's variables, compose file, or file
//! contents in plain text. Only the fields named below are read; the rest
//! of the body is dropped with the buffer and never logged.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use supabase_dashboard_domain::{
    dokploy::{DokployError, DokployUrl},
    dokploy_compose::{
        ComposeDetails, ComposeDomain, ComposeService, ComposeStatus, DeploymentInfo,
        DeploymentRecord, DeploymentStatus, FileMount, MAX_DEPLOYMENTS_READ, NewCompose,
        NewComposeDomain, is_dashboard_compose_name, is_file_mount_path,
    },
    dokploy_placement::DokployId,
};

use supabase_dashboard_application::provisioning::{ComposeApi, ComposeConfig, DokployFuture};

use super::{DokployClient, Input, MAX_LIST_BODY_BYTES, MAX_SMALL_BODY_BYTES, parse_list};

/// Most search results asked for at once, Dokploy's own limit.
const SEARCH_LIMIT: &str = "100";

impl DokployClient {
    /// Compose services named exactly `name` in `environment_id`, among
    /// those the key's member can see (`compose.search`). Dokploy matches
    /// names as substrings, so the exact comparison happens here.
    pub async fn find_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        environment_id: &DokployId,
        name: &str,
    ) -> Result<Vec<ComposeService>, DokployError> {
        // Only names without search wildcards are looked up.
        if !is_dashboard_compose_name(name) {
            return Err(DokployError::InvalidResponse);
        }
        let body = self
            .send(
                url,
                "compose.search",
                key,
                Input::Get(&[
                    ("name", name),
                    ("environmentId", environment_id.as_str()),
                    ("limit", SEARCH_LIMIT),
                ]),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let page: RawSearchPage =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        Ok(page
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<RawCompose>(item).ok())
            .filter_map(RawCompose::into_service)
            .filter(|service| service.name == name && service.environment_id == *environment_id)
            .collect())
    }

    /// The compose services in `environment_id` the key's member can see,
    /// at most [`SEARCH_LIMIT`] (`compose.search`). The answer holds no
    /// compose file and no variables.
    pub async fn list_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        environment_id: &DokployId,
    ) -> Result<Vec<ComposeService>, DokployError> {
        let body = self
            .send(
                url,
                "compose.search",
                key,
                Input::Get(&[
                    ("environmentId", environment_id.as_str()),
                    ("limit", SEARCH_LIMIT),
                ]),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let page: RawSearchPage =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        Ok(page
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_value::<RawCompose>(item).ok())
            .filter_map(RawCompose::into_service)
            .filter(|service| service.environment_id == *environment_id)
            .collect())
    }

    /// Creates a compose service with a raw compose file
    /// (`compose.create`). Not idempotent; see the module documentation.
    pub async fn create_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        new: &NewCompose<'_>,
    ) -> Result<ComposeService, DokployError> {
        if !is_dashboard_compose_name(new.name) {
            return Err(DokployError::InvalidResponse);
        }
        let mut body = serde_json::json!({
            "name": new.name,
            "appName": new.name,
            "description": new.description,
            "environmentId": new.environment_id.as_str(),
            "composeType": "docker-compose",
            "sourceType": "raw",
            "composeFile": new.compose_file,
        });
        if let Some(server) = new.server_id {
            body["serverId"] = server.as_str().into();
        }
        let answer = self
            .send(
                url,
                "compose.create",
                key,
                Input::Post(&body),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let created: RawCompose =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        let service = created
            .into_service()
            .ok_or(DokployError::InvalidResponse)?;
        if service.name != new.name || service.environment_id != *new.environment_id {
            return Err(DokployError::InvalidResponse);
        }
        Ok(service)
    }

    /// Sets the compose file and variables of `compose_id`, with isolated
    /// deployment on (`compose.update`). Repeating it sets the same values.
    /// `env` is dotenv text and must not contain `${`, which Dokploy leaves
    /// unescaped.
    pub async fn configure_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        compose_file: &str,
        env: &SecretString,
    ) -> Result<(), DokployError> {
        if env.expose_secret().contains("${") {
            return Err(DokployError::InvalidResponse);
        }
        let body = serde_json::json!({
            "composeId": compose_id.as_str(),
            "sourceType": "raw",
            "composeFile": compose_file,
            "env": env.expose_secret(),
            "isolatedDeployment": true,
        });
        let answer = self
            .send(
                url,
                "compose.update",
                key,
                Input::Post(&body),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let updated: RawComposeId =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if updated.compose_id != compose_id.as_str() {
            return Err(DokployError::InvalidResponse);
        }
        Ok(())
    }

    /// The file mounts of `compose_id` (`mounts.listByServiceId`).
    pub async fn file_mounts(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<Vec<FileMount>, DokployError> {
        let body = self
            .send(
                url,
                "mounts.listByServiceId",
                key,
                Input::Get(&[
                    ("serviceId", compose_id.as_str()),
                    ("serviceType", "compose"),
                ]),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        Ok(parse_list::<RawMount>(&body)?
            .into_iter()
            .filter_map(RawMount::into_file)
            .collect())
    }

    /// Adds a file Dokploy writes at once, next to the compose file
    /// (`mounts.create`). Not idempotent.
    pub async fn create_file_mount(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        file_path: &str,
        content: &str,
    ) -> Result<FileMount, DokployError> {
        if !is_file_mount_path(file_path) {
            return Err(DokployError::InvalidResponse);
        }
        let body = serde_json::json!({
            "type": "file",
            "serviceType": "compose",
            "serviceId": compose_id.as_str(),
            "filePath": file_path,
            // Required by Dokploy, unused for compose services: the compose
            // file says where the file goes.
            "mountPath": format!("/{file_path}"),
            "content": content,
        });
        let answer = self
            .send(
                url,
                "mounts.create",
                key,
                Input::Post(&body),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let mount: RawMount =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        mount
            .into_file()
            .filter(|mount| mount.file_path == file_path)
            .ok_or(DokployError::InvalidResponse)
    }

    /// Replaces a file mount's content (`mounts.update`). Dokploy answers
    /// with the mount as it was before, so the answer is not read.
    pub async fn update_file_mount(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        mount_id: &DokployId,
        content: &str,
    ) -> Result<(), DokployError> {
        let body = serde_json::json!({ "mountId": mount_id.as_str(), "content": content });
        self.send(
            url,
            "mounts.update",
            key,
            Input::Post(&body),
            MAX_LIST_BODY_BYTES,
        )
        .await
        .map(drop)
    }

    /// Queues a deployment titled `title` (`compose.deploy`). Dokploy
    /// returns no deployment ID; find it in [`Self::deployments`] by its
    /// title, which should be unique. Not idempotent: every call queues
    /// another deployment.
    pub async fn deploy_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        title: &str,
    ) -> Result<(), DokployError> {
        let body = serde_json::json!({ "composeId": compose_id.as_str(), "title": title });
        let answer = self
            .send(
                url,
                "compose.deploy",
                key,
                Input::Post(&body),
                MAX_SMALL_BODY_BYTES,
            )
            .await?;
        let queued: RawQueued =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if queued.success && queued.compose_id.as_deref() == Some(compose_id.as_str()) {
            Ok(())
        } else {
            Err(DokployError::InvalidResponse)
        }
    }

    /// Stops the service's containers (`compose.stop`). Dokploy answers
    /// once they have stopped. Stopping a stopped service changes nothing.
    pub async fn stop_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<(), DokployError> {
        self.compose_switch(url, key, "compose.stop", compose_id)
            .await
    }

    /// Starts the service's containers again (`compose.start`). Starting a
    /// running service changes nothing.
    pub async fn start_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<(), DokployError> {
        self.compose_switch(url, key, "compose.start", compose_id)
            .await
    }

    async fn compose_switch(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        call: &str,
        compose_id: &DokployId,
    ) -> Result<(), DokployError> {
        let body = serde_json::json!({ "composeId": compose_id.as_str() });
        let answer = self
            .send(url, call, key, Input::Post(&body), MAX_LIST_BODY_BYTES)
            .await?;
        // v0.31.1 answers `true`.
        match serde_json::from_slice::<serde_json::Value>(&answer) {
            Ok(serde_json::Value::Bool(true)) => Ok(()),
            _ => Err(DokployError::InvalidResponse),
        }
    }

    /// Queues a redeployment titled `title` (`compose.redeploy`), which
    /// rebuilds the containers from the stored compose file and variables
    /// and keeps the volumes. Not idempotent, like [`Self::deploy_compose`].
    pub async fn redeploy_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        title: &str,
    ) -> Result<(), DokployError> {
        let body = serde_json::json!({ "composeId": compose_id.as_str(), "title": title });
        let answer = self
            .send(
                url,
                "compose.redeploy",
                key,
                Input::Post(&body),
                MAX_SMALL_BODY_BYTES,
            )
            .await?;
        let queued: RawQueued =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if queued.success && queued.compose_id.as_deref() == Some(compose_id.as_str()) {
            Ok(())
        } else {
            Err(DokployError::InvalidResponse)
        }
    }

    /// Deletes the service (`compose.delete`): its containers, its folder
    /// on the server, and its domains. With `delete_volumes`, its named
    /// volumes go too, which deletes the stack's data; without, they stay
    /// on the server. Dokploy answers once it is done (about 10 seconds on
    /// the fixture), and 404 for a service it does not have. The answer
    /// carries the service's variables, so only its ID is read.
    pub async fn delete_compose(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        delete_volumes: bool,
    ) -> Result<(), DokployError> {
        let body = serde_json::json!({
            "composeId": compose_id.as_str(),
            "deleteVolumes": delete_volumes,
        });
        let answer = self
            .send(
                url,
                "compose.delete",
                key,
                Input::Post(&body),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let deleted: RawDeleted =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if deleted.compose_id.as_deref() == Some(compose_id.as_str()) {
            Ok(())
        } else {
            Err(DokployError::InvalidResponse)
        }
    }

    /// The deployments of `compose_id` that have started, newest first
    /// (`deployment.allByCompose`).
    pub async fn deployments(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<Vec<DeploymentInfo>, DokployError> {
        let body = self
            .send(
                url,
                "deployment.allByCompose",
                key,
                Input::Get(&[("composeId", compose_id.as_str())]),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        Ok(parse_list::<RawDeployment>(&body)?
            .into_iter()
            .filter_map(RawDeployment::into_info)
            .collect())
    }

    /// Where `compose_id` is, its status, and its latest deployments
    /// (`compose.one`), or `None` when Dokploy has no such service. The
    /// answer also holds the service's variables and compose file in plain
    /// text; only the fields of [`ComposeDetails`] are read.
    pub async fn compose_details(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<Option<ComposeDetails>, DokployError> {
        let body = match self
            .send(
                url,
                "compose.one",
                key,
                Input::Get(&[("composeId", compose_id.as_str())]),
                MAX_LIST_BODY_BYTES,
            )
            .await
        {
            Ok(body) => body,
            Err(DokployError::Http(404)) => return Ok(None),
            Err(err) => return Err(err),
        };
        let raw: RawComposeOne =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        let details = raw.into_details().ok_or(DokployError::InvalidResponse)?;
        if details.compose_id != *compose_id {
            return Err(DokployError::InvalidResponse);
        }
        Ok(Some(details))
    }

    /// The variables and compose file of `compose_id` (`compose.one`), or
    /// `None` when Dokploy has no such service.
    pub async fn compose_config(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<Option<ComposeConfig>, DokployError> {
        let body = match self
            .send(
                url,
                "compose.one",
                key,
                Input::Get(&[("composeId", compose_id.as_str())]),
                MAX_LIST_BODY_BYTES,
            )
            .await
        {
            Ok(body) => body,
            Err(DokployError::Http(404)) => return Ok(None),
            Err(err) => return Err(err),
        };
        let raw: RawComposeConfig =
            serde_json::from_slice(&body).map_err(|_| DokployError::InvalidResponse)?;
        if raw.compose_id != compose_id.as_str() {
            return Err(DokployError::InvalidResponse);
        }
        Ok(Some(ComposeConfig {
            env: SecretString::from(raw.env.unwrap_or_default()),
            compose_file: raw.compose_file.unwrap_or_default(),
        }))
    }

    /// Replaces the variables of `compose_id` and nothing else
    /// (`compose.update`). Repeating it sets the same values. `env` must
    /// not contain `${`, which Dokploy leaves unescaped.
    pub async fn update_compose_env(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        env: &SecretString,
    ) -> Result<(), DokployError> {
        if env.expose_secret().contains("${") {
            return Err(DokployError::InvalidResponse);
        }
        let body = serde_json::json!({
            "composeId": compose_id.as_str(),
            "env": env.expose_secret(),
        });
        let answer = self
            .send(
                url,
                "compose.update",
                key,
                Input::Post(&body),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        let updated: RawComposeId =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        if updated.compose_id != compose_id.as_str() {
            return Err(DokployError::InvalidResponse);
        }
        Ok(())
    }

    /// The domains of `compose_id` (`domain.byComposeId`).
    pub async fn compose_domains(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
    ) -> Result<Vec<ComposeDomain>, DokployError> {
        let body = self
            .send(
                url,
                "domain.byComposeId",
                key,
                Input::Get(&[("composeId", compose_id.as_str())]),
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        Ok(parse_list::<RawDomainRow>(&body)?
            .into_iter()
            .filter_map(RawDomainRow::into_domain)
            .collect())
    }

    /// Routes `domain.host` to one service of `compose_id`
    /// (`domain.create`). It takes effect at the next deployment. Not
    /// idempotent.
    pub async fn create_compose_domain(
        &self,
        url: &DokployUrl,
        key: &SecretString,
        compose_id: &DokployId,
        domain: &NewComposeDomain<'_>,
    ) -> Result<ComposeDomain, DokployError> {
        // Dokploy checks neither the service name nor the certificate when
        // HTTPS is on, so both are always sent.
        let body = serde_json::json!({
            "host": domain.host,
            "composeId": compose_id.as_str(),
            "domainType": "compose",
            "serviceName": domain.service_name,
            "port": domain.port,
            "https": domain.https,
            "certificateType": if domain.https { "letsencrypt" } else { "none" },
            "path": "/",
        });
        let answer = self
            .send(
                url,
                "domain.create",
                key,
                Input::Post(&body),
                MAX_SMALL_BODY_BYTES,
            )
            .await?;
        let row: RawDomainRow =
            serde_json::from_slice(&answer).map_err(|_| DokployError::InvalidResponse)?;
        row.into_domain()
            .filter(|created| created.host == domain.host)
            .ok_or(DokployError::InvalidResponse)
    }
}

#[derive(Deserialize)]
struct RawSearchPage {
    items: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCompose {
    compose_id: String,
    name: String,
    app_name: String,
    environment_id: String,
}

impl RawCompose {
    fn into_service(self) -> Option<ComposeService> {
        Some(ComposeService {
            compose_id: DokployId::parse(&self.compose_id).ok()?,
            environment_id: DokployId::parse(&self.environment_id).ok()?,
            name: bounded(self.name)?,
            app_name: bounded(self.app_name)?,
        })
    }
}

/// The fields of a `compose.one` answer the dashboard reads, as of
/// Dokploy v0.31.1. The variables and the compose file are not among them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawComposeOne {
    compose_id: String,
    name: String,
    app_name: String,
    description: Option<String>,
    compose_status: Option<String>,
    environment_id: String,
    server_id: Option<String>,
    environment: RawEnvironment,
    server: Option<RawNamed>,
    #[serde(default)]
    deployments: Vec<serde_json::Value>,
}

/// Only the fields [`ComposeConfig`] needs from `compose.one`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawComposeConfig {
    compose_id: String,
    env: Option<String>,
    compose_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEnvironment {
    name: String,
    project_id: String,
    project: RawNamed,
}

#[derive(Deserialize)]
struct RawNamed {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDeploymentRow {
    deployment_id: String,
    title: Option<String>,
    status: String,
    created_at: Option<String>,
    finished_at: Option<String>,
}

impl RawComposeOne {
    fn into_details(self) -> Option<ComposeDetails> {
        let mut deployments: Vec<DeploymentRecord> = self
            .deployments
            .into_iter()
            .filter_map(|row| serde_json::from_value::<RawDeploymentRow>(row).ok())
            .filter_map(RawDeploymentRow::into_record)
            .collect();
        // Newest first, whatever order Dokploy sends them in; rows without
        // a time go last.
        deployments.sort_by_key(|run| std::cmp::Reverse(run.created_at));
        deployments.truncate(MAX_DEPLOYMENTS_READ);
        Some(ComposeDetails {
            compose_id: DokployId::parse(&self.compose_id).ok()?,
            name: bounded(self.name)?,
            app_name: bounded(self.app_name)?,
            description: self.description.and_then(bounded),
            status: self
                .compose_status
                .as_deref()
                .and_then(ComposeStatus::parse),
            environment_id: DokployId::parse(&self.environment_id).ok()?,
            environment_name: bounded(self.environment.name)?,
            project_id: DokployId::parse(&self.environment.project_id).ok()?,
            project_name: bounded(self.environment.project.name)?,
            server_id: match self.server_id.as_deref() {
                Some(raw) => Some(DokployId::parse(raw).ok()?),
                None => None,
            },
            server_name: self.server.and_then(|server| bounded(server.name)),
            deployments,
        })
    }
}

impl RawDeploymentRow {
    fn into_record(self) -> Option<DeploymentRecord> {
        Some(DeploymentRecord {
            deployment_id: DokployId::parse(&self.deployment_id).ok()?,
            title: self.title.and_then(bounded),
            status: DeploymentStatus::parse(&self.status)?,
            created_at: self.created_at.as_deref().and_then(parse_time),
            finished_at: self.finished_at.as_deref().and_then(parse_time),
        })
    }
}

fn parse_time(raw: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339).ok()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawComposeId {
    compose_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMount {
    mount_id: String,
    #[serde(rename = "type")]
    kind: String,
    file_path: Option<String>,
    content: Option<String>,
}

impl RawMount {
    fn into_file(self) -> Option<FileMount> {
        if self.kind != "file" {
            return None;
        }
        Some(FileMount {
            mount_id: DokployId::parse(&self.mount_id).ok()?,
            file_path: self.file_path?,
            content: self.content.unwrap_or_default(),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDeleted {
    compose_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawQueued {
    success: bool,
    compose_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDeployment {
    deployment_id: String,
    title: Option<String>,
    status: String,
}

impl RawDeployment {
    fn into_info(self) -> Option<DeploymentInfo> {
        Some(DeploymentInfo {
            deployment_id: DokployId::parse(&self.deployment_id).ok()?,
            title: self.title.and_then(bounded),
            status: DeploymentStatus::parse(&self.status)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDomainRow {
    domain_id: String,
    host: String,
    service_name: Option<String>,
    port: Option<u16>,
    https: bool,
}

impl RawDomainRow {
    fn into_domain(self) -> Option<ComposeDomain> {
        Some(ComposeDomain {
            domain_id: DokployId::parse(&self.domain_id).ok()?,
            host: bounded(self.host)?,
            service_name: self.service_name.and_then(bounded),
            port: self.port?,
            https: self.https,
        })
    }
}

/// A name or title of at most 256 characters.
fn bounded(value: String) -> Option<String> {
    (value.chars().count() <= 256).then_some(value)
}

impl ComposeApi for DokployClient {
    fn find_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
        name: &'a str,
    ) -> DokployFuture<'a, Vec<ComposeService>> {
        Box::pin(DokployClient::find_compose(
            self,
            url,
            key,
            environment_id,
            name,
        ))
    }

    fn list_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeService>> {
        Box::pin(DokployClient::list_compose(self, url, key, environment_id))
    }

    fn create_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        new: &'a NewCompose<'a>,
    ) -> DokployFuture<'a, ComposeService> {
        Box::pin(DokployClient::create_compose(self, url, key, new))
    }

    fn configure_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        compose_file: &'a str,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::configure_compose(
            self,
            url,
            key,
            compose_id,
            compose_file,
            env,
        ))
    }

    fn file_mounts<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<FileMount>> {
        Box::pin(DokployClient::file_mounts(self, url, key, compose_id))
    }

    fn create_file_mount<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        file_path: &'a str,
        content: &'a str,
    ) -> DokployFuture<'a, FileMount> {
        Box::pin(DokployClient::create_file_mount(
            self, url, key, compose_id, file_path, content,
        ))
    }

    fn update_file_mount<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        mount_id: &'a DokployId,
        content: &'a str,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::update_file_mount(
            self, url, key, mount_id, content,
        ))
    }

    fn compose_domains<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeDomain>> {
        Box::pin(DokployClient::compose_domains(self, url, key, compose_id))
    }

    fn create_compose_domain<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        domain: &'a NewComposeDomain<'a>,
    ) -> DokployFuture<'a, ComposeDomain> {
        Box::pin(DokployClient::create_compose_domain(
            self, url, key, compose_id, domain,
        ))
    }

    fn deploy_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::deploy_compose(
            self, url, key, compose_id, title,
        ))
    }

    fn deployments<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<DeploymentInfo>> {
        Box::pin(DokployClient::deployments(self, url, key, compose_id))
    }

    fn compose_details<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeDetails>> {
        Box::pin(DokployClient::compose_details(self, url, key, compose_id))
    }

    fn stop_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::stop_compose(self, url, key, compose_id))
    }

    fn start_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::start_compose(self, url, key, compose_id))
    }

    fn redeploy_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::redeploy_compose(
            self, url, key, compose_id, title,
        ))
    }

    fn delete_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        delete_volumes: bool,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::delete_compose(
            self,
            url,
            key,
            compose_id,
            delete_volumes,
        ))
    }

    fn compose_config<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeConfig>> {
        Box::pin(DokployClient::compose_config(self, url, key, compose_id))
    }

    fn update_compose_env<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()> {
        Box::pin(DokployClient::update_compose_env(
            self, url, key, compose_id, env,
        ))
    }
}
