//! The Dokploy calls a provisioning job makes, as a port the server wires
//! to the network adapter.

use std::{future::Future, pin::Pin};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    dokploy::{DokployError, DokployUrl},
    dokploy_compose::{
        ComposeDetails, ComposeDomain, ComposeService, DeploymentInfo, FileMount, NewCompose,
        NewComposeDomain,
    },
    dokploy_placement::DokployId,
};

/// A compose service's variables and compose file, as Dokploy keeps them.
/// The variables hold the stack's secrets: they stay on the server.
pub struct ComposeConfig {
    pub env: SecretString,
    pub compose_file: String,
}

pub type DokployFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DokployError>> + Send + 'a>>;

/// Compose service calls. Implementations enforce the same outbound policy
/// as [`crate::dokploy::DokployConnector`]. Creating a service, a file
/// mount, or a domain, and starting a deployment, are sent once and never
/// retried: Dokploy makes a new object for each request.
pub trait ComposeApi: Send + Sync {
    /// Services in `environment_id` named exactly `name`.
    fn find_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
        name: &'a str,
    ) -> DokployFuture<'a, Vec<ComposeService>>;

    /// The compose services in `environment_id`, at most 100.
    fn list_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeService>>;

    fn create_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        new: &'a NewCompose<'a>,
    ) -> DokployFuture<'a, ComposeService>;

    /// Sets the compose file and the variables. Safe to repeat.
    fn configure_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        compose_file: &'a str,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()>;

    fn file_mounts<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<FileMount>>;

    fn create_file_mount<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        file_path: &'a str,
        content: &'a str,
    ) -> DokployFuture<'a, FileMount>;

    /// Replaces a mounted file's content. Safe to repeat.
    fn update_file_mount<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        mount_id: &'a DokployId,
        content: &'a str,
    ) -> DokployFuture<'a, ()>;

    fn compose_domains<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeDomain>>;

    fn create_compose_domain<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        domain: &'a NewComposeDomain<'a>,
    ) -> DokployFuture<'a, ComposeDomain>;

    /// Queues a deployment titled `title`. Dokploy returns no ID, so the
    /// deployment is found by its title in [`Self::deployments`].
    fn deploy_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()>;

    fn deployments<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<DeploymentInfo>>;

    /// Where the service is, its status, and its latest deployments, or
    /// `None` when Dokploy has no service with this ID.
    fn compose_details<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeDetails>>;

    /// Stops the containers; Dokploy answers once they stopped. Safe to
    /// repeat.
    fn stop_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()>;

    /// Starts the containers. Safe to repeat.
    fn start_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()>;

    /// Deletes the service, and its named volumes with `delete_volumes`.
    /// Answers 404 for a service Dokploy does not have. Never sent without
    /// reading the service first.
    fn delete_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        delete_volumes: bool,
    ) -> DokployFuture<'a, ()>;

    /// Queues a redeployment titled `title`. Not idempotent.
    fn redeploy_compose<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()>;

    /// The service's variables and compose file (`compose.one`), or `None`
    /// when Dokploy has no service with this ID.
    fn compose_config<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeConfig>>;

    /// Replaces the service's variables and nothing else
    /// (`compose.update`). Safe to repeat.
    fn update_compose_env<'a>(
        &'a self,
        url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()>;
}
