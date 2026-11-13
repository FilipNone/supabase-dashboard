//! Provisioning a stack as a durable job, against a scratch metadata
//! database, with fakes in place of Dokploy and the stack. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::{ProbeFuture, StackProbe},
    dokploy::{
        ConnectFuture, CreateEnvironmentFuture, DokployConnector, DokployService, InventoryFuture,
        TargetsFuture,
    },
    jobs::{JobHandler, JobRunner, RunResult, RunnerSettings},
    key_rotation::reseal_credentials,
    provisioning::{
        AdoptRequest, ComposeApi, ComposeConfig, DokployFuture, ProvisionError, ProvisionRequest,
        ProvisionStackHandler, ProvisionTimings, ProvisioningService, StackActionHandler,
    },
    secrets::CredentialCipher,
    stack_secrets::StackSecrets,
    stack_template::{GATEWAY_PORT, GATEWAY_SERVICE, STACK_FILES},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    adoption::{AdoptableServices, AdoptionRefusal, KeyState},
    authority::{AuthorityError, AuthorityInfo, ProjectAuthorities},
    authz::OrgRole,
    connection::{ServiceCheck, ServiceStatus, StackService, UnreachableReason},
    dokploy::{DokployError, DokployUrl, TESTED_DOKPLOY_VERSION},
    dokploy_compose::{
        ComposeDetails, ComposeDomain, ComposeService, ComposeStatus, DeploymentInfo,
        DeploymentRecord, DeploymentStatus, FileMount, NewCompose, NewComposeDomain,
    },
    dokploy_placement::{
        DokployDomainInfo, DokployId, DokployInventory, DokployServiceInfo, DokployServiceKind,
        DokployServiceRef,
    },
    dokploy_target::{DokployEnvironmentInfo, DokployTargetInventory},
    job::{JobKind, JobState},
    project::ProjectUrl,
    provisioning::{
        ProvisionStep, ProvisionTargets, StackAction, StackDeploymentView, TargetChoice,
    },
    stack_settings::{EnvChanges, EnvTracking, SettingState},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const URL: &str = "https://dokploy.example.test";
const DOKPLOY_KEY: &str = "dokploy-key-marker-provisioning";
const PUBLIC_HOST: &str = "dashboard.example.test";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-provision"),
        user_agent: None,
    }
}

fn id(raw: &str) -> DokployId {
    DokployId::parse(raw).unwrap()
}

/// A Dokploy whose key sees project `proj1` with the environments `prod`,
/// where the dashboard runs, and `stacks`.
struct FakeConnector;

impl DokployConnector for FakeConnector {
    fn connect<'a>(&'a self, _url: &'a DokployUrl, _key: &'a SecretString) -> ConnectFuture<'a> {
        Box::pin(async { Ok(TESTED_DOKPLOY_VERSION) })
    }

    fn inventory<'a>(
        &'a self,
        _url: &'a DokployUrl,
        _key: &'a SecretString,
    ) -> InventoryFuture<'a> {
        let dashboard = DokployServiceInfo {
            service: DokployServiceRef {
                kind: DokployServiceKind::Compose,
                id: id("dash"),
            },
            name: "dashboard".to_owned(),
            project_id: id("proj1"),
            project_name: "Infra".to_owned(),
            environment_id: id("prod"),
            environment_name: "prod".to_owned(),
            server_id: None,
            server_name: None,
        };
        Box::pin(async move {
            Ok(DokployInventory {
                domains: vec![DokployDomainInfo {
                    host: PUBLIC_HOST.to_owned(),
                    service: dashboard.service.clone(),
                    enabled: true,
                    preview: false,
                }],
                services: vec![dashboard],
            })
        })
    }

    fn targets<'a>(&'a self, _url: &'a DokployUrl, _key: &'a SecretString) -> TargetsFuture<'a> {
        let environment = |env: &str, is_default| DokployEnvironmentInfo {
            project_id: id("proj1"),
            project_name: "Infra".to_owned(),
            environment_id: id(env),
            environment_name: env.to_owned(),
            is_default,
        };
        let answer = DokployTargetInventory {
            environments: vec![environment("prod", true), environment("stacks", false)],
            servers: Some(Vec::new()),
        };
        Box::pin(async move { Ok(answer) })
    }

    fn create_environment<'a>(
        &'a self,
        _url: &'a DokployUrl,
        _key: &'a SecretString,
        _project_id: &'a DokployId,
        _name: &'a str,
    ) -> CreateEnvironmentFuture<'a> {
        Box::pin(async { Err(DokployError::Http(400)) })
    }
}

/// Dokploy's compose calls, kept in memory.
#[derive(Default)]
struct FakeCompose {
    state: Mutex<ComposeState>,
}

#[derive(Default)]
struct ComposeState {
    services: Vec<ComposeService>,
    /// (compose file, variables) as last configured.
    configured: Option<(String, String)>,
    mounts: Vec<FileMount>,
    domains: Vec<ComposeDomain>,
    deployments: Vec<DeploymentInfo>,
    /// Every call, by name.
    calls: Vec<&'static str>,
    /// Keys the calls were made with.
    keys: Vec<String>,
    /// The status a new deployment ends in.
    deploy_result: Option<DeploymentStatus>,
    /// Create the service, then answer as if the connection dropped.
    lose_create_answer: bool,
    /// Queue the deployment, then answer as if the connection dropped.
    lose_deploy_answer: bool,
    /// What `compose_details` answers with instead of the service.
    details_error: Option<DokployError>,
    /// The description each service was created with.
    descriptions: Vec<String>,
    /// The service's containers were stopped and not started again.
    stopped: bool,
    /// Stop the containers, then answer as if the connection dropped.
    lose_stop_answer: bool,
    /// `deleteVolumes` of each delete request.
    deletes: Vec<bool>,
    /// Delete the service, then answer as if the connection dropped.
    lose_delete_answer: bool,
    /// Replace the variables, then answer as if the connection dropped.
    lose_env_answer: bool,
    /// (service, compose file, variables) of services made in Dokploy,
    /// which `compose_config` answers with instead of `configured`.
    made_in_dokploy: Vec<(DokployId, String, String)>,
    next_id: u32,
}

impl ComposeState {
    fn call(&mut self, name: &'static str, key: &SecretString) {
        self.calls.push(name);
        self.keys.push(key.expose_secret().to_owned());
    }

    fn new_id(&mut self, prefix: &str) -> DokployId {
        self.next_id += 1;
        id(&format!("{prefix}{}", self.next_id))
    }

    fn count(&self, name: &str) -> usize {
        self.calls.iter().filter(|c| **c == name).count()
    }
}

fn lost() -> DokployError {
    DokployError::Unreachable(UnreachableReason::Timeout)
}

impl ComposeApi for FakeCompose {
    fn find_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
        name: &'a str,
    ) -> DokployFuture<'a, Vec<ComposeService>> {
        let mut state = self.state.lock().unwrap();
        state.call("find_compose", key);
        let found = state
            .services
            .iter()
            .filter(|s| s.name == name && &s.environment_id == environment_id)
            .cloned()
            .collect();
        Box::pin(async move { Ok(found) })
    }

    fn list_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        environment_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeService>> {
        let mut state = self.state.lock().unwrap();
        state.call("list_compose", key);
        let found = state
            .services
            .iter()
            .filter(|s| &s.environment_id == environment_id)
            .cloned()
            .collect();
        Box::pin(async move { Ok(found) })
    }

    fn create_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        new: &'a NewCompose<'a>,
    ) -> DokployFuture<'a, ComposeService> {
        let mut state = self.state.lock().unwrap();
        state.call("create_compose", key);
        let service = ComposeService {
            compose_id: state.new_id("cmp"),
            name: new.name.to_owned(),
            app_name: format!("{}-abc123", new.name),
            environment_id: new.environment_id.clone(),
        };
        state.services.push(service.clone());
        state.descriptions.push(new.description.to_owned());
        let answer = if state.lose_create_answer {
            state.lose_create_answer = false;
            Err(lost())
        } else {
            Ok(service)
        };
        Box::pin(async move { answer })
    }

    fn configure_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        compose_file: &'a str,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("configure_compose", key);
        state.configured = Some((compose_file.to_owned(), env.expose_secret().to_owned()));
        Box::pin(async { Ok(()) })
    }

    fn file_mounts<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<FileMount>> {
        let mut state = self.state.lock().unwrap();
        state.call("file_mounts", key);
        let mounts = state.mounts.clone();
        Box::pin(async move { Ok(mounts) })
    }

    fn create_file_mount<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        file_path: &'a str,
        content: &'a str,
    ) -> DokployFuture<'a, FileMount> {
        let mut state = self.state.lock().unwrap();
        state.call("create_file_mount", key);
        let mount = FileMount {
            mount_id: state.new_id("mnt"),
            file_path: file_path.to_owned(),
            content: content.to_owned(),
        };
        state.mounts.push(mount.clone());
        Box::pin(async move { Ok(mount) })
    }

    fn update_file_mount<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        mount_id: &'a DokployId,
        content: &'a str,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("update_file_mount", key);
        if let Some(mount) = state.mounts.iter_mut().find(|m| &m.mount_id == mount_id) {
            mount.content = content.to_owned();
        }
        Box::pin(async { Ok(()) })
    }

    fn compose_domains<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<ComposeDomain>> {
        let mut state = self.state.lock().unwrap();
        state.call("compose_domains", key);
        let domains = state.domains.clone();
        Box::pin(async move { Ok(domains) })
    }

    fn create_compose_domain<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        domain: &'a NewComposeDomain<'a>,
    ) -> DokployFuture<'a, ComposeDomain> {
        let mut state = self.state.lock().unwrap();
        state.call("create_compose_domain", key);
        let domain = ComposeDomain {
            domain_id: state.new_id("dom"),
            host: domain.host.to_owned(),
            service_name: Some(domain.service_name.to_owned()),
            port: domain.port,
            https: domain.https,
        };
        state.domains.push(domain.clone());
        Box::pin(async move { Ok(domain) })
    }

    fn deploy_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("deploy_compose", key);
        // Dokploy shows the row as running first.
        let deployment = DeploymentInfo {
            deployment_id: state.new_id("dep"),
            title: Some(title.to_owned()),
            status: DeploymentStatus::Running,
        };
        state.deployments.push(deployment);
        let answer = if state.lose_deploy_answer {
            state.lose_deploy_answer = false;
            Err(lost())
        } else {
            Ok(())
        };
        Box::pin(async move { answer })
    }

    fn deployments<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Vec<DeploymentInfo>> {
        let mut state = self.state.lock().unwrap();
        state.call("deployments", key);
        let answer = state.deployments.clone();
        // A running deployment finishes after it was seen once.
        let result = state.deploy_result.unwrap_or(DeploymentStatus::Done);
        for deployment in &mut state.deployments {
            deployment.status = result;
        }
        Box::pin(async move { Ok(answer) })
    }

    fn compose_details<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeDetails>> {
        let mut state = self.state.lock().unwrap();
        state.call("compose_details", key);
        let answer = match state.details_error.clone() {
            Some(err) => Err(err),
            None => Ok(state
                .services
                .iter()
                .find(|s| &s.compose_id == compose_id)
                .map(|s| ComposeDetails {
                    compose_id: s.compose_id.clone(),
                    name: s.name.clone(),
                    app_name: s.app_name.clone(),
                    description: state.descriptions.first().cloned(),
                    status: Some(ComposeStatus::Done),
                    environment_id: s.environment_id.clone(),
                    environment_name: s.environment_id.as_str().to_owned(),
                    project_id: id("proj1"),
                    project_name: "Infra".to_owned(),
                    server_id: None,
                    server_name: None,
                    deployments: state
                        .deployments
                        .iter()
                        .map(|d| DeploymentRecord {
                            deployment_id: d.deployment_id.clone(),
                            title: d.title.clone(),
                            status: d.status,
                            created_at: None,
                            finished_at: None,
                        })
                        .collect(),
                })),
        };
        Box::pin(async move { answer })
    }

    fn stop_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("stop_compose", key);
        state.stopped = true;
        let answer = if state.lose_stop_answer {
            state.lose_stop_answer = false;
            Err(lost())
        } else {
            Ok(())
        };
        Box::pin(async move { answer })
    }

    fn start_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("start_compose", key);
        state.stopped = false;
        Box::pin(async { Ok(()) })
    }

    fn delete_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
        delete_volumes: bool,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("delete_compose", key);
        state.deletes.push(delete_volumes);
        let before = state.services.len();
        state.services.retain(|s| &s.compose_id != compose_id);
        let answer = if state.services.len() == before {
            Err(DokployError::Http(404))
        } else if state.lose_delete_answer {
            state.lose_delete_answer = false;
            Err(lost())
        } else {
            Ok(())
        };
        Box::pin(async move { answer })
    }

    fn redeploy_compose<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        title: &'a str,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("redeploy_compose", key);
        let deployment = DeploymentInfo {
            deployment_id: state.new_id("dep"),
            title: Some(title.to_owned()),
            status: DeploymentStatus::Running,
        };
        state.deployments.insert(0, deployment);
        let answer = if state.lose_deploy_answer {
            state.lose_deploy_answer = false;
            Err(lost())
        } else {
            Ok(())
        };
        Box::pin(async move { answer })
    }

    fn compose_config<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        compose_id: &'a DokployId,
    ) -> DokployFuture<'a, Option<ComposeConfig>> {
        let mut state = self.state.lock().unwrap();
        state.call("compose_config", key);
        let exists = state.services.iter().any(|s| s.compose_id == *compose_id);
        let made = state
            .made_in_dokploy
            .iter()
            .find(|(id, _, _)| id == compose_id)
            .map(|(_, file, env)| (file.clone(), env.clone()));
        let answer = made
            .or_else(|| state.configured.clone())
            .filter(|_| exists)
            .map(|(compose_file, env)| ComposeConfig {
                env: SecretString::from(env),
                compose_file,
            });
        Box::pin(async move { Ok(answer) })
    }

    fn update_compose_env<'a>(
        &'a self,
        _url: &'a DokployUrl,
        key: &'a SecretString,
        _compose_id: &'a DokployId,
        env: &'a SecretString,
    ) -> DokployFuture<'a, ()> {
        let mut state = self.state.lock().unwrap();
        state.call("update_compose_env", key);
        if let Some((_, stored)) = state.configured.as_mut() {
            *stored = env.expose_secret().to_owned();
        }
        let answer = if state.lose_env_answer {
            state.lose_env_answer = false;
            Err(lost())
        } else {
            Ok(())
        };
        Box::pin(async move { answer })
    }
}

/// Answers health checks, and records the URL and key of each.
#[derive(Default)]
struct FakeProbe {
    calls: Mutex<Vec<(String, StackService, String)>>,
    down: Mutex<bool>,
}

impl StackProbe for FakeProbe {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
        _authorities: Option<&'a ProjectAuthorities>,
    ) -> ProbeFuture<'a> {
        self.calls.lock().unwrap().push((
            api_url.as_str().to_owned(),
            service,
            key.expose_secret().to_owned(),
        ));
        let status = if *self.down.lock().unwrap() {
            ServiceStatus::Unreachable {
                reason: UnreachableReason::Connect,
            }
        } else {
            ServiceStatus::Healthy
        };
        Box::pin(async move {
            ServiceCheck {
                service,
                status,
                version: None,
                latency_ms: Some(1),
                certificate_expires_at: None,
            }
        })
    }

    fn read_authorities(&self, _pem: &str) -> Result<Vec<AuthorityInfo>, AuthorityError> {
        Err(AuthorityError::NotACertificate)
    }
}

struct Fixture {
    db: Database,
    compose: Arc<FakeCompose>,
    probe: Arc<FakeProbe>,
    service: ProvisioningService,
    runner: JobRunner,
    owner: CurrentSession,
    organization: Uuid,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let cipher = || CredentialCipher::from_base64(&SecretString::from(KEY_A)).unwrap();
    let dokploy = Arc::new(
        DokployService::new(db.clone(), Some(cipher()), Arc::new(FakeConnector))
            .with_public_host(Some(PUBLIC_HOST)),
    );
    let admin = account(&db, "Admin", true).await;
    dokploy
        .connect(&admin, URL, &SecretString::from(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    // New stacks go next to the dashboard by default.
    dokploy
        .confirm_placement(&admin, "compose", "dash", ctx())
        .await
        .unwrap();
    let compose = Arc::new(FakeCompose::default());
    let probe = Arc::new(FakeProbe::default());
    let timings = ProvisionTimings {
        deploy_poll: Duration::ZERO,
        deploy_deadline: Duration::from_secs(600),
        transient_retry: Duration::ZERO,
        max_transient_errors: 3,
        health_attempts: 3,
        health_poll: Duration::ZERO,
    };
    let handler: Arc<dyn JobHandler> = Arc::new(
        ProvisionStackHandler::new(
            db.clone(),
            Some(cipher()),
            dokploy.clone(),
            compose.clone(),
            probe.clone(),
        )
        .with_timings(timings),
    );
    let actions: Arc<dyn JobHandler> = Arc::new(
        StackActionHandler::new(db.clone(), Some(cipher()), dokploy.clone(), compose.clone())
            .with_timings(timings),
    );
    let runner = JobRunner::new(
        db.clone(),
        vec![handler, actions],
        RunnerSettings {
            lease: Duration::from_secs(10),
            step_timeout: Duration::from_secs(5),
            retry_after_timeout: Duration::ZERO,
            max_interruptions: 2,
            max_steps_per_claim: 50,
            idle_poll: Duration::from_millis(10),
        },
    );
    let service =
        ProvisioningService::new(db.clone(), Some(cipher()), dokploy).with_compose(compose.clone());
    let owner = account(&db, "Olivia", false).await;
    let organization = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, 'Acme')")
        .bind(organization)
        .execute(db.pool())
        .await
        .unwrap();
    add_member(&db, organization, &owner, OrgRole::Owner).await;
    Fixture {
        db,
        compose,
        probe,
        service,
        runner,
        owner,
        organization,
    }
}

async fn account(db: &Database, name: &str, admin: bool) -> CurrentSession {
    let id = Uuid::now_v7();
    let email = format!("{}@example.test", name.to_lowercase());
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash, is_installation_admin) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&email)
    .bind(name)
    .bind(HASH)
    .bind(admin)
    .execute(db.pool())
    .await
    .unwrap();
    CurrentSession {
        session_id: Uuid::now_v7(),
        account: AccountRecord {
            id,
            email: Email::parse(&email).unwrap(),
            display_name: DisplayName::parse(name).unwrap(),
            is_installation_admin: admin,
            disabled: false,
        },
    }
}

async fn add_member(db: &Database, org: Uuid, who: &CurrentSession, role: OrgRole) {
    sqlx::query(
        "INSERT INTO organization_members (organization_id, account_id, role) VALUES ($1, $2, $3)",
    )
    .bind(org)
    .bind(who.account.id)
    .bind(role.as_str())
    .execute(db.pool())
    .await
    .unwrap();
}

fn shop() -> ProvisionRequest<'static> {
    ProvisionRequest {
        name: "Shop",
        target: "prod",
        host: "Shop.Example.test",
        https: true,
    }
}

/// Runs due jobs until none is left, as a runner would.
async fn run_all(f: &Fixture) {
    for _ in 0..100 {
        if f.runner.run_due().await.unwrap() == RunResult::Idle {
            return;
        }
    }
    panic!("the job did not finish");
}

/// Whether the owner sees variables edited in Dokploy.
async fn tracking(f: &Fixture, project: Uuid) -> EnvTracking {
    f.service
        .stack_settings(&f.owner, project)
        .await
        .unwrap()
        .unwrap()
        .tracking
}

/// The key the project's variable record is sealed under.
async fn record_key(f: &Fixture, project: Uuid) -> String {
    sqlx::query_scalar("SELECT key_id FROM project_dokploy_env_records WHERE project_id = $1")
        .bind(project)
        .fetch_one(f.db.pool())
        .await
        .unwrap()
}

async fn count(db: &Database, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(db.pool()).await.unwrap()
}

/// The value of `name` in the variables Dokploy was given.
fn variable(f: &Fixture, name: &str) -> String {
    let state = f.compose.state.lock().unwrap();
    let (_, env) = state.configured.clone().unwrap();
    env.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_stack_is_created_deployed_registered_and_checked() {
    let Some(scratch) = ScratchDb::create("provision_ok").await else {
        return;
    };
    let f = setup(&scratch).await;
    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(&f).await;

    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    assert_eq!(
        stored.message.as_deref(),
        Some("The stack is running and registered.")
    );
    // The secrets go once the job succeeds.
    assert!(f.db.job_secrets(job).await.unwrap().is_none());

    {
        let state = f.compose.state.lock().unwrap();
        assert_eq!(state.count("create_compose"), 1);
        assert_eq!(state.count("deploy_compose"), 1);
        assert!(state.keys.iter().all(|k| k == DOKPLOY_KEY));
        let name = format!("sd-{}", job.simple());
        assert_eq!(state.services[0].name, name);
        assert_eq!(state.mounts.len(), STACK_FILES.len());
        for file in STACK_FILES {
            assert!(
                state
                    .mounts
                    .iter()
                    .any(|m| m.file_path == file.path && m.content == file.content)
            );
        }
        assert_eq!(state.domains.len(), 1);
        let domain = &state.domains[0];
        assert_eq!(domain.host, "shop.example.test");
        assert_eq!(domain.service_name.as_deref(), Some(GATEWAY_SERVICE));
        assert_eq!(domain.port, GATEWAY_PORT);
        assert!(domain.https);
        assert_eq!(
            state.deployments[0].title.as_deref(),
            Some(format!("supabase-dashboard provision {job}").as_str())
        );
    }
    assert_eq!(
        variable(&f, "SUPABASE_PUBLIC_URL"),
        "https://shop.example.test"
    );

    // The project is registered with its keys and its Dokploy service.
    let (project, api_url): (Uuid, String) = sqlx::query_as(
        "SELECT id, api_url FROM projects WHERE organization_id = $1 AND name = 'Shop'",
    )
    .bind(f.organization)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(api_url, "https://shop.example.test");
    let (compose_id, app_name, environment, job_id): (String, String, String, Uuid) =
        sqlx::query_as(
            "SELECT compose_id, app_name, environment_id, job_id \
             FROM project_dokploy_services WHERE project_id = $1",
        )
        .bind(project)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(compose_id, "cmp1");
    assert_eq!(app_name, format!("sd-{}-abc123", job.simple()));
    assert_eq!(environment, "prod");
    assert_eq!(job_id, job);
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM project_credentials WHERE project_id = $1 ORDER BY kind",
    )
    .bind(project)
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert_eq!(kinds, ["anon_key", "service_role_key", "studio_login"]);

    // The health check used the stack's own anon key at its public URL.
    let anon = variable(&f, "ANON_KEY");
    let calls = f.probe.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        [(
            "https://shop.example.test".to_owned(),
            StackService::Auth,
            anon
        )]
    );

    // Nothing the server keeps in the clear holds a secret.
    for name in [
        "POSTGRES_PASSWORD",
        "JWT_SECRET",
        "ANON_KEY",
        "SERVICE_ROLE_KEY",
        "DASHBOARD_PASSWORD",
    ] {
        let value = variable(&f, name);
        assert!(!stored.data.contains(&value), "{name} in the job data");
        let leaked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE \
             strpos(coalesce(target_id, '') || coalesce(request_id, ''), $1) > 0",
        )
        .bind(&value)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert_eq!(leaked, 0, "{name} in the audit log");
    }
    for action in ["project.provision", "project.provisioned"] {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = 'success'",
        )
        .bind(action)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert_eq!(n, 1, "{action}");
    }
}

#[tokio::test]
async fn lost_answers_are_followed_by_lookups_not_second_requests() {
    let Some(scratch) = ScratchDb::create("provision_lost").await else {
        return;
    };
    let f = setup(&scratch).await;
    {
        let mut state = f.compose.state.lock().unwrap();
        state.lose_create_answer = true;
        state.lose_deploy_answer = true;
    }
    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    let state = f.compose.state.lock().unwrap();
    assert_eq!(state.count("create_compose"), 1);
    assert_eq!(state.count("deploy_compose"), 1);
    assert_eq!(state.services.len(), 1);
    assert_eq!(state.deployments.len(), 1);
}

#[tokio::test]
async fn a_failed_deployment_fails_the_job_and_leaves_the_service() {
    let Some(scratch) = ScratchDb::create("provision_deploy_fail").await else {
        return;
    };
    let f = setup(&scratch).await;
    f.compose.state.lock().unwrap().deploy_result = Some(DeploymentStatus::Error);
    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(
        stored
            .message
            .as_deref()
            .unwrap()
            .starts_with("The deployment failed."),
        "{:?}",
        stored.message
    );
    // The administrator view lists it under the name it was given.
    let listed = f.db.list_registered_resources(500).await.unwrap();
    assert!(!listed.failed_jobs_truncated);
    let [failed] = listed.failed_jobs.as_slice() else {
        panic!("one failed job: {:?}", listed.failed_jobs);
    };
    assert_eq!(
        (failed.id, failed.kind, failed.action),
        (job, JobKind::ProvisionStack, None)
    );
    assert_eq!(failed.project_id, None);
    assert_eq!(failed.project_name.as_deref(), Some("Shop"));
    assert_eq!(failed.message, stored.message);
    // Nothing registered, nothing removed, and the secrets kept for the
    // stack that may already use them.
    assert_eq!(count(&f.db, "SELECT count(*) FROM projects").await, 0);
    assert_eq!(f.compose.state.lock().unwrap().services.len(), 1);
    assert!(f.db.job_secrets(job).await.unwrap().is_some());
}

#[tokio::test]
async fn an_unreachable_stack_is_registered_with_a_warning() {
    let Some(scratch) = ScratchDb::create("provision_unhealthy").await else {
        return;
    };
    let f = setup(&scratch).await;
    *f.probe.down.lock().unwrap() = true;
    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded");
    assert!(
        stored.message.as_deref().unwrap().contains("DNS"),
        "{:?}",
        stored.message
    );
    assert_eq!(f.probe.calls.lock().unwrap().len(), 3);
    assert_eq!(count(&f.db, "SELECT count(*) FROM projects").await, 1);
}

#[tokio::test]
async fn only_owners_and_admins_provision_and_the_role_is_checked_again() {
    let Some(scratch) = ScratchDb::create("provision_authz").await else {
        return;
    };
    let f = setup(&scratch).await;
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;
    let stranger = account(&f.db, "Stranger", false).await;
    assert!(matches!(
        f.service.start(&dev, f.organization, shop(), ctx()).await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .start(&stranger, f.organization, shop(), ctx())
            .await,
        Err(ProvisionError::NotFound)
    ));
    let denied = count(
        &f.db,
        "SELECT count(*) FROM audit_events \
         WHERE action = 'project.provision' AND outcome = 'denied'",
    )
    .await;
    assert_eq!(denied, 1);

    // An admin queues a stack, then loses the role before it runs.
    let admin = account(&f.db, "Ada", false).await;
    add_member(&f.db, f.organization, &admin, OrgRole::Admin).await;
    let job = f
        .service
        .start(&admin, f.organization, shop(), ctx())
        .await
        .unwrap();
    sqlx::query("UPDATE organization_members SET role = 'viewer' WHERE account_id = $1")
        .bind(admin.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(f.compose.state.lock().unwrap().calls.is_empty());
    assert_eq!(count(&f.db, "SELECT count(*) FROM projects").await, 0);
}

#[tokio::test]
async fn names_hosts_and_targets_are_checked_before_queueing() {
    let Some(scratch) = ScratchDb::create("provision_input").await else {
        return;
    };
    let f = setup(&scratch).await;
    let start = |request| f.service.start(&f.owner, f.organization, request, ctx());
    for host in [
        "",
        "localhost",
        "10.0.0.5",
        "shop.example.test/x",
        "a b.test",
    ] {
        assert!(
            matches!(
                start(ProvisionRequest { host, ..shop() }).await,
                Err(ProvisionError::InvalidHost)
            ),
            "{host}"
        );
    }
    // `stacks` is not allowed until an installation admin allows it.
    for target in ["stacks", "elsewhere", "prod@srv1", "bad id"] {
        assert!(
            matches!(
                start(ProvisionRequest { target, ..shop() }).await,
                Err(ProvisionError::TargetNotAllowed)
            ),
            "{target}"
        );
    }
    assert!(matches!(
        start(ProvisionRequest { name: "", ..shop() }).await,
        Err(ProvisionError::Input(_))
    ));
    assert!(matches!(
        f.service
            .start(&f.owner, Uuid::now_v7(), shop(), ctx())
            .await,
        Err(ProvisionError::NotFound)
    ));
    assert_eq!(count(&f.db, "SELECT count(*) FROM jobs").await, 0);
}

#[tokio::test]
async fn members_see_targets_and_progress_by_their_role() {
    let Some(scratch) = ScratchDb::create("provision_views").await else {
        return;
    };
    let f = setup(&scratch).await;
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;
    let stranger = account(&f.db, "Stranger", false).await;

    let targets = f.service.targets(&f.owner, f.organization).await.unwrap();
    assert_eq!(
        targets,
        ProvisionTargets::Choices(vec![TargetChoice {
            value: "prod".to_owned(),
            label: "Infra / prod, on Dokploy's own server".to_owned(),
        }])
    );
    assert!(matches!(
        f.service.targets(&dev, f.organization).await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service.targets(&stranger, f.organization).await,
        Err(ProvisionError::NotFound)
    ));

    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    let queued = f.service.job(&dev, job).await.unwrap();
    assert_eq!(queued.state, JobState::Queued);
    assert_eq!(queued.step, Some(ProvisionStep::Check));
    assert_eq!(queued.name, "Shop");
    assert_eq!(queued.public_url(), "https://shop.example.test");
    assert_eq!(queued.project_id, None);

    run_all(&f).await;
    let done = f.service.job(&dev, job).await.unwrap();
    assert_eq!(done.state, JobState::Succeeded);
    let project: Uuid = sqlx::query_scalar("SELECT id FROM projects")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(done.project_id, Some(project));
    assert_eq!(
        f.service.jobs(&dev, f.organization).await.unwrap(),
        vec![done]
    );

    assert!(matches!(
        f.service.job(&stranger, job).await,
        Err(ProvisionError::NotFound)
    ));
    assert!(matches!(
        f.service.jobs(&stranger, f.organization).await,
        Err(ProvisionError::NotFound)
    ));
    assert!(matches!(
        f.service.job(&f.owner, Uuid::now_v7()).await,
        Err(ProvisionError::NotFound)
    ));
}

#[tokio::test]
async fn members_see_the_service_as_dokploy_reports_it_now() {
    let Some(scratch) = ScratchDb::create("provision_deployment").await else {
        return;
    };
    let f = setup(&scratch).await;
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;
    let stranger = account(&f.db, "Stranger", false).await;

    // A registered project has no Dokploy service.
    let registered = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO projects (id, organization_id, name, api_url) \
         VALUES ($1, $2, 'Old', 'https://old.example.test')",
    )
    .bind(registered)
    .bind(f.organization)
    .execute(f.db.pool())
    .await
    .unwrap();
    assert_eq!(
        f.service.deployment(&dev, registered).await.unwrap(),
        StackDeploymentView::NotProvisioned
    );

    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let project = f
        .service
        .job(&f.owner, job)
        .await
        .unwrap()
        .project_id
        .unwrap();
    let compose_id = f.compose.state.lock().unwrap().services[0]
        .compose_id
        .clone();

    let StackDeploymentView::Found(owner_view) =
        f.service.deployment(&f.owner, project).await.unwrap()
    else {
        panic!("the owner should see the service");
    };
    assert_eq!(owner_view.name, format!("sd-{}", job.simple()));
    assert_eq!(owner_view.status, Some(ComposeStatus::Done));
    assert!(!owner_view.moved);
    let location = owner_view.location.clone().unwrap();
    assert_eq!(location.project_name, "Infra");
    assert_eq!(location.environment_name, "prod");
    assert_eq!(location.compose_id, compose_id.as_str());
    assert_eq!(
        location.dokploy_link.as_deref(),
        Some(
            format!(
                "{URL}/dashboard/project/proj1/environment/prod/services/compose/{}",
                compose_id.as_str()
            )
            .as_str()
        )
    );
    assert_eq!(owner_view.deployments.len(), 1);
    assert!(owner_view.deployments[0].from_dashboard);
    assert!(!owner_view.more_deployments);

    // Developers see the status and deployments, not where it runs.
    let StackDeploymentView::Found(dev_view) = f.service.deployment(&dev, project).await.unwrap()
    else {
        panic!("a developer should see the service");
    };
    assert_eq!(dev_view.location, None);
    assert_eq!(dev_view.deployments, owner_view.deployments);
    assert!(matches!(
        f.service.deployment(&stranger, project).await,
        Err(ProvisionError::NotFound)
    ));

    // A redeploy in Dokploy and a move to another environment show up.
    {
        let mut state = f.compose.state.lock().unwrap();
        state.deployments.insert(
            0,
            DeploymentInfo {
                deployment_id: id("manual1"),
                title: Some("Manual deployment".to_owned()),
                status: DeploymentStatus::Error,
            },
        );
        state.services[0].environment_id = id("stacks");
    }
    let StackDeploymentView::Found(changed) =
        f.service.deployment(&f.owner, project).await.unwrap()
    else {
        panic!("the service should still be found");
    };
    assert!(changed.moved);
    assert_eq!(changed.location.unwrap().environment_name, "stacks");
    assert!(!changed.deployments[0].from_dashboard);
    assert_eq!(changed.deployments[0].status, DeploymentStatus::Error);
    assert!(changed.deployments[1].from_dashboard);

    // Dokploy refusing the key is reported, not raised.
    f.compose.state.lock().unwrap().details_error = Some(DokployError::KeyRejected);
    let StackDeploymentView::Unavailable { reason, .. } =
        f.service.deployment(&dev, project).await.unwrap()
    else {
        panic!("a refused key should be reported");
    };
    assert!(reason.contains("refused the API key"));
    assert!(!reason.contains(DOKPLOY_KEY));

    // A service deleted in Dokploy is reported; owners get its name.
    {
        let mut state = f.compose.state.lock().unwrap();
        state.details_error = None;
        state.services.clear();
    }
    assert_eq!(
        f.service.deployment(&f.owner, project).await.unwrap(),
        StackDeploymentView::Missing {
            compose_name: Some(format!("sd-{}", job.simple())),
            last_action: None,
        }
    );
    assert_eq!(
        f.service.deployment(&dev, project).await.unwrap(),
        StackDeploymentView::Missing {
            compose_name: None,
            last_action: None,
        }
    );

    // Without the connection there is nothing to ask.
    let admin = account(&f.db, "Admin2", true).await;
    let dokploy = DokployService::new(
        f.db.clone(),
        Some(CredentialCipher::from_base64(&SecretString::from(KEY_A)).unwrap()),
        Arc::new(FakeConnector),
    );
    dokploy.remove(&admin, ctx()).await.unwrap();
    assert_eq!(
        f.service.deployment(&dev, project).await.unwrap(),
        StackDeploymentView::NotConnected
    );
    // The key was only ever sent to Dokploy, never shown.
    assert!(
        f.compose
            .state
            .lock()
            .unwrap()
            .keys
            .iter()
            .all(|key| key == DOKPLOY_KEY)
    );
}

/// Provisions the Shop stack and returns its job and project IDs.
async fn provisioned(f: &Fixture) -> (Uuid, Uuid) {
    let job = f
        .service
        .start(&f.owner, f.organization, shop(), ctx())
        .await
        .unwrap();
    run_all(f).await;
    let project = f
        .service
        .job(&f.owner, job)
        .await
        .unwrap()
        .project_id
        .unwrap();
    (job, project)
}

#[tokio::test]
async fn owners_stop_start_and_redeploy_a_provisioned_stack() {
    let Some(scratch) = ScratchDb::create("stack_actions").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (_, project) = provisioned(&f).await;
    f.compose.state.lock().unwrap().lose_stop_answer = true;

    // Stop; a second action waits for the first. A lost answer to stop
    // is followed by another stop, which is harmless.
    let stop = f
        .service
        .queue_action(&f.owner, project, StackAction::Stop, true, ctx())
        .await
        .unwrap();
    assert!(matches!(
        f.service
            .queue_action(&f.owner, project, StackAction::Start, true, ctx())
            .await,
        Err(ProvisionError::Busy)
    ));
    run_all(&f).await;
    let stored = f.db.get_job(stop).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    {
        let state = f.compose.state.lock().unwrap();
        assert!(state.stopped);
        assert_eq!(state.count("stop_compose"), 2);
    }
    let StackDeploymentView::Found(view) = f.service.deployment(&f.owner, project).await.unwrap()
    else {
        panic!("the owner should see the service");
    };
    assert!(view.can_operate);
    let last = view.last_action.unwrap();
    assert_eq!(
        (last.id, last.action, last.state),
        (stop, StackAction::Stop, JobState::Succeeded)
    );

    // Start.
    let start = f
        .service
        .queue_action(&f.owner, project, StackAction::Start, true, ctx())
        .await
        .unwrap();
    run_all(&f).await;
    assert_eq!(
        f.db.get_job(start).await.unwrap().unwrap().state,
        "succeeded"
    );
    assert!(!f.compose.state.lock().unwrap().stopped);

    // Redeploy: a lost answer is followed by a lookup, never a second
    // request.
    f.compose.state.lock().unwrap().lose_deploy_answer = true;
    let redeploy = f
        .service
        .queue_action(&f.owner, project, StackAction::Redeploy, true, ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(redeploy).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    assert_eq!(f.compose.state.lock().unwrap().count("redeploy_compose"), 1);
    let StackDeploymentView::Found(view) = f.service.deployment(&f.owner, project).await.unwrap()
    else {
        panic!("the owner should see the service");
    };
    let newest = &view.deployments[0];
    assert_eq!(
        newest.title.as_deref(),
        Some(format!("supabase-dashboard redeploy {redeploy}").as_str())
    );
    assert!(newest.from_dashboard);

    let audited = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE outcome = 'success' \
         AND action IN ('stack.stop', 'stack.start', 'stack.redeploy')",
    )
    .await;
    assert_eq!(audited, 3);
    // The refused second action is recorded too.
    let refused = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE outcome = 'failure' AND action = 'stack.start'",
    )
    .await;
    assert_eq!(refused, 1);
    let leaked = count(
        &f.db,
        "SELECT count(*) FROM jobs WHERE kind = 'stack_action' \
         AND data::text LIKE '%dokploy-key-marker%'",
    )
    .await;
    assert_eq!(leaked, 0);
}

#[tokio::test]
async fn only_owners_and_admins_operate_and_the_job_checks_again() {
    let Some(scratch) = ScratchDb::create("stack_actions_authz").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (_, project) = provisioned(&f).await;
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;
    let stranger = account(&f.db, "Stranger", false).await;

    assert!(matches!(
        f.service
            .queue_action(&dev, project, StackAction::Stop, true, ctx())
            .await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .queue_action(&stranger, project, StackAction::Stop, true, ctx())
            .await,
        Err(ProvisionError::NotFound)
    ));
    let denied = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE action = 'stack.stop' AND outcome = 'denied'",
    )
    .await;
    assert_eq!(denied, 1);
    let StackDeploymentView::Found(view) = f.service.deployment(&dev, project).await.unwrap()
    else {
        panic!("a developer should see the service");
    };
    assert!(!view.can_operate);

    // Only stacks the dashboard provisioned can be operated.
    let registered = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO projects (id, organization_id, name, api_url) \
         VALUES ($1, $2, 'Old', 'https://old.example.test')",
    )
    .bind(registered)
    .bind(f.organization)
    .execute(f.db.pool())
    .await
    .unwrap();
    assert!(matches!(
        f.service
            .queue_action(&f.owner, registered, StackAction::Stop, true, ctx())
            .await,
        Err(ProvisionError::NotProvisioned)
    ));

    // An admin asks, then loses the role before the job runs.
    let admin = account(&f.db, "Ada", false).await;
    add_member(&f.db, f.organization, &admin, OrgRole::Admin).await;
    let job = f
        .service
        .queue_action(&admin, project, StackAction::Stop, true, ctx())
        .await
        .unwrap();
    sqlx::query("UPDATE organization_members SET role = 'developer' WHERE account_id = $1")
        .bind(admin.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(stored.message.unwrap().contains("may no longer operate"));
    assert_eq!(f.compose.state.lock().unwrap().count("stop_compose"), 0);

    // A service deleted in Dokploy fails the job before anything is sent.
    f.compose.state.lock().unwrap().services.clear();
    let job = f
        .service
        .queue_action(&f.owner, project, StackAction::Redeploy, true, ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(
        stored
            .message
            .unwrap()
            .contains("no longer has this service")
    );
    assert_eq!(f.compose.state.lock().unwrap().count("redeploy_compose"), 0);
}

#[tokio::test]
async fn removing_and_destroying_need_the_name_and_the_right_role() {
    let Some(scratch) = ScratchDb::create("stack_removal").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (job, project) = provisioned(&f).await;
    let admin = account(&f.db, "Ada", false).await;
    add_member(&f.db, f.organization, &admin, OrgRole::Admin).await;
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;

    // Only owners destroy; admins remove; developers do neither.
    assert!(matches!(
        f.service
            .queue_removal(&admin, project, StackAction::Destroy, "Shop", ctx())
            .await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .queue_removal(&dev, project, StackAction::Remove, "Shop", ctx())
            .await,
        Err(ProvisionError::Forbidden)
    ));
    // The name must be typed; the plain path refuses deletions.
    for typed in ["", "shop", "Shopping"] {
        assert!(matches!(
            f.service
                .queue_removal(&f.owner, project, StackAction::Destroy, typed, ctx())
                .await,
            Err(ProvisionError::NameMismatch)
        ));
    }
    assert!(matches!(
        f.service
            .queue_action(&f.owner, project, StackAction::Remove, true, ctx())
            .await,
        Err(ProvisionError::NameMismatch)
    ));
    assert!(matches!(
        f.service
            .queue_action(&f.owner, project, StackAction::Stop, false, ctx())
            .await,
        Err(ProvisionError::NotConfirmed)
    ));
    let StackDeploymentView::Found(view) = f.service.deployment(&admin, project).await.unwrap()
    else {
        panic!("the admin should see the service");
    };
    assert!(view.can_remove && !view.can_destroy);
    assert!(f.compose.state.lock().unwrap().deletes.is_empty());

    // An admin removes it and keeps the volumes. The delete's answer is
    // lost; the job reads the service and does not ask again.
    f.compose.state.lock().unwrap().lose_delete_answer = true;
    let removal = f
        .service
        .queue_removal(&admin, project, StackAction::Remove, " Shop ", ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(removal).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    assert!(stored.message.unwrap().contains("kept the data volumes"));
    assert_eq!(f.compose.state.lock().unwrap().deletes, vec![false]);
    let view = f.service.deployment(&admin, project).await.unwrap();
    let StackDeploymentView::Removed {
        volumes_deleted,
        app_name,
        last_action,
        ..
    } = view
    else {
        panic!("the removal should show: {view:?}");
    };
    assert!(!volumes_deleted);
    assert!(
        app_name
            .unwrap()
            .starts_with(&format!("sd-{}", job.simple()))
    );
    assert_eq!(last_action.unwrap().action, StackAction::Remove);
    let StackDeploymentView::Removed { app_name, .. } =
        f.service.deployment(&dev, project).await.unwrap()
    else {
        panic!("a developer should see the removal");
    };
    assert_eq!(app_name, None);
    // The project stays registered, and nothing more can be done to it.
    assert_eq!(count(&f.db, "SELECT count(*) FROM projects").await, 1);
    assert!(matches!(
        f.service
            .queue_removal(&f.owner, project, StackAction::Destroy, "Shop", ctx())
            .await,
        Err(ProvisionError::AlreadyRemoved)
    ));
    assert!(matches!(
        f.service
            .queue_action(&f.owner, project, StackAction::Start, true, ctx())
            .await,
        Err(ProvisionError::AlreadyRemoved)
    ));
    let audited = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE action = 'stack.remove' AND outcome = 'success'",
    )
    .await;
    assert_eq!(audited, 1);
}

#[tokio::test]
async fn destroying_deletes_the_volumes_and_a_vanished_service_is_not_deleted() {
    let Some(scratch) = ScratchDb::create("stack_destroy").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (_, project) = provisioned(&f).await;

    // A service already gone in Dokploy: nothing is sent.
    let saved = f.compose.state.lock().unwrap().services.clone();
    f.compose.state.lock().unwrap().services.clear();
    let job = f
        .service
        .queue_removal(&f.owner, project, StackAction::Destroy, "Shop", ctx())
        .await
        .unwrap();
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(stored.message.unwrap().contains("nothing was changed"));
    assert!(f.compose.state.lock().unwrap().deletes.is_empty());
    let listed = f.db.list_registered_resources(500).await.unwrap();
    let failed = listed
        .failed_jobs
        .iter()
        .find(|failed| failed.id == job)
        .expect("the failed removal is listed");
    assert_eq!(
        (failed.kind, failed.action, failed.project_id),
        (
            JobKind::StackAction,
            Some(StackAction::Destroy),
            Some(project)
        )
    );
    assert_eq!(failed.project_name.as_deref(), Some("Shop"));

    // The owner destroys it with its data.
    f.compose.state.lock().unwrap().services = saved.clone();
    let job = f
        .service
        .queue_removal(&f.owner, project, StackAction::Destroy, "Shop", ctx())
        .await
        .unwrap();
    // Between Dokploy deleting the service and the job recording it, the
    // panel still sees the running removal, so it keeps following it.
    f.compose.state.lock().unwrap().services.clear();
    let view = f.service.deployment(&f.owner, project).await.unwrap();
    let StackDeploymentView::Missing { last_action, .. } = &view else {
        panic!("a vanished service should show as missing: {view:?}");
    };
    let last = last_action.as_ref().expect("the removal is reported");
    assert_eq!((last.id, last.action), (job, StackAction::Destroy));
    assert!(view.action_running());
    f.compose.state.lock().unwrap().services = saved;
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    assert!(stored.message.unwrap().starts_with("Destroyed"));
    assert_eq!(f.compose.state.lock().unwrap().deletes, vec![true]);
    let StackDeploymentView::Removed {
        volumes_deleted, ..
    } = f.service.deployment(&f.owner, project).await.unwrap()
    else {
        panic!("the removal should show");
    };
    assert!(volumes_deleted);
}

#[tokio::test]
async fn owners_change_settings_and_edits_in_dokploy_stop_the_change() {
    let Some(scratch) = ScratchDb::create("stack_settings").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (_, project) = provisioned(&f).await;

    let view = f
        .service
        .stack_settings(&f.owner, project)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.settings.len(), 7);
    assert!(!view.busy);
    // The provisioning job recorded what it wrote.
    assert_eq!(view.tracking, EnvTracking::Compared(EnvChanges::default()));
    let value = |name: &str| {
        view.settings
            .iter()
            .find(|s| s.name == name)
            .map(|s| (s.value.clone(), s.state.clone()))
            .unwrap()
    };
    assert_eq!(
        value("SITE_URL"),
        (
            Some("https://shop.example.test".to_owned()),
            SettingState::Editable
        )
    );
    assert_eq!(
        value("DISABLE_SIGNUP"),
        (Some("true".to_owned()), SettingState::Editable)
    );

    // Developers neither read nor change settings, and the refusal is
    // audited.
    let developer = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &developer, OrgRole::Developer).await;
    assert!(matches!(
        f.service.stack_settings(&developer, project).await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .queue_settings(
                &developer,
                project,
                &[("DISABLE_SIGNUP", "false")],
                "any",
                ctx()
            )
            .await,
        Err(ProvisionError::Forbidden)
    ));
    let denied = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE outcome = 'denied' AND action = 'stack.configure'",
    )
    .await;
    assert_eq!(denied, 1);

    // Only real changes are listed, with the services that restart.
    let submitted = [
        ("DISABLE_SIGNUP", "false"),
        ("JWT_EXPIRY", "3600"),
        ("SITE_URL", "https://shop.example.test"),
    ];
    let preview = f
        .service
        .preview_settings(&f.owner, project, &submitted)
        .await
        .unwrap();
    assert_eq!(preview.changed, ["DISABLE_SIGNUP"]);
    assert_eq!(preview.restarts, ["auth"]);
    assert!(matches!(
        f.service
            .preview_settings(&f.owner, project, &[("JWT_EXPIRY", "10")])
            .await,
        Err(ProvisionError::Setting(_))
    ));
    assert!(matches!(
        f.service
            .preview_settings(&f.owner, project, &[("JWT_EXPIRY", "3600")])
            .await,
        Err(ProvisionError::NoChanges)
    ));
    assert!(matches!(
        f.service
            .preview_settings(&f.owner, project, &[("JWT_SECRET", "x")])
            .await,
        Err(ProvisionError::SettingUnavailable(_))
    ));
    // The settings must still be what the review saw.
    assert!(matches!(
        f.service
            .queue_settings(&f.owner, project, &submitted, "stale", ctx())
            .await,
        Err(ProvisionError::PreviewOutdated)
    ));

    // A lost answer to the update is followed by a read, not a second
    // update; the stack is redeployed once.
    let secret = variable(&f, "JWT_SECRET");
    f.compose.state.lock().unwrap().lose_env_answer = true;
    let job = f
        .service
        .queue_settings(&f.owner, project, &submitted, &preview.base, ctx())
        .await
        .unwrap();
    assert!(
        f.service
            .stack_settings(&f.owner, project)
            .await
            .unwrap()
            .unwrap()
            .busy
    );
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "succeeded", "{:?}", stored.message);
    assert_eq!(
        stored.message.as_deref(),
        Some("Settings changed and the stack redeployed.")
    );
    assert_eq!(variable(&f, "DISABLE_SIGNUP"), "false");
    assert_eq!(variable(&f, "JWT_SECRET"), secret);
    {
        let state = f.compose.state.lock().unwrap();
        assert_eq!(state.count("update_compose_env"), 1);
        assert_eq!(state.count("redeploy_compose"), 1);
    }
    // The dashboard's own change is not reported as an edit in Dokploy.
    assert_eq!(
        tracking(&f, project).await,
        EnvTracking::Compared(EnvChanges::default())
    );

    // A variable edited in Dokploy between the review and applying it
    // is not overwritten: applying is refused.
    let schemas = [("PGRST_DB_SCHEMAS", "public, api")];
    let reviewed = f
        .service
        .preview_settings(&f.owner, project, &schemas)
        .await
        .unwrap();
    if let Some((_, env)) = f.compose.state.lock().unwrap().configured.as_mut() {
        env.push_str("PGRST_DB_SCHEMAS=public\n");
    }
    // The edit shows by name, without its value.
    assert_eq!(
        tracking(&f, project).await,
        EnvTracking::Compared(EnvChanges {
            added: vec!["PGRST_DB_SCHEMAS".to_owned()],
            ..EnvChanges::default()
        })
    );
    assert!(matches!(
        f.service
            .queue_settings(&f.owner, project, &schemas, &reviewed.base, ctx())
            .await,
        Err(ProvisionError::PreviewOutdated)
    ));

    // One edited after the change was queued stops the job before
    // anything is written.
    let reviewed = f
        .service
        .preview_settings(&f.owner, project, &schemas)
        .await
        .unwrap();
    let job = f
        .service
        .queue_settings(&f.owner, project, &schemas, &reviewed.base, ctx())
        .await
        .unwrap();
    if let Some((_, env)) = f.compose.state.lock().unwrap().configured.as_mut() {
        *env = env.replace(
            "PGRST_DB_SCHEMAS=public\n",
            "PGRST_DB_SCHEMAS=public,storage\n",
        );
    }
    run_all(&f).await;
    let stored = f.db.get_job(job).await.unwrap().unwrap();
    assert_eq!(stored.state, "failed");
    assert!(
        stored
            .message
            .as_deref()
            .unwrap()
            .starts_with("PGRST_DB_SCHEMAS changed in Dokploy"),
        "{:?}",
        stored.message
    );
    assert_eq!(
        f.compose.state.lock().unwrap().count("update_compose_env"),
        1
    );

    // A compose file that does not read a variable makes it read-only.
    if let Some((file, _)) = f.compose.state.lock().unwrap().configured.as_mut() {
        *file = file.replace("${JWT_EXPIRY:-3600}", "3600");
    }
    let view = f
        .service
        .stack_settings(&f.owner, project)
        .await
        .unwrap()
        .unwrap();
    let jwt = view
        .settings
        .iter()
        .find(|s| s.name == "JWT_EXPIRY")
        .unwrap();
    assert_eq!(jwt.state, SettingState::NotInComposeFile);
    assert!(matches!(
        f.service
            .preview_settings(&f.owner, project, &[("JWT_EXPIRY", "7200")])
            .await,
        Err(ProvisionError::SettingUnavailable(_))
    ));

    // A secret changed in Dokploy is reported by name.
    if let Some((_, env)) = f.compose.state.lock().unwrap().configured.as_mut() {
        *env = env.replace(&format!("JWT_SECRET={secret}\n"), "JWT_SECRET=rotated\n");
    }
    let EnvTracking::Compared(changes) = tracking(&f, project).await else {
        panic!("the record should be readable");
    };
    assert_eq!(changes.changed, ["JWT_SECRET"]);
    assert!(changes.removed.is_empty());

    // Rotating the credential key reseals the record, and rotating back
    // leaves it readable.
    const KEY_B: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    let rotate = |to: &str, from: &str| {
        let mut cipher = CredentialCipher::from_base64(&SecretString::from(to.to_owned())).unwrap();
        cipher
            .add_previous_keys(&SecretString::from(from.to_owned()))
            .unwrap();
        cipher
    };
    let rotated = rotate(KEY_B, KEY_A);
    let summary = reseal_credentials(&f.db, &rotated).await.unwrap();
    assert_eq!(summary.unreadable, 0);
    assert_eq!(record_key(&f, project).await, rotated.key_id());
    let back = rotate(KEY_A, KEY_B);
    reseal_credentials(&f.db, &back).await.unwrap();
    assert_eq!(record_key(&f, project).await, back.key_id());
    let EnvTracking::Compared(again) = tracking(&f, project).await else {
        panic!("the resealed record should open");
    };
    assert_eq!(again, changes);

    // A record under a key this server lacks is reported as such.
    sqlx::query("UPDATE project_dokploy_env_records SET key_id = 'gone'")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(tracking(&f, project).await, EnvTracking::Unreadable);

    // A stack provisioned before the record existed has none.
    sqlx::query("DELETE FROM project_dokploy_env_records")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(tracking(&f, project).await, EnvTracking::NotRecorded);

    let audited = count(
        &f.db,
        "SELECT count(*) FROM audit_events WHERE outcome = 'success' AND action = 'stack.configure'",
    )
    .await;
    assert_eq!(audited, 2);
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE kind = 'stack_action' AND data::text LIKE '%' || $1 || '%'",
    )
    .bind(&secret)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(leaked, 0);
}

#[tokio::test]
async fn owners_accept_variables_edited_in_dokploy() {
    let Some(scratch) = ScratchDb::create("accept_variables").await else {
        return;
    };
    let f = setup(&scratch).await;
    let (_, project) = provisioned(&f).await;
    let accept = |seen: String| {
        f.service
            .accept_variables(&f.owner, project, seen.leak(), ctx())
    };
    let edit = |from: &str, to: &str| {
        if let Some((_, env)) = f.compose.state.lock().unwrap().configured.as_mut() {
            *env = if from.is_empty() {
                format!("{env}{to}")
            } else {
                env.replace(from, to)
            };
        }
    };

    // Nothing was edited, so there is nothing to accept.
    let seen = tracking(&f, project).await.seen();
    assert!(matches!(accept(seen).await, Err(ProvisionError::NoEdits)));

    // Developers may not accept.
    let dev = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &dev, OrgRole::Developer).await;
    edit("", "PGRST_DB_SCHEMAS=public\n");
    let listed = tracking(&f, project).await;
    assert!(matches!(
        f.service
            .accept_variables(&dev, project, &listed.seen(), ctx())
            .await,
        Err(ProvisionError::Forbidden)
    ));

    // A list read before another edit is not accepted.
    let stale = listed.seen();
    edit("", "EXTRA_FLAG=1\n");
    assert!(matches!(
        accept(stale).await,
        Err(ProvisionError::EditsOutdated)
    ));
    let listed = tracking(&f, project).await;
    assert_eq!(
        listed,
        EnvTracking::Compared(EnvChanges {
            added: vec!["EXTRA_FLAG".to_owned(), "PGRST_DB_SCHEMAS".to_owned()],
            ..EnvChanges::default()
        })
    );
    accept(listed.seen()).await.unwrap();
    assert_eq!(
        tracking(&f, project).await,
        EnvTracking::Compared(EnvChanges::default())
    );
    // Nothing was written to Dokploy.
    assert_eq!(
        f.compose.state.lock().unwrap().count("update_compose_env"),
        0
    );

    // An accepted variable edited again is listed again.
    edit("PGRST_DB_SCHEMAS=public\n", "PGRST_DB_SCHEMAS=public,api\n");
    let EnvTracking::Compared(changes) = tracking(&f, project).await else {
        panic!("the record should be readable");
    };
    assert_eq!(changes.changed, ["PGRST_DB_SCHEMAS"]);

    // Not while an action on the stack runs.
    let reviewed = f
        .service
        .preview_settings(&f.owner, project, &[("JWT_EXPIRY", "7200")])
        .await
        .unwrap();
    f.service
        .queue_settings(
            &f.owner,
            project,
            &[("JWT_EXPIRY", "7200")],
            &reviewed.base,
            ctx(),
        )
        .await
        .unwrap();
    let seen = tracking(&f, project).await.seen();
    assert!(matches!(accept(seen).await, Err(ProvisionError::Busy)));
    run_all(&f).await;
    // The job recorded its own change, and the edit is still listed.
    let EnvTracking::Compared(changes) = tracking(&f, project).await else {
        panic!("the record should be readable");
    };
    assert_eq!(changes.changed, ["PGRST_DB_SCHEMAS"]);

    // A record under a key this server lacks is replaced.
    sqlx::query("UPDATE project_dokploy_env_records SET key_id = 'gone'")
        .execute(f.db.pool())
        .await
        .unwrap();
    let unreadable = tracking(&f, project).await;
    assert_eq!(unreadable, EnvTracking::Unreadable);
    accept(unreadable.seen()).await.unwrap();
    assert_ne!(record_key(&f, project).await, "gone");
    assert_eq!(
        tracking(&f, project).await,
        EnvTracking::Compared(EnvChanges::default())
    );

    // A stack without a record gets one.
    sqlx::query("DELETE FROM project_dokploy_env_records")
        .execute(f.db.pool())
        .await
        .unwrap();
    let missing = tracking(&f, project).await;
    assert_eq!(missing, EnvTracking::NotRecorded);
    accept(missing.seen()).await.unwrap();
    edit("EXTRA_FLAG=1\n", "");
    let EnvTracking::Compared(changes) = tracking(&f, project).await else {
        panic!("the record should be readable");
    };
    assert_eq!(changes.removed, ["EXTRA_FLAG"]);

    let audited = |outcome: &'static str| {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE action = 'stack.variables_accept' AND outcome = $1",
        )
        .bind(outcome)
        .fetch_one(f.db.pool())
    };
    assert_eq!(audited("success").await.unwrap(), 3);
    assert_eq!(audited("denied").await.unwrap(), 1);
}

/// A compose file like Dokploy's Supabase template: Studio, Auth, and a
/// Kong gateway.
const TEMPLATE_COMPOSE: &str = "services:\n  studio:\n    image: supabase/studio:2026.11.02\n  auth:\n    image: supabase/gotrue:v2.197.0\n  kong:\n    image: kong:2.8.1\n";
const STUDIO_PASSWORD_MARKER: &str = "studio-password-marker-adopt";

/// Adds a service made in Dokploy, not by the dashboard, and returns its
/// ID.
fn made_in_dokploy(f: &Fixture, name: &str, environment: &str, file: &str, env: &str) -> String {
    let mut state = f.compose.state.lock().unwrap();
    let compose_id = state.new_id("tpl");
    state.services.push(ComposeService {
        compose_id: compose_id.clone(),
        name: name.to_owned(),
        app_name: format!("{name}-xyz789"),
        environment_id: id(environment),
    });
    state
        .made_in_dokploy
        .push((compose_id.clone(), file.to_owned(), env.to_owned()));
    compose_id.as_str().to_owned()
}

fn template_env(keys: &StackSecrets) -> String {
    format!(
        "ANON_KEY={}\nSERVICE_ROLE_KEY={}\nDASHBOARD_USERNAME=supabase\nDASHBOARD_PASSWORD={STUDIO_PASSWORD_MARKER}\nPOSTGRES_PASSWORD=pw\n",
        keys.anon_key.expose_secret(),
        keys.service_role_key.expose_secret(),
    )
}

fn adopt_request<'a>(compose_id: &'a str, name: &'a str, copy_keys: bool) -> AdoptRequest<'a> {
    AdoptRequest {
        compose_id,
        name,
        api_url: "https://db.example.test",
        copy_keys,
    }
}

#[tokio::test]
async fn owners_adopt_supabase_services_from_allowed_environments() {
    let Some(scratch) = ScratchDb::create("provision_adopt").await else {
        return;
    };
    let f = setup(&scratch).await;
    let developer = account(&f.db, "Dev", false).await;
    add_member(&f.db, f.organization, &developer, OrgRole::Developer).await;
    let keys = StackSecrets::generate().unwrap();
    let env = template_env(&keys);
    let shop = made_in_dokploy(&f, "shop", "stacks", TEMPLATE_COMPOSE, &env);
    let blog = made_in_dokploy(
        &f,
        "blog",
        "stacks",
        "services:\n  web:\n    image: nginx:1\n",
        "",
    );
    let outside = made_in_dokploy(&f, "outside", "prod", TEMPLATE_COMPOSE, &env);
    let broken = made_in_dokploy(
        &f,
        "broken",
        "stacks",
        TEMPLATE_COMPOSE,
        &format!(
            "ANON_KEY={}\nSERVICE_ROLE_KEY={}\nDASHBOARD_USERNAME=supabase\n",
            keys.service_role_key.expose_secret(),
            keys.anon_key.expose_secret()
        ),
    );
    f.compose.state.lock().unwrap().domains = vec![ComposeDomain {
        domain_id: id("dom9"),
        host: "db.example.test".to_owned(),
        service_name: Some("kong".to_owned()),
        port: 8000,
        https: true,
    }];

    // Developers may neither list nor adopt.
    assert!(matches!(
        f.service.adoptable(&developer, f.organization).await,
        Err(ProvisionError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .adopt(
                &developer,
                f.organization,
                adopt_request(&shop, "Shop", true),
                ctx()
            )
            .await,
        Err(ProvisionError::Forbidden)
    ));

    // The default environment, shared by every organization without
    // targets, is not searched.
    assert_eq!(
        f.service.adoptable(&f.owner, f.organization).await.unwrap(),
        AdoptableServices::NoTarget
    );
    sqlx::query(
        "INSERT INTO dokploy_stack_targets \
         (id, organization_id, project_id, project_name, environment_id, environment_name) \
         VALUES ($1, $2, 'proj1', 'Infra', 'stacks', 'stacks')",
    )
    .bind(Uuid::now_v7())
    .bind(f.organization)
    .execute(f.db.pool())
    .await
    .unwrap();
    let AdoptableServices::Found {
        services,
        truncated,
        unavailable,
    } = f.service.adoptable(&f.owner, f.organization).await.unwrap()
    else {
        panic!("expected services");
    };
    let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["blog", "broken", "shop"]);
    assert_eq!(services[2].location, "Infra / stacks");
    assert!(!truncated && unavailable.is_empty());

    // A service outside the allowed environments is refused before its
    // variables are read.
    let reads = f.compose.state.lock().unwrap().count("compose_config");
    assert!(matches!(
        f.service
            .adoption_preview(&f.owner, f.organization, &outside)
            .await,
        Err(ProvisionError::AdoptionNotAllowed)
    ));
    assert!(matches!(
        f.service
            .adoption_preview(&f.owner, f.organization, "no such id!")
            .await,
        Err(ProvisionError::AdoptionNotAllowed)
    ));
    assert_eq!(
        f.compose.state.lock().unwrap().count("compose_config"),
        reads
    );

    let not_supabase = f
        .service
        .adoption_preview(&f.owner, f.organization, &blog)
        .await
        .unwrap();
    assert_eq!(not_supabase.refusal, Some(AdoptionRefusal::NotSupabase));
    assert!(matches!(
        f.service
            .adopt(
                &f.owner,
                f.organization,
                adopt_request(&blog, "Blog", false),
                ctx()
            )
            .await,
        Err(ProvisionError::NotAdoptable(AdoptionRefusal::NotSupabase))
    ));

    let preview = f
        .service
        .adoption_preview(&f.owner, f.organization, &shop)
        .await
        .unwrap();
    assert_eq!(preview.refusal, None);
    assert_eq!(preview.urls, ["https://db.example.test"]);
    assert_eq!(preview.suggested_name.as_deref(), Some("shop"));
    assert!(preview.keys.iter().all(|k| k.state == KeyState::Found));
    let shown = format!("{preview:?}");
    assert!(!shown.contains(keys.anon_key.expose_secret()));
    assert!(!shown.contains(STUDIO_PASSWORD_MARKER));

    let broken_keys = f
        .service
        .adoption_preview(&f.owner, f.organization, &broken)
        .await
        .unwrap()
        .keys;
    assert!(matches!(broken_keys[0].state, KeyState::Invalid(_)));
    assert!(matches!(broken_keys[1].state, KeyState::Invalid(_)));
    assert_eq!(broken_keys[2].state, KeyState::Missing);
    let shown = format!("{broken_keys:?}");
    assert!(!shown.contains(keys.anon_key.expose_secret()));
    assert!(!shown.contains(keys.service_role_key.expose_secret()));

    let mut elsewhere = adopt_request(&shop, "Shop", true);
    elsewhere.api_url = "https://evil.example.test";
    assert!(matches!(
        f.service
            .adopt(&f.owner, f.organization, elsewhere, ctx())
            .await,
        Err(ProvisionError::UrlNotOffered)
    ));

    // Adopting without copying the keys stores none.
    let without = f
        .service
        .adopt(
            &f.owner,
            f.organization,
            adopt_request(&broken, "Broken", true),
            ctx(),
        )
        .await
        .unwrap();
    assert_eq!(
        count(&f.db, "SELECT count(*) FROM project_credentials").await,
        0,
        "the broken service has no usable key"
    );
    let project = f
        .service
        .adopt(
            &f.owner,
            f.organization,
            adopt_request(&shop, "Shop", true),
            ctx(),
        )
        .await
        .unwrap();
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM project_credentials WHERE project_id = $1 ORDER BY kind",
    )
    .bind(project)
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert_eq!(kinds, ["anon_key", "service_role_key", "studio_login"]);
    let stored: Option<Uuid> =
        sqlx::query_scalar("SELECT job_id FROM project_dokploy_services WHERE project_id = $1")
            .bind(project)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(stored, None);

    // Adopting changes nothing in Dokploy, and the stack works like a
    // provisioned one: its service is read, and its variables are tracked.
    {
        let state = f.compose.state.lock().unwrap();
        for call in [
            "create_compose",
            "configure_compose",
            "update_compose_env",
            "deploy_compose",
            "create_compose_domain",
        ] {
            assert_eq!(state.count(call), 0, "{call}");
        }
    }
    assert!(matches!(
        f.service.deployment(&f.owner, project).await.unwrap(),
        StackDeploymentView::Found(_)
    ));
    assert_eq!(
        tracking(&f, project).await,
        EnvTracking::Compared(EnvChanges::default())
    );
    assert_ne!(without, project);

    // An adopted service is listed no more and cannot be adopted twice.
    let AdoptableServices::Found { services, .. } =
        f.service.adoptable(&f.owner, f.organization).await.unwrap()
    else {
        panic!("expected services");
    };
    let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["blog"]);
    assert!(matches!(
        f.service
            .adopt(
                &f.owner,
                f.organization,
                adopt_request(&shop, "Shop again", false),
                ctx()
            )
            .await,
        Err(ProvisionError::AlreadyAdopted)
    ));

    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM audit_events WHERE action = 'project.adopt' AND outcome = 'success'"
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM audit_events WHERE action = 'project.adopt' AND outcome = 'denied'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM audit_events WHERE action = 'project.adopt_keys'"
        )
        .await,
        1
    );
}
