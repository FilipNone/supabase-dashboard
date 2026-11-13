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
    provisioning::{
        ComposeApi, DokployFuture, ProvisionError, ProvisionRequest, ProvisionStackHandler,
        ProvisionTimings, ProvisioningService, StackActionHandler,
    },
    secrets::CredentialCipher,
    stack_template::{GATEWAY_PORT, GATEWAY_SERVICE, STACK_FILES},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
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
    job::JobState,
    project::ProjectUrl,
    provisioning::{
        ProvisionStep, ProvisionTargets, StackAction, StackDeploymentView, TargetChoice,
    },
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
        StackActionHandler::new(db.clone(), dokploy.clone(), compose.clone()).with_timings(timings),
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
