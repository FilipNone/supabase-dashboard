//! Dokploy client against the disposable Dokploy fixture
//! (`tests/fixtures/dokploy`). Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DOKPLOY_URL` is set, for example to
//! `http://127.0.0.1:54340`. The API key is the one the fixture's
//! `setup.sh` wrote to `tests/fixtures/dokploy/api-key`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use secrecy::SecretString;
use supabase_dashboard_adapters::{
    dokploy::{DokployClient, DokployError, DokploySettings},
    net::TargetPolicy,
};
use supabase_dashboard_domain::dokploy::{DokployUrl, TESTED_DOKPLOY_VERSION};

const ENV: &str = "SUPABASE_DASHBOARD_TEST_DOKPLOY_URL";

fn fixture_url() -> Option<DokployUrl> {
    match std::env::var(ENV) {
        Ok(raw) => Some(DokployUrl::parse(&raw).unwrap()),
        Err(_) => {
            eprintln!("skipping: {ENV} is not set");
            None
        }
    }
}

fn fixture_key() -> SecretString {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/dokploy/api-key"
    );
    let key = std::fs::read_to_string(path).expect("run tests/fixtures/dokploy/setup.sh first");
    SecretString::from(key.trim().to_owned())
}

/// The fixture binds to loopback.
fn client() -> DokployClient {
    DokployClient::new(DokploySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..DokploySettings::default()
    })
    .unwrap()
}

#[tokio::test]
async fn fixture_dokploy_reports_the_tested_version() {
    let Some(url) = fixture_url() else { return };
    let connection = client().connect(&url, &fixture_key()).await.unwrap();
    assert_eq!(connection.version, TESTED_DOKPLOY_VERSION);
}

#[tokio::test]
async fn fixture_dokploy_rejects_an_unknown_key() {
    let Some(url) = fixture_url() else { return };
    let wrong = SecretString::from("not-a-dokploy-key");
    assert_eq!(
        client().connect(&url, &wrong).await.unwrap_err(),
        DokployError::KeyRejected
    );
}

/// Calls a Dokploy mutation directly, to create synthetic records the
/// client only reads.
async fn post(url: &DokployUrl, call: &str, body: serde_json::Value) -> serde_json::Value {
    use secrecy::ExposeSecret;
    // reqwest is built without a default TLS provider; the fixture is
    // plain HTTP, but the client still needs one to build.
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let response = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .build()
        .unwrap()
        .post(url.api(call))
        .header("x-api-key", fixture_key().expose_secret())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{call}: {}",
        response.status()
    );
    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
}

#[tokio::test]
async fn fixture_dokploy_lists_the_service_behind_a_domain() {
    use supabase_dashboard_domain::dokploy_placement::DokployServiceKind;

    let Some(url) = fixture_url() else { return };
    // A unique host per run, so earlier runs' records do not match.
    let host = format!(
        "dashboard-{}.fixture.test",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let created = post(
        &url,
        "project.create",
        serde_json::json!({ "name": "placement-probe" }),
    )
    .await;
    let environment_id = created["environment"]["environmentId"].as_str().unwrap();
    let compose = post(
        &url,
        "compose.create",
        serde_json::json!({
            "name": "dashboard",
            "environmentId": environment_id,
            "composeType": "docker-compose",
        }),
    )
    .await;
    let compose_id = compose["composeId"].as_str().unwrap();
    post(
        &url,
        "domain.create",
        serde_json::json!({
            "host": host,
            "composeId": compose_id,
            "serviceName": "server",
            "port": 8080,
            "https": false,
            "certificateType": "none",
            "domainType": "compose",
        }),
    )
    .await;

    let inventory = client().inventory(&url, &fixture_key()).await.unwrap();
    let matches = inventory.services_serving(&host);
    assert_eq!(matches.len(), 1, "{inventory:?}");
    assert_eq!(matches[0].service.kind, DokployServiceKind::Compose);
    assert_eq!(matches[0].service.id.as_str(), compose_id);
    assert_eq!(matches[0].environment_id.as_str(), environment_id);
    assert_eq!(matches[0].project_name, "placement-probe");
    assert_eq!(matches[0].environment_name, "production");

    post(
        &url,
        "project.remove",
        serde_json::json!({ "projectId": created["project"]["projectId"] }),
    )
    .await;
}

#[tokio::test]
async fn fixture_dokploy_lists_environments_and_servers_and_creates_an_environment() {
    use supabase_dashboard_domain::dokploy_placement::DokployId;

    let Some(url) = fixture_url() else { return };
    let created = post(
        &url,
        "project.create",
        serde_json::json!({ "name": "targets-probe" }),
    )
    .await;
    let project_id = DokployId::parse(created["project"]["projectId"].as_str().unwrap()).unwrap();
    // A server record on a documentation address; Dokploy stores it
    // without connecting, and nothing is ever deployed to it.
    let server = post(
        &url,
        "server.create",
        serde_json::json!({
            "name": "targets-probe-server",
            "description": null,
            "ipAddress": "192.0.2.10",
            "port": 22,
            "username": "root",
            "sshKeyId": null,
            "serverType": "deploy",
        }),
    )
    .await;
    let server_id = server["serverId"].as_str().unwrap().to_owned();

    let key = fixture_key();
    let environment_id = client()
        .create_environment(&url, &key, &project_id, "stacks")
        .await
        .unwrap();
    let targets = client().targets(&url, &key).await.unwrap();
    let mine: Vec<_> = targets
        .environments
        .iter()
        .filter(|env| env.project_id == project_id)
        .collect();
    assert_eq!(mine.len(), 2, "{targets:?}");
    assert!(
        mine.iter()
            .any(|env| env.environment_name == "production" && env.is_default)
    );
    assert!(mine.iter().any(|env| env.environment_id == environment_id
        && env.environment_name == "stacks"
        && !env.is_default
        && env.project_name == "targets-probe"));
    let servers = targets.servers.as_ref().unwrap();
    assert!(
        servers
            .iter()
            .any(|s| s.id.as_str() == server_id && s.name == "targets-probe-server"),
        "{servers:?}"
    );

    // A project that does not exist is Dokploy's 404, not a new record.
    assert_eq!(
        client()
            .create_environment(&url, &key, &DokployId::parse("missing").unwrap(), "x")
            .await
            .unwrap_err(),
        DokployError::Http(404)
    );

    post(
        &url,
        "server.remove",
        serde_json::json!({ "serverId": server_id }),
    )
    .await;
    post(
        &url,
        "project.remove",
        serde_json::json!({ "projectId": project_id.as_str() }),
    )
    .await;
}

/// The calls a provisioning job makes, end to end on the fixture: a raw
/// compose service with a variable and a mounted file, a domain, and a
/// real deployment of a small public image.
#[tokio::test]
async fn fixture_dokploy_creates_configures_and_deploys_a_compose_service() {
    use std::time::Duration;
    use supabase_dashboard_domain::{
        dokploy_compose::{ComposeStatus, DeploymentStatus, NewCompose, NewComposeDomain},
        dokploy_placement::DokployId,
    };

    let Some(url) = fixture_url() else { return };
    let created = post(
        &url,
        "project.create",
        serde_json::json!({ "name": "compose-probe" }),
    )
    .await;
    let project_id = created["project"]["projectId"].as_str().unwrap().to_owned();
    let environment =
        DokployId::parse(created["environment"]["environmentId"].as_str().unwrap()).unwrap();
    let key = fixture_key();
    let client = client();
    let name = "sd-compose-probe";
    let compose_file = "services:\n  whoami:\n    image: traefik/whoami:v1.10.3\n    \
                        environment:\n      GREETING: ${GREETING}\n    \
                        volumes:\n      - ../files/probe/hello.txt:/hello.txt:ro\n";

    assert!(
        client
            .find_compose(&url, &key, &environment, name)
            .await
            .unwrap()
            .is_empty()
    );
    let service = client
        .create_compose(
            &url,
            &key,
            &NewCompose {
                environment_id: &environment,
                server_id: None,
                name,
                description: "Synthetic compose probe",
                compose_file,
            },
        )
        .await
        .unwrap();
    assert!(service.app_name.starts_with("sd-compose-probe-"));
    // Found again by name, as a job resumed after a lost answer would.
    let found = client
        .find_compose(&url, &key, &environment, name)
        .await
        .unwrap();
    assert_eq!(found, vec![service.clone()]);

    let compose = service.compose_id.clone();
    client
        .configure_compose(
            &url,
            &key,
            &compose,
            compose_file,
            &SecretString::from("GREETING=hello-synthetic\n"),
        )
        .await
        .unwrap();
    let mount = client
        .create_file_mount(&url, &key, &compose, "probe/hello.txt", "first\n")
        .await
        .unwrap();
    client
        .update_file_mount(&url, &key, &mount.mount_id, "second\n")
        .await
        .unwrap();
    let mounts = client.file_mounts(&url, &key, &compose).await.unwrap();
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].content, "second\n");

    let domain = client
        .create_compose_domain(
            &url,
            &key,
            &compose,
            &NewComposeDomain {
                host: "probe.example.test",
                service_name: "whoami",
                port: 80,
                https: false,
            },
        )
        .await
        .unwrap();
    let domains = client.compose_domains(&url, &key, &compose).await.unwrap();
    assert_eq!(domains, vec![domain]);

    client
        .deploy_compose(&url, &key, &compose, "sd compose probe 1")
        .await
        .unwrap();
    let mut status = None;
    for _ in 0..120 {
        let deployments = client.deployments(&url, &key, &compose).await.unwrap();
        status = deployments
            .iter()
            .find(|d| d.title.as_deref() == Some("sd compose probe 1"))
            .map(|d| d.status);
        if status.is_some_and(DeploymentStatus::is_finished) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(status, Some(DeploymentStatus::Done));

    // The service's place and history, as the project overview reads them.
    let details = client
        .compose_details(&url, &key, &compose)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(details.name, name);
    assert_eq!(details.app_name, service.app_name);
    assert_eq!(
        details.description.as_deref(),
        Some("Synthetic compose probe")
    );
    assert_eq!(details.status, Some(ComposeStatus::Done));
    assert_eq!(details.environment_id, environment);
    assert_eq!(details.project_id.as_str(), project_id);
    assert_eq!(details.project_name, "compose-probe");
    assert_eq!(details.server_id, None);
    let run = &details.deployments[0];
    assert_eq!(run.title.as_deref(), Some("sd compose probe 1"));
    assert_eq!(run.status, DeploymentStatus::Done);
    assert!(run.created_at.is_some() && run.finished_at >= run.created_at);
    let made_up = DokployId::parse("noSuchCompose1").unwrap();
    assert_eq!(
        client.compose_details(&url, &key, &made_up).await.unwrap(),
        None
    );

    post(
        &url,
        "compose.delete",
        serde_json::json!({ "composeId": compose.as_str(), "deleteVolumes": true }),
    )
    .await;
    assert_eq!(
        client.compose_details(&url, &key, &compose).await.unwrap(),
        None
    );
    post(
        &url,
        "project.remove",
        serde_json::json!({ "projectId": project_id }),
    )
    .await;
}

/// The pinned Supabase stack, deployed through the fixture with its
/// mounted files and generated variables. Dokploy reports the deployment
/// done only once every service the gateway depends on is healthy. Pulls
/// about ten images into the fixture's Docker, so it is opt-in:
/// `cargo test -p supabase-dashboard-adapters --test dokploy_fixture -- --ignored`.
#[tokio::test]
#[ignore = "deploys a whole Supabase stack into the Dokploy fixture"]
async fn fixture_dokploy_deploys_the_pinned_supabase_stack() {
    use std::time::Duration;
    use supabase_dashboard_application::{
        stack_secrets::StackSecrets,
        stack_template::{COMPOSE_FILE, GATEWAY_PORT, GATEWAY_SERVICE, STACK_FILES, stack_env},
    };
    use supabase_dashboard_domain::{
        dokploy_compose::{DeploymentStatus, NewCompose, NewComposeDomain},
        dokploy_placement::DokployId,
    };

    let Some(url) = fixture_url() else { return };
    let created = post(
        &url,
        "project.create",
        serde_json::json!({ "name": "stack-probe" }),
    )
    .await;
    let project_id = created["project"]["projectId"].as_str().unwrap().to_owned();
    let environment =
        DokployId::parse(created["environment"]["environmentId"].as_str().unwrap()).unwrap();
    let key = fixture_key();
    let client = client();
    let service = client
        .create_compose(
            &url,
            &key,
            &NewCompose {
                environment_id: &environment,
                server_id: None,
                name: "sd-stack-probe",
                description: "Synthetic Supabase stack probe",
                compose_file: COMPOSE_FILE,
            },
        )
        .await
        .unwrap();
    let compose = service.compose_id.clone();
    let secrets = StackSecrets::generate().unwrap();
    let env = stack_env(&secrets, "http://stack-probe.example.test").unwrap();
    client
        .configure_compose(&url, &key, &compose, COMPOSE_FILE, &env)
        .await
        .unwrap();
    for file in STACK_FILES {
        client
            .create_file_mount(&url, &key, &compose, file.path, file.content)
            .await
            .unwrap();
    }
    client
        .create_compose_domain(
            &url,
            &key,
            &compose,
            &NewComposeDomain {
                host: "stack-probe.example.test",
                service_name: GATEWAY_SERVICE,
                port: GATEWAY_PORT,
                https: false,
            },
        )
        .await
        .unwrap();
    client
        .deploy_compose(&url, &key, &compose, "sd stack probe 1")
        .await
        .unwrap();
    let mut status = None;
    for _ in 0..600 {
        let deployments = client.deployments(&url, &key, &compose).await.unwrap();
        status = deployments
            .iter()
            .find(|d| d.title.as_deref() == Some("sd stack probe 1"))
            .map(|d| d.status);
        if status.is_some_and(DeploymentStatus::is_finished) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    eprintln!("app name: {}", service.app_name);
    if std::env::var_os("SUPABASE_DASHBOARD_TEST_KEEP_STACK").is_none() {
        post(
            &url,
            "compose.delete",
            serde_json::json!({ "composeId": compose.as_str(), "deleteVolumes": true }),
        )
        .await;
        post(
            &url,
            "project.remove",
            serde_json::json!({ "projectId": project_id }),
        )
        .await;
    }
    assert_eq!(status, Some(DeploymentStatus::Done));
}
