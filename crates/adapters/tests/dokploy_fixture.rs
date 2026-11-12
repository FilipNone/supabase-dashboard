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
