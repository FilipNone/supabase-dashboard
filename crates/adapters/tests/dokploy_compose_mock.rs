//! Dokploy's compose, mount, deployment, and domain calls against an
//! in-process server that answers the way Dokploy v0.31.1 did on the test
//! fixture. `dokploy_fixture.rs` covers a real Dokploy.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use supabase_dashboard_adapters::{
    dokploy::{DokployClient, DokployError, DokploySettings},
    net::TargetPolicy,
};
use supabase_dashboard_domain::{
    dokploy::DokployUrl,
    dokploy_compose::{DeploymentStatus, NewCompose, NewComposeDomain},
    dokploy_placement::DokployId,
};

const GOOD_KEY: &str = "good-dokploy-key";

/// Requests the server saw, as (path, query, JSON body).
type Seen = Arc<Mutex<Vec<(String, Option<String>, Value)>>>;

fn json_response(value: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

async fn record(
    State(seen): State<Seen>,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: String,
) -> Response {
    if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let body: Value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap()
    };
    seen.lock()
        .unwrap()
        .push((uri.path().to_owned(), query, body.clone()));
    let env = "EN-1";
    let answer = match uri.path() {
        "/api/compose.search" => json!({
            "items": [
                {"composeId": "c-exact", "name": "sd-stack-1", "appName": "sd-stack-1-ab12cd",
                 "environmentId": env, "composeStatus": "idle"},
                // Dokploy matches names as substrings.
                {"composeId": "c-longer", "name": "sd-stack-10", "appName": "sd-stack-10-zz99aa",
                 "environmentId": env},
                {"composeId": "c-broken", "name": "sd-stack-1"},
            ],
            "total": 3,
        }),
        "/api/compose.create" => json!({
            "composeId": "c-new",
            "name": body["name"],
            "appName": format!("{}-j0unfi", body["appName"].as_str().unwrap()),
            "environmentId": body["environmentId"],
            "env": null,
            "composeFile": body["composeFile"],
            "sourceType": "raw",
        }),
        // The whole row comes back, variables included.
        "/api/compose.update" => json!({
            "composeId": body["composeId"],
            "env": body["env"],
            "composeFile": body["composeFile"],
        }),
        "/api/mounts.listByServiceId" => json!([
            {"mountId": "m-1", "type": "file", "filePath": "api/kong.yml", "content": "_format_version: '2.1'\n"},
            {"mountId": "m-2", "type": "volume", "volumeName": "data"},
        ]),
        "/api/mounts.create" => json!({
            "mountId": "m-new", "type": "file", "filePath": body["filePath"],
            "content": body["content"], "serviceType": "compose",
        }),
        // The mount as it was before the update.
        "/api/mounts.update" => json!({"mountId": "m-1", "type": "file", "content": "old"}),
        "/api/compose.deploy" => json!({
            "success": true, "message": "Deployment queued", "composeId": body["composeId"],
        }),
        "/api/deployment.allByCompose" => json!([
            {"deploymentId": "d-2", "title": "sd job 2", "status": "running", "errorMessage": null},
            {"deploymentId": "d-1", "title": "sd job 1", "status": "error", "errorMessage": null},
            {"deploymentId": "d-0", "title": null, "status": "queued"},
        ]),
        "/api/domain.byComposeId" => json!([
            {"domainId": "dm-1", "host": "api.shop.example.test", "serviceName": "envoy",
             "port": 8000, "https": true, "compose": {"composeId": "c-exact"}},
        ]),
        "/api/domain.create" => json!({
            "domainId": "dm-new", "host": body["host"], "serviceName": body["serviceName"],
            "port": body["port"], "https": body["https"], "certificateType": body["certificateType"],
        }),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    json_response(answer)
}

async fn serve() -> (DokployUrl, Seen) {
    let seen = Seen::default();
    let router = Router::new()
        .route("/api/{call}", get(record).post(record))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (DokployUrl::parse(&format!("http://{addr}")).unwrap(), seen)
}

fn client() -> DokployClient {
    DokployClient::new(DokploySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        ..DokploySettings::default()
    })
    .unwrap()
}

fn key() -> SecretString {
    SecretString::from(GOOD_KEY)
}

fn id(raw: &str) -> DokployId {
    DokployId::parse(raw).unwrap()
}

fn last(seen: &Seen) -> (String, Option<String>, Value) {
    seen.lock().unwrap().last().unwrap().clone()
}

#[tokio::test]
async fn a_service_is_found_by_its_exact_name_in_the_environment() {
    let (url, seen) = serve().await;
    let found = client()
        .find_compose(&url, &key(), &id("EN-1"), "sd-stack-1")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].compose_id.as_str(), "c-exact");
    assert_eq!(found[0].app_name, "sd-stack-1-ab12cd");
    let (path, query, _) = last(&seen);
    assert_eq!(path, "/api/compose.search");
    assert_eq!(
        query.as_deref(),
        Some("name=sd-stack-1&environmentId=EN-1&limit=100")
    );

    // A name with a search wildcard is refused before Dokploy is asked.
    let before = seen.lock().unwrap().len();
    assert_eq!(
        client()
            .find_compose(&url, &key(), &id("EN-1"), "sd_stack%")
            .await
            .unwrap_err(),
        DokployError::InvalidResponse
    );
    assert_eq!(seen.lock().unwrap().len(), before);
}

#[tokio::test]
async fn a_service_is_created_raw_on_the_chosen_server() {
    let (url, seen) = serve().await;
    let server = id("SV-1");
    let created = client()
        .create_compose(
            &url,
            &key(),
            &NewCompose {
                environment_id: &id("EN-1"),
                server_id: Some(&server),
                name: "sd-stack-2",
                description: "Dashboard project Shop",
                compose_file: "services: {}\n",
            },
        )
        .await
        .unwrap();
    assert_eq!(created.compose_id.as_str(), "c-new");
    assert_eq!(created.app_name, "sd-stack-2-j0unfi");
    let (_, query, body) = last(&seen);
    assert_eq!(query, None);
    assert_eq!(body["sourceType"], "raw");
    assert_eq!(body["composeType"], "docker-compose");
    assert_eq!(body["serverId"], "SV-1");
    assert_eq!(body["appName"], "sd-stack-2");
    assert_eq!(body["composeFile"], "services: {}\n");

    // Dokploy's own server: no serverId at all.
    client()
        .create_compose(
            &url,
            &key(),
            &NewCompose {
                environment_id: &id("EN-1"),
                server_id: None,
                name: "sd-stack-3",
                description: "",
                compose_file: "",
            },
        )
        .await
        .unwrap();
    assert!(last(&seen).2.get("serverId").is_none());
}

#[tokio::test]
async fn variables_are_set_with_isolated_deployment_and_never_with_a_reference() {
    let (url, seen) = serve().await;
    let compose = id("c-exact");
    client()
        .configure_compose(
            &url,
            &key(),
            &compose,
            "services: {}\n",
            &SecretString::from("POSTGRES_PASSWORD=0a1b\nJWT_SECRET=c2Vj\n"),
        )
        .await
        .unwrap();
    let (path, _, body) = last(&seen);
    assert_eq!(path, "/api/compose.update");
    assert_eq!(body["isolatedDeployment"], true);
    assert_eq!(body["sourceType"], "raw");
    assert_eq!(body["env"], "POSTGRES_PASSWORD=0a1b\nJWT_SECRET=c2Vj\n");

    // Dokploy leaves `${` unescaped, so such a value is refused here.
    let before = seen.lock().unwrap().len();
    assert!(
        client()
            .configure_compose(&url, &key(), &compose, "", &SecretString::from("A=${B}\n"))
            .await
            .is_err()
    );
    assert_eq!(seen.lock().unwrap().len(), before);
}

#[tokio::test]
async fn file_mounts_are_listed_created_and_updated() {
    let (url, seen) = serve().await;
    let compose = id("c-exact");
    let mounts = client().file_mounts(&url, &key(), &compose).await.unwrap();
    assert_eq!(mounts.len(), 1, "volume mounts are not file mounts");
    assert_eq!(mounts[0].file_path, "api/kong.yml");
    assert_eq!(
        last(&seen).1.as_deref(),
        Some("serviceId=c-exact&serviceType=compose")
    );

    let created = client()
        .create_file_mount(&url, &key(), &compose, "db/roles.sql", "select 1;\n")
        .await
        .unwrap();
    assert_eq!(created.mount_id.as_str(), "m-new");
    let (_, _, body) = last(&seen);
    assert_eq!(body["type"], "file");
    assert_eq!(body["serviceType"], "compose");
    assert_eq!(body["mountPath"], "/db/roles.sql");

    // A path leaving the files folder is refused before Dokploy is asked.
    let before = seen.lock().unwrap().len();
    assert!(
        client()
            .create_file_mount(&url, &key(), &compose, "../escape", "x")
            .await
            .is_err()
    );
    assert_eq!(seen.lock().unwrap().len(), before);

    client()
        .update_file_mount(&url, &key(), &id("m-1"), "new")
        .await
        .unwrap();
    assert_eq!(last(&seen).2, json!({"mountId": "m-1", "content": "new"}));
}

#[tokio::test]
async fn a_deployment_is_queued_with_a_title_and_found_by_it() {
    let (url, seen) = serve().await;
    let compose = id("c-exact");
    client()
        .deploy_compose(&url, &key(), &compose, "sd job 3")
        .await
        .unwrap();
    assert_eq!(
        last(&seen).2,
        json!({"composeId": "c-exact", "title": "sd job 3"})
    );
    let deployments = client().deployments(&url, &key(), &compose).await.unwrap();
    // An unknown status is skipped.
    assert_eq!(deployments.len(), 2);
    assert_eq!(deployments[0].title.as_deref(), Some("sd job 2"));
    assert_eq!(deployments[0].status, DeploymentStatus::Running);
    assert_eq!(deployments[1].status, DeploymentStatus::Error);
}

#[tokio::test]
async fn a_domain_is_routed_to_one_service_with_its_certificate() {
    let (url, seen) = serve().await;
    let compose = id("c-exact");
    let domains = client()
        .compose_domains(&url, &key(), &compose)
        .await
        .unwrap();
    assert_eq!(domains[0].service_name.as_deref(), Some("envoy"));
    assert_eq!(domains[0].port, 8000);

    let created = client()
        .create_compose_domain(
            &url,
            &key(),
            &compose,
            &NewComposeDomain {
                host: "api.shop.example.test",
                service_name: "envoy",
                port: 8000,
                https: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.domain_id.as_str(), "dm-new");
    let (_, _, body) = last(&seen);
    assert_eq!(body["domainType"], "compose");
    assert_eq!(body["certificateType"], "letsencrypt");
    assert_eq!(body["path"], "/");
}

#[tokio::test]
async fn a_refused_key_is_reported_as_such() {
    let (url, _) = serve().await;
    assert_eq!(
        client()
            .deployments(&url, &SecretString::from("wrong"), &id("c-exact"))
            .await
            .unwrap_err(),
        DokployError::KeyRejected
    );
}
