//! Dokploy client against an in-process server that imitates Dokploy's
//! API. `dokploy_fixture.rs` covers a real Dokploy.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::{
    Router,
    extract::RawQuery,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    dokploy::{DokployClient, DokployError, DokploySettings},
    net::TargetPolicy,
};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    dokploy::{DokployUrl, DokployVersion, TESTED_DOKPLOY_VERSION},
};

const GOOD_KEY: &str = "good-dokploy-key";
const VERSION_PATH: &str = "/api/settings.getDokployVersion";

async fn serve(router: Router) -> DokployUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    DokployUrl::parse(&format!("http://{addr}")).unwrap()
}

/// Answers the version call the way Dokploy does: 401 without a valid
/// key, otherwise `answer` as JSON.
fn dokploy(answer: &'static str) -> Router {
    Router::new().route(
        VERSION_PATH,
        get(
            move |headers: HeaderMap, RawQuery(query): RawQuery| async move {
                assert_eq!(query, None, "nothing goes in the query string");
                if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
                    return (StatusCode::UNAUTHORIZED, r#"{"message":"Unauthorized"}"#)
                        .into_response();
                }
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    answer,
                )
                    .into_response()
            },
        ),
    )
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

fn key(raw: &str) -> SecretString {
    SecretString::from(raw.to_owned())
}

#[tokio::test]
async fn a_supported_version_connects() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let connection = client().connect(&url, &key(GOOD_KEY)).await.unwrap();
    assert_eq!(connection.version, TESTED_DOKPLOY_VERSION);
}

#[tokio::test]
async fn another_minor_release_is_refused_with_its_version() {
    let url = serve(dokploy(r#""v0.32.0""#)).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(
        err,
        DokployError::UnsupportedVersion {
            found: DokployVersion::parse("v0.32.0").unwrap()
        }
    );
    assert_eq!(
        err.to_string(),
        "Dokploy v0.32.0 is not supported. This dashboard works with Dokploy v0.31.x, tested with v0.31.1."
    );
    // The version itself is still readable, for diagnostics.
    let version = client().version(&url, &key(GOOD_KEY)).await.unwrap();
    assert_eq!(version.to_string(), "v0.32.0");
}

#[tokio::test]
async fn a_wrong_key_is_rejected() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let err = client().connect(&url, &key("wrong")).await.unwrap_err();
    assert_eq!(err, DokployError::KeyRejected);
}

#[tokio::test]
async fn unreadable_versions_are_invalid_responses() {
    for answer in [r#""canary""#, r#"{"version":"v0.31.1"}"#, "v0.31.1", ""] {
        let url = serve(dokploy(answer)).await;
        let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
        assert_eq!(err, DokployError::InvalidResponse, "{answer:?}");
    }
}

#[tokio::test]
async fn oversized_answers_are_not_read() {
    let big: &'static str = Box::leak(format!("\"{}\"", "1".repeat(8 * 1024)).into_boxed_str());
    let url = serve(dokploy(big)).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::InvalidResponse);
}

#[tokio::test]
async fn errors_and_redirects_are_reported_not_followed() {
    let router = Router::new()
        .route(
            VERSION_PATH,
            get(|| async { Redirect::temporary("http://169.254.169.254/latest") }),
        )
        .route(
            "/other/api/settings.getDokployVersion",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
    let url = serve(router).await;
    let err = client().connect(&url, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::Http(307));

    let other = DokployUrl::parse(&format!("{}/other", url.as_str())).unwrap();
    let err = client().connect(&other, &key(GOOD_KEY)).await.unwrap_err();
    assert_eq!(err, DokployError::Http(500));
}

#[tokio::test]
async fn refused_destinations_are_not_contacted() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let strict = DokployClient::new(DokploySettings::default()).unwrap();
    assert_eq!(
        strict.connect(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
    let named = DokployUrl::parse("http://localhost:9").unwrap();
    assert_eq!(
        strict.connect(&named, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
    let metadata = DokployUrl::parse("http://169.254.169.254").unwrap();
    assert_eq!(
        strict.connect(&metadata, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
}

#[tokio::test]
async fn only_the_enrolled_url_may_be_on_loopback() {
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let other = serve(dokploy(r#""v0.31.1""#)).await;
    let enrolled = DokployClient::new(DokploySettings {
        enrolled_url: Some(url.clone()),
        ..DokploySettings::default()
    })
    .unwrap();
    assert_eq!(
        enrolled
            .connect(&url, &key(GOOD_KEY))
            .await
            .unwrap()
            .version,
        TESTED_DOKPLOY_VERSION
    );
    // Another port on the same loopback address is not enrolled.
    assert_eq!(
        enrolled.connect(&other, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
    // Enrolling loopback does not open metadata addresses.
    let metadata = DokployUrl::parse("http://169.254.169.254").unwrap();
    let enrolled_metadata = DokployClient::new(DokploySettings {
        enrolled_url: Some(metadata.clone()),
        connect_timeout: Duration::from_secs(1),
        ..DokploySettings::default()
    })
    .unwrap();
    assert_eq!(
        enrolled_metadata
            .connect(&metadata, &key(GOOD_KEY))
            .await
            .unwrap_err(),
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed)
    );
}

#[tokio::test]
async fn a_closed_port_is_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = DokployUrl::parse(&format!("http://{addr}")).unwrap();
    assert_eq!(
        client().connect(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Unreachable(UnreachableReason::Connect)
    );
}

#[tokio::test]
async fn errors_never_carry_the_key() {
    let secret = "sk-dokploy-must-not-leak";
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    let err = client().connect(&url, &key(secret)).await.unwrap_err();
    assert!(!err.to_string().contains(secret));
    assert!(!format!("{err:?}").contains(secret));
    // A key that cannot be a header value is refused without a request.
    let err = client().connect(&url, &key("bad\nkey")).await.unwrap_err();
    assert_eq!(err, DokployError::KeyRejected);
}

#[tokio::test]
async fn the_application_connector_reports_the_version_or_the_refusal() {
    // A trait object, as the server holds it.
    let connector = DokployClient::shared(DokploySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..DokploySettings::default()
    })
    .unwrap();
    let url = serve(dokploy(r#""v0.31.1""#)).await;
    assert_eq!(
        connector.connect(&url, &key(GOOD_KEY)).await.unwrap(),
        TESTED_DOKPLOY_VERSION
    );
    assert_eq!(
        connector.connect(&url, &key("wrong")).await.unwrap_err(),
        DokployError::KeyRejected
    );
    let newer = serve(dokploy(r#""v0.32.0""#)).await;
    assert!(matches!(
        connector.connect(&newer, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::UnsupportedVersion { .. }
    ));
}

/// Serves `services` and `domains` as Dokploy's overview calls, behind the
/// key check.
fn overview(services: String, domains: String) -> Router {
    let answer = |body: String| {
        move |headers: HeaderMap| {
            let body = body.clone();
            async move {
                if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response()
            }
        }
    };
    Router::new()
        .route("/api/overview.services", get(answer(services)))
        .route("/api/overview.domains", get(answer(domains)))
}

/// Entries shaped like Dokploy v0.31.1's `overview.services`.
const SERVICES: &str = r#"[
  {"id":"xR0PpmF7yhLc7UYgqcPjo","name":"dash-app","appName":"app-x","status":"idle",
   "createdAt":"2026-11-12T21:33:18.220Z","serverId":null,"serverName":null,
   "projectId":"DFLuZTBRvbt4IvItevQcM","projectName":"probe","environmentId":"35--oTNsDM0g3O_k9V72j",
   "environmentName":"production","icon":null,"type":"application","lastDeployAt":null},
  {"id":"_IK3e1y1IwxNCLnlLGXEZ","name":"dashboard","appName":"compose-y","status":"idle",
   "serverId":"srv1","serverName":"edge-1",
   "projectId":"DFLuZTBRvbt4IvItevQcM","projectName":"probe","environmentId":"35--oTNsDM0g3O_k9V72j",
   "environmentName":"production","type":"compose"},
  {"id":"pg1","name":"db","projectId":"p","projectName":"p","environmentId":"e",
   "environmentName":"e","type":"postgres"},
  {"id":"bad id","name":"x","projectId":"p","projectName":"p","environmentId":"e",
   "environmentName":"e","type":"compose"},
  {"unexpected":"shape"}
]"#;

const DOMAINS: &str = r#"[
  {"domainId":"Swpf98Az7OrNWOxy1N0BN","host":"Dashboard.Example.Test","path":"/","port":8080,
   "https":true,"enabled":true,"domainType":"compose","serviceOwnerId":"_IK3e1y1IwxNCLnlLGXEZ",
   "serviceOwnerType":"compose","serviceName":"dashboard","projectId":"DFLuZTBRvbt4IvItevQcM",
   "projectName":"probe","environmentId":"35--oTNsDM0g3O_k9V72j","environmentName":"production"},
  {"host":"pr-1.example.test","enabled":true,"domainType":"preview",
   "serviceOwnerId":"xR0PpmF7yhLc7UYgqcPjo","serviceOwnerType":"application"},
  {"host":"off.example.test","enabled":false,"domainType":"application",
   "serviceOwnerId":"xR0PpmF7yhLc7UYgqcPjo","serviceOwnerType":"application"},
  {"host":"","enabled":true,"domainType":"compose",
   "serviceOwnerId":"_IK3e1y1IwxNCLnlLGXEZ","serviceOwnerType":"compose"}
]"#;

#[tokio::test]
async fn the_inventory_keeps_application_and_compose_services_and_their_domains() {
    use supabase_dashboard_domain::dokploy_placement::DokployServiceKind;

    let url = serve(overview(SERVICES.to_owned(), DOMAINS.to_owned())).await;
    let inventory = client().inventory(&url, &key(GOOD_KEY)).await.unwrap();
    let kinds: Vec<_> = inventory
        .services
        .iter()
        .map(|info| (info.service.kind, info.service.id.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            (DokployServiceKind::Application, "xR0PpmF7yhLc7UYgqcPjo"),
            (DokployServiceKind::Compose, "_IK3e1y1IwxNCLnlLGXEZ"),
        ]
    );
    assert_eq!(inventory.services[1].server_name.as_deref(), Some("edge-1"));
    assert_eq!(inventory.services[1].environment_name, "production");

    // The empty host is dropped; hosts are lowercased; preview and
    // disabled domains are kept but marked.
    assert_eq!(inventory.domains.len(), 3);
    assert_eq!(inventory.domains[0].host, "dashboard.example.test");
    assert!(inventory.domains[1].preview);
    assert!(!inventory.domains[2].enabled);
    let matches = inventory.services_serving("dashboard.example.test");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "dashboard");

    assert_eq!(
        client().inventory(&url, &key("wrong")).await.unwrap_err(),
        DokployError::KeyRejected
    );
}

#[tokio::test]
async fn an_inventory_that_is_not_a_list_or_too_large_is_refused() {
    let url = serve(overview(r#"{"items":[]}"#.to_owned(), "[]".to_owned())).await;
    assert_eq!(
        client().inventory(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::InvalidResponse
    );

    // Over the 4 MiB list bound.
    let entry = r#"{"id":"a","name":"n","projectId":"p","projectName":"p","environmentId":"e","environmentName":"e","type":"compose"},"#;
    let mut huge = String::from("[");
    while huge.len() <= 4 * 1024 * 1024 {
        huge.push_str(entry);
    }
    huge.push_str(r#"{"id":"b"}]"#);
    let url = serve(overview(huge, "[]".to_owned())).await;
    assert_eq!(
        client().inventory(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::InvalidResponse
    );
}

/// Entries shaped like Dokploy v0.31.1's `project.all`.
const PROJECTS: &str = r#"[
  {"projectId":"QlbI3adcGw0aceVUvZHIu","name":"Infra","description":null,"env":"",
   "organizationId":"o","environments":[
     {"name":"production","environmentId":"OYAGyOPBPVVsxJOj5jGOX","isDefault":true,
      "applications":[],"compose":[{"composeId":"c1","name":"x","composeStatus":"idle"}]},
     {"name":"stacks","environmentId":"2EzIU5fQhBLtL1YVZ4zLP","isDefault":false},
     {"name":"bad","environmentId":"bad id"},
     {"unexpected":"shape"}
   ],"projectTags":[]},
  {"projectId":"bad id","name":"Skipped","environments":[
     {"name":"production","environmentId":"e1","isDefault":true}]},
  {"unexpected":"shape"}
]"#;

/// Entries shaped like Dokploy v0.31.1's `server.all`.
const SERVERS: &str = r#"[
  {"serverId":"FrFq15ucKbuYbI3kSEpRS","name":"edge-1","ipAddress":"192.0.2.10",
   "serverStatus":"active","serverType":"deploy",
   "metricsConfig":{"server":{"token":"metrics-token-marker"}}},
  {"serverId":"b1","name":"builder","serverStatus":"active","serverType":"build"},
  {"serverId":"i1","name":"off","serverStatus":"inactive","serverType":"deploy"},
  {"serverId":"bad id","name":"x","serverStatus":"active","serverType":"deploy"}
]"#;

fn projects_and_servers(servers: StatusCode) -> Router {
    let checked = |status: StatusCode, body: &'static str| {
        move |headers: HeaderMap| async move {
            if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
    };
    Router::new()
        .route("/api/project.all", get(checked(StatusCode::OK, PROJECTS)))
        .route("/api/server.all", get(checked(servers, SERVERS)))
}

#[tokio::test]
async fn targets_keep_valid_environments_and_active_deploy_servers() {
    let url = serve(projects_and_servers(StatusCode::OK)).await;
    let targets = client().targets(&url, &key(GOOD_KEY)).await.unwrap();
    let envs: Vec<(&str, &str, &str, bool)> = targets
        .environments
        .iter()
        .map(|env| {
            (
                env.project_name.as_str(),
                env.environment_id.as_str(),
                env.environment_name.as_str(),
                env.is_default,
            )
        })
        .collect();
    assert_eq!(
        envs,
        [
            ("Infra", "OYAGyOPBPVVsxJOj5jGOX", "production", true),
            ("Infra", "2EzIU5fQhBLtL1YVZ4zLP", "stacks", false),
        ]
    );
    let servers = targets.servers.unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].id.as_str(), "FrFq15ucKbuYbI3kSEpRS");
    assert_eq!(servers[0].name, "edge-1");
    // Nothing else from the server entry is kept.
    assert!(!format!("{servers:?}").contains("metrics-token-marker"));

    assert_eq!(
        client().targets(&url, &key("wrong")).await.unwrap_err(),
        DokployError::KeyRejected
    );
}

#[tokio::test]
async fn a_key_that_may_not_list_servers_still_lists_environments() {
    let url = serve(projects_and_servers(StatusCode::FORBIDDEN)).await;
    let targets = client().targets(&url, &key(GOOD_KEY)).await.unwrap();
    assert_eq!(targets.environments.len(), 2);
    assert_eq!(targets.servers, None);

    let url = serve(projects_and_servers(StatusCode::INTERNAL_SERVER_ERROR)).await;
    assert_eq!(
        client().targets(&url, &key(GOOD_KEY)).await.unwrap_err(),
        DokployError::Http(500)
    );
}

#[tokio::test]
async fn creating_an_environment_posts_its_name_and_project() {
    use supabase_dashboard_domain::dokploy_placement::DokployId;

    let router = Router::new().route(
        "/api/environment.create",
        post(
            |headers: HeaderMap, RawQuery(query): RawQuery, body: String| async move {
                assert_eq!(query, None, "nothing goes in the query string");
                assert_eq!(
                    headers.get(header::CONTENT_TYPE).unwrap(),
                    "application/json"
                );
                if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(GOOD_KEY) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
                let project = sent["projectId"].as_str().unwrap();
                assert_eq!(sent["name"], "staging");
                // Answers for another project when asked for `other`.
                let answered = if project == "other" { "p9" } else { project };
                let answer = serde_json::json!({
                    "environmentId": "Gr8jX76uotrD6gnwzCmtY",
                    "name": "staging",
                    "projectId": answered,
                    "isDefault": false,
                });
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    answer.to_string(),
                )
                    .into_response()
            },
        ),
    );
    let url = serve(router).await;
    let project = DokployId::parse("QlbI3adcGw0aceVUvZHIu").unwrap();
    let created = client()
        .create_environment(&url, &key(GOOD_KEY), &project, "staging")
        .await
        .unwrap();
    assert_eq!(created.as_str(), "Gr8jX76uotrD6gnwzCmtY");
    assert_eq!(
        client()
            .create_environment(
                &url,
                &key(GOOD_KEY),
                &DokployId::parse("other").unwrap(),
                "staging"
            )
            .await
            .unwrap_err(),
        DokployError::InvalidResponse
    );
    assert_eq!(
        client()
            .create_environment(&url, &key("wrong"), &project, "staging")
            .await
            .unwrap_err(),
        DokployError::KeyRejected
    );
}
