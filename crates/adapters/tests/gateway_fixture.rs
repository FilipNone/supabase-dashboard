//! Gateway probe against the disposable Supabase fixture's Kong gateway
//! (`tests/fixtures/supabase`). Skipped unless
//! `SUPABASE_DASHBOARD_TEST_FIXTURE_URL` is set, for example to
//! `http://127.0.0.1:54321`. Keys come from the fixture's env file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
    connection::{ServiceStatus, StackService},
    project::ProjectUrl,
};

const ENV: &str = "SUPABASE_DASHBOARD_TEST_FIXTURE_URL";

fn fixture_value(name: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/supabase/fixture.env"
    );
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} missing from fixture.env"))
        .to_owned()
}

#[tokio::test]
async fn fixture_gateway_reports_auth_and_rest() {
    let Ok(raw) = std::env::var(ENV) else {
        eprintln!("skipping: {ENV} is not set");
        return;
    };
    let url = ProjectUrl::parse(&raw).unwrap();
    let probe = GatewayProbe::new(GatewaySettings {
        // The fixture binds to loopback.
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..GatewaySettings::default()
    })
    .unwrap();
    let anon = SecretString::from(fixture_value("ANON_KEY"));
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));

    let auth = probe.check(&url, StackService::Auth, &anon).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));

    // Upstream limits the PostgREST root to the service role.
    let rest = probe.check(&url, StackService::Rest, &service).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    let rest_anon = probe.check(&url, StackService::Rest, &anon).await;
    assert_eq!(
        rest_anon.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );

    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe.check(&url, StackService::Auth, &wrong).await.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_meta_lists_structure() {
    use supabase_dashboard_application::schema::SchemaSource;
    use supabase_dashboard_domain::schema::{IdentityGeneration, MetaUnavailable, SchemaName};

    let Ok(raw) = std::env::var(ENV) else {
        eprintln!("skipping: {ENV} is not set");
        return;
    };
    let url = ProjectUrl::parse(&raw).unwrap();
    let probe = GatewayProbe::new(GatewaySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..GatewaySettings::default()
    })
    .unwrap();
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));
    let anon = SecretString::from(fixture_value("ANON_KEY"));

    let schemas = probe.schemas(&url, &service).await.unwrap();
    let names: Vec<_> = schemas.schemas.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"public") && names.contains(&"auth"),
        "{names:?}"
    );
    assert!(names.windows(2).all(|w| w[0] <= w[1]), "sorted: {names:?}");
    assert!(!schemas.truncated);

    // The gateway limits /pg/ to the service role.
    assert_eq!(
        probe.schemas(&url, &anon).await.unwrap_err(),
        MetaUnavailable::KeyRejected { http_status: 403 }
    );

    let public = SchemaName::parse("public").unwrap();
    let tables = probe.tables(&url, &service, &public).await.unwrap();
    let names: Vec<_> = tables.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["tags", "todos"]);
    let todos = &tables.tables[1];
    assert!(todos.rls_enabled);
    assert_eq!(todos.comment.as_deref(), Some("Synthetic fixture table"));

    let detail = probe
        .table(&url, &service, todos.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.primary_key, ["id"]);
    let columns: Vec<_> = detail.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        columns,
        ["id", "title", "status", "slug", "note", "created_at"]
    );
    assert_eq!(
        detail.columns[0].identity,
        Some(IdentityGeneration::ByDefault)
    );
    assert_eq!(detail.columns[1].comment.as_deref(), Some("What to do"));
    assert_eq!(detail.columns[2].enum_labels, ["open", "done"]);
    assert!(detail.columns[3].unique);
    assert!(detail.columns[4].nullable);

    let tags = &tables.tables[0];
    let detail = probe.table(&url, &service, tags.id).await.unwrap().unwrap();
    assert_eq!(detail.primary_key, ["todo_id", "label"]);

    // postgres-meta's own 404 means no such table.
    assert_eq!(probe.table(&url, &service, u32::MAX).await.unwrap(), None);
}
