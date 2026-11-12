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
