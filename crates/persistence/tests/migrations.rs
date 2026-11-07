//! Runs against a disposable PostgreSQL database named by
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL`. Each test creates and drops its
//! own database, so the server only needs CREATEDB permission. Without the
//! variable the tests are skipped with a message.

use std::time::Duration;

use secrecy::SecretString;
// Database names below are built only from a fixed label and the process
// ID, never from external input.
use sqlx::{AssertSqlSafe, Connection, PgConnection};
use supabase_dashboard_persistence::{Database, DatabaseSettings};

const ENV: &str = "SUPABASE_DASHBOARD_TEST_DATABASE_URL";

struct ScratchDb {
    admin_url: String,
    name: String,
    settings: DatabaseSettings,
}

impl ScratchDb {
    async fn create(label: &str) -> Option<Self> {
        let Ok(admin_url) = std::env::var(ENV) else {
            eprintln!("skipping: {ENV} is not set");
            return None;
        };
        let name = format!("sd_test_{label}_{}", std::process::id());
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        sqlx::query(AssertSqlSafe(format!(
            r#"DROP DATABASE IF EXISTS "{name}""#
        )))
        .execute(&mut admin)
        .await
        .unwrap();
        sqlx::query(AssertSqlSafe(format!(r#"CREATE DATABASE "{name}""#)))
            .execute(&mut admin)
            .await
            .unwrap();

        let settings = DatabaseSettings {
            url: SecretString::from(url_with_database(&admin_url, &name)),
            max_connections: 2,
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(5),
        };
        Some(Self {
            admin_url,
            name,
            settings,
        })
    }

    async fn drop(self) {
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        sqlx::query(AssertSqlSafe(format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            self.name
        )))
        .execute(&mut admin)
        .await
        .unwrap();
    }
}

fn url_with_database(url: &str, database: &str) -> String {
    let (base, _) = url.rsplit_once('/').unwrap();
    format!("{base}/{database}")
}

#[tokio::test]
async fn migrations_apply_to_a_fresh_database_and_are_idempotent() {
    let Some(scratch) = ScratchDb::create("fresh").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    db.migrate().await.unwrap();

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM installation")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "installation is a singleton");

    let second_insert =
        sqlx::query("INSERT INTO installation (installation_id) VALUES (gen_random_uuid())")
            .execute(db.pool())
            .await;
    assert!(second_insert.is_err(), "singleton constraint must hold");

    db.ping(Duration::from_secs(2)).await.unwrap();
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn statement_timeout_is_enforced_by_the_database() {
    let Some(scratch) = ScratchDb::create("timeout").await else {
        return;
    };
    let settings = DatabaseSettings {
        statement_timeout: Duration::from_secs(1),
        ..scratch.settings.clone()
    };
    let db = Database::connect(&settings).await.unwrap();
    let result = sqlx::query("SELECT pg_sleep(3)").execute(db.pool()).await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("statement timeout"), "{err}");
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn invalid_url_error_does_not_echo_the_url() {
    let settings = DatabaseSettings {
        url: SecretString::from("postgres://user:hunter2@[not-a-host"),
        max_connections: 1,
        acquire_timeout: Duration::from_secs(1),
        statement_timeout: Duration::from_secs(1),
    };
    let err = Database::connect_lazy(&settings).unwrap_err().to_string();
    assert!(!err.contains("hunter2"), "{err}");
}
