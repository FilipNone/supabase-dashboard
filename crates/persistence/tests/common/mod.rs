//! Shared scratch-database helper for the integration tests.

#![allow(clippy::unwrap_used, dead_code)]

use std::time::Duration;

use secrecy::SecretString;
// Database names below are built only from a fixed label and the process
// ID, never from external input.
use sqlx::{AssertSqlSafe, Connection, PgConnection};
use supabase_dashboard_persistence::DatabaseSettings;

pub const ENV: &str = "SUPABASE_DASHBOARD_TEST_DATABASE_URL";

pub struct ScratchDb {
    admin_url: String,
    name: String,
    pub settings: DatabaseSettings,
}

impl ScratchDb {
    pub async fn create(label: &str) -> Option<Self> {
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

    /// Drops the database now. Dropping the value does the same, so a
    /// test that returns early or panics leaves nothing behind either.
    pub async fn drop(self) {}
}

impl Drop for ScratchDb {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        // `Drop` cannot await, and the test's runtime may be busy or
        // shutting down, so the drop runs on its own thread and runtime.
        // `WITH (FORCE)` closes connections the test's pool still holds.
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&admin_url).await.unwrap();
                sqlx::query(AssertSqlSafe(format!(
                    r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#
                )))
                .execute(&mut admin)
                .await
                .unwrap();
            });
        })
        .join();
        assert!(
            dropped.is_ok() || std::thread::panicking(),
            "could not drop the scratch database {}",
            self.name
        );
    }
}

fn url_with_database(url: &str, database: &str) -> String {
    let (base, _) = url.rsplit_once('/').unwrap();
    format!("{base}/{database}")
}
