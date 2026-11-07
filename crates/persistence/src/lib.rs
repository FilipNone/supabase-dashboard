//! Control-plane metadata storage.
//!
//! This crate is server-only. It must never be a dependency of the browser
//! (`hydrate`) build.

pub mod accounts;
pub mod audit;
pub mod organizations;
pub mod sessions;

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

/// Embedded, versioned migrations for the metadata database.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// The connection URL could not be parsed. The URL itself is never
    /// included because it may contain a password.
    #[error("the metadata database URL is invalid")]
    InvalidUrl,
    #[error("could not connect to the metadata database: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("metadata database migration failed: {0}")]
    Migrate(#[source] sqlx::migrate::MigrateError),
    #[error("metadata database query failed: {0}")]
    Query(#[source] sqlx::Error),
    #[error("metadata database did not respond within {0:?}")]
    Timeout(Duration),
    /// A stored value no longer passes domain validation. Names the column,
    /// never the value.
    #[error("metadata database holds an invalid value in {0}")]
    InvalidRow(&'static str),
}

/// Connection settings for the metadata database.
#[derive(Debug, Clone)]
pub struct DatabaseSettings {
    pub url: SecretString,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    /// Server-side limit for any single statement on the pool.
    pub statement_timeout: Duration,
}

/// Handle to the control-plane metadata database.
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Opens a pool and verifies one connection.
    pub async fn connect(settings: &DatabaseSettings) -> Result<Self, PersistenceError> {
        let pool = pool_options(settings)
            .connect_with(connect_options(settings)?)
            .await
            .map_err(PersistenceError::Connect)?;
        Ok(Self { pool })
    }

    /// Creates a pool without connecting. Connections are opened on first
    /// use, so an unreachable database surfaces as a query error later.
    pub fn connect_lazy(settings: &DatabaseSettings) -> Result<Self, PersistenceError> {
        let pool = pool_options(settings).connect_lazy_with(connect_options(settings)?);
        Ok(Self { pool })
    }

    /// Applies pending migrations. Fails if the database contains a
    /// migration this binary does not know, which prevents an older binary
    /// from running against a newer schema.
    pub async fn migrate(&self) -> Result<(), PersistenceError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(PersistenceError::Migrate)
    }

    /// Round-trips a trivial query, bounded by `timeout`.
    pub async fn ping(&self, timeout: Duration) -> Result<(), PersistenceError> {
        let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool);
        match tokio::time::timeout(timeout, query).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) => Err(PersistenceError::Query(err)),
            Err(_) => Err(PersistenceError::Timeout(timeout)),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Waits for checked-out connections to return, then closes the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

fn pool_options(settings: &DatabaseSettings) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
}

fn connect_options(settings: &DatabaseSettings) -> Result<PgConnectOptions, PersistenceError> {
    let statement_timeout_ms = settings.statement_timeout.as_millis().to_string();
    let options: PgConnectOptions = settings
        .url
        .expose_secret()
        .parse()
        .map_err(|_| PersistenceError::InvalidUrl)?;
    Ok(options
        .application_name("supabase-dashboard")
        .options([("statement_timeout", statement_timeout_ms.as_str())]))
}
