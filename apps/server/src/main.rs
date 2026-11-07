//! supabase-dashboard HTTP server.

mod app;
mod config;
mod error;
mod health;
mod state;
mod telemetry;

use std::process::ExitCode;

use supabase_dashboard_persistence::{Database, PersistenceError};
use tokio::net::TcpListener;

use crate::{
    app::HttpLimits,
    config::{Config, ConfigError},
    state::AppState,
};

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("could not initialize logging: {0}")]
    Telemetry(#[from] tracing_subscriber::util::TryInitError),
    #[error("Leptos configuration error: {0}")]
    Leptos(#[from] leptos::config::errors::LeptosConfigError),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("could not bind {addr}: {source}")]
    Bind {
        addr: std::net::SocketAddr,
        source: std::io::Error,
    },
    #[error("server error: {0}")]
    Serve(std::io::Error),
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Logging may not be initialized yet, so also print to stderr.
            tracing::error!(error = %err, "startup failed");
            eprintln!("supabase-dashboard: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), StartupError> {
    let config = Config::from_env()?;
    telemetry::init(config.log_format)?;

    let leptos_options = leptos::config::get_configuration(None)?.leptos_options;
    let addr = leptos_options.site_addr;

    let db = Database::connect(&config.database).await?;
    db.migrate().await?;
    tracing::info!("metadata database migrations are up to date");

    let state = AppState {
        leptos_options,
        db: db.clone(),
        readiness_timeout: config.readiness_timeout,
    };
    let limits = HttpLimits {
        max_body_bytes: config.max_body_bytes,
        request_timeout: config.request_timeout,
    };
    let router = app::router(state, &limits);

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| StartupError::Bind { addr, source })?;
    tracing::info!(
        %addr,
        environment = ?config.environment,
        public_url = config.public_url.as_ref().map(url::Url::as_str),
        "listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(StartupError::Serve)?;

    tracing::info!("draining database connections");
    db.close().await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM. In-flight requests finish (bounded by the
/// request timeout) before the server exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "could not listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
