//! supabase-dashboard HTTP server.

mod app;
mod cli;
mod config;
mod error;
mod health;
#[cfg(test)]
#[path = "../../../crates/persistence/tests/common/mod.rs"]
mod scratch_db;
mod session;
mod state;
mod telemetry;

use std::{process::ExitCode, sync::Arc, time::Duration};

use supabase_dashboard_application::{
    auth::{AuthConfig, AuthError, AuthService, BootstrapError, PasswordResetError},
    organizations::OrganizationService,
};
use supabase_dashboard_persistence::{Database, PersistenceError};
use tokio::net::TcpListener;

use crate::{
    app::HttpLimits,
    config::{Config, ConfigError},
    session::CookieSettings,
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
    #[error("{0}\n\n{usage}", usage = cli::USAGE)]
    Usage(String),
    #[error(transparent)]
    PasswordInput(#[from] cli::PasswordInputError),
    #[error("could not create the owner account: {0}")]
    Bootstrap(#[from] BootstrapError),
    #[error("authentication setup failed: {0}")]
    Auth(#[from] AuthError),
    #[error("could not reset the password: {0}")]
    PasswordReset(#[from] PasswordResetError),
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match cli::parse(std::env::args().skip(1)) {
        Ok(cli::Command::Serve) => run().await,
        Ok(cli::Command::CreateOwner { email, name }) => create_owner(&email, &name).await,
        Ok(cli::Command::ResetPassword { email }) => reset_password(&email).await,
        Ok(cli::Command::Help) => {
            println!("{}", cli::USAGE);
            Ok(())
        }
        Err(message) => Err(StartupError::Usage(message)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Logging may not be initialized yet, so also print to stderr.
            tracing::error!(error = %err, "startup failed");
            eprintln!("supabase-dashboard: {err}");
            ExitCode::FAILURE
        }
    }
}

fn auth_config(config: &Config) -> AuthConfig {
    AuthConfig {
        session_lifetime: config.session_lifetime,
        idle_timeout: config.session_idle_timeout,
        ..AuthConfig::default()
    }
}

async fn create_owner(email: &str, name: &str) -> Result<(), StartupError> {
    let config = Config::from_env()?;
    telemetry::init(config.log_format)?;
    let db = Database::connect(&config.database).await?;
    db.migrate().await?;
    let auth = AuthService::new(db.clone(), auth_config(&config)).await?;
    // Check before prompting, so the operator does not type a password for
    // nothing.
    if auth.is_initialized().await? {
        return Err(BootstrapError::AlreadyInitialized.into());
    }
    let password = cli::read_new_password()?;
    auth.bootstrap_owner(email, name, &password).await?;
    db.close().await;
    let sign_in = config.public_url.as_ref().map_or_else(
        || "/dashboard/sign-in".to_owned(),
        |url| format!("{}dashboard/sign-in", ensure_trailing_slash(url.as_str())),
    );
    println!("Created the owner account. Sign in at {sign_in}");
    Ok(())
}

async fn reset_password(email: &str) -> Result<(), StartupError> {
    let config = Config::from_env()?;
    telemetry::init(config.log_format)?;
    let db = Database::connect(&config.database).await?;
    db.migrate().await?;
    let auth = AuthService::new(db.clone(), auth_config(&config)).await?;
    let password = cli::read_new_password()?;
    let revoked = auth.reset_password(email, &password).await?;
    db.close().await;
    println!(
        "Password changed. {revoked} session(s) signed out. If sign-in is blocked after failed \
         attempts, it unblocks when the throttle window ends or the server restarts."
    );
    Ok(())
}

fn ensure_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_owned()
    } else {
        format!("{url}/")
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

    let auth = Arc::new(AuthService::new(db.clone(), auth_config(&config)).await?);
    if !auth.is_initialized().await? {
        tracing::warn!(
            "no operator account exists; create one with `supabase-dashboard-server create-owner`"
        );
    }
    tokio::spawn(prune_sessions(Arc::clone(&auth)));

    let secure_cookie = config
        .public_url
        .as_ref()
        .is_some_and(|u| u.scheme() == "https");
    let state = AppState {
        leptos_options,
        db: db.clone(),
        readiness_timeout: config.readiness_timeout,
        auth,
        organizations: Arc::new(OrganizationService::new(db.clone())),
        cookie: CookieSettings::new(secure_cookie, config.session_lifetime.as_secs()),
        expected_origin: config
            .public_url
            .as_ref()
            .map(|url| url.origin().ascii_serialization()),
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

/// Deletes unusable sessions once an hour so the table stays small.
async fn prune_sessions(auth: Arc<AuthService>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        match auth.prune_sessions().await {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "pruned expired sessions"),
            Err(err) => tracing::warn!(error = %err, "could not prune sessions"),
        }
    }
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
