//! supabase-dashboard HTTP server.

mod access_export;
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
mod studio;
mod studio_host;
mod telemetry;

use std::{process::ExitCode, sync::Arc, time::Duration};

use supabase_dashboard_adapters::{
    gateway::{GatewayError, GatewayProbe, GatewaySettings},
    net::TargetPolicy,
    studio_proxy::{StudioProxy, StudioProxySettings},
    tls::{ExtraRoots, ExtraRootsError, MAX_EXTRA_CA_FILE_BYTES},
};
use supabase_dashboard_application::{
    auth::{AuthConfig, AuthError, AuthService, BootstrapError, PasswordResetError},
    connections::{ConnectionService, ScheduledChecks},
    key_rotation::{RotationError, key_usage, reseal_credentials},
    organizations::OrganizationService,
    projects::ProjectService,
    secrets::{CredentialCipher, KeyError},
    studio::StudioService,
    studio_access::{StudioAccessRecorder, StudioAccessService},
};
use supabase_dashboard_persistence::{Database, PersistenceError};
use tokio::net::TcpListener;

use crate::{
    app::HttpLimits,
    config::{Config, ConfigError, SecretKeySource},
    session::CookieSettings,
    state::AppState,
    studio::StudioGateway,
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
    #[error("could not read the credential encryption key file {path}: {source}")]
    SecretKeyFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("SUPABASE_DASHBOARD_SECRET_KEY(_FILE) is invalid: {0}")]
    SecretKey(#[from] KeyError),
    #[error("could not read SUPABASE_DASHBOARD_PREVIOUS_SECRET_KEYS_FILE {path}: {source}")]
    PreviousKeysFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("SUPABASE_DASHBOARD_PREVIOUS_SECRET_KEYS_FILE {path} is invalid: {reason}")]
    PreviousKeys {
        path: std::path::PathBuf,
        reason: String,
    },
    #[error("no credential encryption key is configured; set SUPABASE_DASHBOARD_SECRET_KEY_FILE")]
    NoSecretKey,
    #[error("could not reseal stored credentials: {0}")]
    Rotation(#[from] RotationError),
    #[error("could not set up project connections: {0}")]
    Gateway(#[from] GatewayError),
    #[error("could not read SUPABASE_DASHBOARD_EXTRA_CA_FILE {path}: {source}")]
    ExtraCaFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("SUPABASE_DASHBOARD_EXTRA_CA_FILE {path} is invalid: {source}")]
    ExtraCa {
        path: std::path::PathBuf,
        source: ExtraRootsError,
    },
}

/// Loads the extra certificate authorities, if a file is configured. The
/// size is checked before reading, so a wrong path fails fast.
fn extra_roots(config: &Config) -> Result<ExtraRoots, StartupError> {
    let Some(path) = &config.extra_ca_file else {
        return Ok(ExtraRoots::default());
    };
    let read_err = |source| StartupError::ExtraCaFile {
        path: path.clone(),
        source,
    };
    let invalid = |source| StartupError::ExtraCa {
        path: path.clone(),
        source,
    };
    let len = std::fs::metadata(path).map_err(read_err)?.len();
    if usize::try_from(len).map_or(true, |len| len > MAX_EXTRA_CA_FILE_BYTES) {
        return Err(invalid(ExtraRootsError::TooLarge));
    }
    let pem = std::fs::read(path).map_err(read_err)?;
    let roots = ExtraRoots::from_pem(&pem).map_err(invalid)?;
    tracing::info!(
        count = roots.len(),
        "trusting extra certificate authorities for project connections"
    );
    Ok(roots)
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match cli::parse(std::env::args().skip(1)) {
        Ok(cli::Command::Serve) => run().await,
        Ok(cli::Command::CreateOwner { email, name }) => create_owner(&email, &name).await,
        Ok(cli::Command::ResetPassword { email }) => reset_password(&email).await,
        Ok(cli::Command::RotateSecretKey) => rotate_secret_key().await,
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

/// Loads the credential encryption key, if one is configured.
fn credential_cipher(config: &Config) -> Result<Option<CredentialCipher>, StartupError> {
    let encoded = match &config.secret_key {
        None => return Ok(None),
        Some(SecretKeySource::Inline(key)) => key.clone(),
        Some(SecretKeySource::File(path)) => std::fs::read_to_string(path)
            .map(secrecy::SecretString::from)
            .map_err(|source| StartupError::SecretKeyFile {
                path: path.clone(),
                source,
            })?,
    };
    let mut cipher = CredentialCipher::from_base64(&encoded)?;
    if let Some(path) = &config.previous_secret_keys_file {
        let read_err = |source| StartupError::PreviousKeysFile {
            path: path.clone(),
            source,
        };
        let invalid = |reason: &str| StartupError::PreviousKeys {
            path: path.clone(),
            reason: reason.to_owned(),
        };
        let len = std::fs::metadata(path).map_err(read_err)?.len();
        if len > MAX_PREVIOUS_KEYS_FILE_BYTES {
            return Err(invalid("the file is larger than 64 KiB"));
        }
        let text = std::fs::read_to_string(path)
            .map(secrecy::SecretString::from)
            .map_err(read_err)?;
        // The error names the format, never the line, which may be a key.
        let added = cipher
            .add_previous_keys(&text)
            .map_err(|err| invalid(&err.to_string()))?;
        tracing::info!(
            count = added,
            previous_key_ids = ?cipher.previous_key_ids().collect::<Vec<_>>(),
            "previous credential encryption keys loaded for reading only"
        );
    }
    Ok(Some(cipher))
}

/// Largest previous-keys file read; a line per key is about 45 bytes.
const MAX_PREVIOUS_KEYS_FILE_BYTES: u64 = 64 * 1024;

/// Warns when stored values are under a key other than the current one.
async fn report_key_usage(db: &Database, cipher: &CredentialCipher) -> Result<(), StartupError> {
    let usage = key_usage(db, cipher).await?;
    if usage.previous > 0 {
        tracing::warn!(
            count = usage.previous,
            "stored project credentials are still under a previous encryption key; \
             run `supabase-dashboard-server rotate-secret-key`"
        );
    }
    if usage.unknown > 0 {
        tracing::warn!(
            count = usage.unknown,
            "stored project credentials are under an encryption key this server does not have; \
             they cannot be used until they are entered again"
        );
    }
    Ok(())
}

async fn rotate_secret_key() -> Result<(), StartupError> {
    let config = Config::from_env()?;
    telemetry::init(config.log_format)?;
    let cipher = credential_cipher(&config)?.ok_or(StartupError::NoSecretKey)?;
    let db = Database::connect(&config.database).await?;
    db.migrate().await?;
    let summary = reseal_credentials(&db, &cipher).await?;
    let usage = key_usage(&db, &cipher).await?;
    db.close().await;
    println!(
        "Resealed {} stored credential(s) under key {}.",
        summary.resealed,
        cipher.key_id()
    );
    if summary.changed_meanwhile > 0 {
        println!(
            "{} credential(s) were replaced while this ran and already use the current key or \
             will on the next run.",
            summary.changed_meanwhile
        );
    }
    if summary.unreadable > 0 {
        println!(
            "{} credential(s) are under a key this server does not have and were left as they \
             are. Enter them again on each project's settings page.",
            summary.unreadable
        );
    }
    if usage.previous == 0 {
        println!(
            "No stored credential needs a previous key now. Remove the old keys from \
             SUPABASE_DASHBOARD_PREVIOUS_SECRET_KEYS_FILE and restart the server."
        );
    }
    Ok(())
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

    let cipher = credential_cipher(&config)?;
    match &cipher {
        Some(cipher) => {
            tracing::info!(key_id = cipher.key_id(), "credential encryption key loaded");
            report_key_usage(&db, cipher).await?;
        }
        None => tracing::warn!(
            "no credential encryption key is configured; project API keys cannot be stored \
             (set SUPABASE_DASHBOARD_SECRET_KEY_FILE)"
        ),
    }
    if config.allow_loopback_targets {
        tracing::warn!("project checks may connect to loopback addresses");
    }
    let policy = TargetPolicy {
        allow_loopback: config.allow_loopback_targets,
    };
    let extra_roots = extra_roots(&config)?;
    let probe = GatewayProbe::shared(GatewaySettings {
        policy,
        extra_roots: extra_roots.clone(),
        ..GatewaySettings::default()
    })?;
    let studio = match (&config.studio_hosts, &config.public_url) {
        (Some(hosts), Some(public_url)) => {
            let service =
                StudioService::new(db.clone(), cipher.clone(), config.session_idle_timeout);
            let proxy = StudioProxy::new(StudioProxySettings {
                policy,
                read_timeout: config.studio_request_timeout,
                extra_roots,
                ..StudioProxySettings::default()
            })?;
            tracing::info!(
                example = %hosts.origin(uuid::Uuid::nil()),
                "Studio access is enabled"
            );
            let gateway = StudioGateway::new(
                hosts.clone(),
                Arc::new(service),
                proxy,
                public_url.origin().ascii_serialization(),
            );
            Some(Arc::new(match config.studio_access_log_days {
                Some(days) => {
                    tracing::info!(retention_days = days, "Studio requests are logged");
                    gateway.with_access_log(StudioAccessRecorder::start(db.clone()))
                }
                None => gateway,
            }))
        }
        _ => {
            tracing::warn!(
                "Studio access is off; set SUPABASE_DASHBOARD_STUDIO_DOMAIN to open projects in Studio"
            );
            None
        }
    };

    // Pruning runs even with the log off, so turning it off also clears
    // what it recorded before.
    let studio_access = Arc::new(StudioAccessService::new(
        db.clone(),
        config.studio_access_log_days,
    ));
    tokio::spawn(prune_studio_access(Arc::clone(&studio_access)));

    let connections = Arc::new(ConnectionService::new(db.clone(), cipher, probe));
    match config.health_check_interval {
        Some(interval) => {
            tracing::info!(
                interval_mins = interval.as_secs() / 60,
                "projects are checked on a schedule"
            );
            tokio::spawn(scheduled_checks(Arc::clone(&connections), interval));
        }
        None => tracing::info!("scheduled project checks are off"),
    }

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
        projects: Arc::new(ProjectService::new(db.clone())),
        connections,
        studio_access,
        cookie: CookieSettings::new(secure_cookie, config.session_lifetime.as_secs()),
        expected_origin: config
            .public_url
            .as_ref()
            .map(|url| url.origin().ascii_serialization()),
        studio,
    };
    let limits = HttpLimits {
        max_body_bytes: config.max_body_bytes,
        request_timeout: config.request_timeout,
        studio_max_body_bytes: config.studio_max_body_bytes,
        studio_request_timeout: config.studio_request_timeout,
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

/// Deletes Studio access log entries past their retention once an hour.
async fn prune_studio_access(log: Arc<StudioAccessService>) {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        match log.prune().await {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "pruned Studio access log entries"),
            Err(err) => tracing::warn!(error = %err, "could not prune the Studio access log"),
        }
    }
}

/// Checks projects whose last check is older than `interval`, once a
/// minute, a bounded number at a time, so a large registry is spread over
/// several minutes instead of checked all at once. The first pass waits a
/// minute after startup.
async fn scheduled_checks(connections: Arc<ConnectionService>, interval: Duration) {
    let schedule = ScheduledChecks {
        older_than: interval,
        batch: 20,
        concurrency: 4,
        // A check makes five requests of at most 10 s each, and a batch of
        // 20 at 4 at a time takes about 250 s at worst.
        lease: Duration::from_secs(600),
    };
    let period = Duration::from_secs(60);
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        match connections.check_due(schedule).await {
            Ok(run) if run.checked + run.skipped + run.failed == 0 => {}
            Ok(run) => tracing::info!(
                checked = run.checked,
                skipped = run.skipped,
                failed = run.failed,
                "scheduled project checks ran"
            ),
            Err(err) => tracing::warn!(error = %err, "could not run scheduled project checks"),
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
