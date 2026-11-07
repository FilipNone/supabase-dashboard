use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::LogFormat;

/// Installs the global tracing subscriber. `RUST_LOG` overrides the default
/// filter. Request spans never record headers, query strings, or bodies.
pub fn init(format: LogFormat) -> Result<(), tracing_subscriber::util::TryInitError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info,sqlx=warn"));
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true))
            .try_init(),
        LogFormat::Pretty => registry.with(fmt::layer()).try_init(),
    }
}
