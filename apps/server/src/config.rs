//! Runtime configuration, read from environment variables and validated at
//! startup. Invalid configuration stops the server before it binds a port.

use std::{fmt, time::Duration};

use secrecy::SecretString;
use supabase_dashboard_persistence::DatabaseSettings;

use crate::studio_host::StudioHosts;

const PREFIX: &str = "SUPABASE_DASHBOARD_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Local development: plain HTTP and human-readable logs are allowed.
    Development,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub environment: Environment,
    /// External URL operators use to reach the dashboard. Required in
    /// production, where it must use HTTPS.
    pub public_url: Option<url::Url>,
    pub database: DatabaseSettings,
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub readiness_timeout: Duration,
    pub log_format: LogFormat,
    /// A session unused for this long stops working.
    pub session_idle_timeout: Duration,
    /// Absolute session lifetime from sign-in.
    pub session_lifetime: Duration,
    /// Where the key that encrypts stored project credentials comes from.
    /// Without one, the dashboard cannot store or use project API keys.
    pub secret_key: Option<SecretKeySource>,
    /// Let project checks connect to loopback addresses. For development
    /// against a stack on the same host only.
    pub allow_loopback_targets: bool,
    /// Where each project's Studio is served. Without it, Studio cannot be
    /// opened through the dashboard.
    pub studio_hosts: Option<StudioHosts>,
    /// Largest request body on a Studio host. Separate from the dashboard's
    /// limit because Studio uploads files to Storage.
    pub studio_max_body_bytes: usize,
    /// Longest time a Studio request may take to answer, because Studio's
    /// SQL editor can run long queries.
    pub studio_request_timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum SecretKeySource {
    /// A file holding the base64 key, such as a Docker secret. Read once at
    /// startup.
    File(std::path::PathBuf),
    /// The base64 key itself, from the environment.
    Inline(SecretString),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{name} is required")]
    Missing { name: String },
    #[error("{name} is invalid: {reason}")]
    Invalid { name: String, reason: String },
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Builds configuration from any key lookup, so tests do not touch the
    /// process environment.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |key: &str| {
            lookup(&format!("{PREFIX}{key}"))
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let environment = match get("ENV").as_deref() {
            None | Some("production") => Environment::Production,
            Some("development") => Environment::Development,
            Some(_) => return Err(invalid("ENV", "expected `production` or `development`")),
        };

        let public_url = match get("PUBLIC_URL") {
            Some(raw) => Some(parse_public_url(&raw, environment)?),
            None if environment == Environment::Production => {
                return Err(missing("PUBLIC_URL"));
            }
            None => None,
        };

        let database_url = get("DATABASE_URL").ok_or_else(|| missing("DATABASE_URL"))?;
        if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
            // Do not echo the value: it normally contains a password.
            return Err(invalid("DATABASE_URL", "expected a postgres:// URL"));
        }

        let database = DatabaseSettings {
            url: SecretString::from(database_url),
            max_connections: u32::try_from(bounded(&get, "DB_MAX_CONNECTIONS", 10, 1, 200)?)
                .map_err(|_| invalid("DB_MAX_CONNECTIONS", "out of range"))?,
            acquire_timeout: secs(bounded(&get, "DB_ACQUIRE_TIMEOUT_SECS", 5, 1, 120)?),
            statement_timeout: secs(bounded(&get, "DB_STATEMENT_TIMEOUT_SECS", 30, 1, 3600)?),
        };

        let max_body_bytes = bounded(&get, "MAX_BODY_BYTES", 1024 * 1024, 1024, 64 * 1024 * 1024)?;
        let request_timeout = secs(bounded(&get, "REQUEST_TIMEOUT_SECS", 30, 1, 600)?);
        let readiness_timeout = secs(bounded(&get, "READINESS_TIMEOUT_SECS", 2, 1, 30)?);
        let session_idle_timeout =
            secs(bounded(&get, "SESSION_IDLE_TIMEOUT_MINS", 60, 5, 24 * 60)? * 60);
        let session_lifetime =
            secs(bounded(&get, "SESSION_LIFETIME_HOURS", 12, 1, 30 * 24)? * 3600);
        if session_idle_timeout > session_lifetime {
            return Err(invalid(
                "SESSION_IDLE_TIMEOUT_MINS",
                "must not exceed SUPABASE_DASHBOARD_SESSION_LIFETIME_HOURS",
            ));
        }

        let log_format = match get("LOG_FORMAT").as_deref() {
            Some("json") => LogFormat::Json,
            Some("pretty") => LogFormat::Pretty,
            None if environment == Environment::Development => LogFormat::Pretty,
            None => LogFormat::Json,
            Some(_) => return Err(invalid("LOG_FORMAT", "expected `json` or `pretty`")),
        };

        let secret_key = match (get("SECRET_KEY_FILE"), get("SECRET_KEY")) {
            (Some(_), Some(_)) => {
                return Err(invalid(
                    "SECRET_KEY",
                    "set either SUPABASE_DASHBOARD_SECRET_KEY or SUPABASE_DASHBOARD_SECRET_KEY_FILE, not both",
                ));
            }
            (Some(path), None) => Some(SecretKeySource::File(path.into())),
            // Do not echo the value in any error.
            (None, Some(key)) => Some(SecretKeySource::Inline(SecretString::from(key))),
            (None, None) => None,
        };
        let allow_loopback_targets = match get("ALLOW_LOOPBACK_TARGETS").as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                return Err(invalid(
                    "ALLOW_LOOPBACK_TARGETS",
                    "expected `true` or `false`",
                ));
            }
        };

        let studio_hosts = match (get("STUDIO_DOMAIN"), &public_url) {
            (None, _) => None,
            (Some(_), None) => {
                return Err(invalid(
                    "STUDIO_DOMAIN",
                    "needs SUPABASE_DASHBOARD_PUBLIC_URL, whose scheme Studio hosts share",
                ));
            }
            (Some(raw), Some(url)) => {
                Some(StudioHosts::parse(&raw, url).map_err(|e| invalid("STUDIO_DOMAIN", e))?)
            }
        };
        let studio_max_body_bytes = bounded(
            &get,
            "STUDIO_MAX_BODY_BYTES",
            50 * 1024 * 1024,
            1024,
            1024 * 1024 * 1024,
        )?;
        let studio_request_timeout =
            secs(bounded(&get, "STUDIO_REQUEST_TIMEOUT_SECS", 300, 10, 3600)?);

        Ok(Self {
            environment,
            public_url,
            database,
            max_body_bytes: usize::try_from(max_body_bytes)
                .map_err(|_| invalid("MAX_BODY_BYTES", "does not fit in memory size"))?,
            request_timeout,
            readiness_timeout,
            log_format,
            session_idle_timeout,
            session_lifetime,
            secret_key,
            allow_loopback_targets,
            studio_hosts,
            studio_max_body_bytes: usize::try_from(studio_max_body_bytes)
                .map_err(|_| invalid("STUDIO_MAX_BODY_BYTES", "does not fit in memory size"))?,
            studio_request_timeout,
        })
    }
}

fn parse_public_url(raw: &str, environment: Environment) -> Result<url::Url, ConfigError> {
    let url = url::Url::parse(raw).map_err(|e| invalid("PUBLIC_URL", e))?;
    match (url.scheme(), environment) {
        ("https", _) | ("http", Environment::Development) => {}
        ("http", Environment::Production) => {
            return Err(invalid(
                "PUBLIC_URL",
                "must use https outside development (set SUPABASE_DASHBOARD_ENV=development for local HTTP)",
            ));
        }
        _ => return Err(invalid("PUBLIC_URL", "expected an http(s) URL")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("PUBLIC_URL", "must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "PUBLIC_URL",
            "must not contain a query or fragment",
        ));
    }
    Ok(url)
}

fn bounded(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let Some(raw) = get(key) else {
        return Ok(default);
    };
    let value: u64 = raw
        .parse()
        .map_err(|_| invalid(key, "expected a whole number"))?;
    if !(min..=max).contains(&value) {
        return Err(invalid(key, format!("must be between {min} and {max}")));
    }
    Ok(value)
}

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn missing(key: &str) -> ConfigError {
    ConfigError::Missing {
        name: format!("{PREFIX}{key}"),
    }
}

fn invalid(key: &str, reason: impl fmt::Display) -> ConfigError {
    ConfigError::Invalid {
        name: format!("{PREFIX}{key}"),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (format!("{PREFIX}{k}"), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    const DB: (&str, &str) = ("DATABASE_URL", "postgres://dash:pw@localhost/dash");

    #[test]
    fn production_is_the_default_and_requires_public_url() {
        assert_eq!(
            load(&[DB]).unwrap_err(),
            ConfigError::Missing {
                name: "SUPABASE_DASHBOARD_PUBLIC_URL".into()
            }
        );
        let config = load(&[DB, ("PUBLIC_URL", "https://dash.example.test")]).unwrap();
        assert_eq!(config.environment, Environment::Production);
        assert_eq!(config.log_format, LogFormat::Json);
    }

    #[test]
    fn production_rejects_plain_http() {
        let err = load(&[DB, ("PUBLIC_URL", "http://dash.example.test")]).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }));
    }

    #[test]
    fn development_allows_http_and_no_public_url() {
        let config = load(&[DB, ("ENV", "development")]).unwrap();
        assert_eq!(config.public_url, None);
        assert_eq!(config.log_format, LogFormat::Pretty);
        load(&[
            DB,
            ("ENV", "development"),
            ("PUBLIC_URL", "http://localhost:3000"),
        ])
        .unwrap();
    }

    #[test]
    fn public_url_with_credentials_is_rejected() {
        let err = load(&[DB, ("PUBLIC_URL", "https://user:pw@dash.example.test")]).unwrap_err();
        assert!(err.to_string().contains("credentials"));
    }

    #[test]
    fn database_url_is_required_and_never_echoed() {
        let err = load(&[("ENV", "development")]).unwrap_err();
        assert!(matches!(err, ConfigError::Missing { .. }));

        let err = load(&[
            ("ENV", "development"),
            ("DATABASE_URL", "mysql://root:hunter2@db"),
        ])
        .unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn database_url_is_not_in_debug_output() {
        let config = load(&[DB, ("ENV", "development")]).unwrap();
        assert!(!format!("{config:?}").contains("pw@"));
        assert_eq!(
            config.database.url.expose_secret(),
            "postgres://dash:pw@localhost/dash"
        );
    }

    #[test]
    fn numeric_settings_are_bounded() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev, ("MAX_BODY_BYTES", "10")]).is_err());
        assert!(load(&[DB, dev, ("DB_MAX_CONNECTIONS", "0")]).is_err());
        assert!(load(&[DB, dev, ("REQUEST_TIMEOUT_SECS", "abc")]).is_err());
        let config = load(&[DB, dev, ("MAX_BODY_BYTES", "2048")]).unwrap();
        assert_eq!(config.max_body_bytes, 2048);
    }

    #[test]
    fn session_timeouts_are_bounded_and_consistent() {
        let dev = ("ENV", "development");
        let config = load(&[DB, dev]).unwrap();
        assert_eq!(config.session_idle_timeout, Duration::from_secs(3600));
        assert_eq!(config.session_lifetime, Duration::from_secs(12 * 3600));
        assert!(load(&[DB, dev, ("SESSION_IDLE_TIMEOUT_MINS", "1")]).is_err());
        assert!(load(&[DB, dev, ("SESSION_LIFETIME_HOURS", "0")]).is_err());
        let err = load(&[
            DB,
            dev,
            ("SESSION_IDLE_TIMEOUT_MINS", "120"),
            ("SESSION_LIFETIME_HOURS", "1"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn secret_key_comes_from_one_source_and_is_not_printed() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev]).unwrap().secret_key.is_none());
        let config = load(&[DB, dev, ("SECRET_KEY", "c2VjcmV0LWtleS12YWx1ZQ==")]).unwrap();
        assert!(matches!(
            config.secret_key,
            Some(SecretKeySource::Inline(_))
        ));
        assert!(!format!("{config:?}").contains("c2VjcmV0"));
        let config = load(&[DB, dev, ("SECRET_KEY_FILE", "/run/secrets/key")]).unwrap();
        assert!(matches!(config.secret_key, Some(SecretKeySource::File(_))));
        let err = load(&[
            DB,
            dev,
            ("SECRET_KEY", "c2VjcmV0LWtleS12YWx1ZQ=="),
            ("SECRET_KEY_FILE", "/run/secrets/key"),
        ])
        .unwrap_err();
        assert!(!err.to_string().contains("c2VjcmV0"));
    }

    #[test]
    fn loopback_targets_are_off_by_default() {
        let dev = ("ENV", "development");
        assert!(!load(&[DB, dev]).unwrap().allow_loopback_targets);
        assert!(
            load(&[DB, dev, ("ALLOW_LOOPBACK_TARGETS", "true")])
                .unwrap()
                .allow_loopback_targets
        );
        assert!(load(&[DB, dev, ("ALLOW_LOOPBACK_TARGETS", "yes")]).is_err());
    }

    #[test]
    fn studio_domain_needs_a_public_url_outside_it() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev]).unwrap().studio_hosts.is_none());
        let err = load(&[DB, dev, ("STUDIO_DOMAIN", "studio.localhost")]).unwrap_err();
        assert!(err.to_string().contains("PUBLIC_URL"), "{err}");
        let config = load(&[
            DB,
            ("PUBLIC_URL", "https://dash.example.test"),
            ("STUDIO_DOMAIN", "studio.example.test"),
        ])
        .unwrap();
        assert!(config.studio_hosts.unwrap().is_https());
        assert_eq!(config.studio_max_body_bytes, 50 * 1024 * 1024);
        assert_eq!(config.studio_request_timeout, Duration::from_secs(300));
        let err = load(&[
            DB,
            ("PUBLIC_URL", "https://studio.example.test"),
            ("STUDIO_DOMAIN", "studio.example.test"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("STUDIO_DOMAIN"), "{err}");
        assert!(load(&[DB, dev, ("STUDIO_REQUEST_TIMEOUT_SECS", "1")]).is_err());
    }

    #[test]
    fn unknown_environment_is_rejected() {
        assert!(load(&[DB, ("ENV", "staging")]).is_err());
    }
}
