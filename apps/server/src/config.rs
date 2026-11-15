//! Runtime configuration, read from environment variables and validated at
//! startup. Invalid configuration stops the server before it binds a port.

use std::{fmt, time::Duration};

use secrecy::SecretString;
use supabase_dashboard_adapters::{
    mail::{DEFAULT_SMTP_TIMEOUT, SmtpEndpoint, SmtpSecurity, check_from_address},
    resend::DEFAULT_RESEND_TIMEOUT,
};
use supabase_dashboard_domain::{
    dokploy::DokployUrl, studio_access::STUDIO_ACCESS_MAX_RETENTION_DAYS,
};
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
    /// A PEM file of certificate authorities trusted, in addition to the
    /// bundled Mozilla roots, for project checks and Studio traffic.
    pub extra_ca_file: Option<std::path::PathBuf>,
    /// File of retired credential encryption keys, one per line, kept so
    /// values sealed under them can still be read and resealed.
    pub previous_secret_keys_file: Option<std::path::PathBuf>,
    /// Where each project's Studio is served. Without it, Studio cannot be
    /// opened through the dashboard.
    pub studio_hosts: Option<StudioHosts>,
    /// Largest request body on a Studio host. Separate from the dashboard's
    /// limit because Studio uploads files to Storage.
    pub studio_max_body_bytes: usize,
    /// Longest time a Studio request may take to answer, because Studio's
    /// SQL editor can run long queries.
    pub studio_request_timeout: Duration,
    /// How old a project's last check may get before the server checks it
    /// again on its own. `None` turns the server's own checks off.
    pub health_check_interval: Option<Duration>,
    /// Days to keep the Studio access log. `None` (the default) records
    /// nothing.
    pub studio_access_log_days: Option<u16>,
    /// A Dokploy connection the deployment supplies. The server stores it
    /// at startup, and administrators cannot replace or remove it.
    pub dokploy: Option<DeploymentDokploy>,
    /// Outgoing email for invitations and password resets. `None` (the
    /// default) sends nothing.
    pub mail: Option<MailConfig>,
}

/// Outgoing email: where it goes and who it is from.
#[derive(Debug, Clone)]
pub struct MailConfig {
    pub transport: MailTransport,
    /// The From address, as `address` or `Name <address>`.
    pub from: String,
}

/// How outgoing email is sent: `SUPABASE_DASHBOARD_SMTP_URL` or a Resend
/// API key, never both.
#[derive(Debug, Clone)]
pub enum MailTransport {
    Smtp(SmtpConfig),
    Resend(ResendConfig),
}

/// `SUPABASE_DASHBOARD_SMTP_URL` and the settings that go with it.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub endpoint: SmtpEndpoint,
    /// Username and where the password comes from, when the server needs
    /// them.
    pub credentials: Option<(String, SecretKeySource)>,
    pub timeout: Duration,
}

/// `SUPABASE_DASHBOARD_RESEND_API_KEY_FILE` or `_RESEND_API_KEY`, and the
/// settings that go with it.
#[derive(Debug, Clone)]
pub struct ResendConfig {
    pub api_key: SecretKeySource,
    pub timeout: Duration,
}

/// `SUPABASE_DASHBOARD_DOKPLOY_URL` and the file holding the API key.
#[derive(Debug, Clone)]
pub struct DeploymentDokploy {
    pub url: DokployUrl,
    /// Read once at startup, like the credential encryption key file.
    pub key_file: std::path::PathBuf,
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
        if secret_key.is_none() && get("PREVIOUS_SECRET_KEYS_FILE").is_some() {
            return Err(invalid(
                "PREVIOUS_SECRET_KEYS_FILE",
                "previous keys need a current key; set SUPABASE_DASHBOARD_SECRET_KEY_FILE too",
            ));
        }
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
        let health_check_interval =
            match bounded(&get, "HEALTH_CHECK_INTERVAL_MINS", 15, 0, 24 * 60)? {
                0 => None,
                1..5 => {
                    return Err(invalid(
                        "HEALTH_CHECK_INTERVAL_MINS",
                        "must be 0 (off) or between 5 and 1440",
                    ));
                }
                mins => Some(secs(mins * 60)),
            };
        let studio_access_log_days = match bounded(
            &get,
            "STUDIO_ACCESS_LOG_DAYS",
            0,
            0,
            u64::from(STUDIO_ACCESS_MAX_RETENTION_DAYS),
        )? {
            0 => None,
            days => Some(
                u16::try_from(days)
                    .map_err(|_| invalid("STUDIO_ACCESS_LOG_DAYS", "is out of range"))?,
            ),
        };

        let dokploy = match (get("DOKPLOY_URL"), get("DOKPLOY_API_KEY_FILE")) {
            (None, None) => None,
            (Some(_), None) => {
                return Err(invalid(
                    "DOKPLOY_URL",
                    "needs SUPABASE_DASHBOARD_DOKPLOY_API_KEY_FILE with the API key",
                ));
            }
            (None, Some(_)) => {
                return Err(invalid(
                    "DOKPLOY_API_KEY_FILE",
                    "needs SUPABASE_DASHBOARD_DOKPLOY_URL",
                ));
            }
            (Some(_), Some(_)) if secret_key.is_none() => {
                return Err(invalid(
                    "DOKPLOY_URL",
                    "the Dokploy key is stored encrypted, so it needs a credential encryption \
                     key; set SUPABASE_DASHBOARD_SECRET_KEY_FILE too",
                ));
            }
            (Some(url), Some(key_file)) => Some(DeploymentDokploy {
                url: DokployUrl::parse(&url).map_err(|e| invalid("DOKPLOY_URL", e))?,
                key_file: key_file.into(),
            }),
        };

        let mail = mail_config(&get, environment, public_url.as_ref())?;

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
            extra_ca_file: get("EXTRA_CA_FILE").map(Into::into),
            previous_secret_keys_file: get("PREVIOUS_SECRET_KEYS_FILE").map(Into::into),
            studio_hosts,
            studio_max_body_bytes: usize::try_from(studio_max_body_bytes)
                .map_err(|_| invalid("STUDIO_MAX_BODY_BYTES", "does not fit in memory size"))?,
            studio_request_timeout,
            health_check_interval,
            studio_access_log_days,
            dokploy,
            mail,
        })
    }
}

/// Mail is off unless `SMTP_URL` or a Resend API key is set, and every
/// other mail setting needs one of them. Secrets come from a file or the
/// environment, never from a URL, and no error repeats them.
fn mail_config(
    get: &impl Fn(&str) -> Option<String>,
    environment: Environment,
    public_url: Option<&url::Url>,
) -> Result<Option<MailConfig>, ConfigError> {
    const SMTP_DEPENDENT: [&str; 5] = [
        "SMTP_USERNAME",
        "SMTP_PASSWORD",
        "SMTP_PASSWORD_FILE",
        "SMTP_PLAINTEXT",
        "SMTP_TIMEOUT_SECS",
    ];
    let smtp_url = get("SMTP_URL");
    if smtp_url.is_none()
        && let Some(name) = SMTP_DEPENDENT.into_iter().find(|name| get(name).is_some())
    {
        return Err(invalid(name, "needs SUPABASE_DASHBOARD_SMTP_URL"));
    }
    let resend_key = secret_source(get, "RESEND_API_KEY")?;
    if resend_key.is_none() && get("RESEND_TIMEOUT_SECS").is_some() {
        return Err(invalid(
            "RESEND_TIMEOUT_SECS",
            "needs SUPABASE_DASHBOARD_RESEND_API_KEY_FILE or SUPABASE_DASHBOARD_RESEND_API_KEY",
        ));
    }
    let (transport, setting) = match (smtp_url, resend_key) {
        (None, None) => {
            if get("MAIL_FROM").is_some() {
                return Err(invalid(
                    "MAIL_FROM",
                    "needs SUPABASE_DASHBOARD_SMTP_URL or SUPABASE_DASHBOARD_RESEND_API_KEY_FILE",
                ));
            }
            return Ok(None);
        }
        (Some(_), Some(_)) => {
            return Err(invalid(
                "RESEND_API_KEY_FILE",
                "send mail either over SMTP (SUPABASE_DASHBOARD_SMTP_URL) or through Resend, \
                 not both",
            ));
        }
        (Some(raw_url), None) => (
            MailTransport::Smtp(smtp_config(get, environment, &raw_url)?),
            "SMTP_URL",
        ),
        (None, Some(api_key)) => (
            MailTransport::Resend(ResendConfig {
                api_key,
                timeout: secs(bounded(
                    get,
                    "RESEND_TIMEOUT_SECS",
                    DEFAULT_RESEND_TIMEOUT.as_secs(),
                    1,
                    120,
                )?),
            }),
            "RESEND_API_KEY_FILE",
        ),
    };
    if public_url.is_none() {
        return Err(invalid(
            setting,
            "emailed links need SUPABASE_DASHBOARD_PUBLIC_URL",
        ));
    }
    let from = get("MAIL_FROM").ok_or_else(|| missing("MAIL_FROM"))?;
    if from.chars().any(char::is_control) {
        return Err(invalid("MAIL_FROM", "must be a single line"));
    }
    check_from_address(&from).map_err(|e| invalid("MAIL_FROM", e))?;
    Ok(Some(MailConfig { transport, from }))
}

/// `{name}_FILE` or `{name}`, not both. The value is never echoed.
fn secret_source(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<Option<SecretKeySource>, ConfigError> {
    let file_name = format!("{name}_FILE");
    match (get(&file_name), get(name)) {
        (Some(_), Some(_)) => Err(invalid(
            name,
            format!("set either {PREFIX}{name} or {PREFIX}{file_name}, not both"),
        )),
        (Some(path), None) => Ok(Some(SecretKeySource::File(path.into()))),
        (None, Some(value)) => Ok(Some(SecretKeySource::Inline(SecretString::from(value)))),
        (None, None) => Ok(None),
    }
}

/// TLS is required outside development, and a password is never sent
/// without it.
fn smtp_config(
    get: &impl Fn(&str) -> Option<String>,
    environment: Environment,
    raw_url: &str,
) -> Result<SmtpConfig, ConfigError> {
    let allow_plaintext = match get("SMTP_PLAINTEXT").as_deref() {
        None | Some("false") => false,
        Some("true") if environment == Environment::Development => true,
        Some("true") => {
            return Err(invalid(
                "SMTP_PLAINTEXT",
                "plain SMTP is allowed only with SUPABASE_DASHBOARD_ENV=development",
            ));
        }
        Some(_) => return Err(invalid("SMTP_PLAINTEXT", "expected `true` or `false`")),
    };
    let endpoint =
        SmtpEndpoint::parse(raw_url, allow_plaintext).map_err(|e| invalid("SMTP_URL", e))?;
    let password = secret_source(get, "SMTP_PASSWORD")?;
    let credentials = match (get("SMTP_USERNAME"), password) {
        (Some(username), Some(password)) => Some((username, password)),
        (None, None) => None,
        (Some(_), None) => {
            return Err(invalid(
                "SMTP_USERNAME",
                "needs SUPABASE_DASHBOARD_SMTP_PASSWORD_FILE or SUPABASE_DASHBOARD_SMTP_PASSWORD",
            ));
        }
        (None, Some(_)) => {
            return Err(invalid(
                "SMTP_PASSWORD",
                "needs SUPABASE_DASHBOARD_SMTP_USERNAME",
            ));
        }
    };
    if credentials.is_some() && endpoint.security == SmtpSecurity::Plaintext {
        return Err(invalid(
            "SMTP_PLAINTEXT",
            "a password is never sent over plain SMTP; remove the credentials or use TLS",
        ));
    }
    let timeout = secs(bounded(
        get,
        "SMTP_TIMEOUT_SECS",
        DEFAULT_SMTP_TIMEOUT.as_secs(),
        1,
        120,
    )?);
    Ok(SmtpConfig {
        endpoint,
        credentials,
        timeout,
    })
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
    fn health_checks_default_to_every_fifteen_minutes_and_can_be_turned_off() {
        let dev = (("ENV", "development"), DB);
        let config = load(&[dev.0, dev.1]).unwrap();
        assert_eq!(config.health_check_interval, Some(Duration::from_secs(900)));
        let off = load(&[dev.0, dev.1, ("HEALTH_CHECK_INTERVAL_MINS", "0")]).unwrap();
        assert_eq!(off.health_check_interval, None);
        let hourly = load(&[dev.0, dev.1, ("HEALTH_CHECK_INTERVAL_MINS", "60")]).unwrap();
        assert_eq!(
            hourly.health_check_interval,
            Some(Duration::from_secs(3600))
        );
        for bad in ["1", "4", "1441", "soon"] {
            assert!(
                load(&[dev.0, dev.1, ("HEALTH_CHECK_INTERVAL_MINS", bad)]).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_studio_access_log_is_off_unless_given_a_retention() {
        let dev = (("ENV", "development"), DB);
        assert_eq!(load(&[dev.0, dev.1]).unwrap().studio_access_log_days, None);
        let on = load(&[dev.0, dev.1, ("STUDIO_ACCESS_LOG_DAYS", "30")]).unwrap();
        assert_eq!(on.studio_access_log_days, Some(30));
        let off = load(&[dev.0, dev.1, ("STUDIO_ACCESS_LOG_DAYS", "0")]).unwrap();
        assert_eq!(off.studio_access_log_days, None);
        for bad in ["91", "-1", "week"] {
            assert!(
                load(&[dev.0, dev.1, ("STUDIO_ACCESS_LOG_DAYS", bad)]).is_err(),
                "{bad}"
            );
        }
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
    fn previous_keys_need_a_current_key() {
        let dev = ("ENV", "development");
        assert!(
            load(&[DB, dev])
                .unwrap()
                .previous_secret_keys_file
                .is_none()
        );
        let config = load(&[
            DB,
            dev,
            ("SECRET_KEY_FILE", "/run/secrets/key"),
            ("PREVIOUS_SECRET_KEYS_FILE", "/run/secrets/old-keys"),
        ])
        .unwrap();
        assert_eq!(
            config.previous_secret_keys_file,
            Some("/run/secrets/old-keys".into())
        );
        let err = load(&[
            DB,
            dev,
            ("PREVIOUS_SECRET_KEYS_FILE", "/run/secrets/old-keys"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("need a current key"));
    }

    #[test]
    fn extra_authorities_are_read_from_a_file() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev]).unwrap().extra_ca_file.is_none());
        assert_eq!(
            load(&[DB, dev, ("EXTRA_CA_FILE", "/run/secrets/ca.pem")])
                .unwrap()
                .extra_ca_file,
            Some("/run/secrets/ca.pem".into())
        );
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
        // A flat pattern puts Studio hosts next to the dashboard's.
        let hosts = load(&[
            DB,
            ("PUBLIC_URL", "https://dash.example.test"),
            ("STUDIO_DOMAIN", "*-studio.example.test"),
        ])
        .unwrap()
        .studio_hosts
        .unwrap();
        assert_eq!(
            hosts.origin(uuid::Uuid::nil()),
            "https://00000000000000000000000000000000-studio.example.test"
        );
        let err = load(&[
            DB,
            ("PUBLIC_URL", "https://dash-studio.example.test"),
            ("STUDIO_DOMAIN", "*-studio.example.test"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("STUDIO_DOMAIN"), "{err}");
        assert!(load(&[DB, dev, ("STUDIO_REQUEST_TIMEOUT_SECS", "1")]).is_err());
    }

    #[test]
    fn a_dokploy_connection_needs_a_url_a_key_file_and_an_encryption_key() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev]).unwrap().dokploy.is_none());

        let key = ("SECRET_KEY_FILE", "/run/secrets/key");
        let url = ("DOKPLOY_URL", "https://dokploy.example.test/");
        let file = ("DOKPLOY_API_KEY_FILE", "/run/secrets/dokploy");
        let dokploy = load(&[DB, dev, key, url, file]).unwrap().dokploy.unwrap();
        assert_eq!(dokploy.url.as_str(), "https://dokploy.example.test");
        assert_eq!(
            dokploy.key_file,
            std::path::PathBuf::from("/run/secrets/dokploy")
        );

        let refused =
            |pairs: &[(&str, &str)]| matches!(load(pairs), Err(ConfigError::Invalid { .. }));
        assert!(refused(&[DB, dev, key, url]));
        assert!(refused(&[DB, dev, key, file]));
        assert!(refused(&[DB, dev, url, file]));
        assert!(refused(&[
            DB,
            dev,
            key,
            file,
            ("DOKPLOY_URL", "ftp://dokploy.example.test")
        ]));
    }

    fn smtp_of(mail: &MailConfig) -> &SmtpConfig {
        match &mail.transport {
            MailTransport::Smtp(smtp) => smtp,
            MailTransport::Resend(_) => panic!("expected SMTP"),
        }
    }

    #[test]
    fn resend_needs_a_key_from_one_source_and_excludes_smtp() {
        let public = ("PUBLIC_URL", "https://dash.example.test");
        let from = ("MAIL_FROM", "dash@example.test");
        let key = ("RESEND_API_KEY", "re_hunter2");
        let mail = load(&[DB, public, from, key]).unwrap().mail.unwrap();
        let MailTransport::Resend(resend) = &mail.transport else {
            panic!("expected Resend");
        };
        assert_eq!(resend.timeout, DEFAULT_RESEND_TIMEOUT);
        assert!(!format!("{mail:?}").contains("hunter2"));
        let file = ("RESEND_API_KEY_FILE", "/run/secrets/resend");
        let mail = load(&[DB, public, from, file, ("RESEND_TIMEOUT_SECS", "30")])
            .unwrap()
            .mail
            .unwrap();
        assert!(matches!(
            mail.transport,
            MailTransport::Resend(ResendConfig {
                api_key: SecretKeySource::File(_),
                timeout,
            }) if timeout == Duration::from_secs(30)
        ));

        for pairs in [
            vec![DB, public, from, key, file],
            vec![
                DB,
                public,
                from,
                key,
                ("SMTP_URL", "smtps://mail.example.test"),
            ],
            vec![DB, ("ENV", "development"), from, key],
            vec![DB, public, key],
            vec![DB, public, from, ("RESEND_TIMEOUT_SECS", "30")],
            vec![DB, public, from, key, ("SMTP_USERNAME", "dash")],
        ] {
            let err = load(&pairs).unwrap_err();
            assert!(!err.to_string().contains("hunter2"), "{err}");
        }
    }

    #[test]
    fn mail_is_off_by_default_and_needs_an_smtp_url() {
        let dev = ("ENV", "development");
        assert!(load(&[DB, dev]).unwrap().mail.is_none());
        let err = load(&[DB, dev, ("MAIL_FROM", "dash@example.test")]).unwrap_err();
        assert!(err.to_string().contains("SMTP_URL"), "{err}");
        let err = load(&[DB, dev, ("SMTP_PASSWORD", "hunter2")]).unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    #[test]
    fn mail_needs_a_from_address_and_a_public_url() {
        let public = ("PUBLIC_URL", "https://dash.example.test");
        let smtp = ("SMTP_URL", "smtps://mail.example.test");
        let err = load(&[DB, public, smtp]).unwrap_err();
        assert!(err.to_string().contains("MAIL_FROM"), "{err}");
        let err = load(&[DB, ("ENV", "development"), smtp, ("MAIL_FROM", "a@b.test")]).unwrap_err();
        assert!(err.to_string().contains("PUBLIC_URL"), "{err}");
        let err = load(&[DB, public, smtp, ("MAIL_FROM", "nobody")]).unwrap_err();
        assert!(err.to_string().contains("MAIL_FROM"), "{err}");
        let mail = load(&[
            DB,
            public,
            smtp,
            ("MAIL_FROM", "Dashboard <dash@example.test>"),
        ])
        .unwrap()
        .mail
        .unwrap();
        let smtp = smtp_of(&mail);
        assert_eq!(smtp.endpoint.port, 465);
        assert!(smtp.credentials.is_none());
        assert_eq!(smtp.timeout, DEFAULT_SMTP_TIMEOUT);
    }

    #[test]
    fn plain_smtp_only_in_development_and_never_with_a_password() {
        let from = ("MAIL_FROM", "dash@example.test");
        let smtp = ("SMTP_URL", "smtp://localhost:1025");
        let plain = ("SMTP_PLAINTEXT", "true");
        let public = ("PUBLIC_URL", "https://dash.example.test");
        let err = load(&[DB, public, smtp, from, plain]).unwrap_err();
        assert!(err.to_string().contains("development"), "{err}");
        let starttls = load(&[DB, public, smtp, from]).unwrap().mail.unwrap();
        assert_eq!(smtp_of(&starttls).endpoint.security, SmtpSecurity::StartTls);
        let dev = [
            DB,
            ("ENV", "development"),
            ("PUBLIC_URL", "http://localhost:3000"),
            smtp,
            from,
            plain,
        ];
        let mail = load(&dev).unwrap().mail.unwrap();
        assert_eq!(smtp_of(&mail).endpoint.security, SmtpSecurity::Plaintext);
        let mut with_password = dev.to_vec();
        with_password.extend([("SMTP_USERNAME", "dash"), ("SMTP_PASSWORD", "hunter2")]);
        let err = load(&with_password).unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    #[test]
    fn smtp_credentials_come_in_pairs_from_one_source() {
        let with = |url: &'static str, extra: &[(&'static str, &'static str)]| {
            let mut pairs = vec![
                DB,
                ("PUBLIC_URL", "https://dash.example.test"),
                ("SMTP_URL", url),
                ("MAIL_FROM", "dash@example.test"),
            ];
            pairs.extend_from_slice(extra);
            load(&pairs)
        };
        let url = "smtp://mail.example.test";
        with(url, &[("SMTP_USERNAME", "dash")]).unwrap_err();
        with(url, &[("SMTP_PASSWORD_FILE", "/run/secrets/smtp")]).unwrap_err();
        let err = with(
            url,
            &[
                ("SMTP_USERNAME", "dash"),
                ("SMTP_PASSWORD_FILE", "/run/secrets/smtp"),
                ("SMTP_PASSWORD", "hunter2"),
            ],
        )
        .unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        let mail = with(
            url,
            &[("SMTP_USERNAME", "dash"), ("SMTP_PASSWORD", "hunter2")],
        )
        .unwrap()
        .mail
        .unwrap();
        assert!(!format!("{mail:?}").contains("hunter2"));
        let err = with("smtp://dash:hunter2@mail.example.test", &[]).unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        with(url, &[("SMTP_TIMEOUT_SECS", "0")]).unwrap_err();
    }

    #[test]
    fn unknown_environment_is_rejected() {
        assert!(load(&[DB, ("ENV", "staging")]).is_err());
    }
}
