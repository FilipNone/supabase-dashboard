//! Stack settings the dashboard may change on a provisioned stack, and a
//! line model of the dotenv text Dokploy keeps for a compose service.
//!
//! The pinned compose file reads each setting as `${NAME:-default}`, so a
//! stack without the variable keeps the default. Changing a setting
//! rewrites only that variable's line; every other line, including ones
//! the dashboard does not know, is kept as it was.

use serde::{Deserialize, Serialize};

/// What values a setting takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingKind {
    /// `true` or `false`.
    Bool,
    /// Whole seconds in `min..=max`.
    Seconds { min: u32, max: u32 },
    /// One `http://` or `https://` URL.
    Url,
    /// Comma-separated redirect URLs, possibly empty. Each has a scheme
    /// and may use `*` wildcards.
    UrlList,
    /// Comma-separated PostgreSQL schema names, at least one.
    SchemaList,
    /// A host name or IP address, or empty for none.
    Host,
    /// A TCP port, 1 to 65535.
    Port,
    /// An email address, or empty for none.
    EmailAddress,
    /// A login name of plain characters, or empty for none.
    Username,
    /// An OAuth client ID of plain characters, or empty for none.
    ClientId,
}

/// A variable of the pinned stack the dashboard may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackSetting {
    /// The variable's name, also the form field's name.
    pub name: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub kind: SettingKind,
    /// The value the compose file uses when the variable is not set.
    /// `None` when provisioning always sets it.
    pub default: Option<&'static str>,
    /// The compose services that read it; Docker Compose recreates them
    /// when it changes.
    pub services: &'static [&'static str],
}

pub const MAX_REDIRECT_URLS: usize = 20;
pub const MAX_SCHEMAS: usize = 20;
pub const MAX_SETTING_LEN: usize = 2048;

/// Every setting the dashboard may change, in display order.
pub const STACK_SETTINGS: [StackSetting; 11] = [
    StackSetting {
        name: "SITE_URL",
        label: "Site URL",
        help: "Where Auth sends users after they confirm an email or sign in, unless the request names an allowed redirect URL.",
        kind: SettingKind::Url,
        default: None,
        services: &["auth"],
    },
    StackSetting {
        name: "ADDITIONAL_REDIRECT_URLS",
        label: "Additional redirect URLs",
        help: "Comma-separated URLs Auth may redirect to besides the site URL. Use * as a wildcard, for example https://*.example.com/**.",
        kind: SettingKind::UrlList,
        default: Some(""),
        services: &["auth"],
    },
    StackSetting {
        name: "DISABLE_SIGNUP",
        label: "Disable sign-ups",
        help: "Nobody can create an account through the API. Existing users still sign in, and the service role can still create users.",
        kind: SettingKind::Bool,
        default: Some("true"),
        services: &["auth"],
    },
    StackSetting {
        name: "ENABLE_EMAIL_AUTOCONFIRM",
        label: "Confirm email addresses automatically",
        help: "Users who sign up with an email can sign in without confirming it. Before turning this off, set up the stack's mail server below; without one, nobody can confirm.",
        kind: SettingKind::Bool,
        default: Some("true"),
        services: &["auth"],
    },
    StackSetting {
        name: "ENABLE_ANONYMOUS_USERS",
        label: "Allow anonymous sign-ins",
        help: "Clients can create anonymous users that later link an email or provider.",
        kind: SettingKind::Bool,
        default: Some("false"),
        services: &["auth"],
    },
    StackSetting {
        name: "JWT_EXPIRY",
        label: "Access token lifetime (seconds)",
        help: "How long an access token Auth issues stays valid, from 30 seconds to 7 days.",
        kind: SettingKind::Seconds {
            min: 30,
            max: 604_800,
        },
        default: Some("3600"),
        services: &["auth"],
    },
    StackSetting {
        name: "PGRST_DB_SCHEMAS",
        label: "Exposed schemas",
        help: "Comma-separated schemas the REST API serves. Studio's API docs read the same list. Each must exist in the database: the REST API does not start with one that does not.",
        kind: SettingKind::SchemaList,
        default: Some("public,storage,graphql_public"),
        services: &["rest", "studio"],
    },
    StackSetting {
        name: "SMTP_HOST",
        label: "Mail server host",
        help: "The SMTP server Auth sends confirmation, magic link, invitation, and password recovery emails through. Empty means the stack sends no email.",
        kind: SettingKind::Host,
        default: Some(""),
        services: &["auth"],
    },
    StackSetting {
        name: "SMTP_PORT",
        label: "Mail server port",
        help: "Usually 587 (STARTTLS) or 465 (TLS).",
        kind: SettingKind::Port,
        default: Some("587"),
        services: &["auth"],
    },
    StackSetting {
        name: "SMTP_USER",
        label: "Mail server username",
        help: "Leave empty when the server needs no login. The password is the next field.",
        kind: SettingKind::Username,
        default: Some(""),
        services: &["auth"],
    },
    StackSetting {
        name: "SMTP_ADMIN_EMAIL",
        label: "Sender address",
        help: "The From address of the emails Auth sends. The mail server must accept it.",
        kind: SettingKind::EmailAddress,
        default: Some(""),
        services: &["auth"],
    },
];

/// A variable of the pinned stack that holds a secret. Owners and admins
/// may replace or remove it, but the dashboard never shows it: the page
/// learns only whether it is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretSetting {
    /// The variable's name, also the form field's name.
    pub name: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    /// The label of the box that removes the value.
    pub remove_label: &'static str,
    /// The compose services that read it; Docker Compose recreates them
    /// when it changes. The compose file's default is always empty.
    pub services: &'static [&'static str],
}

/// The secret settings other than the sign-in providers' secrets, in
/// display order. [`secret_settings`] lists them all.
pub const SECRET_SETTINGS: [SecretSetting; 1] = [SecretSetting {
    name: "SMTP_PASS",
    label: "Mail server password",
    help: "Leave empty to keep the current password. The dashboard writes it to Dokploy and never shows it again. Passwords with spaces, quotes, $, #, backslashes, or backticks must be set in Dokploy.",
    remove_label: "Remove the password",
    services: &["auth"],
}];

/// An external OAuth sign-in provider of Auth. The pinned compose file
/// passes `<KEY>_ENABLED`, `<KEY>_CLIENT_ID`, and `<KEY>_SECRET` to GoTrue
/// as `GOTRUE_EXTERNAL_<KEY>_ENABLED`, `_CLIENT_ID`, and `_SECRET`, and
/// sets `_REDIRECT_URI` to the stack's public URL and
/// [`AUTH_CALLBACK_PATH`]. Only providers that need nothing else are
/// listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthProvider {
    /// The variables' prefix, such as `GITHUB`.
    pub key: &'static str,
    /// The provider's name, such as `GitHub`.
    pub label: &'static str,
    /// Where the operator registers the OAuth app.
    pub help: &'static str,
    pub enabled: StackSetting,
    pub client_id: StackSetting,
    pub secret: SecretSetting,
}

/// Where Auth receives the providers' answers, under the stack's public
/// URL. The gateway serves Auth under `/auth/v1`.
pub const AUTH_CALLBACK_PATH: &str = "/auth/v1/callback";

/// Longest OAuth client ID.
pub const MAX_CLIENT_ID_LEN: usize = 256;

macro_rules! auth_provider {
    ($key:literal, $label:literal, $help:literal) => {
        AuthProvider {
            key: $key,
            label: $label,
            help: $help,
            enabled: StackSetting {
                name: concat!($key, "_ENABLED"),
                label: concat!($label, " sign-in"),
                help: concat!(
                    "Users can sign in with their ",
                    $label,
                    " account. Turning it on needs the client ID and the client secret."
                ),
                kind: SettingKind::Bool,
                default: Some("false"),
                services: &["auth"],
            },
            client_id: StackSetting {
                name: concat!($key, "_CLIENT_ID"),
                label: concat!($label, " client ID"),
                help: concat!("The client ID of the stack's OAuth app on ", $label, "."),
                kind: SettingKind::ClientId,
                default: Some(""),
                services: &["auth"],
            },
            secret: SecretSetting {
                name: concat!($key, "_SECRET"),
                label: concat!($label, " client secret"),
                help: "Leave empty to keep the current secret. The dashboard writes it to Dokploy and never shows it again. Secrets with spaces, quotes, $, #, backslashes, or backticks must be set in Dokploy.",
                remove_label: "Remove the client secret",
                services: &["auth"],
            },
        }
    };
}

/// The sign-in providers the dashboard sets up, in display order. Adding
/// one that needs only a client ID and a secret is one line here and four
/// lines in the pinned compose file.
pub const AUTH_PROVIDERS: [AuthProvider; 2] = [
    auth_provider!(
        "GITHUB",
        "GitHub",
        "Register an OAuth app on GitHub under Settings, Developer settings, OAuth Apps, with the callback URL below."
    ),
    auth_provider!(
        "GOOGLE",
        "Google",
        "Create an OAuth client ID of type Web application in the Google Cloud console under APIs & Services, Credentials, with the callback URL below as an authorized redirect URI."
    ),
];

/// The provider whose variables start with `key`.
pub fn auth_provider(key: &str) -> Option<&'static AuthProvider> {
    AUTH_PROVIDERS.iter().find(|provider| provider.key == key)
}

/// Every plain setting, in display order: [`STACK_SETTINGS`], then each
/// provider's toggle and client ID.
pub fn stack_settings() -> impl Iterator<Item = &'static StackSetting> {
    STACK_SETTINGS.iter().chain(
        AUTH_PROVIDERS
            .iter()
            .flat_map(|provider| [&provider.enabled, &provider.client_id]),
    )
}

/// Every secret setting, in display order: [`SECRET_SETTINGS`], then each
/// provider's client secret.
pub fn secret_settings() -> impl Iterator<Item = &'static SecretSetting> {
    SECRET_SETTINGS
        .iter()
        .chain(AUTH_PROVIDERS.iter().map(|provider| &provider.secret))
}

/// The URL to register with the providers for a stack served at
/// `public_url`, or `None` when that is not a plain `http://` or
/// `https://` URL.
pub fn auth_callback_url(public_url: &str) -> Option<String> {
    let public_url = public_url.trim_end_matches('/');
    is_plain_url(public_url).then(|| format!("{public_url}{AUTH_CALLBACK_PATH}"))
}

impl AuthProvider {
    /// Refuses a provider that would be on without a client ID or a client
    /// secret. `client_id` is the ID in effect after the change; `None`
    /// when the dashboard cannot read it, which counts as set, as does a
    /// secret it cannot read.
    pub fn check(
        &self,
        enabled: bool,
        client_id: Option<&str>,
        secret_set: bool,
    ) -> Result<(), SettingError> {
        let id_set = client_id.is_none_or(|id| !id.trim().is_empty());
        if enabled && !(id_set && secret_set) {
            Err(SettingError::ProviderIncomplete { label: self.label })
        } else {
            Ok(())
        }
    }
}

/// Longest secret setting value.
pub const MAX_SECRET_LEN: usize = 512;

/// Longest host name, per DNS.
pub const MAX_HOST_LEN: usize = 253;
/// Longest email address.
pub const MAX_EMAIL_LEN: usize = 254;
/// Longest SMTP username.
pub const MAX_USERNAME_LEN: usize = 256;

/// The setting named `name`.
pub fn stack_setting(name: &str) -> Option<&'static StackSetting> {
    stack_settings().find(|setting| setting.name == name)
}

/// The secret setting named `name`.
pub fn secret_setting(name: &str) -> Option<&'static SecretSetting> {
    secret_settings().find(|setting| setting.name == name)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingError {
    #[error("{label}: choose on or off")]
    Bool { label: &'static str },
    #[error("{label}: enter whole seconds from {min} to {max}")]
    Seconds {
        label: &'static str,
        min: u32,
        max: u32,
    },
    #[error(
        "{label}: enter an http:// or https:// URL without a trailing slash, quotes, $, #, or spaces"
    )]
    Url { label: &'static str },
    #[error(
        "{label}: enter at most {MAX_REDIRECT_URLS} URLs, each with a scheme such as https://, separated by commas, without quotes, $, #, or spaces"
    )]
    UrlList { label: &'static str },
    #[error(
        "{label}: enter 1 to {MAX_SCHEMAS} schema names of lowercase letters, digits, and underscores, separated by commas"
    )]
    SchemaList { label: &'static str },
    #[error(
        "{label}: enter a host name such as smtp.example.com or an IP address, or leave it empty"
    )]
    Host { label: &'static str },
    #[error("{label}: enter a port from 1 to 65535")]
    Port { label: &'static str },
    #[error(
        "{label}: enter an email address without spaces, quotes, $, #, or backslashes, or leave it empty"
    )]
    EmailAddress { label: &'static str },
    #[error(
        "{label}: enter at most {MAX_USERNAME_LEN} characters without spaces, quotes, $, #, or backslashes, or leave it empty"
    )]
    Username { label: &'static str },
    #[error(
        "{label}: enter at most {MAX_CLIENT_ID_LEN} characters without spaces, quotes, $, #, or backslashes, or leave it empty"
    )]
    ClientId { label: &'static str },
    /// The value is never part of the message.
    #[error(
        "{label}: enter 1 to {MAX_SECRET_LEN} characters without spaces, quotes, $, #, backslashes, or backticks; set a value with those in Dokploy"
    )]
    Secret { label: &'static str },
    #[error(
        "{label} sign-in: enter a client ID and a client secret before turning it on, or leave it off"
    )]
    ProviderIncomplete { label: &'static str },
}

impl StackSetting {
    /// The value to write for `raw`, or why it is refused. Values never
    /// contain spaces, quotes, `$`, `#`, `\`, or line breaks, so they are
    /// written unquoted and Docker Compose reads them literally.
    pub fn normalize(&self, raw: &str) -> Result<String, SettingError> {
        let label = self.label;
        let raw = raw.trim();
        match self.kind {
            SettingKind::Bool => match raw {
                "true" | "false" => Ok(raw.to_owned()),
                _ => Err(SettingError::Bool { label }),
            },
            SettingKind::Seconds { min, max } => raw
                .parse::<u32>()
                .ok()
                .filter(|value| (min..=max).contains(value) && raw.len() <= 7)
                .map(|value| value.to_string())
                .ok_or(SettingError::Seconds { label, min, max }),
            SettingKind::Url => {
                if is_plain_url(raw) {
                    Ok(raw.to_owned())
                } else {
                    Err(SettingError::Url { label })
                }
            }
            SettingKind::UrlList => {
                let urls: Vec<&str> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|url| !url.is_empty())
                    .collect();
                let joined = urls.join(",");
                if urls.len() <= MAX_REDIRECT_URLS
                    && joined.len() <= MAX_SETTING_LEN
                    && urls.iter().all(|url| is_redirect_url(url))
                {
                    Ok(joined)
                } else {
                    Err(SettingError::UrlList { label })
                }
            }
            SettingKind::SchemaList => {
                let schemas: Vec<&str> = raw.split(',').map(str::trim).collect();
                let unique = schemas
                    .iter()
                    .enumerate()
                    .all(|(i, schema)| !schemas[..i].contains(schema));
                if (1..=MAX_SCHEMAS).contains(&schemas.len())
                    && unique
                    && schemas.iter().all(|schema| is_schema_name(schema))
                {
                    Ok(schemas.join(","))
                } else {
                    Err(SettingError::SchemaList { label })
                }
            }
            SettingKind::Host => {
                if raw.is_empty() || is_host(raw) {
                    Ok(raw.to_ascii_lowercase())
                } else {
                    Err(SettingError::Host { label })
                }
            }
            SettingKind::Port => raw
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0 && raw.len() <= 5)
                .map(|port| port.to_string())
                .ok_or(SettingError::Port { label }),
            SettingKind::EmailAddress => {
                if raw.is_empty() || is_email(raw) {
                    Ok(raw.to_owned())
                } else {
                    Err(SettingError::EmailAddress { label })
                }
            }
            SettingKind::Username => {
                if raw.len() <= MAX_USERNAME_LEN && raw.bytes().all(is_plain_char) {
                    Ok(raw.to_owned())
                } else {
                    Err(SettingError::Username { label })
                }
            }
            SettingKind::ClientId => {
                if raw.len() <= MAX_CLIENT_ID_LEN && raw.bytes().all(is_plain_char) {
                    Ok(raw.to_owned())
                } else {
                    Err(SettingError::ClientId { label })
                }
            }
        }
    }

    /// Whether `compose_file` reads this setting's variable.
    pub fn read_by(&self, compose_file: &str) -> bool {
        compose_reads(compose_file, self.name)
    }
}

impl SecretSetting {
    /// Checks a new value without changing it: values are written as
    /// typed, unquoted, so they hold only visible ASCII other than quotes,
    /// `$`, `#`, `\`, and backtick. The error never holds the value.
    pub fn check(&self, value: &str) -> Result<(), SettingError> {
        if (1..=MAX_SECRET_LEN).contains(&value.len()) && value.bytes().all(is_plain_char) {
            Ok(())
        } else {
            Err(SettingError::Secret { label: self.label })
        }
    }

    /// Whether `compose_file` reads this setting's variable.
    pub fn read_by(&self, compose_file: &str) -> bool {
        compose_reads(compose_file, self.name)
    }
}

/// Whether `compose_file` reads `name` as `${NAME}` or `${NAME:-...}`.
fn compose_reads(compose_file: &str, name: &str) -> bool {
    compose_file.match_indices("${").any(|(at, _)| {
        let rest = &compose_file[at + 2..];
        rest.strip_prefix(name)
            .is_some_and(|after| after.starts_with('}') || after.starts_with(":-"))
    })
}

/// Characters allowed in an unquoted value: visible ASCII other than
/// quotes, `$`, `#`, `\`, and backtick.
fn is_plain_char(b: u8) -> bool {
    b.is_ascii_graphic() && !matches!(b, b'$' | b'"' | b'\'' | b'#' | b'\\' | b'`')
}

/// An `http://` or `https://` URL of plain characters, with something
/// after the scheme and no trailing slash.
pub fn is_plain_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    matches!(rest, Some(rest) if !rest.is_empty())
        && url.len() <= MAX_SETTING_LEN
        && !url.ends_with('/')
        && url.bytes().all(is_plain_char)
}

/// `scheme://rest` of plain characters other than commas.
fn is_redirect_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let mut scheme_bytes = scheme.bytes();
    scheme_bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && scheme_bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
        && !rest.is_empty()
        && url.bytes().all(|b| is_plain_char(b) && b != b',')
}

/// A DNS name of letter, digit, and hyphen labels, or an IPv4 address.
/// IPv6 literals are not accepted: GoTrue joins host and port with a colon.
fn is_host(host: &str) -> bool {
    host.len() <= MAX_HOST_LEN
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `local@domain` of plain characters, where the domain is a host name.
fn is_email(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    address.len() <= MAX_EMAIL_LEN
        && !local.is_empty()
        && local
            .bytes()
            .all(|b| is_plain_char(b) && b != b'@' && b != b',')
        && is_host(domain)
}

fn is_schema_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && name.len() <= 63
}

/// A variable's current value in the service's variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvValue<'a> {
    /// Not set; the compose file's default applies.
    Missing,
    Set(&'a str),
    /// Set more than once, quoted with escapes, or using `$`, so the
    /// dashboard cannot tell what Docker Compose reads and will not
    /// change it.
    Unreadable,
}

/// Dokploy's variables of a compose service, one entry per line. Only
/// [`Self::set`] changes anything, and only the line of the variable it
/// sets; [`Self::to_text`] gives back every other line unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    lines: Vec<String>,
}

impl EnvFile {
    pub fn parse(text: &str) -> Self {
        let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        Self { lines }
    }

    /// The name and raw value of a `NAME=value` line, ignoring comments
    /// and a leading `export `.
    fn entry(line: &str) -> Option<(&str, &str)> {
        let line = line.trim_start();
        if line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line.split_once('=')?;
        let name = name.trim_end();
        let mut bytes = name.bytes();
        let valid = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
        valid.then_some((name, value))
    }

    pub fn get(&self, name: &str) -> EnvValue<'_> {
        let mut found = self
            .lines
            .iter()
            .filter_map(|line| Self::entry(line))
            .filter(|(entry, _)| *entry == name)
            .map(|(_, value)| value);
        let Some(raw) = found.next() else {
            return EnvValue::Missing;
        };
        if found.next().is_some() {
            return EnvValue::Unreadable;
        }
        let raw = raw.trim_end_matches('\r').trim();
        let unquoted = ['"', '\'']
            .iter()
            .find_map(|q| raw.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
            .unwrap_or(raw);
        let plain = |v: &str| {
            !v.bytes()
                .any(|b| matches!(b, b'"' | b'\'' | b'\\' | b'$' | b'`'))
        };
        if plain(unquoted) && !unquoted.contains(" #") {
            EnvValue::Set(unquoted)
        } else {
            EnvValue::Unreadable
        }
    }

    /// Sets `name` to `value`, replacing its only line or adding one at
    /// the end. `value` comes from [`StackSetting::normalize`]; refused
    /// when the current value is [`EnvValue::Unreadable`].
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), UnreadableVariable> {
        match self.get(name) {
            EnvValue::Unreadable => Err(UnreadableVariable),
            EnvValue::Missing => {
                self.lines.push(format!("{name}={value}"));
                Ok(())
            }
            EnvValue::Set(_) => {
                for line in &mut self.lines {
                    if Self::entry(line).is_some_and(|(entry, _)| entry == name) {
                        *line = format!("{name}={value}");
                    }
                }
                Ok(())
            }
        }
    }

    /// Every variable with its raw values as written, in line order; a
    /// variable set on several lines has several. Comments are skipped.
    pub fn raw_values(&self) -> std::collections::BTreeMap<&str, Vec<&str>> {
        let mut values: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for (name, value) in self.lines.iter().filter_map(|line| Self::entry(line)) {
            values
                .entry(name)
                .or_default()
                .push(value.trim_end_matches('\r'));
        }
        values
    }

    pub fn to_text(&self) -> String {
        let mut text = self.lines.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        text
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the variable's current value cannot be read safely")]
pub struct UnreadableVariable;

/// Whether a setting can be changed on a stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingState {
    Editable,
    /// The stack's compose file does not read the variable; it was made
    /// before the dashboard could change it, or edited in Dokploy.
    NotInComposeFile,
    /// The variable is set in a form the dashboard will not rewrite.
    Unreadable,
}

/// One setting as an owner or admin sees it. Settings hold no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackSettingView {
    pub name: String,
    pub label: String,
    pub help: String,
    pub kind: SettingKind,
    /// The value in effect: the variable's, or the compose file's
    /// default when it is not set. `None` when not known, such as a
    /// value the compose file sets itself.
    pub value: Option<String>,
    pub state: SettingState,
}

/// One secret setting as an owner or admin sees it: whether it is set,
/// never its value or length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSettingView {
    pub name: String,
    pub label: String,
    pub help: String,
    pub remove_label: String,
    /// The variable has a value other than empty. A value the dashboard
    /// cannot read ([`SettingState::Unreadable`]) counts as set.
    pub set: bool,
    pub state: SettingState,
}

/// A sign-in provider as an owner or admin sees it. Its settings are in
/// [`StackSettingsView::settings`] and [`StackSettingsView::secrets`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProviderView {
    /// [`AuthProvider::key`].
    pub key: String,
    pub label: String,
    pub help: String,
    /// The callback URL to register with the provider, `None` when the
    /// stack's public URL cannot be read.
    pub callback_url: Option<String>,
}

/// A provisioned stack's settings, read from Dokploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackSettingsView {
    pub settings: Vec<StackSettingView>,
    /// The secret settings, after the others.
    pub secrets: Vec<SecretSettingView>,
    /// The sign-in providers, whose settings are among the others.
    pub providers: Vec<AuthProviderView>,
    /// An action on the stack is unfinished, so changes are refused.
    pub busy: bool,
    /// Variables edited in Dokploy since the dashboard wrote them.
    pub tracking: EnvTracking,
}

/// What applying the submitted settings would change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackConfigPreview {
    /// The changed variables' names, in display order, secret settings
    /// last. Values are not repeated here.
    pub changed: Vec<String>,
    /// The changed secret settings, also in `changed`.
    pub secrets: Vec<ChangedSecret>,
    /// The compose services Docker Compose recreates, sorted.
    pub restarts: Vec<String>,
    /// A digest of the settings' current values; applying is refused
    /// when they changed since. For a secret setting it covers only
    /// whether the variable is set, never its value, because the page
    /// holds the digest.
    pub base: String,
}

/// A secret setting a change writes, by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedSecret {
    pub name: String,
    /// The change removes the value instead of replacing it.
    pub removed: bool,
}

/// Variables changed in Dokploy since the dashboard last wrote the
/// stack's variables, by name. Values are never included.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvChanges {
    /// Set by the dashboard and changed since, sorted.
    pub changed: Vec<String>,
    /// Not set by the dashboard, sorted.
    pub added: Vec<String>,
    /// Set by the dashboard and no longer set, sorted.
    pub removed: Vec<String>,
}

impl EnvChanges {
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }
}

/// Whether variables were edited in Dokploy, as far as the dashboard
/// can tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvTracking {
    /// The dashboard keeps no record of what it wrote, as for stacks
    /// provisioned before it kept one.
    NotRecorded,
    /// The record is sealed under a credential key this server lacks.
    Unreadable,
    Compared(EnvChanges),
}

/// The longest [`EnvTracking::seen`] text the server takes back.
pub const ENV_SEEN_MAX_LEN: usize = 16 * 1024;

impl EnvTracking {
    /// What the operator was shown, as text the page sends back when they
    /// accept the variables as Dokploy has them: the listed names, never
    /// a value or a digest of one. The server accepts only when it still
    /// finds the same, so an edit made in Dokploy after the page was read
    /// is not accepted unseen. Variable names hold no `,`, `;`, or `=`.
    pub fn seen(&self) -> String {
        match self {
            Self::NotRecorded => "none".to_owned(),
            Self::Unreadable => "unreadable".to_owned(),
            Self::Compared(changes) => format!(
                "changed={};added={};removed={}",
                changes.changed.join(","),
                changes.added.join(","),
                changes.removed.join(",")
            ),
        }
    }

    /// Whether accepting would change anything.
    pub fn has_edits(&self) -> bool {
        !matches!(self, Self::Compared(changes) if changes.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_lists_names_only() {
        let tracking = EnvTracking::Compared(EnvChanges {
            changed: vec!["A".into(), "B".into()],
            added: vec![],
            removed: vec!["C".into()],
        });
        assert_eq!(tracking.seen(), "changed=A,B;added=;removed=C");
        assert!(tracking.has_edits());
        assert!(!EnvTracking::Compared(EnvChanges::default()).has_edits());
        assert_eq!(EnvTracking::NotRecorded.seen(), "none");
        assert!(EnvTracking::Unreadable.has_edits());
    }

    #[test]
    fn raw_values_keep_every_line_of_a_variable() {
        let env = EnvFile::parse("# note\nA=1\r\nexport B = \"x\"\nA=2\nnot a line\n");
        let values = env.raw_values();
        assert_eq!(values.get("A"), Some(&vec!["1", "2"]));
        assert_eq!(values.get("B"), Some(&vec![" \"x\""]));
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn values_are_normalized_or_refused() {
        let jwt = stack_setting("JWT_EXPIRY").unwrap();
        assert_eq!(jwt.normalize(" 0600 ").unwrap(), "600");
        assert!(jwt.normalize("29").is_err());
        assert!(jwt.normalize("604801").is_err());
        assert!(jwt.normalize("1e3").is_err());
        let toggle = stack_setting("DISABLE_SIGNUP").unwrap();
        assert_eq!(toggle.normalize("false").unwrap(), "false");
        assert!(toggle.normalize("no").is_err());
        let site = stack_setting("SITE_URL").unwrap();
        assert!(site.normalize("https://app.example.com").is_ok());
        for bad in [
            "https://a.example.com/",
            "ftp://x",
            "https://a b",
            "https://x/$HOME",
            "https://x\ny",
        ] {
            assert!(site.normalize(bad).is_err(), "{bad:?}");
        }
        let redirects = stack_setting("ADDITIONAL_REDIRECT_URLS").unwrap();
        assert_eq!(redirects.normalize("").unwrap(), "");
        assert_eq!(
            redirects
                .normalize(" https://*.example.com/** , myapp://callback,")
                .unwrap(),
            "https://*.example.com/**,myapp://callback"
        );
        assert!(redirects.normalize("example.com").is_err());
        assert!(redirects.normalize("https://x/'a'").is_err());
        let schemas = stack_setting("PGRST_DB_SCHEMAS").unwrap();
        assert_eq!(schemas.normalize("public, api").unwrap(), "public,api");
        for bad in ["", "public,public", "Public", "public;drop", "a,,b"] {
            assert!(schemas.normalize(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mail_server_values_are_normalized_or_refused() {
        let host = stack_setting("SMTP_HOST").unwrap();
        assert_eq!(host.normalize("").unwrap(), "");
        assert_eq!(
            host.normalize(" SMTP.Example.com ").unwrap(),
            "smtp.example.com"
        );
        assert_eq!(host.normalize("10.0.0.25").unwrap(), "10.0.0.25");
        assert_eq!(host.normalize("mailpit").unwrap(), "mailpit");
        for bad in [
            "smtp.example.com:587",
            "smtp://x",
            "-x.example.com",
            "a..b",
            "::1",
            "x y",
            "x$y",
        ] {
            assert!(host.normalize(bad).is_err(), "{bad:?}");
        }
        assert!(host.normalize(&"a.".repeat(127)).is_err());
        let port = stack_setting("SMTP_PORT").unwrap();
        assert_eq!(port.normalize("0465").unwrap(), "465");
        for bad in ["", "0", "65536", "587a", "-1"] {
            assert!(port.normalize(bad).is_err(), "{bad:?}");
        }
        let from = stack_setting("SMTP_ADMIN_EMAIL").unwrap();
        assert_eq!(from.normalize("").unwrap(), "");
        assert_eq!(
            from.normalize("no-reply+auth@example.com").unwrap(),
            "no-reply+auth@example.com"
        );
        for bad in [
            "Name <a@example.com>",
            "a@@example.com",
            "@example.com",
            "a@",
            "a\"b@example.com",
            "a@exa mple.com",
        ] {
            assert!(from.normalize(bad).is_err(), "{bad:?}");
        }
        let user = stack_setting("SMTP_USER").unwrap();
        assert_eq!(user.normalize("").unwrap(), "");
        assert_eq!(user.normalize("apikey").unwrap(), "apikey");
        assert_eq!(
            user.normalize("ops@example.com").unwrap(),
            "ops@example.com"
        );
        for bad in ["a b", "a$b", "a#b", "a'b"] {
            assert!(user.normalize(bad).is_err(), "{bad:?}");
        }
        assert!(user.normalize(&"u".repeat(MAX_USERNAME_LEN + 1)).is_err());
    }

    #[test]
    fn secret_values_are_checked_and_never_echoed() {
        let pass = secret_setting("SMTP_PASS").unwrap();
        assert!(stack_setting("SMTP_PASS").is_none());
        for good in ["x", "SG.abc-123_def+/=", "p@ss:w0rd!%&*()[]{}<>?~^|;,."] {
            assert_eq!(pass.check(good), Ok(()), "{good:?}");
        }
        assert_eq!(pass.check(&"a".repeat(MAX_SECRET_LEN)), Ok(()));
        let long = "a".repeat(MAX_SECRET_LEN + 1);
        for bad in [
            "",
            " ",
            "two words",
            " leading",
            "trailing ",
            "pa$$word",
            "pass#word",
            "it's",
            "say\"hi\"",
            "back\\slash",
            "back`tick",
            "line\nbreak",
            "tab\there",
            "caf\u{e9}",
            long.as_str(),
        ] {
            let err = pass.check(bad).unwrap_err();
            assert_eq!(err, SettingError::Secret { label: pass.label });
            if !bad.trim().is_empty() {
                assert!(!err.to_string().contains(bad), "{bad:?}");
            }
        }
    }

    #[test]
    fn secret_settings_are_not_plain_settings() {
        for secret in secret_settings() {
            assert!(stack_setting(secret.name).is_none(), "{}", secret.name);
            assert!(!secret.services.is_empty(), "{}", secret.name);
        }
        let pass = secret_setting("SMTP_PASS").unwrap();
        assert!(pass.read_by("x: ${SMTP_PASS:-}"));
        assert!(!pass.read_by("x: ${SMTP_PASSWORD:-}"));
    }

    #[test]
    fn providers_have_their_variables_and_labels() {
        let github = auth_provider("GITHUB").unwrap();
        assert_eq!(github.enabled.name, "GITHUB_ENABLED");
        assert_eq!(github.client_id.name, "GITHUB_CLIENT_ID");
        assert_eq!(github.secret.name, "GITHUB_SECRET");
        assert_eq!(github.client_id.label, "GitHub client ID");
        assert_eq!(
            stack_setting("GOOGLE_ENABLED"),
            Some(&AUTH_PROVIDERS[1].enabled)
        );
        assert_eq!(
            stack_setting("GOOGLE_CLIENT_ID"),
            Some(&AUTH_PROVIDERS[1].client_id)
        );
        assert_eq!(
            secret_setting("GOOGLE_SECRET"),
            Some(&AUTH_PROVIDERS[1].secret)
        );
        assert!(stack_setting("GOOGLE_SECRET").is_none());
        assert!(auth_provider("github").is_none());
        // Names are unique across every setting.
        let mut names: Vec<&str> = stack_settings()
            .map(|s| s.name)
            .chain(secret_settings().map(|s| s.name))
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(
            count,
            STACK_SETTINGS.len() + SECRET_SETTINGS.len() + 3 * AUTH_PROVIDERS.len()
        );
    }

    #[test]
    fn client_ids_are_plain_and_bounded() {
        let id = stack_setting("GOOGLE_CLIENT_ID").unwrap();
        assert_eq!(id.normalize("").unwrap(), "");
        assert_eq!(
            id.normalize(" 1234-abc.apps.googleusercontent.com ")
                .unwrap(),
            "1234-abc.apps.googleusercontent.com"
        );
        assert_eq!(id.normalize("Iv1.0123abcd").unwrap(), "Iv1.0123abcd");
        for bad in ["a b", "a$b", "a#b", "a'b", "a\\b", "caf\u{e9}"] {
            assert_eq!(
                id.normalize(bad),
                Err(SettingError::ClientId { label: id.label }),
                "{bad:?}"
            );
        }
        assert!(id.normalize(&"i".repeat(MAX_CLIENT_ID_LEN)).is_ok());
        assert!(id.normalize(&"i".repeat(MAX_CLIENT_ID_LEN + 1)).is_err());
        let secret = secret_setting("GITHUB_SECRET").unwrap();
        assert_eq!(
            secret.check("0123456789abcdef0123456789abcdef01234567"),
            Ok(())
        );
        let err = secret.check("has space").unwrap_err();
        assert!(!err.to_string().contains("has space"));
        assert!(err.to_string().starts_with("GitHub client secret: "));
    }

    #[test]
    fn a_provider_is_not_turned_on_without_its_id_and_secret() {
        let github = auth_provider("GITHUB").unwrap();
        assert_eq!(github.check(true, Some("id"), true), Ok(()));
        assert_eq!(github.check(false, Some(""), false), Ok(()));
        assert_eq!(github.check(false, Some("id"), false), Ok(()));
        let incomplete = Err(SettingError::ProviderIncomplete { label: "GitHub" });
        assert_eq!(github.check(true, Some(""), true), incomplete);
        assert_eq!(github.check(true, Some("  "), true), incomplete);
        assert_eq!(github.check(true, Some("id"), false), incomplete);
        assert_eq!(github.check(true, Some(""), false), incomplete);
        // An ID the dashboard cannot read counts as set.
        assert_eq!(github.check(true, None, true), Ok(()));
        assert!(
            SettingError::ProviderIncomplete { label: "GitHub" }
                .to_string()
                .starts_with("GitHub sign-in: enter a client ID and a client secret")
        );
    }

    #[test]
    fn the_callback_url_is_under_the_public_url() {
        assert_eq!(
            auth_callback_url("https://api.example.com").as_deref(),
            Some("https://api.example.com/auth/v1/callback")
        );
        assert_eq!(
            auth_callback_url("http://10.0.0.5:8000/").as_deref(),
            Some("http://10.0.0.5:8000/auth/v1/callback")
        );
        for bad in [
            "",
            "api.example.com",
            "https://",
            "https://a b",
            "javascript:x",
        ] {
            assert_eq!(auth_callback_url(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_setting_is_read_only_through_its_own_variable() {
        let jwt = stack_setting("JWT_EXPIRY").unwrap();
        assert!(jwt.read_by("x: ${JWT_EXPIRY:-3600}"));
        assert!(jwt.read_by("x: ${JWT_EXPIRY}"));
        assert!(!jwt.read_by("x: ${JWT_EXPIRY_MS:-1}"));
        assert!(!jwt.read_by("x: $JWT_EXPIRY"));
    }

    #[test]
    fn setting_a_variable_keeps_every_other_line() {
        let text = "# keys\nJWT_SECRET=abc\nexport SITE_URL=\"https://old.example.com\"\nCUSTOM=1 # note\n";
        let mut env = EnvFile::parse(text);
        assert_eq!(
            env.get("SITE_URL"),
            EnvValue::Set("https://old.example.com")
        );
        assert_eq!(env.get("DISABLE_SIGNUP"), EnvValue::Missing);
        env.set("SITE_URL", "https://new.example.com").unwrap();
        env.set("DISABLE_SIGNUP", "false").unwrap();
        assert_eq!(
            env.to_text(),
            "# keys\nJWT_SECRET=abc\nSITE_URL=https://new.example.com\nCUSTOM=1 # note\nDISABLE_SIGNUP=false\n"
        );
    }

    #[test]
    fn values_the_dashboard_cannot_read_are_not_rewritten() {
        let mut env = EnvFile::parse("A=1\nA=2\nB=${A}\nC=\"x\\\"y\"\nD= plain \n");
        for name in ["A", "B", "C"] {
            assert_eq!(env.get(name), EnvValue::Unreadable, "{name}");
            assert_eq!(env.set(name, "3"), Err(UnreadableVariable));
        }
        assert_eq!(env.get("D"), EnvValue::Set("plain"));
        assert_eq!(EnvFile::parse("").to_text(), "");
    }
}
