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
pub const STACK_SETTINGS: [StackSetting; 7] = [
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
        help: "Users who sign up with an email can sign in without confirming it. The stack has no mail server configured, so turning this off means nobody can confirm.",
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
];

/// The setting named `name`.
pub fn stack_setting(name: &str) -> Option<&'static StackSetting> {
    STACK_SETTINGS.iter().find(|setting| setting.name == name)
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
        }
    }

    /// Whether `compose_file` reads this setting's variable.
    pub fn read_by(&self, compose_file: &str) -> bool {
        compose_file.match_indices("${").any(|(at, _)| {
            let rest = &compose_file[at + 2..];
            rest.strip_prefix(self.name)
                .is_some_and(|after| after.starts_with('}') || after.starts_with(":-"))
        })
    }
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

/// A provisioned stack's settings, read from Dokploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackSettingsView {
    pub settings: Vec<StackSettingView>,
    /// An action on the stack is unfinished, so changes are refused.
    pub busy: bool,
    /// Variables edited in Dokploy since the dashboard wrote them.
    pub tracking: EnvTracking,
}

/// What applying the submitted settings would change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackConfigPreview {
    /// The changed variables' names, in display order. Values are not
    /// repeated here.
    pub changed: Vec<String>,
    /// The compose services Docker Compose recreates, sorted.
    pub restarts: Vec<String>,
    /// A digest of the settings' current values; applying is refused
    /// when they changed since. Settings hold no secret.
    pub base: String,
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
