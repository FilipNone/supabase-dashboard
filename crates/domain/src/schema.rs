//! Database structure read from a stack's postgres-meta service: schemas,
//! tables, and columns. Read-only.
//!
//! Everything here comes from a remote service, so every list and string is
//! bounded before it reaches the browser, and failures are fixed states
//! rather than the service's error text.

use serde::{Deserialize, Serialize};

use crate::connection::{SkipReason, UnreachableReason};

/// Longest identifier PostgreSQL keeps (`NAMEDATALEN - 1`), in bytes.
pub const IDENTIFIER_MAX_BYTES: usize = 63;

/// Most schemas listed for one project.
pub const SCHEMA_LIST_LIMIT: usize = 500;

/// Most tables listed for one schema. postgres-meta does not sort its
/// results, so offset pages could skip or repeat tables; the dashboard reads
/// up to this many, sorts them, and says when the list was cut off.
pub const TABLE_LIST_LIMIT: usize = 1000;

/// PostgreSQL's own limit on columns per table.
pub const TABLE_COLUMN_LIMIT: usize = 1600;

/// Most enum labels kept per column.
pub const ENUM_LABEL_LIMIT: usize = 100;

/// Bounds on free text from the service, in characters.
pub const COMMENT_MAX_CHARS: usize = 1000;
pub const EXPRESSION_MAX_CHARS: usize = 500;
pub const TYPE_NAME_MAX_CHARS: usize = 128;

/// A schema name typed into a URL or form, checked before it is sent to the
/// stack.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SchemaName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchemaNameError {
    #[error("enter a schema name")]
    Empty,
    #[error("schema names are at most {IDENTIFIER_MAX_BYTES} bytes")]
    TooLong,
    /// postgres-meta takes schema filters as a comma-separated list, so a
    /// name with a comma would be read as two schemas.
    #[error("schemas with commas or control characters in their names cannot be browsed")]
    Unsupported,
}

impl SchemaName {
    pub fn parse(raw: &str) -> Result<Self, SchemaNameError> {
        if raw.is_empty() {
            return Err(SchemaNameError::Empty);
        }
        if raw.len() > IDENTIFIER_MAX_BYTES {
            return Err(SchemaNameError::TooLong);
        }
        if raw.chars().any(|c| c == ',' || c.is_control()) {
            return Err(SchemaNameError::Unsupported);
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaName {
    type Error = SchemaNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SchemaName> for String {
    fn from(value: SchemaName) -> Self {
        value.0
    }
}

/// The schema shown when none is chosen, as in the reference dashboard.
pub const DEFAULT_SCHEMA: &str = "public";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaSummary {
    pub name: String,
    pub owner: String,
    /// False when the name cannot be used as a filter (see
    /// [`SchemaName::parse`]).
    pub browsable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaListing {
    /// Sorted by name.
    pub schemas: Vec<SchemaSummary>,
    /// More schemas exist than [`SCHEMA_LIST_LIMIT`].
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSummary {
    /// The table's OID, which identifies it in postgres-meta.
    pub id: u32,
    pub schema: String,
    pub name: String,
    pub rls_enabled: bool,
    pub rls_forced: bool,
    /// PostgreSQL's statistics estimate, not a count.
    pub live_rows_estimate: i64,
    /// Total size as PostgreSQL formats it, such as `16 kB`.
    pub size: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableListing {
    pub schema: String,
    /// Sorted by name.
    pub tables: Vec<TableSummary>,
    /// More tables exist than [`TABLE_LIST_LIMIT`].
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityGeneration {
    Always,
    ByDefault,
}

impl IdentityGeneration {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Always => "Identity (always)",
            Self::ByDefault => "Identity (by default)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnSummary {
    pub position: u16,
    pub name: String,
    /// SQL type name, such as `text` or `USER-DEFINED`.
    pub data_type: String,
    /// The underlying type, such as `int8` or an enum's name.
    pub format: String,
    pub nullable: bool,
    pub unique: bool,
    pub identity: Option<IdentityGeneration>,
    pub generated: bool,
    /// The default expression as PostgreSQL prints it.
    pub default_value: Option<String>,
    pub comment: Option<String>,
    pub enum_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDetail {
    pub table: TableSummary,
    /// Primary key column names in key order.
    pub primary_key: Vec<String>,
    /// Sorted by position.
    pub columns: Vec<ColumnSummary>,
}

/// Why the structure of a project's database could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MetaUnavailable {
    /// No usable service role key is stored.
    NoKey {
        reason: SkipReason,
    },
    /// The gateway refused the key (HTTP 401 or 403).
    KeyRejected {
        http_status: u16,
    },
    /// The gateway has no `/pg/` route, as when postgres-meta is not part
    /// of the stack or is kept off the gateway.
    NotExposed,
    /// postgres-meta answered with an error status.
    ServiceError {
        http_status: u16,
    },
    Unreachable {
        reason: UnreachableReason,
    },
}

impl MetaUnavailable {
    pub const fn title(self) -> &'static str {
        match self {
            Self::NoKey { .. } => "A service role key is needed",
            Self::KeyRejected { .. } => "The stack refused the service role key",
            Self::NotExposed => "postgres-meta is not available through the gateway",
            Self::ServiceError { .. } => "postgres-meta reported an error",
            Self::Unreachable { .. } => "The stack could not be reached",
        }
    }

    pub fn detail(self) -> String {
        match self {
            Self::NoKey {
                reason: SkipReason::MissingKey,
            } => "The table editor reads the database structure through postgres-meta, which \
                  the stack's gateway limits to the service role key. Add it on the Settings \
                  tab."
                .to_owned(),
            Self::NoKey {
                reason: SkipReason::UnreadableKey,
            } => "The stored service role key was saved under a different server encryption \
                  key. Enter it again on the Settings tab."
                .to_owned(),
            Self::KeyRejected { http_status } => format!(
                "The gateway answered HTTP {http_status}. Check that the stored key matches \
                 SERVICE_ROLE_KEY in the stack's configuration."
            ),
            Self::NotExposed => "The gateway answered HTTP 404 for /pg/. The standard \
                                 self-hosted configuration routes it to postgres-meta for the \
                                 service role; this stack does not."
                .to_owned(),
            Self::ServiceError { http_status } => format!(
                "postgres-meta answered HTTP {http_status}. Its logs on the stack have the \
                 details."
            ),
            Self::Unreachable { reason } => reason.message().to_owned(),
        }
    }
}

/// Cuts `text` to at most `max` characters, marking the cut with an
/// ellipsis.
pub fn bounded(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_owned(),
        Some(_) => {
            let keep = max.saturating_sub(1);
            let end = text.char_indices().nth(keep).map_or(text.len(), |(i, _)| i);
            let mut out = text[..end].to_owned();
            out.push('…');
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_checked() {
        assert_eq!(SchemaName::parse("public").unwrap().as_str(), "public");
        assert_eq!(
            SchemaName::parse("Mixed Case ü").unwrap().as_str(),
            "Mixed Case ü"
        );
        assert_eq!(SchemaName::parse(""), Err(SchemaNameError::Empty));
        assert_eq!(
            SchemaName::parse(&"a".repeat(64)),
            Err(SchemaNameError::TooLong)
        );
        assert!(SchemaName::parse(&"a".repeat(63)).is_ok());
        assert_eq!(
            SchemaName::parse("public,auth"),
            Err(SchemaNameError::Unsupported)
        );
        assert_eq!(SchemaName::parse("a\nb"), Err(SchemaNameError::Unsupported));
    }

    #[test]
    fn schema_name_deserialization_validates() {
        assert!(serde_json::from_str::<SchemaName>(r#""public""#).is_ok());
        assert!(serde_json::from_str::<SchemaName>(r#""a,b""#).is_err());
    }

    #[test]
    fn text_is_bounded_by_characters() {
        assert_eq!(bounded("short", 10), "short");
        assert_eq!(bounded("exactly10!", 10), "exactly10!");
        assert_eq!(bounded("abcdefghijk", 10), "abcdefghi…");
        assert_eq!(bounded("ééééé", 3), "éé…");
        assert_eq!(bounded("", 0), "");
    }

    #[test]
    fn unavailable_states_serialize_with_a_tag() {
        let json =
            serde_json::to_string(&MetaUnavailable::KeyRejected { http_status: 401 }).unwrap();
        assert_eq!(json, r#"{"state":"key_rejected","http_status":401}"#);
        let json = serde_json::to_string(&MetaUnavailable::NoKey {
            reason: SkipReason::MissingKey,
        })
        .unwrap();
        assert_eq!(json, r#"{"state":"no_key","reason":"missing_key"}"#);
    }
}
