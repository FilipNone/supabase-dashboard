//! Database structure read from a stack's postgres-meta service: schemas,
//! tables, columns, and foreign keys. Read-only.
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

/// Most relations listed for one schema, counting tables, views,
/// materialized views, and foreign tables together. postgres-meta does not
/// sort its results, so offset pages could skip or repeat entries; the
/// dashboard reads up to this many of each kind, sorts them, keeps this
/// many, and says when the list was cut off.
pub const TABLE_LIST_LIMIT: usize = 1000;

/// PostgreSQL's own limit on columns per table.
pub const TABLE_COLUMN_LIMIT: usize = 1600;

/// Most enum labels kept per column.
pub const ENUM_LABEL_LIMIT: usize = 100;

/// Bounds on free text from the service, in characters.
pub const COMMENT_MAX_CHARS: usize = 1000;
pub const EXPRESSION_MAX_CHARS: usize = 500;
pub const TYPE_NAME_MAX_CHARS: usize = 128;

/// Rows on one page of table data.
pub const ROW_PAGE_SIZE: u32 = 50;
/// Highest page number accepted. Deep offsets make PostgreSQL read and
/// discard every earlier row, so paging stops well before that gets slow.
pub const ROW_PAGE_LIMIT: u32 = 2000;
/// Most columns shown in the data view. Together with the cell bound this
/// keeps a page under a few megabytes whatever the table looks like.
pub const ROW_COLUMN_LIMIT: usize = 50;
/// Characters kept from each value. Longer values are cut on the server.
pub const CELL_MAX_CHARS: usize = 200;
/// How long the database may spend on one page, in milliseconds.
pub const ROW_QUERY_TIMEOUT_MS: u32 = 5000;

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

/// What kind of relation a table editor entry is. postgres-meta lists each
/// kind at its own path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelationKind {
    /// An ordinary or partitioned table.
    Table,
    View,
    MaterializedView {
        /// False until the first `REFRESH`; reading it fails until then.
        populated: bool,
    },
    /// A table whose rows live elsewhere and are fetched through a foreign
    /// data wrapper on every read.
    ForeignTable,
}

impl RelationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Table => "Table",
            Self::View => "View",
            Self::MaterializedView { .. } => "Materialized view",
            Self::ForeignTable => "Foreign table",
        }
    }

    /// Only tables have row-level security, statistics, and a size of
    /// their own in postgres-meta's answers.
    pub const fn is_table(self) -> bool {
        matches!(self, Self::Table)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSummary {
    /// The relation's OID, which identifies it in postgres-meta.
    pub id: u32,
    pub schema: String,
    pub name: String,
    pub kind: RelationKind,
    /// The next four are only meaningful for [`RelationKind::Table`];
    /// other kinds have `false`, `0`, and an empty size.
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
    /// Tables, views, materialized views, and foreign tables, sorted by
    /// name.
    pub tables: Vec<TableSummary>,
    /// More relations exist than [`TABLE_LIST_LIMIT`].
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

impl ColumnSummary {
    /// The type as the table editor shows it: the SQL name, or for enums,
    /// composite types, and arrays the underlying type name.
    pub fn type_label(&self) -> &str {
        if self.data_type == "USER-DEFINED" || self.data_type == "ARRAY" {
            &self.format
        } else {
            &self.data_type
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDetail {
    pub table: TableSummary,
    /// Primary key column names in key order.
    pub primary_key: Vec<String>,
    /// Sorted by position.
    pub columns: Vec<ColumnSummary>,
}

/// Most foreign keys read for one table, counting both directions.
pub const FOREIGN_KEY_LIST_LIMIT: usize = 200;
/// PostgreSQL's limit on columns in one key (`INDEX_MAX_KEYS`).
pub const FOREIGN_KEY_COLUMN_LIMIT: usize = 32;

/// What a foreign key does when the row it points to is updated or deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForeignKeyAction {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

impl ForeignKeyAction {
    /// The one-letter code PostgreSQL stores in `pg_constraint`.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "a" => Some(Self::NoAction),
            "r" => Some(Self::Restrict),
            "c" => Some(Self::Cascade),
            "n" => Some(Self::SetNull),
            "d" => Some(Self::SetDefault),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::NoAction => "No action",
            Self::Restrict => "Restrict",
            Self::Cascade => "Cascade",
            Self::SetNull => "Set null",
            Self::SetDefault => "Set default",
        }
    }
}

/// A foreign key constraint. `columns[i]` points at
/// `referenced_columns[i]`; both are in key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub name: String,
    pub schema: String,
    pub table: String,
    pub columns: Vec<String>,
    pub referenced_schema: String,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
    pub on_update: ForeignKeyAction,
    pub on_delete: ForeignKeyAction,
}

/// The foreign keys that touch one table. A key from the table to itself
/// is in both lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRelations {
    /// Keys on this table, sorted by name.
    pub outgoing: Vec<ForeignKey>,
    /// Keys on other tables that point at this one, sorted by table and
    /// name.
    pub incoming: Vec<ForeignKey>,
    /// More keys exist than [`FOREIGN_KEY_LIST_LIMIT`].
    pub truncated: bool,
}

/// What the Definition tab shows. The keys are read separately, so a
/// failure there still leaves the columns visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableDefinition {
    pub detail: TableDetail,
    pub relations: Result<TableRelations, MetaUnavailable>,
}

/// A page number for table data, from 1 to [`ROW_PAGE_LIMIT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct RowPageNumber(u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("page numbers go from 1 to {ROW_PAGE_LIMIT}")]
pub struct RowPageOutOfRange;

impl RowPageNumber {
    pub const FIRST: Self = Self(1);

    pub fn new(page: u32) -> Result<Self, RowPageOutOfRange> {
        if (1..=ROW_PAGE_LIMIT).contains(&page) {
            Ok(Self(page))
        } else {
            Err(RowPageOutOfRange)
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    /// Rows skipped before this page. Cannot overflow: the largest page
    /// times the page size fits easily in a `u32`.
    pub const fn offset(self) -> u32 {
        (self.0 - 1) * ROW_PAGE_SIZE
    }

    pub fn next(self) -> Option<Self> {
        Self::new(self.0.checked_add(1)?).ok()
    }

    pub fn previous(self) -> Option<Self> {
        Self::new(self.0.checked_sub(1)?).ok()
    }
}

impl TryFrom<u32> for RowPageNumber {
    type Error = RowPageOutOfRange;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RowPageNumber> for u32 {
    fn from(value: RowPageNumber) -> Self {
        value.0
    }
}

/// A column shown in the data view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowColumn {
    pub name: String,
    pub type_label: String,
}

/// One value as PostgreSQL prints it, cut to [`CELL_MAX_CHARS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub text: String,
    /// The value was longer than what is kept.
    pub truncated: bool,
}

/// How the rows on a page are ordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "columns", rename_all = "snake_case")]
pub enum RowOrder {
    /// By the primary key, so pages do not overlap.
    PrimaryKey(Vec<String>),
    /// The table has no primary key. PostgreSQL returns rows in whatever
    /// order is cheapest, so pages can overlap or skip rows.
    Unordered,
}

/// One page of a table's rows. Read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowPage {
    pub table: TableSummary,
    /// The first [`ROW_COLUMN_LIMIT`] columns by position.
    pub columns: Vec<RowColumn>,
    /// Columns left out because of [`ROW_COLUMN_LIMIT`].
    pub hidden_columns: usize,
    /// Each row has one entry per column; `None` is SQL `NULL`.
    pub rows: Vec<Vec<Option<Cell>>>,
    pub page: RowPageNumber,
    /// At least one more row exists after this page.
    pub has_more: bool,
    pub order: RowOrder,
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
    /// The database stopped the read after [`ROW_QUERY_TIMEOUT_MS`].
    QueryTimeout,
    /// A materialized view that has never been refreshed has no rows to
    /// read; PostgreSQL refuses the query.
    NotPopulated,
    /// Rows of a foreign table are not read: each read goes to the remote
    /// source, which may be slow, rate limited, or billed per request.
    ForeignRows,
}

impl MetaUnavailable {
    pub const fn title(self) -> &'static str {
        match self {
            Self::NoKey { .. } => "A service role key is needed",
            Self::KeyRejected { .. } => "The stack refused the service role key",
            Self::NotExposed => "postgres-meta is not available through the gateway",
            Self::ServiceError { .. } => "postgres-meta reported an error",
            Self::Unreachable { .. } => "The stack could not be reached",
            Self::QueryTimeout => "The database took too long",
            Self::NotPopulated => "This materialized view has no data yet",
            Self::ForeignRows => "Rows of foreign tables are not shown",
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
            Self::QueryTimeout => format!(
                "PostgreSQL stopped the read after {} seconds. For table data, later pages of a \
                 large table take longer, because the database reads every earlier row first.",
                ROW_QUERY_TIMEOUT_MS / 1000
            ),
            Self::NotPopulated => "It was created WITH NO DATA and has not been refreshed. \
                                   Run REFRESH MATERIALIZED VIEW on the database to fill it."
                .to_owned(),
            Self::ForeignRows => "Each read of a foreign table goes to its remote source \
                                  through a foreign data wrapper, which can be slow, rate \
                                  limited, or billed per request. The Definition tab lists its \
                                  columns."
                .to_owned(),
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
    fn row_pages_are_bounded() {
        assert!(RowPageNumber::new(0).is_err());
        assert!(RowPageNumber::new(ROW_PAGE_LIMIT + 1).is_err());
        assert_eq!(RowPageNumber::FIRST.offset(), 0);
        let last = RowPageNumber::new(ROW_PAGE_LIMIT).unwrap();
        assert_eq!(last.offset(), (ROW_PAGE_LIMIT - 1) * ROW_PAGE_SIZE);
        assert_eq!(last.next(), None);
        assert_eq!(RowPageNumber::FIRST.previous(), None);
        assert_eq!(RowPageNumber::FIRST.next().map(RowPageNumber::get), Some(2));
        assert!(serde_json::from_str::<RowPageNumber>("0").is_err());
        assert!(serde_json::from_str::<RowPageNumber>("3").is_ok());
    }

    #[test]
    fn relation_kinds_serialize_with_a_tag() {
        let json =
            serde_json::to_string(&RelationKind::MaterializedView { populated: false }).unwrap();
        assert_eq!(json, r#"{"kind":"materialized_view","populated":false}"#);
        assert!(RelationKind::Table.is_table());
        assert!(!RelationKind::View.is_table());
    }

    #[test]
    fn foreign_key_actions_are_read_from_catalog_codes() {
        assert_eq!(
            ForeignKeyAction::from_code("a"),
            Some(ForeignKeyAction::NoAction)
        );
        assert_eq!(
            ForeignKeyAction::from_code("c"),
            Some(ForeignKeyAction::Cascade)
        );
        assert_eq!(
            ForeignKeyAction::from_code("d"),
            Some(ForeignKeyAction::SetDefault)
        );
        assert_eq!(ForeignKeyAction::from_code("x"), None);
        assert_eq!(ForeignKeyAction::from_code("cc"), None);
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
