//! SQL that a member writes in a project's SQL editor, and what running it
//! gave back.
//!
//! The text is sent to the stack as written. Nothing here decides whether a
//! statement is safe: running SQL is a privileged action granted by role
//! (see [`crate::authz::Permission::SqlExecute`]), and the limits below are
//! enforced by the database and by the dashboard when it reads the answer.

use serde::{Deserialize, Serialize};

use crate::{
    connection::SkipReason,
    schema::{Cell, MetaUnavailable},
};

/// Longest SQL text accepted, in bytes.
pub const SQL_TEXT_MAX_BYTES: usize = 256 * 1024;
/// The database cancels a statement that runs longer than this. It stays
/// below the server's default 30 second request timeout, with room for
/// the two waits that follow it in the adapter.
pub const SQL_STATEMENT_TIMEOUT_SECS: u32 = 20;
/// Rows kept from a result. The rest are counted, not kept.
pub const SQL_RESULT_ROW_LIMIT: usize = 1000;
/// Columns kept from a result.
pub const SQL_RESULT_COLUMN_LIMIT: usize = 100;
/// Characters kept from one value.
pub const SQL_CELL_MAX_CHARS: usize = 500;
/// Characters kept from a database error message.
pub const SQL_ERROR_MAX_CHARS: usize = 4000;

/// SQL text to run, as the member wrote it.
#[derive(Clone, PartialEq, Eq)]
pub struct SqlText(String);

/// Debug output leaves the text out: it can hold data or secrets.
impl std::fmt::Debug for SqlText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SqlText({} bytes)", self.0.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SqlTextError {
    #[error("enter a SQL statement to run")]
    Empty,
    #[error("the SQL text is longer than {} KiB", SQL_TEXT_MAX_BYTES / 1024)]
    TooLong,
    /// PostgreSQL refuses a NUL character anywhere in a query.
    #[error("the SQL text contains a NUL character")]
    NulCharacter,
}

impl SqlText {
    pub fn parse(text: &str) -> Result<Self, SqlTextError> {
        if text.len() > SQL_TEXT_MAX_BYTES {
            return Err(SqlTextError::TooLong);
        }
        if text.trim().is_empty() {
            return Err(SqlTextError::Empty);
        }
        if text.contains('\0') {
            return Err(SqlTextError::NulCharacter);
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `application_name` of the database connection that runs one SQL
/// editor request, so the run can be found in `pg_stat_activity` and
/// cancelled. It fits PostgreSQL's 63-byte limit.
pub fn sql_application_name(run_id: uuid::Uuid) -> String {
    format!("supabase-dashboard sql {}", run_id.simple())
}

/// The rows a statement returned, cut to the limits above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlResult {
    /// Column names of the first kept row, in the order PostgreSQL
    /// returned them.
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<Cell>>>,
    /// Rows the database returned, kept or not.
    pub row_count: u64,
    /// Columns past [`SQL_RESULT_COLUMN_LIMIT`].
    pub hidden_columns: usize,
    pub elapsed_ms: u64,
}

impl SqlResult {
    pub fn rows_cut(&self) -> bool {
        self.row_count > self.rows.len() as u64
    }
}

/// Why a run gave no rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SqlFailure {
    /// PostgreSQL refused or failed the statement. The message is the
    /// database's own, cut to [`SQL_ERROR_MAX_CHARS`]; it is shown to the
    /// member who ran the SQL and never logged.
    Database {
        code: Option<String>,
        message: String,
    },
    /// The statement ran past [`SQL_STATEMENT_TIMEOUT_SECS`].
    Timeout,
    /// The member stopped the run.
    Cancelled,
    /// The answer was larger than the dashboard reads.
    ResultTooLarge,
    /// Another run by the same member on this project has not finished.
    Busy,
    /// The stack could not run SQL.
    Unavailable { reason: MetaUnavailable },
}

impl SqlFailure {
    pub fn title(&self) -> &'static str {
        match self {
            Self::Database { .. } => "The query failed",
            Self::Timeout => "The query took too long",
            Self::Cancelled => "The query was cancelled",
            Self::ResultTooLarge => "The result is too large to show",
            Self::Busy => "Another query is still running",
            Self::Unavailable { reason } => reason.title(),
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Database { message, .. } => message.clone(),
            Self::Timeout => format!(
                "PostgreSQL stopped the statement after {SQL_STATEMENT_TIMEOUT_SECS} seconds. \
                 Changes made by the statement were rolled back."
            ),
            Self::Cancelled => "PostgreSQL stopped the statement on request. Changes made by \
                                the statement were rolled back."
                .to_owned(),
            Self::ResultTooLarge => "The rows came to more than the dashboard reads in one \
                                     answer. Add a LIMIT or select fewer columns."
                .to_owned(),
            Self::Busy => "Wait for it to finish or cancel it, then run this one.".to_owned(),
            Self::Unavailable {
                reason:
                    MetaUnavailable::NoKey {
                        reason: SkipReason::MissingKey,
                    },
            } => "SQL runs through postgres-meta, which the stack's gateway limits to the \
                  service role key. Add it on the Settings tab."
                .to_owned(),
            Self::Unavailable { reason } => reason.detail(),
        }
    }
}

/// What a run gave: the rows, or why there are none.
pub type SqlOutcome = Result<SqlResult, SqlFailure>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_must_have_a_statement_and_fit() {
        assert_eq!(SqlText::parse(""), Err(SqlTextError::Empty));
        assert_eq!(SqlText::parse(" \n\t "), Err(SqlTextError::Empty));
        assert_eq!(
            SqlText::parse("select '\0'"),
            Err(SqlTextError::NulCharacter)
        );
        let long = "x".repeat(SQL_TEXT_MAX_BYTES + 1);
        assert_eq!(SqlText::parse(&long), Err(SqlTextError::TooLong));
        let text = SqlText::parse("  select 1;\n").unwrap();
        // Kept as written, spaces included.
        assert_eq!(text.as_str(), "  select 1;\n");
    }

    #[test]
    fn debug_output_hides_the_text() {
        let text = SqlText::parse("select 'secret'").unwrap();
        assert_eq!(format!("{text:?}"), "SqlText(15 bytes)");
    }

    #[test]
    fn application_names_fit_postgres() {
        let name = sql_application_name(uuid::Uuid::from_u128(u128::MAX));
        assert!(name.len() <= 63, "{name}");
        assert!(name.starts_with("supabase-dashboard sql "));
    }

    #[test]
    fn cut_rows_are_reported() {
        let result = SqlResult {
            columns: vec!["a".into()],
            rows: vec![vec![None]],
            row_count: 2,
            hidden_columns: 0,
            elapsed_ms: 1,
        };
        assert!(result.rows_cut());
    }
}
