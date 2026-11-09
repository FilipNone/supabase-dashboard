//! SQL editor runs through postgres-meta's `POST /query`, behind the
//! stack's gateway at `/pg/query`.
//!
//! postgres-meta v0.100 opens a new pool of one connection for every
//! `/query` request and closes it afterwards, so settings made by the SQL
//! do not outlive the request. The dashboard asks it for two limits:
//! `statementTimeoutSecs`, which postgres-meta applies with
//! `SET statement_timeout` (and `idle_session_timeout`) on that connection
//! before the SQL, and `queryTimeoutSecs`, after which postgres-meta stops
//! waiting. The `x-pg-application-name` header names the connection, so a
//! cancel can find it in `pg_stat_activity`.
//!
//! The SQL text is sent as written and never logged. postgres-meta answers
//! the rows of the last statement that returned any, as an array of JSON
//! objects; their keys are read in order, so columns keep the order
//! PostgreSQL gave them. Two columns with the same name collapse into one,
//! as they do in postgres-meta itself. Database errors are shown to the
//! member who ran the SQL; they are never logged.

use std::time::Duration;

use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use secrecy::SecretString;
use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use supabase_dashboard_application::sql::{SqlFuture, SqlRunner};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    project::ProjectUrl,
    schema::{Cell, MetaUnavailable, bounded},
    sql::{
        SQL_CELL_MAX_CHARS, SQL_ERROR_MAX_CHARS, SQL_RESULT_COLUMN_LIMIT, SQL_RESULT_ROW_LIMIT,
        SQL_STATEMENT_TIMEOUT_SECS, SqlFailure, SqlOutcome, SqlResult, SqlText,
        sql_application_name,
    },
};
use uuid::Uuid;

use crate::gateway::{GatewayProbe, ReadError, classify, read_bounded, read_limited};

/// Largest answer read for a run. Rows past [`SQL_RESULT_ROW_LIMIT`] are
/// still sent by postgres-meta, so this bounds what is read, not what the
/// database produced.
const MAX_RESULT_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Largest error body read.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// Largest answer read for a cancel.
const MAX_CANCEL_BODY_BYTES: usize = 4 * 1024;
/// postgres-meta stops waiting a little after the database timeout, so the
/// database's own error normally arrives first.
const QUERY_TIMEOUT_SECS: u32 = SQL_STATEMENT_TIMEOUT_SECS + 3;
/// The dashboard stops waiting after postgres-meta would have.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(SQL_STATEMENT_TIMEOUT_SECS as u64 + 6);
/// SQLSTATE `query_canceled`: a statement timeout or `pg_cancel_backend`.
const QUERY_CANCELED: &str = "57014";
/// postgres-meta's code when a result passes its `PG_META_MAX_RESULT_SIZE_MB`.
const RESULT_SIZE_EXCEEDED: &str = "RESULT_SIZE_EXCEEDED";

/// Cancels the statements running on connections with one
/// `application_name`, passed as the only parameter. The statement's own
/// connection has postgres-meta's name, so it is never among them.
const CANCEL_SQL: &str = "SELECT count(*) FILTER (WHERE pg_cancel_backend(pid)) AS cancelled \
                          FROM pg_catalog.pg_stat_activity WHERE application_name = $1";

impl GatewayProbe {
    async fn run_sql(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        sql: &SqlText,
        run_id: Uuid,
    ) -> SqlOutcome {
        let unavailable = |reason| SqlFailure::Unavailable { reason };
        let unreachable = |reason| unavailable(MetaUnavailable::Unreachable { reason });
        let url = query_url(
            api_url,
            &[
                ("statementTimeoutSecs", SQL_STATEMENT_TIMEOUT_SECS),
                ("queryTimeoutSecs", QUERY_TIMEOUT_SECS),
            ],
        )
        .map_err(unreachable)?;
        let name = HeaderValue::from_str(&sql_application_name(run_id))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        let body = serde_json::to_vec(&serde_json::json!({ "query": sql.as_str() }))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        let request = self
            .request(Method::POST, url, key, "application/json")
            .map_err(unreachable)?
            .header(CONTENT_TYPE, "application/json")
            .header("x-pg-application-name", name)
            .timeout(REQUEST_TIMEOUT)
            .body(body);
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) if err.is_timeout() => {
                // The database should have stopped the statement already;
                // make sure, without waiting on the answer for long.
                let _ = self.cancel_sql(api_url, key, run_id).await;
                return Err(SqlFailure::Timeout);
            }
            Err(err) => return Err(unreachable(classify(&err))),
        };
        let status = response.status();
        if status.is_success() {
            return match read_limited(response, MAX_RESULT_BODY_BYTES).await {
                Ok(body) => decode_result(&body).map_err(unreachable),
                Err(ReadError::TooLarge) => Err(SqlFailure::ResultTooLarge),
                Err(ReadError::Failed(UnreachableReason::Timeout)) => Err(SqlFailure::Timeout),
                Err(ReadError::Failed(reason)) => Err(unreachable(reason)),
            };
        }
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(unavailable(MetaUnavailable::KeyRejected {
                    http_status: status.as_u16(),
                }))
            }
            StatusCode::NOT_FOUND => Err(unavailable(MetaUnavailable::NotExposed)),
            // postgres-meta's "Query read timeout".
            StatusCode::REQUEST_TIMEOUT => Err(SqlFailure::Timeout),
            StatusCode::BAD_REQUEST => {
                let body = read_bounded(response, MAX_ERROR_BODY_BYTES)
                    .await
                    .unwrap_or_default();
                Err(decode_failure(&body))
            }
            _ => Err(unavailable(MetaUnavailable::ServiceError {
                http_status: status.as_u16(),
            })),
        }
    }

    async fn cancel_sql(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        run_id: Uuid,
    ) -> Result<u32, MetaUnavailable> {
        let unreachable = |reason| MetaUnavailable::Unreachable { reason };
        let url = query_url(api_url, &[]).map_err(unreachable)?;
        let body = serde_json::to_vec(&serde_json::json!({
            "query": CANCEL_SQL,
            "parameters": [sql_application_name(run_id)],
        }))
        .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        let response = self
            .request(Method::POST, url, key, "application/json")
            .map_err(unreachable)?
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| unreachable(classify(&err)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => MetaUnavailable::KeyRejected {
                    http_status: status.as_u16(),
                },
                StatusCode::NOT_FOUND => MetaUnavailable::NotExposed,
                _ => MetaUnavailable::ServiceError {
                    http_status: status.as_u16(),
                },
            });
        }
        let body = read_bounded(response, MAX_CANCEL_BODY_BYTES)
            .await
            .map_err(unreachable)?;
        decode_cancelled(&body).ok_or(unreachable(UnreachableReason::InvalidResponse))
    }
}

impl SqlRunner for GatewayProbe {
    fn run<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        sql: &'a SqlText,
        run_id: Uuid,
    ) -> SqlFuture<'a, SqlOutcome> {
        Box::pin(self.run_sql(api_url, key, sql, run_id))
    }

    fn cancel<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        run_id: Uuid,
    ) -> SqlFuture<'a, Result<u32, MetaUnavailable>> {
        Box::pin(self.cancel_sql(api_url, key, run_id))
    }
}

fn query_url(
    api_url: &ProjectUrl,
    query: &[(&str, u32)],
) -> Result<reqwest::Url, UnreachableReason> {
    let mut url = reqwest::Url::parse(&format!("{}/pg/query", api_url.as_str()))
        .map_err(|_| UnreachableReason::InvalidResponse)?;
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in query {
            pairs.append_pair(name, &value.to_string());
        }
    }
    Ok(url)
}

/// postgres-meta's error answer: `error` is its formatted text (severity,
/// code, message, the line with a caret, detail, hint, context), `message`
/// the bare message, and `code` the SQLSTATE or its own code.
fn decode_failure(body: &[u8]) -> SqlFailure {
    #[derive(Deserialize)]
    struct MetaError {
        error: Option<String>,
        message: Option<String>,
        code: Option<String>,
    }
    let Ok(MetaError {
        error,
        message,
        code,
    }) = serde_json::from_slice::<MetaError>(body)
    else {
        // Not postgres-meta's answer, such as a gateway's own 400.
        return SqlFailure::Unavailable {
            reason: MetaUnavailable::ServiceError { http_status: 400 },
        };
    };
    match code.as_deref() {
        Some(QUERY_CANCELED) => return SqlFailure::Timeout,
        Some(RESULT_SIZE_EXCEEDED) => return SqlFailure::ResultTooLarge,
        _ => {}
    }
    let Some(text) = error.or(message) else {
        return SqlFailure::Unavailable {
            reason: MetaUnavailable::ServiceError { http_status: 400 },
        };
    };
    let code = code.filter(|code| {
        code.len() == 5
            && code
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
    });
    SqlFailure::Database {
        code,
        message: bounded(text.trim_end(), SQL_ERROR_MAX_CHARS),
    }
}

fn decode_cancelled(body: &[u8]) -> Option<u32> {
    #[derive(Deserialize)]
    struct Row {
        cancelled: u32,
    }
    let rows: Vec<Row> = serde_json::from_slice(body).ok()?;
    rows.first().map(|row| row.cancelled)
}

fn decode_result(body: &[u8]) -> Result<SqlResult, UnreachableReason> {
    let Rows { kept, count } =
        serde_json::from_slice(body).map_err(|_| UnreachableReason::InvalidResponse)?;
    let (columns, hidden_columns) = kept.first().map_or((Vec::new(), 0), |first| {
        (
            first.entries.iter().map(|(name, _)| name.clone()).collect(),
            first.hidden,
        )
    });
    let rows = kept
        .into_iter()
        .map(|row| {
            let mut entries = row.entries;
            columns
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    // Rows of one result have the same keys in the same
                    // order; look further only if this one does not.
                    let at = if entries.get(i).is_some_and(|(key, _)| key == name) {
                        Some(i)
                    } else {
                        entries.iter().position(|(key, _)| key == name)
                    };
                    at.and_then(|at| cell(std::mem::take(&mut entries[at].1)))
                })
                .collect()
        })
        .collect();
    Ok(SqlResult {
        columns,
        rows,
        row_count: count,
        hidden_columns,
        elapsed_ms: 0,
    })
}

/// A value as text: strings as they are, other JSON values as JSON. JSON
/// null is SQL NULL.
fn cell(value: serde_json::Value) -> Option<Cell> {
    let mut text = match value {
        serde_json::Value::Null => return None,
        serde_json::Value::String(text) => text,
        other => other.to_string(),
    };
    let truncated = match text.char_indices().nth(SQL_CELL_MAX_CHARS) {
        Some((end, _)) => {
            text.truncate(end);
            true
        }
        None => false,
    };
    Some(Cell { text, truncated })
}

/// The first [`SQL_RESULT_ROW_LIMIT`] rows, and how many there were. Rows
/// past the limit are skipped without being kept.
struct Rows {
    kept: Vec<Row>,
    count: u64,
}

impl<'de> Deserialize<'de> for Rows {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowsVisitor;
        impl<'de> Visitor<'de> for RowsVisitor {
            type Value = Rows;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an array of rows")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Rows, A::Error> {
                let mut kept = Vec::new();
                let mut count = 0u64;
                while kept.len() < SQL_RESULT_ROW_LIMIT {
                    match seq.next_element::<Row>()? {
                        Some(row) => {
                            kept.push(row);
                            count += 1;
                        }
                        None => return Ok(Rows { kept, count }),
                    }
                }
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    count = count.saturating_add(1);
                }
                Ok(Rows { kept, count })
            }
        }
        deserializer.deserialize_seq(RowsVisitor)
    }
}

/// One row's columns in the order they came, up to
/// [`SQL_RESULT_COLUMN_LIMIT`].
struct Row {
    entries: Vec<(String, serde_json::Value)>,
    hidden: usize,
}

impl<'de> Deserialize<'de> for Row {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowVisitor;
        impl<'de> Visitor<'de> for RowVisitor {
            type Value = Row;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a row object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Row, A::Error> {
                let mut entries = Vec::new();
                let mut hidden = 0usize;
                while let Some(name) = map.next_key::<String>()? {
                    if entries.len() < SQL_RESULT_COLUMN_LIMIT {
                        entries.push((name, map.next_value()?));
                    } else {
                        map.next_value::<IgnoredAny>()?;
                        hidden = hidden.saturating_add(1);
                    }
                }
                Ok(Row { entries, hidden })
            }
        }
        deserializer.deserialize_map(RowVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_keep_the_order_postgres_gave() {
        let result =
            decode_result(br#"[{"z": 1, "a": "x", "m": null}, {"z": 2, "a": "y", "m": true}]"#)
                .unwrap();
        assert_eq!(result.columns, ["z", "a", "m"]);
        assert_eq!(result.row_count, 2);
        let text = |row: usize, col: usize| result.rows[row][col].as_ref().map(|c| c.text.as_str());
        assert_eq!(text(0, 0), Some("1"));
        assert_eq!(text(0, 1), Some("x"));
        assert_eq!(text(0, 2), None);
        assert_eq!(text(1, 2), Some("true"));
    }

    #[test]
    fn json_values_are_shown_as_json() {
        let result = decode_result(br#"[{"j": {"k": [1, "two"]}}]"#).unwrap();
        assert_eq!(
            result.rows[0][0].as_ref().unwrap().text,
            r#"{"k":[1,"two"]}"#
        );
    }

    #[test]
    fn rows_past_the_limit_are_counted_not_kept() {
        let rows: Vec<String> = (0..SQL_RESULT_ROW_LIMIT + 5)
            .map(|i| format!(r#"{{"n": {i}}}"#))
            .collect();
        let body = format!("[{}]", rows.join(","));
        let result = decode_result(body.as_bytes()).unwrap();
        assert_eq!(result.rows.len(), SQL_RESULT_ROW_LIMIT);
        assert_eq!(result.row_count, SQL_RESULT_ROW_LIMIT as u64 + 5);
        assert!(result.rows_cut());
    }

    #[test]
    fn wide_rows_and_long_values_are_cut() {
        let columns: Vec<String> = (0..SQL_RESULT_COLUMN_LIMIT + 3)
            .map(|i| format!(r#""c{i}": "{}""#, "é".repeat(SQL_CELL_MAX_CHARS + 1)))
            .collect();
        let body = format!("[{{{}}}]", columns.join(","));
        let result = decode_result(body.as_bytes()).unwrap();
        assert_eq!(result.columns.len(), SQL_RESULT_COLUMN_LIMIT);
        assert_eq!(result.hidden_columns, 3);
        let cell = result.rows[0][0].as_ref().unwrap();
        assert!(cell.truncated);
        assert_eq!(cell.text.chars().count(), SQL_CELL_MAX_CHARS);
    }

    #[test]
    fn statements_without_rows_give_an_empty_result() {
        let result = decode_result(b"[]").unwrap();
        assert!(result.columns.is_empty());
        assert_eq!(result.row_count, 0);
        assert!(decode_result(b"{}").is_err());
    }

    #[test]
    fn database_errors_keep_the_formatted_text() {
        let body = br#"{"error": "ERROR:  42P01: relation \"nope\" does not exist\nLINE 1: select * from nope\n                      ^\n", "message": "relation \"nope\" does not exist", "code": "42P01", "position": "15"}"#;
        match decode_failure(body) {
            SqlFailure::Database { code, message } => {
                assert_eq!(code.as_deref(), Some("42P01"));
                assert!(message.starts_with("ERROR:  42P01: relation"));
                assert!(message.ends_with('^'));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cancels_and_size_limits_have_their_own_failures() {
        assert_eq!(
            decode_failure(br#"{"error": "x", "code": "57014"}"#),
            SqlFailure::Timeout
        );
        assert_eq!(
            decode_failure(br#"{"message": "too big", "code": "RESULT_SIZE_EXCEEDED"}"#),
            SqlFailure::ResultTooLarge
        );
    }

    #[test]
    fn other_codes_and_bodies() {
        match decode_failure(br#"{"message": "connect ECONNREFUSED", "code": "ECONNREFUSED"}"#) {
            SqlFailure::Database { code, message } => {
                assert_eq!(code, None);
                assert_eq!(message, "connect ECONNREFUSED");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            decode_failure(b"<html>bad request</html>"),
            SqlFailure::Unavailable {
                reason: MetaUnavailable::ServiceError { http_status: 400 }
            }
        );
    }

    #[test]
    fn long_error_text_is_bounded() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error": "x".repeat(SQL_ERROR_MAX_CHARS * 2),
        }))
        .unwrap();
        match decode_failure(&body) {
            SqlFailure::Database { message, .. } => {
                assert_eq!(message.chars().count(), SQL_ERROR_MAX_CHARS);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cancel_answers_are_read() {
        assert_eq!(decode_cancelled(br#"[{"cancelled": 1}]"#), Some(1));
        assert_eq!(decode_cancelled(br#"[{"cancelled": 0}]"#), Some(0));
        assert_eq!(decode_cancelled(b"[]"), None);
    }
}
