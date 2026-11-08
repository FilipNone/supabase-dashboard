//! Database structure from postgres-meta, which the standard self-hosted
//! gateway exposes at `/pg/` for the service role only.
//!
//! Only three fixed GET paths are requested. No `x-connection-encrypted`
//! header is ever sent, so postgres-meta uses its own configured database
//! connection; the dashboard holds no database password for this. Error
//! bodies can contain database messages, so only the status is kept.

use reqwest::StatusCode;
use secrecy::SecretString;
use serde::Deserialize;
use supabase_dashboard_application::schema::{MetaFuture, SchemaSource};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    project::ProjectUrl,
    schema::{
        COMMENT_MAX_CHARS, ColumnSummary, ENUM_LABEL_LIMIT, EXPRESSION_MAX_CHARS,
        IdentityGeneration, MetaUnavailable, SCHEMA_LIST_LIMIT, SchemaListing, SchemaName,
        SchemaSummary, TABLE_COLUMN_LIMIT, TABLE_LIST_LIMIT, TYPE_NAME_MAX_CHARS, TableDetail,
        TableListing, TableSummary, bounded,
    },
};

use crate::gateway::{GatewayProbe, classify, read_bounded};

/// Largest response read for a list. Table lists carry each table's
/// foreign keys, so they can be much larger than the names alone.
const MAX_LIST_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Largest response read for one table with its columns.
const MAX_TABLE_BODY_BYTES: usize = 4 * 1024 * 1024;

/// What a request came back with, before it is decoded.
enum Answer {
    Body(Vec<u8>),
    /// 404 with postgres-meta's own `{"error": ...}` body: the object does
    /// not exist. A gateway without the route answers 404 too, with a
    /// different body.
    MetaNotFound,
}

impl GatewayProbe {
    async fn meta_get(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        path: &str,
        query: &[(&str, &str)],
        limit: usize,
    ) -> Result<Answer, MetaUnavailable> {
        let unreachable = |reason| MetaUnavailable::Unreachable { reason };
        let mut url = reqwest::Url::parse(&format!("{}/pg{path}", api_url.as_str()))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let response = self
            .request(url, key, "application/json")
            .map_err(unreachable)?
            .send()
            .await
            .map_err(|err| unreachable(classify(&err)))?;
        let status = response.status();
        if status.is_success() {
            return read_bounded(response, limit)
                .await
                .map(Answer::Body)
                .map_err(unreachable);
        }
        match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(MetaUnavailable::KeyRejected {
                http_status: status.as_u16(),
            }),
            StatusCode::NOT_FOUND => {
                // Small bound: only the shape matters, and the text is
                // never kept.
                let body = read_bounded(response, 64 * 1024).await.unwrap_or_default();
                if is_meta_error(&body) {
                    Ok(Answer::MetaNotFound)
                } else {
                    Err(MetaUnavailable::NotExposed)
                }
            }
            _ => Err(MetaUnavailable::ServiceError {
                http_status: status.as_u16(),
            }),
        }
    }

    async fn list_schemas(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
    ) -> Result<SchemaListing, MetaUnavailable> {
        let limit = (SCHEMA_LIST_LIMIT + 1).to_string();
        let answer = self
            .meta_get(
                api_url,
                key,
                "/schemas",
                &[("limit", limit.as_str())],
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        decode_schemas(&body_of(answer)?)
    }

    async fn list_tables(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        schema: &SchemaName,
    ) -> Result<TableListing, MetaUnavailable> {
        let limit = (TABLE_LIST_LIMIT + 1).to_string();
        let answer = self
            .meta_get(
                api_url,
                key,
                "/tables",
                &[
                    ("included_schemas", schema.as_str()),
                    ("include_columns", "false"),
                    ("limit", limit.as_str()),
                ],
                MAX_LIST_BODY_BYTES,
            )
            .await?;
        decode_tables(schema, &body_of(answer)?)
    }

    async fn get_table(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        table_id: u32,
    ) -> Result<Option<TableDetail>, MetaUnavailable> {
        let path = format!("/tables/{table_id}");
        match self
            .meta_get(api_url, key, &path, &[], MAX_TABLE_BODY_BYTES)
            .await?
        {
            Answer::MetaNotFound => Ok(None),
            Answer::Body(body) => decode_table(&body).map(Some),
        }
    }
}

impl SchemaSource for GatewayProbe {
    fn schemas<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
    ) -> MetaFuture<'a, SchemaListing> {
        Box::pin(self.list_schemas(api_url, key))
    }

    fn tables<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        schema: &'a SchemaName,
    ) -> MetaFuture<'a, TableListing> {
        Box::pin(self.list_tables(api_url, key, schema))
    }

    fn table<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        table_id: u32,
    ) -> MetaFuture<'a, Option<TableDetail>> {
        Box::pin(self.get_table(api_url, key, table_id))
    }
}

/// A list endpoint never answers "not found" for an existing route, so a
/// postgres-meta 404 there means the path is not what this adapter expects.
fn body_of(answer: Answer) -> Result<Vec<u8>, MetaUnavailable> {
    match answer {
        Answer::Body(body) => Ok(body),
        Answer::MetaNotFound => Err(MetaUnavailable::ServiceError { http_status: 404 }),
    }
}

fn is_meta_error(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .is_ok_and(|value| value.get("error").is_some_and(serde_json::Value::is_string))
}

fn invalid() -> MetaUnavailable {
    MetaUnavailable::Unreachable {
        reason: UnreachableReason::InvalidResponse,
    }
}

#[derive(Deserialize)]
struct RawSchema {
    name: String,
    owner: String,
}

#[derive(Deserialize)]
struct RawTable {
    id: i64,
    schema: String,
    name: String,
    rls_enabled: bool,
    #[serde(default)]
    rls_forced: bool,
    #[serde(default)]
    live_rows_estimate: i64,
    #[serde(default)]
    size: String,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct RawPrimaryKey {
    name: String,
}

#[derive(Deserialize)]
struct RawColumn {
    ordinal_position: i64,
    name: String,
    data_type: String,
    #[serde(default)]
    format: String,
    is_nullable: bool,
    #[serde(default)]
    is_unique: bool,
    #[serde(default)]
    is_identity: bool,
    identity_generation: Option<String>,
    #[serde(default)]
    is_generated: bool,
    /// Usually a string, but typed loosely by postgres-meta.
    default_value: Option<serde_json::Value>,
    comment: Option<String>,
    #[serde(default)]
    enums: Vec<String>,
}

#[derive(Deserialize)]
struct RawTableDetail {
    #[serde(flatten)]
    table: RawTable,
    #[serde(default)]
    primary_keys: Vec<RawPrimaryKey>,
    #[serde(default)]
    columns: Vec<RawColumn>,
}

fn name(text: &str) -> String {
    bounded(text, TYPE_NAME_MAX_CHARS)
}

fn optional_text(text: Option<String>, max: usize) -> Option<String> {
    text.filter(|t| !t.is_empty()).map(|t| bounded(&t, max))
}

fn decode_schemas(body: &[u8]) -> Result<SchemaListing, MetaUnavailable> {
    let raw: Vec<RawSchema> = serde_json::from_slice(body).map_err(|_| invalid())?;
    let truncated = raw.len() > SCHEMA_LIST_LIMIT;
    let mut schemas: Vec<SchemaSummary> = raw
        .into_iter()
        .take(SCHEMA_LIST_LIMIT)
        .map(|s| SchemaSummary {
            browsable: SchemaName::parse(&s.name).is_ok(),
            name: name(&s.name),
            owner: name(&s.owner),
        })
        .collect();
    schemas.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(SchemaListing { schemas, truncated })
}

fn table_summary(raw: RawTable) -> Result<TableSummary, MetaUnavailable> {
    Ok(TableSummary {
        id: u32::try_from(raw.id).map_err(|_| invalid())?,
        schema: name(&raw.schema),
        name: name(&raw.name),
        rls_enabled: raw.rls_enabled,
        rls_forced: raw.rls_forced,
        live_rows_estimate: raw.live_rows_estimate.max(0),
        size: bounded(&raw.size, 32),
        comment: optional_text(raw.comment, COMMENT_MAX_CHARS),
    })
}

fn decode_tables(schema: &SchemaName, body: &[u8]) -> Result<TableListing, MetaUnavailable> {
    let raw: Vec<RawTable> = serde_json::from_slice(body).map_err(|_| invalid())?;
    let truncated = raw.len() > TABLE_LIST_LIMIT;
    let mut tables = raw
        .into_iter()
        .take(TABLE_LIST_LIMIT)
        // The filter is applied by postgres-meta; this keeps a service that
        // ignored it from mixing in other schemas.
        .filter(|t| t.schema == schema.as_str())
        .map(table_summary)
        .collect::<Result<Vec<_>, _>>()?;
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(TableListing {
        schema: schema.as_str().to_owned(),
        tables,
        truncated,
    })
}

fn decode_column(raw: RawColumn) -> Result<ColumnSummary, MetaUnavailable> {
    let identity = match (raw.is_identity, raw.identity_generation.as_deref()) {
        (false, _) => None,
        (true, Some("ALWAYS")) => Some(IdentityGeneration::Always),
        (true, _) => Some(IdentityGeneration::ByDefault),
    };
    let default_value = match raw.default_value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    };
    Ok(ColumnSummary {
        position: u16::try_from(raw.ordinal_position).map_err(|_| invalid())?,
        name: name(&raw.name),
        data_type: name(&raw.data_type),
        format: name(&raw.format),
        nullable: raw.is_nullable,
        unique: raw.is_unique,
        identity,
        generated: raw.is_generated,
        default_value: optional_text(default_value, EXPRESSION_MAX_CHARS),
        comment: optional_text(raw.comment, COMMENT_MAX_CHARS),
        enum_labels: raw
            .enums
            .iter()
            .take(ENUM_LABEL_LIMIT)
            .map(|label| name(label))
            .collect(),
    })
}

fn decode_table(body: &[u8]) -> Result<TableDetail, MetaUnavailable> {
    let raw: RawTableDetail = serde_json::from_slice(body).map_err(|_| invalid())?;
    if raw.columns.len() > TABLE_COLUMN_LIMIT {
        return Err(invalid());
    }
    let mut columns = raw
        .columns
        .into_iter()
        .map(decode_column)
        .collect::<Result<Vec<_>, _>>()?;
    columns.sort_by_key(|c| c.position);
    Ok(TableDetail {
        table: table_summary(raw.table)?,
        primary_key: raw
            .primary_keys
            .iter()
            .take(TABLE_COLUMN_LIMIT)
            .map(|pk| name(&pk.name))
            .collect(),
        columns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_are_sorted_and_flagged() {
        let listing = decode_schemas(
            br#"[{"id":3,"name":"public","owner":"pg_database_owner"},
                 {"id":2,"name":"auth","owner":"supabase_admin"},
                 {"id":4,"name":"a,b","owner":"postgres"}]"#,
        )
        .unwrap();
        let names: Vec<_> = listing.schemas.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a,b", "auth", "public"]);
        assert!(!listing.schemas[0].browsable);
        assert!(listing.schemas[1].browsable);
        assert!(!listing.truncated);
    }

    #[test]
    fn too_many_schemas_are_cut_off() {
        let items: Vec<String> = (0..=SCHEMA_LIST_LIMIT)
            .map(|i| format!(r#"{{"name":"s{i}","owner":"o"}}"#))
            .collect();
        let body = format!("[{}]", items.join(","));
        let listing = decode_schemas(body.as_bytes()).unwrap();
        assert_eq!(listing.schemas.len(), SCHEMA_LIST_LIMIT);
        assert!(listing.truncated);
    }

    #[test]
    fn tables_from_other_schemas_are_dropped() {
        let schema = SchemaName::parse("public").unwrap();
        let listing = decode_tables(
            &schema,
            br#"[{"id":20,"schema":"public","name":"todos","rls_enabled":true,
                  "live_rows_estimate":3,"size":"16 kB","comment":null},
                 {"id":10,"schema":"auth","name":"users","rls_enabled":false,
                  "size":"8 kB","comment":""},
                 {"id":30,"schema":"public","name":"accounts","rls_enabled":false,
                  "live_rows_estimate":-1,"size":"8 kB","comment":"People"}]"#,
        )
        .unwrap();
        let names: Vec<_> = listing.tables.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["accounts", "todos"]);
        assert_eq!(listing.tables[0].live_rows_estimate, 0);
        assert_eq!(listing.tables[0].comment.as_deref(), Some("People"));
        assert!(listing.tables[1].rls_enabled);
    }

    #[test]
    fn out_of_range_ids_are_invalid() {
        let schema = SchemaName::parse("public").unwrap();
        let result = decode_tables(
            &schema,
            br#"[{"id":-5,"schema":"public","name":"t","rls_enabled":false,"comment":null}]"#,
        );
        assert_eq!(result.unwrap_err(), invalid());
        assert_eq!(decode_schemas(b"{}").unwrap_err(), invalid());
    }

    #[test]
    fn table_detail_is_decoded() {
        let detail = decode_table(
            br#"{"id":20,"schema":"public","name":"todos","rls_enabled":true,"rls_forced":false,
                 "live_rows_estimate":0,"size":"24 kB","comment":null,
                 "primary_keys":[{"schema":"public","table_name":"todos","name":"id","table_id":20}],
                 "relationships":[],
                 "columns":[
                   {"ordinal_position":2,"name":"status","data_type":"USER-DEFINED","format":"todo_status",
                    "is_nullable":false,"is_unique":false,"is_identity":false,"identity_generation":null,
                    "is_generated":false,"default_value":"'open'::todo_status","comment":null,
                    "enums":["open","done"]},
                   {"ordinal_position":1,"name":"id","data_type":"bigint","format":"int8",
                    "is_nullable":false,"is_unique":false,"is_identity":true,"identity_generation":"BY DEFAULT",
                    "is_generated":false,"default_value":null,"comment":"Row ID","enums":[]}
                 ]}"#,
        )
        .unwrap();
        assert_eq!(detail.primary_key, ["id"]);
        assert_eq!(detail.columns[0].name, "id");
        assert_eq!(
            detail.columns[0].identity,
            Some(IdentityGeneration::ByDefault)
        );
        assert_eq!(detail.columns[1].enum_labels, ["open", "done"]);
        assert_eq!(
            detail.columns[1].default_value.as_deref(),
            Some("'open'::todo_status")
        );
    }

    #[test]
    fn long_text_is_bounded() {
        let long = "x".repeat(COMMENT_MAX_CHARS * 2);
        let body = format!(
            r#"{{"id":1,"schema":"public","name":"t","rls_enabled":false,"comment":"{long}","columns":[]}}"#
        );
        let detail = decode_table(body.as_bytes()).unwrap();
        assert_eq!(
            detail.table.comment.unwrap().chars().count(),
            COMMENT_MAX_CHARS
        );
    }

    #[test]
    fn meta_error_bodies_are_recognised() {
        assert!(is_meta_error(
            br#"{"error":"Cannot find a table with ID 9"}"#
        ));
        assert!(!is_meta_error(
            br#"{"message":"no Route matched with those values"}"#
        ));
        assert!(!is_meta_error(b"Not Found"));
    }
}
