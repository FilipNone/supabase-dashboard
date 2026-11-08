//! Database structure from postgres-meta, which the standard self-hosted
//! gateway exposes at `/pg/` for the service role only.
//!
//! Structure comes from fixed GET paths: `/schemas`, and for tables,
//! views, materialized views, and foreign tables each their own list and
//! by-ID path. Table rows and foreign keys
//! come from `POST /query` with statements this module builds itself: a
//! single `SELECT` in a read-only transaction with a statement timeout,
//! whose only inputs are identifiers read from postgres-meta just before
//! (always quoted) and integers. Nothing a dashboard user types reaches the
//! SQL.
//!
//! Foreign keys are read from `pg_constraint` rather than from the
//! `relationships` field of postgres-meta's table detail, which joins key
//! columns with `= any(...)` and so loses which column pairs with which in
//! a key of more than one column.
//!
//! No `x-connection-encrypted` header is ever sent, so postgres-meta uses
//! its own configured database connection; the dashboard holds no database
//! password for this. Error bodies can contain database messages, so only
//! the status, and for queries the SQLSTATE code, is kept.

use reqwest::{Method, StatusCode, header::CONTENT_TYPE};
use secrecy::SecretString;
use serde::Deserialize;
use supabase_dashboard_application::schema::{MetaFuture, SchemaSource};
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    project::ProjectUrl,
    schema::{
        CELL_MAX_CHARS, COMMENT_MAX_CHARS, Cell, ColumnSummary, ENUM_LABEL_LIMIT,
        EXPRESSION_MAX_CHARS, FOREIGN_KEY_COLUMN_LIMIT, FOREIGN_KEY_LIST_LIMIT, ForeignKey,
        ForeignKeyAction, IDENTIFIER_MAX_BYTES, IdentityGeneration, MetaUnavailable,
        ROW_COLUMN_LIMIT, ROW_PAGE_SIZE, ROW_QUERY_TIMEOUT_MS, RelationKind, RowColumn, RowOrder,
        RowPage, RowPageNumber, SCHEMA_LIST_LIMIT, SchemaListing, SchemaName, SchemaSummary,
        TABLE_COLUMN_LIMIT, TABLE_LIST_LIMIT, TYPE_NAME_MAX_CHARS, TableDetail, TableListing,
        TableRelations, TableSummary, bounded,
    },
};

use crate::gateway::{GatewayProbe, classify, read_bounded};

/// Largest response read for a list. Table lists carry each table's
/// foreign keys, so they can be much larger than the names alone.
const MAX_LIST_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Largest response read for one table with its columns.
const MAX_TABLE_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Largest response read for one page of rows. A full page is 51 rows of
/// up to 50 cells of 201 characters, so even with every character escaped
/// it stays below this.
const MAX_ROWS_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Largest response read for a table's foreign keys: at most 201 keys of
/// up to 32 column pairs, with names of at most 63 bytes.
const MAX_RELATIONS_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Largest error body read; only its shape and SQLSTATE code are used.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
/// SQLSTATE `query_canceled`, which a statement timeout raises.
const QUERY_CANCELED: &str = "57014";

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
        self.meta_send(Method::GET, api_url, key, path, query, None, limit)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn meta_send(
        &self,
        method: Method,
        api_url: &ProjectUrl,
        key: &SecretString,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Vec<u8>>,
        limit: usize,
    ) -> Result<Answer, MetaUnavailable> {
        let unreachable = |reason| MetaUnavailable::Unreachable { reason };
        let mut url = reqwest::Url::parse(&format!("{}/pg{path}", api_url.as_str()))
            .map_err(|_| unreachable(UnreachableReason::InvalidResponse))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = self
            .request(method, url, key, "application/json")
            .map_err(unreachable)?;
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request
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
                // Only the shape matters, and the text is never kept.
                let body = read_bounded(response, MAX_ERROR_BODY_BYTES)
                    .await
                    .unwrap_or_default();
                if is_meta_error(&body) {
                    Ok(Answer::MetaNotFound)
                } else {
                    Err(MetaUnavailable::NotExposed)
                }
            }
            StatusCode::BAD_REQUEST => {
                let body = read_bounded(response, MAX_ERROR_BODY_BYTES)
                    .await
                    .unwrap_or_default();
                if sqlstate(&body).as_deref() == Some(QUERY_CANCELED) {
                    Err(MetaUnavailable::QueryTimeout)
                } else {
                    Err(MetaUnavailable::ServiceError { http_status: 400 })
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
        let mut parts = Vec::with_capacity(RelationPath::ALL.len());
        // One after another rather than at once, so a listing holds one
        // connection on the stack like every other request.
        for path in RelationPath::ALL {
            let answer = self
                .meta_get(
                    api_url,
                    key,
                    path.list(),
                    &[
                        ("included_schemas", schema.as_str()),
                        ("include_columns", "false"),
                        ("limit", limit.as_str()),
                    ],
                    MAX_LIST_BODY_BYTES,
                )
                .await?;
            parts.push(decode_tables(schema, path, &body_of(answer)?)?);
        }
        Ok(merge_listings(schema, parts))
    }

    async fn get_table(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        table_id: u32,
    ) -> Result<Option<TableDetail>, MetaUnavailable> {
        // An ID names one relation, but postgres-meta looks each kind up
        // at its own path, so the kinds are tried in order of how common
        // they are.
        for path in RelationPath::ALL {
            let by_id = format!("{}/{table_id}", path.list());
            match self
                .meta_get(api_url, key, &by_id, &[], MAX_TABLE_BODY_BYTES)
                .await?
            {
                Answer::MetaNotFound => continue,
                Answer::Body(body) => {
                    let detail = decode_table(path, &body)?;
                    // postgres-meta v0.100 answers `/foreign-tables/{id}`
                    // for an unknown ID with some other foreign table, so
                    // only an answer for this exact ID counts.
                    if detail.table.id == table_id {
                        return Ok(Some(detail));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn read_rows(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        table: &TableDetail,
        page: RowPageNumber,
    ) -> Result<RowPage, MetaUnavailable> {
        match table.table.kind {
            RelationKind::MaterializedView { populated: false } => {
                return Err(MetaUnavailable::NotPopulated);
            }
            RelationKind::ForeignTable => return Err(MetaUnavailable::ForeignRows),
            _ => {}
        }
        let plan = RowQuery::new(table, page)?;
        let body =
            serde_json::to_vec(&serde_json::json!({ "query": plan.sql })).map_err(|_| invalid())?;
        let answer = self
            .meta_send(
                Method::POST,
                api_url,
                key,
                "/query",
                &[],
                Some(body),
                MAX_ROWS_BODY_BYTES,
            )
            .await?;
        let (rows, has_more) = decode_rows(&body_of(answer)?, plan.columns.len())?;
        Ok(RowPage {
            table: table.table.clone(),
            columns: plan.columns,
            hidden_columns: plan.hidden_columns,
            rows,
            page,
            has_more,
            order: plan.order,
        })
    }

    async fn read_relations(
        &self,
        api_url: &ProjectUrl,
        key: &SecretString,
        table_id: u32,
    ) -> Result<TableRelations, MetaUnavailable> {
        let body = serde_json::to_vec(&serde_json::json!({ "query": relations_sql(table_id) }))
            .map_err(|_| invalid())?;
        let answer = self
            .meta_send(
                Method::POST,
                api_url,
                key,
                "/query",
                &[],
                Some(body),
                MAX_RELATIONS_BODY_BYTES,
            )
            .await?;
        decode_relations(&body_of(answer)?)
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

    fn rows<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        table: &'a TableDetail,
        page: RowPageNumber,
    ) -> MetaFuture<'a, RowPage> {
        Box::pin(self.read_rows(api_url, key, table, page))
    }

    fn relations<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        table_id: u32,
    ) -> MetaFuture<'a, TableRelations> {
        Box::pin(self.read_relations(api_url, key, table_id))
    }
}

/// Quotes an identifier as PostgreSQL's `quote_ident` does for names that
/// need it: in double quotes, with embedded double quotes doubled. Every
/// name is quoted, so case and reserved words survive. Names PostgreSQL
/// could not have produced are refused rather than sent, since the server
/// would silently shorten an overlong one to a different name.
fn quote_ident(name: &str) -> Result<String, MetaUnavailable> {
    if name.is_empty() || name.len() > IDENTIFIER_MAX_BYTES || name.contains('\0') {
        return Err(invalid());
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// The statement for one page of rows, and what its result columns are.
struct RowQuery {
    sql: String,
    columns: Vec<RowColumn>,
    hidden_columns: usize,
    order: RowOrder,
}

impl RowQuery {
    fn new(table: &TableDetail, page: RowPageNumber) -> Result<Self, MetaUnavailable> {
        let visible = &table.columns[..table.columns.len().min(ROW_COLUMN_LIMIT)];
        // Each value is printed as text and cut one character past the
        // bound, so the server can tell a cut value from one that fits.
        let select = visible
            .iter()
            .enumerate()
            .map(|(i, column)| {
                Ok(format!(
                    "left(({})::text, {}) AS c{i}",
                    quote_ident(&column.name)?,
                    CELL_MAX_CHARS + 1
                ))
            })
            .collect::<Result<Vec<_>, MetaUnavailable>>()?
            .join(", ");
        let relation = format!(
            "{}.{}",
            quote_ident(&table.table.schema)?,
            quote_ident(&table.table.name)?
        );
        let (order_by, order) = if table.primary_key.is_empty() {
            (String::new(), RowOrder::Unordered)
        } else {
            let keys = table
                .primary_key
                .iter()
                .map(|name| quote_ident(name))
                .collect::<Result<Vec<_>, _>>()?;
            (
                format!(" ORDER BY {}", keys.join(", ")),
                RowOrder::PrimaryKey(table.primary_key.clone()),
            )
        };
        // The implicit transaction of a multi-statement query keeps both
        // settings local to it, so nothing outlives the read on
        // postgres-meta's pooled connection.
        let sql = format!(
            "SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = {ROW_QUERY_TIMEOUT_MS}; \
             SELECT {select} FROM {relation}{order_by} LIMIT {} OFFSET {}",
            ROW_PAGE_SIZE + 1,
            page.offset()
        );
        Ok(Self {
            sql,
            columns: visible
                .iter()
                .map(|column| RowColumn {
                    name: column.name.clone(),
                    type_label: column.type_label().to_owned(),
                })
                .collect(),
            hidden_columns: table.columns.len().saturating_sub(visible.len()),
            order,
        })
    }
}

/// The statement for the foreign keys on or pointing at one table. Its
/// only input is the table's OID. Key columns are listed in key order by
/// walking `conkey` and `confkey` with their ordinals, so the two lists pair
/// up. Keys on the table itself come first, then keys on other tables.
fn relations_sql(table_id: u32) -> String {
    format!(
        "SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = {ROW_QUERY_TIMEOUT_MS}; \
         SELECT c.conname::text AS name, \
         sn.nspname::text AS schema, sc.relname::text AS \"table\", \
         tn.nspname::text AS referenced_schema, tc.relname::text AS referenced_table, \
         array(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY AS k(num, ord) \
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num \
         ORDER BY k.ord) AS columns, \
         array(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY AS k(num, ord) \
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num \
         ORDER BY k.ord) AS referenced_columns, \
         c.confupdtype::text AS on_update, c.confdeltype::text AS on_delete, \
         c.conrelid = {table_id} AS outgoing, c.confrelid = {table_id} AS incoming \
         FROM pg_catalog.pg_constraint c \
         JOIN pg_catalog.pg_class sc ON sc.oid = c.conrelid \
         JOIN pg_catalog.pg_namespace sn ON sn.oid = sc.relnamespace \
         JOIN pg_catalog.pg_class tc ON tc.oid = c.confrelid \
         JOIN pg_catalog.pg_namespace tn ON tn.oid = tc.relnamespace \
         WHERE c.contype = 'f' AND (c.conrelid = {table_id} OR c.confrelid = {table_id}) \
         ORDER BY c.conrelid = {table_id} DESC, sn.nspname, sc.relname, c.conname \
         LIMIT {}",
        FOREIGN_KEY_LIST_LIMIT + 1
    )
}

#[derive(Deserialize)]
struct RawForeignKey {
    name: String,
    schema: String,
    table: String,
    referenced_schema: String,
    referenced_table: String,
    columns: Vec<String>,
    referenced_columns: Vec<String>,
    on_update: String,
    on_delete: String,
    outgoing: bool,
    incoming: bool,
}

fn decode_foreign_key(raw: &RawForeignKey) -> Result<ForeignKey, MetaUnavailable> {
    if raw.columns.is_empty()
        || raw.columns.len() > FOREIGN_KEY_COLUMN_LIMIT
        || raw.columns.len() != raw.referenced_columns.len()
    {
        return Err(invalid());
    }
    let action = |code: &str| ForeignKeyAction::from_code(code).ok_or_else(invalid);
    Ok(ForeignKey {
        name: name(&raw.name),
        schema: name(&raw.schema),
        table: name(&raw.table),
        columns: raw.columns.iter().map(|c| name(c)).collect(),
        referenced_schema: name(&raw.referenced_schema),
        referenced_table: name(&raw.referenced_table),
        referenced_columns: raw.referenced_columns.iter().map(|c| name(c)).collect(),
        on_update: action(&raw.on_update)?,
        on_delete: action(&raw.on_delete)?,
    })
}

fn decode_relations(body: &[u8]) -> Result<TableRelations, MetaUnavailable> {
    let raw: Vec<RawForeignKey> = serde_json::from_slice(body).map_err(|_| invalid())?;
    if raw.len() > FOREIGN_KEY_LIST_LIMIT + 1 {
        return Err(invalid());
    }
    let truncated = raw.len() > FOREIGN_KEY_LIST_LIMIT;
    let mut relations = TableRelations {
        outgoing: Vec::new(),
        incoming: Vec::new(),
        truncated,
    };
    for raw in raw.iter().take(FOREIGN_KEY_LIST_LIMIT) {
        let key = decode_foreign_key(raw)?;
        match (raw.outgoing, raw.incoming) {
            (true, true) => {
                relations.incoming.push(key.clone());
                relations.outgoing.push(key);
            }
            (true, false) => relations.outgoing.push(key),
            (false, true) => relations.incoming.push(key),
            (false, false) => return Err(invalid()),
        }
    }
    relations.outgoing.sort_by(|a, b| a.name.cmp(&b.name));
    relations
        .incoming
        .sort_by(|a, b| (&a.schema, &a.table, &a.name).cmp(&(&b.schema, &b.table, &b.name)));
    Ok(relations)
}

fn cell(text: String) -> Cell {
    match text.char_indices().nth(CELL_MAX_CHARS) {
        None => Cell {
            text,
            truncated: false,
        },
        Some((end, _)) => Cell {
            text: text[..end].to_owned(),
            truncated: true,
        },
    }
}

type Rows = Vec<Vec<Option<Cell>>>;

/// Rows come back as objects keyed `c0`, `c1`, ..., one string or null per
/// column. The page holds one extra row, which only says more exist.
fn decode_rows(body: &[u8], column_count: usize) -> Result<(Rows, bool), MetaUnavailable> {
    let raw: Vec<serde_json::Map<String, serde_json::Value>> =
        serde_json::from_slice(body).map_err(|_| invalid())?;
    let page_size = ROW_PAGE_SIZE as usize;
    if raw.len() > page_size + 1 {
        return Err(invalid());
    }
    let has_more = raw.len() > page_size;
    let rows = raw
        .into_iter()
        .take(page_size)
        .map(|mut row| {
            (0..column_count)
                .map(|i| match row.remove(&format!("c{i}")) {
                    Some(serde_json::Value::Null) => Ok(None),
                    Some(serde_json::Value::String(text)) => Ok(Some(cell(text))),
                    _ => Err(invalid()),
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((rows, has_more))
}

/// The SQLSTATE code of a postgres-meta query error, if it has one of the
/// right shape. The message next to it is never read.
fn sqlstate(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = value.get("code")?.as_str()?;
    (code.len() == 5 && code.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| code.to_owned())
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

/// The postgres-meta path for each kind of relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelationPath {
    Tables,
    Views,
    MaterializedViews,
    ForeignTables,
}

impl RelationPath {
    const ALL: [Self; 4] = [
        Self::Tables,
        Self::Views,
        Self::MaterializedViews,
        Self::ForeignTables,
    ];

    const fn list(self) -> &'static str {
        match self {
            Self::Tables => "/tables",
            Self::Views => "/views",
            Self::MaterializedViews => "/materialized-views",
            Self::ForeignTables => "/foreign-tables",
        }
    }
}

/// One relation of any kind. Only tables carry the security, statistics,
/// and size fields, and only materialized views `is_populated`.
#[derive(Deserialize)]
struct RawTable {
    id: i64,
    schema: String,
    name: String,
    #[serde(default)]
    rls_enabled: bool,
    #[serde(default)]
    rls_forced: bool,
    #[serde(default)]
    live_rows_estimate: i64,
    #[serde(default)]
    size: String,
    comment: Option<String>,
    is_populated: Option<bool>,
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

fn table_summary(path: RelationPath, raw: RawTable) -> Result<TableSummary, MetaUnavailable> {
    let kind = match path {
        RelationPath::Tables => RelationKind::Table,
        RelationPath::Views => RelationKind::View,
        RelationPath::MaterializedViews => RelationKind::MaterializedView {
            populated: raw.is_populated.ok_or_else(invalid)?,
        },
        RelationPath::ForeignTables => RelationKind::ForeignTable,
    };
    let table = kind.is_table();
    Ok(TableSummary {
        id: u32::try_from(raw.id).map_err(|_| invalid())?,
        schema: name(&raw.schema),
        name: name(&raw.name),
        kind,
        rls_enabled: table && raw.rls_enabled,
        rls_forced: table && raw.rls_forced,
        live_rows_estimate: if table {
            raw.live_rows_estimate.max(0)
        } else {
            0
        },
        size: if table {
            bounded(&raw.size, 32)
        } else {
            String::new()
        },
        comment: optional_text(raw.comment, COMMENT_MAX_CHARS),
    })
}

/// One kind's list. `truncated` means that kind alone had more than
/// [`TABLE_LIST_LIMIT`] entries.
fn decode_tables(
    schema: &SchemaName,
    path: RelationPath,
    body: &[u8],
) -> Result<TableListing, MetaUnavailable> {
    let raw: Vec<RawTable> = serde_json::from_slice(body).map_err(|_| invalid())?;
    let truncated = raw.len() > TABLE_LIST_LIMIT;
    let mut tables = raw
        .into_iter()
        .take(TABLE_LIST_LIMIT)
        // The filter is applied by postgres-meta; this keeps a service that
        // ignored it from mixing in other schemas.
        .filter(|t| t.schema == schema.as_str())
        .map(|raw| table_summary(path, raw))
        .collect::<Result<Vec<_>, _>>()?;
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(TableListing {
        schema: schema.as_str().to_owned(),
        tables,
        truncated,
    })
}

/// All kinds in one list sorted by name, cut to [`TABLE_LIST_LIMIT`]. A
/// kind that was cut on its own may be missing names that sort early, so
/// the result is flagged then too.
fn merge_listings(schema: &SchemaName, parts: Vec<TableListing>) -> TableListing {
    let mut truncated = parts.iter().any(|part| part.truncated);
    let mut tables: Vec<TableSummary> = parts.into_iter().flat_map(|part| part.tables).collect();
    tables.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
    if tables.len() > TABLE_LIST_LIMIT {
        tables.truncate(TABLE_LIST_LIMIT);
        truncated = true;
    }
    TableListing {
        schema: schema.as_str().to_owned(),
        tables,
        truncated,
    }
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

fn decode_table(path: RelationPath, body: &[u8]) -> Result<TableDetail, MetaUnavailable> {
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
        table: table_summary(path, raw.table)?,
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
            RelationPath::Tables,
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
            RelationPath::Tables,
            br#"[{"id":-5,"schema":"public","name":"t","rls_enabled":false,"comment":null}]"#,
        );
        assert_eq!(result.unwrap_err(), invalid());
        assert_eq!(decode_schemas(b"{}").unwrap_err(), invalid());
    }

    #[test]
    fn table_detail_is_decoded() {
        let detail = decode_table(
            RelationPath::Tables,
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
        let detail = decode_table(RelationPath::Tables, body.as_bytes()).unwrap();
        assert_eq!(
            detail.table.comment.unwrap().chars().count(),
            COMMENT_MAX_CHARS
        );
    }

    fn column(position: u16, name: &str) -> ColumnSummary {
        ColumnSummary {
            position,
            name: name.into(),
            data_type: "text".into(),
            format: "text".into(),
            nullable: true,
            unique: false,
            identity: None,
            generated: false,
            default_value: None,
            comment: None,
            enum_labels: Vec::new(),
        }
    }

    fn detail(schema: &str, name: &str, columns: Vec<ColumnSummary>, pk: &[&str]) -> TableDetail {
        TableDetail {
            table: TableSummary {
                id: 1,
                schema: schema.into(),
                name: name.into(),
                kind: RelationKind::Table,
                rls_enabled: false,
                rls_forced: false,
                live_rows_estimate: 0,
                size: String::new(),
                comment: None,
            },
            primary_key: pk.iter().map(|&k| k.to_owned()).collect(),
            columns,
        }
    }

    #[test]
    fn identifiers_are_always_quoted() {
        assert_eq!(quote_ident("todos").unwrap(), r#""todos""#);
        assert_eq!(quote_ident("Mixed Case").unwrap(), r#""Mixed Case""#);
        assert_eq!(
            quote_ident(r#"a"; drop table x; --"#).unwrap(),
            r#""a""; drop table x; --""#
        );
        assert_eq!(quote_ident(&"a".repeat(63)).unwrap().len(), 65);
        assert!(quote_ident("").is_err());
        assert!(quote_ident(&"a".repeat(64)).is_err());
        assert!(quote_ident("a\0b").is_err());
        // Shortened names from `bounded` never reach a query.
        assert!(quote_ident(&bounded(&"é".repeat(40), 32)).is_err());
    }

    #[test]
    fn row_query_is_read_only_ordered_and_bounded() {
        let table = detail(
            "my schema",
            r#"we"ird"#,
            vec![column(1, "id"), column(2, "Note")],
            &["id"],
        );
        let plan = RowQuery::new(&table, RowPageNumber::new(3).unwrap()).unwrap();
        assert_eq!(
            plan.sql,
            "SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = 5000; \
             SELECT left((\"id\")::text, 201) AS c0, left((\"Note\")::text, 201) AS c1 \
             FROM \"my schema\".\"we\"\"ird\" ORDER BY \"id\" LIMIT 51 OFFSET 100"
        );
        assert_eq!(plan.order, RowOrder::PrimaryKey(vec!["id".into()]));
        assert_eq!(plan.columns[1].name, "Note");
        assert_eq!(plan.hidden_columns, 0);
    }

    #[test]
    fn tables_without_a_key_are_unordered_and_wide_tables_cut() {
        let columns = (1..=60).map(|i| column(i, &format!("c{i}"))).collect();
        let plan = RowQuery::new(
            &detail("public", "wide", columns, &[]),
            RowPageNumber::FIRST,
        )
        .unwrap();
        assert_eq!(plan.order, RowOrder::Unordered);
        assert!(!plan.sql.contains("ORDER BY"));
        assert!(plan.sql.ends_with("LIMIT 51 OFFSET 0"));
        assert_eq!(plan.columns.len(), ROW_COLUMN_LIMIT);
        assert_eq!(plan.hidden_columns, 10);
        assert!(!plan.sql.contains("\"c51\""));
    }

    #[test]
    fn rows_are_decoded_and_cells_cut() {
        let long = "y".repeat(CELL_MAX_CHARS + 1);
        let body = format!(r#"[{{"c0":"1","c1":null}},{{"c0":"2","c1":"{long}"}}]"#);
        let (rows, more) = decode_rows(body.as_bytes(), 2).unwrap();
        assert!(!more);
        assert_eq!(rows[0][0].as_ref().unwrap().text, "1");
        assert_eq!(rows[0][1], None);
        let cut = rows[1][1].as_ref().unwrap();
        assert!(cut.truncated);
        assert_eq!(cut.text.chars().count(), CELL_MAX_CHARS);
    }

    #[test]
    fn the_extra_row_only_means_more() {
        let one = r#"{"c0":"x"}"#;
        let full = vec![one; ROW_PAGE_SIZE as usize + 1].join(",");
        let (rows, more) = decode_rows(format!("[{full}]").as_bytes(), 1).unwrap();
        assert!(more);
        assert_eq!(rows.len(), ROW_PAGE_SIZE as usize);
        let over = vec![one; ROW_PAGE_SIZE as usize + 2].join(",");
        assert!(decode_rows(format!("[{over}]").as_bytes(), 1).is_err());
        // A missing or non-text cell means the answer is not what was asked.
        assert!(decode_rows(br#"[{"c0":1}]"#, 1).is_err());
        assert!(decode_rows(br#"[{}]"#, 1).is_err());
        assert_eq!(decode_rows(br#"[{}]"#, 0).unwrap().0, vec![Vec::new()]);
    }

    #[test]
    fn only_well_formed_sqlstates_are_read() {
        assert_eq!(
            sqlstate(br#"{"error":"ERROR: 57014: canceling","code":"57014"}"#).as_deref(),
            Some("57014")
        );
        assert_eq!(sqlstate(br#"{"code":"<script>"}"#), None);
        assert_eq!(sqlstate(br#"{"code":57014}"#), None);
        assert_eq!(sqlstate(b"oops"), None);
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

    fn raw_key(name: &str, outgoing: bool, incoming: bool) -> serde_json::Value {
        serde_json::json!({
            "name": name, "schema": "public", "table": "tags",
            "referenced_schema": "public", "referenced_table": "todos",
            "columns": ["todo_id", "owner"], "referenced_columns": ["id", "owner"],
            "on_update": "a", "on_delete": "c",
            "outgoing": outgoing, "incoming": incoming,
        })
    }

    #[test]
    fn relation_query_takes_only_the_table_id() {
        let sql = relations_sql(16_384);
        assert!(sql.starts_with("SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = "));
        assert!(sql.contains("c.conrelid = 16384 OR c.confrelid = 16384"));
        assert!(sql.contains("WITH ORDINALITY"));
        assert!(sql.ends_with(&format!("LIMIT {}", FOREIGN_KEY_LIST_LIMIT + 1)));
        assert_eq!(sql.matches(';').count(), 2, "one SELECT after the settings");
    }

    #[test]
    fn relations_are_split_by_direction_and_keep_column_pairs() {
        let body = serde_json::to_vec(&serde_json::json!([
            raw_key("z_out", true, false),
            raw_key("a_out", true, false),
            raw_key("self", true, true),
            raw_key("in", false, true),
        ]))
        .unwrap();
        let relations = decode_relations(&body).unwrap();
        let names = |keys: &[ForeignKey]| keys.iter().map(|k| k.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&relations.outgoing), ["a_out", "self", "z_out"]);
        assert_eq!(names(&relations.incoming), ["in", "self"]);
        assert!(!relations.truncated);
        let key = &relations.outgoing[0];
        assert_eq!(key.columns, ["todo_id", "owner"]);
        assert_eq!(key.referenced_columns, ["id", "owner"]);
        assert_eq!(key.on_update, ForeignKeyAction::NoAction);
        assert_eq!(key.on_delete, ForeignKeyAction::Cascade);
    }

    #[test]
    fn malformed_relations_are_invalid() {
        let decode =
            |value: serde_json::Value| decode_relations(&serde_json::to_vec(&value).unwrap());
        let mut uneven = raw_key("k", true, false);
        uneven["referenced_columns"] = serde_json::json!(["id"]);
        assert!(decode(serde_json::json!([uneven])).is_err());
        let mut action = raw_key("k", true, false);
        action["on_delete"] = serde_json::json!("x");
        assert!(decode(serde_json::json!([action])).is_err());
        assert!(decode(serde_json::json!([raw_key("k", false, false)])).is_err());
        let mut empty = raw_key("k", true, false);
        empty["columns"] = serde_json::json!([]);
        empty["referenced_columns"] = serde_json::json!([]);
        assert!(decode(serde_json::json!([empty])).is_err());
    }

    #[test]
    fn too_many_relations_are_cut_off() {
        let keys: Vec<_> = (0..=FOREIGN_KEY_LIST_LIMIT)
            .map(|i| raw_key(&format!("k{i:03}"), true, false))
            .collect();
        let relations = decode_relations(&serde_json::to_vec(&keys).unwrap()).unwrap();
        assert!(relations.truncated);
        assert_eq!(relations.outgoing.len(), FOREIGN_KEY_LIST_LIMIT);
    }
}
