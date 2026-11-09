//! Saved SQL snippets.
//!
//! The application layer checks the caller's role before calling these
//! queries. The queries themselves apply the visibility rule: a caller
//! reads their own snippets and the shared ones, and changes only their
//! own. A snippet the caller may not see reads exactly like one that does
//! not exist.

use supabase_dashboard_domain::snippet::{
    Snippet, SnippetInput, SnippetName, SnippetSummary, SnippetVisibility,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    Database, PersistenceError,
    audit::{AuditEvent, insert_audit_event},
    organizations::query_err,
};

pub struct NewSnippet<'a> {
    pub id: Uuid,
    pub project_id: Uuid,
    pub author_id: Uuid,
    pub input: &'a SnippetInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSnippetOutcome {
    Created,
    /// The project was unregistered before the insert.
    ProjectNotFound,
    /// The author already keeps the maximum number of snippets here.
    LimitReached,
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    id: Uuid,
    name: String,
    visibility: String,
    author: String,
    mine: bool,
    updated_at: OffsetDateTime,
}

impl TryFrom<SummaryRow> for SnippetSummary {
    type Error = PersistenceError;
    fn try_from(row: SummaryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            name: SnippetName::parse(&row.name)
                .map_err(|_| PersistenceError::InvalidRow("sql_snippets.name"))?,
            visibility: SnippetVisibility::parse(&row.visibility)
                .ok_or(PersistenceError::InvalidRow("sql_snippets.visibility"))?,
            author: row.author,
            mine: row.mine,
            updated_at: row.updated_at,
        })
    }
}

/// Columns of [`SummaryRow`], for a query that binds the caller as `$2`.
/// A macro so queries stay string literals.
macro_rules! summary_columns {
    () => {
        "s.id, s.name, s.visibility, a.display_name AS author, \
         s.author_id = $2 AS mine, s.updated_at"
    };
}

impl Database {
    /// The caller's snippets and the shared ones in a project, by name, up
    /// to `limit`. The flag says whether more exist.
    pub async fn list_snippets(
        &self,
        project_id: Uuid,
        account_id: Uuid,
        limit: u32,
    ) -> Result<(Vec<SnippetSummary>, bool), PersistenceError> {
        let rows: Vec<SummaryRow> = sqlx::query_as(concat!(
            "SELECT ",
            summary_columns!(),
            " FROM sql_snippets s \
             JOIN accounts a ON a.id = s.author_id \
             WHERE s.project_id = $1 AND (s.author_id = $2 OR s.visibility = 'project') \
             ORDER BY lower(s.name), s.name, s.id LIMIT $3"
        ))
        .bind(project_id)
        .bind(account_id)
        .bind(i64::from(limit) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        let truncated = rows.len() > limit as usize;
        let items = rows
            .into_iter()
            .take(limit as usize)
            .map(SnippetSummary::try_from)
            .collect::<Result<_, _>>()?;
        Ok((items, truncated))
    }

    /// One snippet with its text, if the caller may see it.
    pub async fn find_snippet(
        &self,
        project_id: Uuid,
        snippet_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<Snippet>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            #[sqlx(flatten)]
            summary: SummaryRow,
            content: String,
        }
        let row: Option<Row> = sqlx::query_as(concat!(
            "SELECT ",
            summary_columns!(),
            ", s.content FROM sql_snippets s \
             JOIN accounts a ON a.id = s.author_id \
             WHERE s.id = $1 AND s.project_id = $3 \
             AND (s.author_id = $2 OR s.visibility = 'project')"
        ))
        .bind(snippet_id)
        .bind(account_id)
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(query_err)?;
        row.map(|row| {
            Ok(Snippet {
                summary: row.summary.try_into()?,
                content: row.content,
            })
        })
        .transpose()
    }

    /// Saves a new snippet unless its author already keeps `per_author`
    /// of them in the project.
    pub async fn create_snippet(
        &self,
        snippet: &NewSnippet<'_>,
        per_author: u32,
        audit: &AuditEvent<'_>,
    ) -> Result<CreateSnippetOutcome, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        // Serializes creates in one project, so two at once cannot both pass
        // the count, and keeps a concurrent unregister from slipping in.
        let exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM projects WHERE id = $1 FOR NO KEY UPDATE")
                .bind(snippet.project_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(query_err)?;
        if exists.is_none() {
            return Ok(CreateSnippetOutcome::ProjectNotFound);
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sql_snippets WHERE project_id = $1 AND author_id = $2",
        )
        .bind(snippet.project_id)
        .bind(snippet.author_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(query_err)?;
        if count >= i64::from(per_author) {
            return Ok(CreateSnippetOutcome::LimitReached);
        }
        sqlx::query(
            "INSERT INTO sql_snippets (id, project_id, author_id, name, visibility, content) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(snippet.id)
        .bind(snippet.project_id)
        .bind(snippet.author_id)
        .bind(snippet.input.name.as_str())
        .bind(snippet.input.visibility.as_str())
        .bind(snippet.input.content.as_str())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?;
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(CreateSnippetOutcome::Created)
    }

    /// Replaces the name, visibility, and text of the author's own
    /// snippet. Returns `false` when there is no such snippet by this
    /// author.
    pub async fn update_snippet(
        &self,
        project_id: Uuid,
        snippet_id: Uuid,
        author_id: Uuid,
        input: &SnippetInput,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let updated = sqlx::query(
            "UPDATE sql_snippets SET name = $4, visibility = $5, content = $6, \
             updated_at = now() \
             WHERE id = $1 AND project_id = $2 AND author_id = $3",
        )
        .bind(snippet_id)
        .bind(project_id)
        .bind(author_id)
        .bind(input.name.as_str())
        .bind(input.visibility.as_str())
        .bind(input.content.as_str())
        .execute(&mut *tx)
        .await
        .map_err(query_err)?
        .rows_affected();
        if updated == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }

    /// Deletes the caller's own snippet, or, with `any_shared`, a snippet
    /// another member shared with the project. Returns `false` when
    /// nothing matched.
    pub async fn delete_snippet(
        &self,
        project_id: Uuid,
        snippet_id: Uuid,
        account_id: Uuid,
        any_shared: bool,
        audit: &AuditEvent<'_>,
    ) -> Result<bool, PersistenceError> {
        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let deleted = sqlx::query(
            "DELETE FROM sql_snippets \
             WHERE id = $1 AND project_id = $2 \
             AND (author_id = $3 OR ($4 AND visibility = 'project'))",
        )
        .bind(snippet_id)
        .bind(project_id)
        .bind(account_id)
        .bind(any_shared)
        .execute(&mut *tx)
        .await
        .map_err(query_err)?
        .rows_affected();
        if deleted == 0 {
            return Ok(false);
        }
        insert_audit_event(&mut *tx, audit).await?;
        tx.commit().await.map_err(query_err)?;
        Ok(true)
    }
}
