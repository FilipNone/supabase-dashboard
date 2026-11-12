//! Storage for the optional Studio access log
//! ([`supabase_dashboard_domain::studio_access`]).

use supabase_dashboard_domain::studio_access::{
    NewStudioAccess, StudioAccessEntry, StudioAccessMember,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Database, PersistenceError, organizations::query_err};

impl Database {
    /// Records a batch of requests in one statement. Entries for projects
    /// unregistered in the meantime are dropped. Returns how many were
    /// stored.
    pub async fn insert_studio_access(
        &self,
        entries: &[NewStudioAccess],
    ) -> Result<u64, PersistenceError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let mut projects = Vec::with_capacity(entries.len());
        let mut accounts = Vec::with_capacity(entries.len());
        let mut times = Vec::with_capacity(entries.len());
        let mut methods = Vec::with_capacity(entries.len());
        let mut paths = Vec::with_capacity(entries.len());
        let mut statuses = Vec::with_capacity(entries.len());
        for entry in entries {
            projects.push(entry.project_id);
            accounts.push(entry.account_id);
            times.push(entry.at);
            methods.push(entry.method.as_str());
            paths.push(entry.path.as_str());
            statuses.push(i16::try_from(entry.status).unwrap_or(i16::MAX));
        }
        let done = sqlx::query(
            "INSERT INTO studio_access_log (project_id, account_id, at, method, path, status) \
             SELECT e.project_id, a.id, e.at, e.method, e.path, e.status \
             FROM UNNEST($1::uuid[], $2::uuid[], $3::timestamptz[], $4::text[], $5::text[], \
                         $6::smallint[]) AS e(project_id, account_id, at, method, path, status) \
             JOIN projects p ON p.id = e.project_id \
             LEFT JOIN accounts a ON a.id = e.account_id",
        )
        .bind(projects)
        .bind(accounts)
        .bind(times)
        .bind(methods)
        .bind(paths)
        .bind(statuses)
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(done.rows_affected())
    }

    /// The newest `limit` entries of a project within `retention_days`,
    /// only those of `member` when given, starting after the entry with id
    /// `before` when given. Entries are
    /// ordered by time and then id, so a page boundary between entries with
    /// the same time neither repeats nor skips one. An id that is not one
    /// of this project's entries (another project's, or one already pruned)
    /// gives an empty page.
    pub async fn list_studio_access(
        &self,
        project_id: Uuid,
        retention_days: u16,
        member: Option<Uuid>,
        before: Option<i64>,
        limit: u16,
    ) -> Result<Vec<StudioAccessEntry>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: i64,
            at: OffsetDateTime,
            account_id: Option<Uuid>,
            display_name: Option<String>,
            email: Option<String>,
            method: String,
            path: String,
            status: i16,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT l.id, l.at, a.id AS account_id, a.display_name, a.email, l.method, l.path, \
                    l.status \
             FROM studio_access_log l LEFT JOIN accounts a ON a.id = l.account_id \
             WHERE l.project_id = $1 AND l.at >= now() - make_interval(days => $2) \
               AND ($5::uuid IS NULL OR l.account_id = $5) \
               AND ($4::bigint IS NULL OR (l.at, l.id) < ( \
                   SELECT c.at, c.id FROM studio_access_log c \
                   WHERE c.id = $4 AND c.project_id = $1)) \
             ORDER BY l.at DESC, l.id DESC LIMIT $3",
        )
        .bind(project_id)
        .bind(i32::from(retention_days))
        .bind(i64::from(limit))
        .bind(before)
        .bind(member)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        rows.into_iter()
            .map(|row| {
                Ok(StudioAccessEntry {
                    id: row.id,
                    at: row.at,
                    member: match (row.account_id, row.display_name, row.email) {
                        (Some(account_id), Some(display_name), Some(email)) => {
                            Some(StudioAccessMember {
                                account_id,
                                display_name,
                                email,
                            })
                        }
                        _ => None,
                    },
                    method: row.method,
                    path: row.path,
                    status: u16::try_from(row.status)
                        .map_err(|_| PersistenceError::InvalidRow("studio_access_log.status"))?,
                })
            })
            .collect()
    }

    /// The accounts with entries for a project within `retention_days`,
    /// ordered by name, at most `limit`.
    pub async fn list_studio_access_members(
        &self,
        project_id: Uuid,
        retention_days: u16,
        limit: u16,
    ) -> Result<Vec<StudioAccessMember>, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            display_name: String,
            email: String,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT a.id, a.display_name, a.email FROM accounts a \
             WHERE EXISTS ( \
                 SELECT 1 FROM studio_access_log l \
                 WHERE l.project_id = $1 AND l.account_id = a.id \
                   AND l.at >= now() - make_interval(days => $2)) \
             ORDER BY lower(a.display_name), a.email, a.id LIMIT $3",
        )
        .bind(project_id)
        .bind(i32::from(retention_days))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|row| StudioAccessMember {
                account_id: row.id,
                display_name: row.display_name,
                email: row.email,
            })
            .collect())
    }

    /// Deletes entries older than `retention_days`, at most `batch` at a
    /// time so a large backlog does not hold one long transaction. Returns
    /// how many were deleted.
    pub async fn prune_studio_access(
        &self,
        retention_days: u16,
        batch: u32,
    ) -> Result<u64, PersistenceError> {
        let done = sqlx::query(
            "DELETE FROM studio_access_log WHERE id IN ( \
                 SELECT id FROM studio_access_log \
                 WHERE at < now() - make_interval(days => $1) LIMIT $2)",
        )
        .bind(i32::from(retention_days))
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(done.rows_affected())
    }
}
