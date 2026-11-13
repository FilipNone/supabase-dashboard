//! Installation-wide listings for the administrator view. The application
//! layer checks that the caller is an installation administrator first.

use supabase_dashboard_domain::{
    admin::{
        ADMIN_FAILED_JOB_DAYS, ADMIN_FAILED_JOB_LIMIT, AdminFailedJob, AdminOrganizationSummary,
        AdminProjectSummary, RegisteredResources,
    },
    connection::{HealthDigest, HealthReport, ServiceCheck},
    job::JobKind,
    organization::OrganizationName,
    project::{ProjectName, ProjectUrl},
    provisioning::StackAction,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Database, PersistenceError, organizations::query_err};

/// Keeps the first `limit` rows and reports whether there were more. The
/// queries fetch one extra row to find out.
fn cut<T>(mut rows: Vec<T>, limit: usize) -> (Vec<T>, bool) {
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    (rows, truncated)
}

impl Database {
    /// Every organization and project, oldest first, at most `limit` of each.
    pub async fn list_registered_resources(
        &self,
        limit: usize,
    ) -> Result<RegisteredResources, PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct OrgRow {
            id: Uuid,
            name: String,
            member_count: i64,
            project_count: i64,
            created_at: OffsetDateTime,
        }
        #[derive(sqlx::FromRow)]
        struct ProjectRow {
            id: Uuid,
            organization_id: Uuid,
            organization_name: String,
            name: String,
            api_url: String,
            created_at: OffsetDateTime,
            checked_at: Option<OffsetDateTime>,
            checks: Option<String>,
        }
        let fetch = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let org_rows: Vec<OrgRow> = sqlx::query_as(
            "SELECT o.id, o.name, o.created_at, \
                    (SELECT count(*) FROM organization_members m WHERE m.organization_id = o.id) \
                        AS member_count, \
                    (SELECT count(*) FROM projects p WHERE p.organization_id = o.id) \
                        AS project_count \
             FROM organizations o ORDER BY o.created_at, o.id LIMIT $1",
        )
        .bind(fetch)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        let project_rows: Vec<ProjectRow> = sqlx::query_as(
            "SELECT p.id, p.organization_id, o.name AS organization_name, p.name, p.api_url, \
                    p.created_at, h.checked_at, h.checks::text AS checks \
             FROM projects p JOIN organizations o ON o.id = p.organization_id \
             LEFT JOIN project_health_reports h ON h.project_id = p.id \
             ORDER BY p.created_at, p.id LIMIT $1",
        )
        .bind(fetch)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;

        let (org_rows, organizations_truncated) = cut(org_rows, limit);
        let (project_rows, projects_truncated) = cut(project_rows, limit);
        let organization_name = |raw: &str| {
            OrganizationName::parse(raw)
                .map_err(|_| PersistenceError::InvalidRow("organizations.name"))
        };
        let organizations = org_rows
            .into_iter()
            .map(|row| {
                Ok(AdminOrganizationSummary {
                    name: organization_name(&row.name)?,
                    id: row.id,
                    member_count: row.member_count,
                    project_count: row.project_count,
                    created_at: row.created_at,
                })
            })
            .collect::<Result<_, PersistenceError>>()?;
        let now = OffsetDateTime::now_utc();
        let projects = project_rows
            .into_iter()
            .map(|row| {
                let health = match (row.checked_at, row.checks) {
                    (Some(checked_at), Some(checks)) => {
                        let checks: Vec<ServiceCheck> =
                            serde_json::from_str(&checks).map_err(|_| {
                                PersistenceError::InvalidRow("project_health_reports.checks")
                            })?;
                        let report = HealthReport { checked_at, checks };
                        Some(HealthDigest::new(row.id, &report, now))
                    }
                    _ => None,
                };
                Ok(AdminProjectSummary {
                    health,
                    organization_name: organization_name(&row.organization_name)?,
                    name: ProjectName::parse(&row.name)
                        .map_err(|_| PersistenceError::InvalidRow("projects.name"))?,
                    api_url: ProjectUrl::parse(&row.api_url)
                        .map_err(|_| PersistenceError::InvalidRow("projects.api_url"))?,
                    id: row.id,
                    organization_id: row.organization_id,
                    created_at: row.created_at,
                })
            })
            .collect::<Result<_, PersistenceError>>()?;
        let (failed_jobs, failed_jobs_truncated) = self.list_failed_jobs().await?;
        Ok(RegisteredResources {
            organizations,
            organizations_truncated,
            projects,
            projects_truncated,
            failed_jobs,
            failed_jobs_truncated,
        })
    }

    /// Jobs that failed in the last [`ADMIN_FAILED_JOB_DAYS`] days, newest
    /// first, at most [`ADMIN_FAILED_JOB_LIMIT`].
    async fn list_failed_jobs(&self) -> Result<(Vec<AdminFailedJob>, bool), PersistenceError> {
        #[derive(sqlx::FromRow)]
        struct JobRow {
            id: Uuid,
            kind: String,
            action: Option<String>,
            organization_id: Uuid,
            organization_name: String,
            project_id: Option<Uuid>,
            project_name: Option<String>,
            job_name: Option<String>,
            message: Option<String>,
            failed_at: OffsetDateTime,
        }
        let fetch = i64::try_from(ADMIN_FAILED_JOB_LIMIT.saturating_add(1)).unwrap_or(i64::MAX);
        // The job's project ID is read from its data only when it is a
        // well-formed UUID, so a malformed row cannot fail the listing.
        let rows: Vec<JobRow> = sqlx::query_as(
            "SELECT j.id, j.kind, j.data->>'action' AS action, j.organization_id, \
                    o.name AS organization_name, p.id AS project_id, p.name AS project_name, \
                    j.data->>'name' AS job_name, j.message, \
                    COALESCE(j.finished_at, j.updated_at) AS failed_at \
             FROM jobs j JOIN organizations o ON o.id = j.organization_id \
             LEFT JOIN projects p ON p.organization_id = j.organization_id \
                 AND p.id = CASE WHEN j.data->>'project_id' ~* \
                     '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
                     THEN (j.data->>'project_id')::uuid END \
             WHERE j.state = 'failed' \
               AND COALESCE(j.finished_at, j.updated_at) > now() - make_interval(days => $1) \
             ORDER BY failed_at DESC, j.id DESC LIMIT $2",
        )
        .bind(i32::try_from(ADMIN_FAILED_JOB_DAYS).unwrap_or(i32::MAX))
        .bind(fetch)
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;
        let (rows, truncated) = cut(rows, ADMIN_FAILED_JOB_LIMIT);
        let jobs = rows
            .into_iter()
            .map(|row| {
                let action = row.action.as_deref().and_then(StackAction::parse);
                Ok(AdminFailedJob {
                    id: row.id,
                    kind: JobKind::parse(&row.kind)
                        .ok_or(PersistenceError::InvalidRow("jobs.kind"))?,
                    action,
                    organization_id: row.organization_id,
                    organization_name: OrganizationName::parse(&row.organization_name)
                        .map_err(|_| PersistenceError::InvalidRow("organizations.name"))?,
                    project_id: row.project_id,
                    project_name: row.project_name.or(row.job_name),
                    message: row.message,
                    failed_at: row.failed_at,
                })
            })
            .collect::<Result<_, PersistenceError>>()?;
        Ok((jobs, truncated))
    }
}

#[cfg(test)]
mod tests {
    use super::cut;

    #[test]
    fn cut_reports_extra_rows() {
        assert_eq!(cut(vec![1, 2, 3], 2), (vec![1, 2], true));
        assert_eq!(cut(vec![1, 2], 2), (vec![1, 2], false));
        assert_eq!(cut(Vec::<i32>::new(), 0), (vec![], false));
    }
}
