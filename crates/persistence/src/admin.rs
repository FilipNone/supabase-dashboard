//! Installation-wide listings for the administrator view. The application
//! layer checks that the caller is an installation administrator first.

use supabase_dashboard_domain::{
    admin::{AdminOrganizationSummary, AdminProjectSummary, RegisteredResources},
    organization::OrganizationName,
    project::{ProjectName, ProjectUrl},
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
                    p.created_at \
             FROM projects p JOIN organizations o ON o.id = p.organization_id \
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
        let projects = project_rows
            .into_iter()
            .map(|row| {
                Ok(AdminProjectSummary {
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
        Ok(RegisteredResources {
            organizations,
            organizations_truncated,
            projects,
            projects_truncated,
        })
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
