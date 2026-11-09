//! Saved SQL snippets for the SQL editor.
//!
//! Every operation needs [`Permission::SqlExecute`] on the project, the
//! same as running SQL. The ownership and sharing rules are described in
//! [`supabase_dashboard_domain::snippet`]. Changes are audited by snippet
//! ID; names and SQL text never reach the audit log.

use supabase_dashboard_domain::{
    authz::Permission,
    snippet::{SNIPPET_LIST_LIMIT, SNIPPETS_PER_AUTHOR, Snippet, SnippetInput, SnippetList},
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    audit::AuditOutcome,
    projects::ProjectAccess,
    snippets::{CreateSnippetOutcome, NewSnippet},
};
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    organizations::event,
};

#[derive(Debug, thiserror::Error)]
pub enum SnippetError {
    /// The project or the snippet does not exist, or the caller may not
    /// see it.
    #[error("not found")]
    NotFound,
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    #[error("you already keep {SNIPPETS_PER_AUTHOR} snippets in this project")]
    LimitReached,
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

pub struct SnippetService {
    db: Database,
}

impl SnippetService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<SnippetList, SnippetError> {
        self.access(current, project_id, None).await?;
        let (items, truncated) = self
            .db
            .list_snippets(project_id, current.account.id, SNIPPET_LIST_LIMIT)
            .await?;
        Ok(SnippetList { items, truncated })
    }

    pub async fn get(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        snippet_id: Uuid,
    ) -> Result<Snippet, SnippetError> {
        self.access(current, project_id, None).await?;
        self.db
            .find_snippet(project_id, snippet_id, current.account.id)
            .await?
            .ok_or(SnippetError::NotFound)
    }

    /// Saves a new snippet and gives its ID.
    pub async fn create(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        input: &SnippetInput,
        ctx: RequestContext<'_>,
    ) -> Result<Uuid, SnippetError> {
        const ACTION: &str = "sql_snippet.create";
        self.access(current, project_id, Some((ACTION, ctx)))
            .await?;
        let id = Uuid::now_v7();
        let audit = event(
            current,
            ACTION,
            ("sql_snippet", id.to_string()),
            AuditOutcome::Success,
            ctx,
        );
        let snippet = NewSnippet {
            id,
            project_id,
            author_id: current.account.id,
            input,
        };
        match self
            .db
            .create_snippet(&snippet, SNIPPETS_PER_AUTHOR, &audit)
            .await?
        {
            CreateSnippetOutcome::Created => Ok(id),
            CreateSnippetOutcome::ProjectNotFound => Err(SnippetError::NotFound),
            CreateSnippetOutcome::LimitReached => Err(SnippetError::LimitReached),
        }
    }

    /// Replaces the caller's own snippet. Someone else's snippet, shared or
    /// not, reads as not found.
    pub async fn update(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        snippet_id: Uuid,
        input: &SnippetInput,
        ctx: RequestContext<'_>,
    ) -> Result<(), SnippetError> {
        const ACTION: &str = "sql_snippet.update";
        self.access(current, project_id, Some((ACTION, ctx)))
            .await?;
        let audit = event(
            current,
            ACTION,
            ("sql_snippet", snippet_id.to_string()),
            AuditOutcome::Success,
            ctx,
        );
        if self
            .db
            .update_snippet(project_id, snippet_id, current.account.id, input, &audit)
            .await?
        {
            Ok(())
        } else {
            Err(SnippetError::NotFound)
        }
    }

    /// Deletes the caller's own snippet, or a shared one when the caller's
    /// role may manage shared snippets.
    pub async fn delete(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        snippet_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), SnippetError> {
        const ACTION: &str = "sql_snippet.delete";
        let access = self
            .access(current, project_id, Some((ACTION, ctx)))
            .await?;
        let audit = event(
            current,
            ACTION,
            ("sql_snippet", snippet_id.to_string()),
            AuditOutcome::Success,
            ctx,
        );
        let any_shared = access.role.allows(Permission::SqlSnippetsManage);
        if self
            .db
            .delete_snippet(
                project_id,
                snippet_id,
                current.account.id,
                any_shared,
                &audit,
            )
            .await?
        {
            Ok(())
        } else {
            Err(SnippetError::NotFound)
        }
    }

    /// The project if the caller may use snippets in it. A non-member gets
    /// the same answer as for a project that does not exist. A refused
    /// change is audited under `audit`'s action; a refused read is not.
    async fn access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        audit: Option<(&'static str, RequestContext<'_>)>,
    ) -> Result<ProjectAccess, SnippetError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(SnippetError::NotFound)?;
        if access.role.allows(Permission::SqlExecute) {
            return Ok(access);
        }
        if let Some((action, ctx)) = audit {
            let denied = event(
                current,
                action,
                ("project", project_id.to_string()),
                AuditOutcome::Denied,
                ctx,
            );
            if let Err(err) = self.db.record_audit_event(&denied).await {
                tracing::error!(error = %err, action, "could not record audit event");
            }
        }
        Err(SnippetError::Forbidden)
    }
}
