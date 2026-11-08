//! Read-only browsing of a project's database structure.
//!
//! The structure comes from the stack's postgres-meta service through its
//! API gateway, using the stored service role key on the server. Members
//! see the result; they never see the key, and nothing here changes the
//! database.

use std::{future::Future, pin::Pin, sync::Arc};

use secrecy::SecretString;
use supabase_dashboard_domain::{
    authz::Permission,
    connection::CredentialKind,
    project::ProjectUrl,
    schema::{MetaUnavailable, SchemaListing, SchemaName, TableDetail, TableListing},
};
use supabase_dashboard_persistence::{Database, PersistenceError, projects::ProjectAccess};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{auth::CurrentSession, connections::open_key, secrets::CredentialCipher};

/// postgres-meta requests running at once from this process, across all
/// projects. Each one holds a database connection on the stack.
const MAX_CONCURRENT_REQUESTS: usize = 16;

pub type MetaFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MetaUnavailable>> + Send + 'a>>;

/// Reads structure from a stack's postgres-meta. Implementations must apply
/// the outbound network policy, never follow redirects, bound time and
/// response size, and report failures as [`MetaUnavailable`] states, never
/// as the service's error text.
pub trait SchemaSource: Send + Sync {
    fn schemas<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
    ) -> MetaFuture<'a, SchemaListing>;

    fn tables<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        schema: &'a SchemaName,
    ) -> MetaFuture<'a, TableListing>;

    /// `Ok(None)` when the stack has no table with this ID.
    fn table<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        key: &'a SecretString,
        table_id: u32,
    ) -> MetaFuture<'a, Option<TableDetail>>;
}

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("project not found")]
    NotFound,
    #[error("table not found")]
    TableNotFound,
    #[error("your role in this organization does not allow this action")]
    Forbidden,
    /// The request limiter was shut down; only possible while the server
    /// stops.
    #[error("the dashboard is shutting down")]
    Unavailable,
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

/// The outcome of a read: the structure, or why the stack could not provide
/// it. Errors of the dashboard itself are the outer `Result`.
pub type Browse<T> = Result<T, MetaUnavailable>;

pub struct SchemaService {
    db: Database,
    cipher: Option<CredentialCipher>,
    source: Arc<dyn SchemaSource>,
    permits: Arc<Semaphore>,
}

impl SchemaService {
    pub fn new(
        db: Database,
        cipher: Option<CredentialCipher>,
        source: Arc<dyn SchemaSource>,
    ) -> Self {
        Self {
            db,
            cipher,
            source,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }
    }

    pub async fn schemas(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<Browse<SchemaListing>, SchemaError> {
        let access = self.access(current, project_id).await?;
        let key = match self.service_key(&access).await? {
            Ok(key) => key,
            Err(state) => return Ok(Err(state)),
        };
        let _permit = self.permit().await?;
        Ok(self.source.schemas(&access.project.api_url, &key).await)
    }

    pub async fn tables(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        schema: &SchemaName,
    ) -> Result<Browse<TableListing>, SchemaError> {
        let access = self.access(current, project_id).await?;
        let key = match self.service_key(&access).await? {
            Ok(key) => key,
            Err(state) => return Ok(Err(state)),
        };
        let _permit = self.permit().await?;
        Ok(self
            .source
            .tables(&access.project.api_url, &key, schema)
            .await)
    }

    pub async fn table(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        table_id: u32,
    ) -> Result<Browse<TableDetail>, SchemaError> {
        let access = self.access(current, project_id).await?;
        let key = match self.service_key(&access).await? {
            Ok(key) => key,
            Err(state) => return Ok(Err(state)),
        };
        let _permit = self.permit().await?;
        match self
            .source
            .table(&access.project.api_url, &key, table_id)
            .await
        {
            Ok(Some(detail)) => Ok(Ok(detail)),
            Ok(None) => Err(SchemaError::TableNotFound),
            Err(state) => Ok(Err(state)),
        }
    }

    /// postgres-meta is limited to the service role in the standard gateway
    /// configuration, so the anon key is never tried.
    async fn service_key(
        &self,
        access: &ProjectAccess,
    ) -> Result<Browse<SecretString>, SchemaError> {
        let stored = self.db.list_credentials(access.project.id).await?;
        Ok(open_key(
            self.cipher.as_ref(),
            access.project.id,
            &[CredentialKind::ServiceRoleKey],
            &stored,
        )
        .map_err(|reason| MetaUnavailable::NoKey { reason }))
    }

    async fn permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>, SchemaError> {
        self.permits
            .acquire()
            .await
            .map_err(|_| SchemaError::Unavailable)
    }

    async fn access(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
    ) -> Result<ProjectAccess, SchemaError> {
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(SchemaError::NotFound)?;
        if access.role.allows(Permission::TableDataRead) {
            Ok(access)
        } else {
            Err(SchemaError::Forbidden)
        }
    }
}
