//! Dashboard API tokens: creating, listing, and revoking them, and the
//! read-only API they give access to.
//!
//! A token acts as the account that created it. Every API call goes through
//! the same services and role checks as the dashboard's pages, after the
//! token's scopes are checked. [`TokenApi`] offers only reads, and a
//! [`TokenPrincipal`] cannot be turned into a session for other services, so
//! a token cannot change anything, open Studio, or read a stack's keys.

use std::sync::Arc;

use supabase_dashboard_domain::{
    api_token::{
        API_TOKEN_DISPLAY_CHARS, API_TOKEN_LIST_LIMIT, API_TOKEN_PREFIX, ApiTokenInputError,
        ApiTokenLifetime, ApiTokenName, ApiTokenScope, ApiTokenSecret, ApiTokenState,
        ApiTokenSummary, IssuedApiToken, MAX_ACTIVE_API_TOKENS, parse_scopes,
    },
    connection::HealthDigest,
    organization::OrganizationSummary,
    project::ProjectSummary,
};
use supabase_dashboard_persistence::{
    Database, PersistenceError,
    api_tokens::{CreateApiTokenOutcome, NewApiToken},
    audit::{AuditEvent, AuditOutcome},
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    connections::{ConnectionError, ConnectionService},
    organizations::{OrganizationError, OrganizationService},
    projects::{ProjectError, ProjectService},
    token::{RandomToken, RandomnessError},
};

#[derive(Debug, thiserror::Error)]
pub enum ApiTokenError {
    #[error(transparent)]
    Input(#[from] ApiTokenInputError),
    #[error(
        "you already have {MAX_ACTIVE_API_TOKENS} working API tokens; revoke one before creating another"
    )]
    LimitReached,
    /// The token does not exist, is not the operator's, or is already
    /// revoked.
    #[error("API token not found")]
    NotFound,
    /// The account was disabled while the request ran.
    #[error("your account is not available")]
    AccountUnavailable,
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
}

/// What the operator entered to create a token.
#[derive(Debug, Clone, Copy)]
pub struct NewToken<'a> {
    pub name: &'a str,
    /// Days, as offered by [`ApiTokenLifetime`].
    pub lifetime: &'a str,
    pub scopes: &'a [String],
}

/// The account a valid token acts as, and what the token may read. Only
/// [`ApiTokenService::authenticate`] makes one.
#[derive(Debug, Clone)]
pub struct TokenPrincipal {
    token_id: Uuid,
    scopes: Vec<ApiTokenScope>,
    actor: CurrentSession,
}

impl TokenPrincipal {
    pub const fn token_id(&self) -> Uuid {
        self.token_id
    }

    pub const fn account_id(&self) -> Uuid {
        self.actor.account.id
    }

    pub fn scopes(&self) -> &[ApiTokenScope] {
        &self.scopes
    }

    fn require(&self, scope: ApiTokenScope) -> Result<&CurrentSession, ApiAccessError> {
        if self.scopes.contains(&scope) {
            Ok(&self.actor)
        } else {
            Err(ApiAccessError::MissingScope(scope))
        }
    }
}

pub struct ApiTokenService {
    db: Database,
}

impl ApiTokenService {
    pub const fn new(db: Database) -> Self {
        Self { db }
    }

    /// Creates a token for the operator's own account. The answer holds the
    /// only copy of the token; the database keeps its hash.
    pub async fn create(
        &self,
        current: &CurrentSession,
        input: NewToken<'_>,
        ctx: RequestContext<'_>,
    ) -> Result<IssuedApiToken, ApiTokenError> {
        let name = ApiTokenName::parse(input.name)?;
        let lifetime =
            ApiTokenLifetime::parse(input.lifetime).ok_or(ApiTokenInputError::UnknownLifetime)?;
        let scopes = parse_scopes(input.scopes.iter().map(String::as_str))?;
        let random = RandomToken::generate()?;
        let encoded = random.expose_code();
        let secret = ApiTokenSecret::new(format!("{API_TOKEN_PREFIX}{encoded}"));
        let display_prefix = format!(
            "{API_TOKEN_PREFIX}{}",
            encoded.get(..API_TOKEN_DISPLAY_CHARS).unwrap_or_default()
        );
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::days(i64::from(lifetime.days()));
        let id = Uuid::now_v7();
        let outcome = self
            .db
            .create_api_token(
                &NewApiToken {
                    id,
                    account_id: current.account.id,
                    name: &name,
                    token_hash: random.hash(),
                    display_prefix: &display_prefix,
                    scopes: &scopes,
                    expires_at,
                },
                MAX_ACTIVE_API_TOKENS,
                &event(current, "api_token.create", id, ctx),
            )
            .await?;
        match outcome {
            CreateApiTokenOutcome::Created => Ok(IssuedApiToken {
                token: ApiTokenSummary {
                    id,
                    name,
                    display_prefix,
                    scopes,
                    created_at: now,
                    expires_at,
                    last_used_at: None,
                    revoked_at: None,
                    state: ApiTokenState::Active,
                },
                secret,
            }),
            CreateApiTokenOutcome::LimitReached => Err(ApiTokenError::LimitReached),
            CreateApiTokenOutcome::AccountUnavailable => Err(ApiTokenError::AccountUnavailable),
        }
    }

    /// The operator's own tokens, newest first, including revoked and
    /// expired ones for a while. Never the tokens themselves.
    pub async fn list(
        &self,
        current: &CurrentSession,
    ) -> Result<Vec<ApiTokenSummary>, ApiTokenError> {
        Ok(self
            .db
            .list_api_tokens(current.account.id, API_TOKEN_LIST_LIMIT)
            .await?)
    }

    /// Revokes one of the operator's own tokens. It stops working at once.
    pub async fn revoke(
        &self,
        current: &CurrentSession,
        token_id: Uuid,
        ctx: RequestContext<'_>,
    ) -> Result<(), ApiTokenError> {
        if self
            .db
            .revoke_api_token(
                current.account.id,
                token_id,
                &event(current, "api_token.revoke", token_id, ctx),
            )
            .await?
        {
            Ok(())
        } else {
            Err(ApiTokenError::NotFound)
        }
    }

    /// Resolves a bearer token. Malformed, unknown, revoked, and expired
    /// tokens, and tokens of disabled accounts, all give `None`, so callers
    /// cannot tell them apart. Failures are not audited: anyone can send a
    /// token, and a token has 256 random bits, so guessing one is not a
    /// practical attack worth an unbounded number of audit rows.
    pub async fn authenticate(&self, token: &str) -> Result<Option<TokenPrincipal>, ApiTokenError> {
        let Some(token) = token
            .strip_prefix(API_TOKEN_PREFIX)
            .and_then(RandomToken::parse)
        else {
            return Ok(None);
        };
        Ok(self
            .db
            .find_active_api_token(token.hash())
            .await?
            .map(|found| TokenPrincipal {
                token_id: found.token_id,
                scopes: found.scopes,
                actor: CurrentSession {
                    // No browser session stands behind a token. The ID only
                    // ever reaches the read-only services below.
                    session_id: found.token_id,
                    account: found.account,
                },
            }))
    }
}

fn event<'a>(
    current: &CurrentSession,
    action: &'static str,
    token_id: Uuid,
    ctx: RequestContext<'a>,
) -> AuditEvent<'a> {
    AuditEvent {
        actor_account_id: Some(current.account.id),
        action,
        target_type: Some("api_token"),
        target_id: Some(token_id.to_string()),
        outcome: AuditOutcome::Success,
        request_id: ctx.request_id,
        organization_id: None,
    }
}

/// Why an API call was refused.
#[derive(Debug, thiserror::Error)]
pub enum ApiAccessError {
    #[error("this token does not have the {} scope", .0.as_str())]
    MissingScope(ApiTokenScope),
    /// The account's role in the organization does not allow the read.
    #[error("your role in this organization does not allow this")]
    Forbidden,
    /// Not found, or in an organization the account does not belong to.
    #[error("not found")]
    NotFound,
    /// Internal failure. The message is for server logs only.
    #[error("{0}")]
    Internal(String),
}

impl From<OrganizationError> for ApiAccessError {
    fn from(err: OrganizationError) -> Self {
        match err {
            OrganizationError::NotFound => Self::NotFound,
            OrganizationError::Forbidden => Self::Forbidden,
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<ProjectError> for ApiAccessError {
    fn from(err: ProjectError) -> Self {
        match err {
            ProjectError::NotFound => Self::NotFound,
            ProjectError::Forbidden => Self::Forbidden,
            other => Self::Internal(other.to_string()),
        }
    }
}

impl From<ConnectionError> for ApiAccessError {
    fn from(err: ConnectionError) -> Self {
        match err {
            ConnectionError::NotFound => Self::NotFound,
            ConnectionError::Forbidden => Self::Forbidden,
            other => Self::Internal(other.to_string()),
        }
    }
}

/// A project as the API shows it, with its last saved health check.
#[derive(Debug, Clone)]
pub struct ApiProject {
    pub project: ProjectSummary,
    /// `None` when the project was never checked.
    pub last_check: Option<HealthDigest>,
}

/// The reads a token may make. Nothing here changes state.
pub struct TokenApi {
    organizations: Arc<OrganizationService>,
    projects: Arc<ProjectService>,
    connections: Arc<ConnectionService>,
}

impl TokenApi {
    pub const fn new(
        organizations: Arc<OrganizationService>,
        projects: Arc<ProjectService>,
        connections: Arc<ConnectionService>,
    ) -> Self {
        Self {
            organizations,
            projects,
            connections,
        }
    }

    /// The account's organizations, by name. Needs `organizations:read`.
    pub async fn organizations(
        &self,
        principal: &TokenPrincipal,
    ) -> Result<Vec<OrganizationSummary>, ApiAccessError> {
        let actor = principal.require(ApiTokenScope::OrganizationsRead)?;
        Ok(self.organizations.list(actor).await?)
    }

    /// One organization's projects, by name. Needs `projects:read`.
    pub async fn projects(
        &self,
        principal: &TokenPrincipal,
        organization_id: Uuid,
    ) -> Result<Vec<ApiProject>, ApiAccessError> {
        let actor = principal.require(ApiTokenScope::ProjectsRead)?;
        let projects = self.projects.list(actor, organization_id).await?;
        let mut digests = self
            .connections
            .health_digests(actor, organization_id)
            .await?;
        Ok(projects
            .into_iter()
            .map(|project| {
                let last_check = digests
                    .iter()
                    .position(|digest| digest.project_id == project.id)
                    .map(|index| digests.swap_remove(index));
                ApiProject {
                    project,
                    last_check,
                }
            })
            .collect())
    }

    /// One project. Needs `projects:read`.
    pub async fn project(
        &self,
        principal: &TokenPrincipal,
        project_id: Uuid,
    ) -> Result<ApiProject, ApiAccessError> {
        let actor = principal.require(ApiTokenScope::ProjectsRead)?;
        let project = self.projects.get(actor, project_id).await?;
        let last_check = self
            .connections
            .last_report(actor, project_id)
            .await?
            .map(|report| HealthDigest::new(project_id, &report, OffsetDateTime::now_utc()));
        Ok(ApiProject {
            project,
            last_check,
        })
    }
}
