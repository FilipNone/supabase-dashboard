//! Opening a project's Supabase Studio through the dashboard
//! (docs/adr/0002-studio-access.md).
//!
//! [`StudioService::begin`] runs on the dashboard host for a signed-in
//! member and gives a one-time code. [`StudioService::redeem`] runs on the
//! project's Studio host and turns the code into a Studio session.
//! [`StudioService::authorize`] runs for every request on the Studio host
//! and returns where to forward it and with which login. Studio has no
//! roles of its own, so every step requires [`Permission::StudioOpen`].

use std::time::Duration;

use secrecy::SecretString;
use supabase_dashboard_domain::{
    authority::ProjectAuthorities, authz::Permission, connection::CredentialKind,
    project::ProjectUrl,
};
use supabase_dashboard_persistence::{Database, PersistenceError, audit::AuditOutcome};
use uuid::Uuid;

use crate::{
    auth::{CurrentSession, RequestContext},
    organizations::event,
    secrets::{CredentialCipher, Sealed},
    token::{RandomToken, RandomnessError},
};

/// How long a handoff code works.
pub const HANDOFF_TTL: Duration = Duration::from_secs(60);
/// Longest life of a Studio session; it also ends with its dashboard
/// session.
pub const STUDIO_SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
/// Upper bound on the Studio path a member returns to after signing in.
pub const RETURN_PATH_MAX_LEN: usize = 2048;
/// Where Studio's self-hosted UI starts.
pub const STUDIO_HOME: &str = "/project/default";

#[derive(Debug, thiserror::Error)]
pub enum StudioError {
    /// The project does not exist or the caller is not a member.
    #[error("project not found")]
    NotFound,
    #[error("your role in this organization does not allow opening Studio")]
    Forbidden,
    /// No Studio login is stored, or it cannot be decrypted with this
    /// server's key.
    #[error("Studio access is not set up for this project")]
    NotConfigured,
    /// The code or Studio session is missing, used, expired, or revoked.
    #[error("sign in again to open Studio")]
    Expired,
    #[error(transparent)]
    Randomness(#[from] RandomnessError),
    #[error(transparent)]
    Internal(#[from] PersistenceError),
}

/// A code to send to the project's Studio host.
pub struct Handoff {
    pub code: RandomToken,
    pub project_id: Uuid,
}

/// Where to forward a Studio request, and the login to add.
pub struct StudioUpstream {
    pub api_url: ProjectUrl,
    pub login: SecretString,
    pub account_id: Uuid,
    /// The project's own certificate authorities, if any are stored.
    pub authorities: Option<ProjectAuthorities>,
}

/// Accepts a Studio path to return to: an absolute path on the Studio host,
/// no scheme or host, no backslashes or control characters. Anything else
/// becomes Studio's start page.
pub fn studio_return_path(raw: Option<&str>) -> String {
    match raw {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && path.len() <= RETURN_PATH_MAX_LEN
                && !path.contains('\\')
                && !path.chars().any(char::is_control)
                && !path.starts_with("/__dashboard/") =>
        {
            path.to_owned()
        }
        _ => STUDIO_HOME.to_owned(),
    }
}

pub struct StudioService {
    db: Database,
    cipher: Option<CredentialCipher>,
    idle_timeout: Duration,
}

impl StudioService {
    /// `idle_timeout` must match the dashboard session idle timeout.
    pub fn new(db: Database, cipher: Option<CredentialCipher>, idle_timeout: Duration) -> Self {
        Self {
            db,
            cipher,
            idle_timeout,
        }
    }

    /// Starts opening Studio for the signed-in member. Audited as
    /// `studio.open`, including refusals.
    pub async fn begin(
        &self,
        current: &CurrentSession,
        project_id: Uuid,
        return_path: Option<&str>,
        ctx: RequestContext<'_>,
    ) -> Result<Handoff, StudioError> {
        const ACTION: &str = "studio.open";
        let access = self
            .db
            .find_project_access(project_id, current.account.id)
            .await?
            .ok_or(StudioError::NotFound)?;
        let target = ("project", project_id.to_string());
        let refuse = |outcome, error| {
            let refusal = event(current, ACTION, target.clone(), outcome, ctx);
            async move {
                if let Err(err) = self.db.record_audit_event(&refusal).await {
                    tracing::error!(error = %err, "could not record audit event");
                }
                Err(error)
            }
        };
        if !access.role.allows(Permission::StudioOpen) {
            return refuse(AuditOutcome::Denied, StudioError::Forbidden).await;
        }
        let usable = self.db.list_credentials(project_id).await?.iter().any(|c| {
            c.kind == CredentialKind::StudioLogin
                && self.cipher.as_ref().is_some_and(|k| k.can_open(&c.key_id))
        });
        if !usable {
            return refuse(AuditOutcome::Failure, StudioError::NotConfigured).await;
        }
        let code = RandomToken::generate()?;
        let audit = event(current, ACTION, target, AuditOutcome::Success, ctx);
        self.db
            .create_studio_handoff(
                code.hash(),
                current.session_id,
                project_id,
                &studio_return_path(return_path),
                HANDOFF_TTL,
                &audit,
            )
            .await?;
        Ok(Handoff { code, project_id })
    }

    /// Exchanges a handoff code on the Studio host for a Studio session
    /// token and the path to land on.
    pub async fn redeem(
        &self,
        project_id: Uuid,
        code: &str,
    ) -> Result<(RandomToken, String), StudioError> {
        let code = RandomToken::parse(code).ok_or(StudioError::Expired)?;
        let token = RandomToken::generate()?;
        let path = self
            .db
            .redeem_studio_handoff(
                code.hash(),
                project_id,
                token.hash(),
                STUDIO_SESSION_LIFETIME,
            )
            .await?
            .ok_or(StudioError::Expired)?;
        Ok((token, path))
    }

    /// Whether a reverse proxy may obtain a TLS certificate for this
    /// project's Studio host: the project is registered. No session is
    /// involved, because the proxy asks during the TLS handshake. The answer
    /// tells only whether a random project ID exists, and the deployment
    /// keeps the endpoint that asks this off the public internet.
    pub async fn certificate_allowed(&self, project_id: Uuid) -> Result<bool, StudioError> {
        Ok(self.db.project_exists(project_id).await?)
    }

    /// Checks a Studio session for one request. Every check reads the
    /// current state, so revocation takes effect on the next request.
    pub async fn authorize(
        &self,
        project_id: Uuid,
        token: &str,
    ) -> Result<StudioUpstream, StudioError> {
        let token = RandomToken::parse(token).ok_or(StudioError::Expired)?;
        let grant = self
            .db
            .find_studio_grant(token.hash(), project_id, self.idle_timeout)
            .await?
            .ok_or(StudioError::Expired)?;
        if !grant.role.allows(Permission::StudioOpen) {
            return Err(StudioError::Forbidden);
        }
        let cipher = self.cipher.as_ref().ok_or(StudioError::NotConfigured)?;
        let login = cipher
            .open(
                project_id,
                CredentialKind::StudioLogin,
                &Sealed {
                    key_id: grant.login.key_id,
                    nonce: grant.login.nonce,
                    ciphertext: grant.login.ciphertext,
                },
            )
            .map_err(|_| StudioError::NotConfigured)?;
        Ok(StudioUpstream {
            api_url: grant.api_url,
            login,
            account_id: grant.account_id,
            authorities: grant
                .authorities
                .as_deref()
                .map(ProjectAuthorities::from_stored),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_paths_stay_on_the_studio_host() {
        assert_eq!(
            studio_return_path(Some("/project/default/editor?x=1")),
            "/project/default/editor?x=1"
        );
        for bad in [
            None,
            Some(""),
            Some("project"),
            Some("//evil.example"),
            Some("/\\evil.example"),
            Some("https://evil.example/"),
            Some("/a\nb"),
            Some("/__dashboard/handoff?code=x"),
        ] {
            assert_eq!(studio_return_path(bad), STUDIO_HOME, "{bad:?}");
        }
        assert_eq!(
            studio_return_path(Some(&format!("/{}", "a".repeat(RETURN_PATH_MAX_LEN)))),
            STUDIO_HOME
        );
    }
}
