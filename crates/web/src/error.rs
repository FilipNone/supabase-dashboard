//! The error type every server function returns to the browser.
//!
//! Messages are fixed or come from input validation, so nothing internal
//! (SQL, file paths, connection details) can reach the browser through
//! them. Internal failures are logged on the server and arrive here as
//! [`AppError::Unavailable`].

use leptos::server_fn::{
    codec::JsonEncoding,
    error::{FromServerFnError, ServerFnErrorErr},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum AppError {
    #[error("Your session has ended. Sign in again to continue.")]
    Unauthenticated,
    /// Also returned for records the operator may not see, so their
    /// existence is not revealed.
    #[error("This was not found, or you do not have access to it.")]
    NotFound,
    #[error("Your role does not allow this action.")]
    Forbidden,
    /// A validation or business-rule message meant for the operator.
    #[error("{0}")]
    Rejected(String),
    #[error("The dashboard could not complete the request. Try again shortly.")]
    Unavailable,
    /// The request did not reach the server function, or its response could
    /// not be read. Details stay out of the UI.
    #[error("The request could not be sent. Check your connection and try again.")]
    Transport,
}

impl FromServerFnError for AppError {
    type Encoder = JsonEncoding;

    fn from_server_fn_error(_value: ServerFnErrorErr) -> Self {
        Self::Transport
    }
}

#[cfg(feature = "ssr")]
mod server {
    use supabase_dashboard_application::{
        auth::{AccountUpdateError, AdminError, AuthError, InvitationSignUpError},
        organizations::OrganizationError,
        projects::ProjectError,
    };

    use super::AppError;

    impl From<AuthError> for AppError {
        fn from(err: AuthError) -> Self {
            tracing::error!(error = %err, "account operation failed");
            Self::Unavailable
        }
    }

    impl From<AdminError> for AppError {
        fn from(err: AdminError) -> Self {
            match err {
                AdminError::Forbidden => Self::Forbidden,
                AdminError::NotFound => Self::NotFound,
                AdminError::CannotDisableSelf | AdminError::LastAdmin => {
                    Self::Rejected(err.to_string())
                }
                AdminError::Internal(err) => err.into(),
            }
        }
    }

    impl From<AccountUpdateError> for AppError {
        fn from(err: AccountUpdateError) -> Self {
            match err {
                AccountUpdateError::WrongPassword
                | AccountUpdateError::Conflict
                | AccountUpdateError::Input(_) => Self::Rejected(err.to_string()),
                AccountUpdateError::Throttled { retry_after } => Self::Rejected(format!(
                    "Too many failed attempts. Try again in {} minutes.",
                    retry_after.as_secs().div_ceil(60).max(1)
                )),
                AccountUpdateError::Internal(err) => err.into(),
            }
        }
    }

    impl From<InvitationSignUpError> for AppError {
        fn from(err: InvitationSignUpError) -> Self {
            match err {
                InvitationSignUpError::InvalidInvitation
                | InvitationSignUpError::AccountExists
                | InvitationSignUpError::Input(_) => Self::Rejected(err.to_string()),
                InvitationSignUpError::Internal(err) => {
                    tracing::error!(error = %err, "invitation sign-up failed");
                    Self::Unavailable
                }
            }
        }
    }

    impl From<ProjectError> for AppError {
        fn from(err: ProjectError) -> Self {
            match err {
                ProjectError::NotFound => Self::NotFound,
                ProjectError::Forbidden => Self::Forbidden,
                ProjectError::LimitReached
                | ProjectError::ConfirmationMismatch
                | ProjectError::Input(_) => Self::Rejected(err.to_string()),
                ProjectError::Internal(err) => {
                    tracing::error!(error = %err, "project operation failed");
                    Self::Unavailable
                }
            }
        }
    }

    impl From<OrganizationError> for AppError {
        fn from(err: OrganizationError) -> Self {
            match err {
                OrganizationError::NotFound | OrganizationError::MemberNotFound => Self::NotFound,
                OrganizationError::Forbidden => Self::Forbidden,
                OrganizationError::LimitReached
                | OrganizationError::AlreadyMember
                | OrganizationError::TooManyInvitations
                | OrganizationError::InvitationNotFound
                | OrganizationError::InvitationInvalid
                | OrganizationError::InvitationEmailMismatch
                | OrganizationError::Input(_)
                | OrganizationError::AccountInput(_)
                | OrganizationError::Membership(_) => Self::Rejected(err.to_string()),
                OrganizationError::Internal(err) => {
                    tracing::error!(error = %err, "organization operation failed");
                    Self::Unavailable
                }
                OrganizationError::Randomness(err) => {
                    tracing::error!(error = %err, "organization operation failed");
                    Self::Unavailable
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_details_are_dropped() {
        let err = AppError::from_server_fn_error(ServerFnErrorErr::ServerError(
            "connection to 10.0.0.5:5432 refused".into(),
        ));
        assert_eq!(err, AppError::Transport);
        assert!(!err.to_string().contains("10.0.0.5"));
    }
}
