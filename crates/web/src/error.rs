//! The error type every server function returns to the browser.
//!
//! Messages are fixed or come from input validation, so nothing internal
//! (SQL, file paths, connection details) can reach the browser through
//! them. Internal failures are logged on the server and arrive here as
//! [`AppError::Unavailable`].

use leptos::server_fn::{
    Bytes, Encodes,
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

    /// Server functions serialize their error just before answering, so
    /// this is where the response gets a status that says what happened.
    /// Without it every error, including a rejected form, would be a 500.
    fn ser(&self) -> Bytes {
        #[cfg(feature = "ssr")]
        if let Some(response) = leptos::prelude::use_context::<leptos_axum::ResponseOptions>() {
            response.set_status(self.http_status());
        }
        <JsonEncoding as Encodes<Self>>::encode(self)
            .or_else(|_| <JsonEncoding as Encodes<Self>>::encode(&Self::Transport))
            .unwrap_or_default()
    }
}

impl AppError {
    /// The HTTP status a server function answers with for this error.
    #[cfg(feature = "ssr")]
    pub fn http_status(&self) -> http::StatusCode {
        use http::StatusCode;
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Rejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable | Self::Transport => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(feature = "ssr")]
mod server {
    use supabase_dashboard_application::{
        auth::{AccountUpdateError, AdminError, AuthError, InvitationSignUpError},
        connections::ConnectionError,
        dokploy::DokployServiceError,
        organizations::OrganizationError,
        projects::ProjectError,
        provisioning::ProvisionError,
        studio_access::StudioAccessError,
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

    impl From<ConnectionError> for AppError {
        fn from(err: ConnectionError) -> Self {
            match err {
                ConnectionError::NotFound => Self::NotFound,
                ConnectionError::Forbidden => Self::Forbidden,
                ConnectionError::StorageUnavailable
                | ConnectionError::NotStored
                | ConnectionError::CheckTooSoon { .. }
                | ConnectionError::CheckInProgress
                | ConnectionError::StudioLoginRejected { .. }
                | ConnectionError::NoAuthorities
                | ConnectionError::Authority(_)
                | ConnectionError::Input(_) => Self::Rejected(sentence(&err.to_string())),
                ConnectionError::Cipher(err) => {
                    tracing::error!(error = %err, "credential encryption failed");
                    Self::Unavailable
                }
                ConnectionError::Internal(err) => {
                    tracing::error!(error = %err, "project connection operation failed");
                    Self::Unavailable
                }
            }
        }
    }

    impl From<StudioAccessError> for AppError {
        fn from(err: StudioAccessError) -> Self {
            match err {
                StudioAccessError::NotFound => Self::NotFound,
                StudioAccessError::Forbidden => Self::Forbidden,
                StudioAccessError::Internal(err) => {
                    tracing::error!(error = %err, "Studio access log could not be read");
                    Self::Unavailable
                }
            }
        }
    }

    impl From<DokployServiceError> for AppError {
        fn from(err: DokployServiceError) -> Self {
            match err {
                DokployServiceError::Forbidden => Self::Forbidden,
                // Dokploy's own errors name no address or key, so they are
                // shown as they are.
                DokployServiceError::StorageUnavailable
                | DokployServiceError::AlreadyConnected
                | DokployServiceError::NotConnected
                | DokployServiceError::ServiceNotVisible
                | DokployServiceError::TargetNotVisible
                | DokployServiceError::ProjectNotVisible
                | DokployServiceError::TargetAlreadyAllowed
                | DokployServiceError::TooManyTargets
                | DokployServiceError::OrganizationNotFound
                | DokployServiceError::TargetNotFound
                | DokployServiceError::EnvironmentExists
                | DokployServiceError::EnvironmentOutcomeUnknown
                | DokployServiceError::EnvironmentName(_)
                | DokployServiceError::FromDeployment
                | DokployServiceError::DeploymentConflict { .. }
                | DokployServiceError::Url(_)
                | DokployServiceError::Key(_)
                | DokployServiceError::Dokploy(_) => Self::Rejected(sentence(&err.to_string())),
                DokployServiceError::Cipher(err) => {
                    tracing::error!(error = %err, "Dokploy key encryption failed");
                    Self::Unavailable
                }
                DokployServiceError::Internal(err) => {
                    tracing::error!(error = %err, "Dokploy connection operation failed");
                    Self::Unavailable
                }
            }
        }
    }

    impl From<ProvisionError> for AppError {
        fn from(err: ProvisionError) -> Self {
            match err {
                ProvisionError::Forbidden => Self::Forbidden,
                ProvisionError::NotFound => Self::NotFound,
                ProvisionError::Input(_)
                | ProvisionError::InvalidHost
                | ProvisionError::TargetNotAllowed
                | ProvisionError::NotConnected
                | ProvisionError::NoCipher
                | ProvisionError::LimitReached
                | ProvisionError::NotProvisioned
                | ProvisionError::Busy
                | ProvisionError::AlreadyRemoved
                | ProvisionError::NameMismatch
                | ProvisionError::NotConfirmed
                | ProvisionError::AdoptionNotAllowed
                | ProvisionError::AlreadyAdopted
                | ProvisionError::NotAdoptable(_)
                | ProvisionError::UrlNotOffered
                | ProvisionError::Setting(_)
                | ProvisionError::SettingUnavailable(_)
                | ProvisionError::NoChanges
                | ProvisionError::PreviewOutdated
                | ProvisionError::NoEdits
                | ProvisionError::EditsOutdated
                | ProvisionError::ServiceMissing
                | ProvisionError::DokployUnavailable(_) => {
                    Self::Rejected(sentence(&err.to_string()))
                }
                ProvisionError::Internal(err) => {
                    tracing::error!(error = %err, "provisioning operation failed");
                    Self::Unavailable
                }
            }
        }
    }

    /// Service messages are lowercase clauses; the UI shows sentences.
    fn sentence(message: &str) -> String {
        let mut chars = message.chars();
        let mut out: String = chars
            .next()
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_default();
        out.push_str(chars.as_str());
        if !out.ends_with('.') {
            out.push('.');
        }
        out
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

    #[test]
    fn errors_round_trip_through_their_encoding() {
        for err in [
            AppError::Unauthenticated,
            AppError::NotFound,
            AppError::Forbidden,
            AppError::Rejected("Name is too long.".into()),
            AppError::Unavailable,
            AppError::Transport,
        ] {
            assert_eq!(AppError::de(err.ser()), err);
        }
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn rejected_input_is_not_a_server_error() {
        use http::StatusCode;
        assert_eq!(
            AppError::Rejected("x".into()).http_status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(AppError::Forbidden.http_status(), StatusCode::FORBIDDEN);
        assert_eq!(AppError::NotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            AppError::Unauthenticated.http_status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Unavailable.http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn provisioning_errors_are_sentences_and_hide_internals() {
        use supabase_dashboard_application::provisioning::ProvisionError;
        let internal = AppError::from(ProvisionError::Internal(
            "postgres://dashboard:secret-pw@10.0.0.5/metadata refused".into(),
        ));
        assert_eq!(internal, AppError::Unavailable);
        assert!(!internal.to_string().contains("secret-pw"));
        assert_eq!(
            AppError::from(ProvisionError::Forbidden),
            AppError::Forbidden
        );
        assert_eq!(AppError::from(ProvisionError::NotFound), AppError::NotFound);
        assert_eq!(
            AppError::from(ProvisionError::InvalidHost),
            AppError::Rejected("Enter a host name such as shop.example.com.".into())
        );
        assert_eq!(
            AppError::from(ProvisionError::NotConnected),
            AppError::Rejected(
                "Dokploy is not connected; ask an installation administrator to connect it.".into()
            )
        );
        for err in [
            ProvisionError::TargetNotAllowed,
            ProvisionError::NoCipher,
            ProvisionError::LimitReached,
        ] {
            let AppError::Rejected(message) = AppError::from(err) else {
                panic!("not shown to the operator");
            };
            assert!(message.starts_with(char::is_uppercase), "{message}");
            assert!(message.ends_with('.'), "{message}");
        }
    }
}
