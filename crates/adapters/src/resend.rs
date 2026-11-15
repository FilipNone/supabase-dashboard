//! Sends the dashboard's own email through Resend's HTTP API.
//!
//! One request per message to `POST /emails` at [`RESEND_API_URL`], over
//! HTTPS checked against the bundled Mozilla roots plus
//! `SUPABASE_DASHBOARD_EXTRA_CA_FILE`. Redirects are not followed and no
//! proxy is used. The API key goes only in the `Authorization` header and
//! never appears in errors or logs. Errors name Resend's error code and the
//! HTTP status, never Resend's message, which can repeat the recipient
//! address.

use std::time::Duration;

use reqwest::{Client, StatusCode, redirect};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use supabase_dashboard_application::mail::{MailError, Mailer, OutgoingEmail, SendFuture};

use crate::tls::{ExtraRoots, client_config};

/// Resend's API. The deployment cannot point the mailer anywhere else.
pub const RESEND_API_URL: &str = "https://api.resend.com";

/// Longest time a whole send may take when the deployment does not choose
/// one.
pub const DEFAULT_RESEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Most of an error answer that is read.
const MAX_ERROR_BODY_BYTES: usize = 4096;

pub struct ResendSettings {
    pub api_key: SecretString,
    /// The From address, as `address` or `Name <address>`, on a domain
    /// verified in Resend.
    pub from: String,
    /// Bounds each send, connection included.
    pub timeout: Duration,
    pub extra_roots: ExtraRoots,
    /// [`RESEND_API_URL`] outside tests.
    pub api_url: url::Url,
}

#[derive(Debug, thiserror::Error)]
pub enum ResendSetupError {
    #[error("the Resend API URL cannot have emails sent to it")]
    Url,
    #[error("could not set up TLS for Resend: {0}")]
    Tls(String),
    #[error("could not build the HTTP client for Resend: {0}")]
    Client(String),
}

pub struct ResendMailer {
    client: Client,
    endpoint: url::Url,
    api_key: SecretString,
    from: String,
}

#[derive(Serialize)]
struct SendEmail<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    text: &'a str,
}

/// Resend's error answer, of which only the code is used.
#[derive(Deserialize)]
struct ErrorBody {
    name: Option<String>,
}

impl ResendMailer {
    pub fn new(settings: ResendSettings) -> Result<Self, ResendSetupError> {
        let endpoint = settings
            .api_url
            .join("emails")
            .map_err(|_| ResendSetupError::Url)?;
        if endpoint.cannot_be_a_base() {
            return Err(ResendSetupError::Url);
        }
        let tls = client_config(&settings.extra_roots)
            .map_err(|err| ResendSetupError::Tls(err.to_string()))?;
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(settings.timeout)
            .timeout(settings.timeout)
            .pool_idle_timeout(Duration::from_secs(30))
            .user_agent(concat!("supabase-dashboard/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| ResendSetupError::Client(err.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            api_key: settings.api_key,
            from: settings.from,
        })
    }

    async fn deliver(&self, message: &OutgoingEmail) -> Result<(), MailError> {
        let body = SendEmail {
            from: &self.from,
            to: [message.to.as_str()],
            subject: &message.subject,
            text: &message.body,
        };
        let body = serde_json::to_vec(&body).map_err(|err| MailError::Invalid(err.to_string()))?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(request_error)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let mut raw: Vec<u8> = Vec::new();
        while raw.len() < MAX_ERROR_BODY_BYTES {
            match response.chunk().await {
                Ok(Some(chunk)) => raw.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(err) if err.is_timeout() => return Err(MailError::Timeout),
                Err(_) => break,
            }
        }
        raw.truncate(MAX_ERROR_BODY_BYTES);
        Err(status_error(status, error_code(&raw).as_deref()))
    }
}

impl Mailer for ResendMailer {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a> {
        Box::pin(self.deliver(message))
    }
}

fn request_error(err: reqwest::Error) -> MailError {
    if err.is_timeout() {
        return MailError::Timeout;
    }
    // reqwest's message can include the URL, which holds no secret; the
    // key is a header and is never part of it.
    MailError::Unavailable(format!("could not reach Resend: {err}"))
}

/// Resend's error code, kept only when it looks like one, such as
/// `validation_error`.
fn error_code(raw: &[u8]) -> Option<String> {
    let name = serde_json::from_slice::<ErrorBody>(raw).ok()?.name?;
    let looks_like_code = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    looks_like_code.then_some(name)
}

fn status_error(status: StatusCode, code: Option<&str>) -> MailError {
    let detail = match code {
        Some(code) => format!("Resend answered {} ({code})", status.as_u16()),
        None => format!("Resend answered {}", status.as_u16()),
    };
    match status {
        // The key, the account's quota, or Resend itself: nothing about
        // this message.
        StatusCode::UNAUTHORIZED
        | StatusCode::FORBIDDEN
        | StatusCode::TOO_MANY_REQUESTS
        | StatusCode::REQUEST_TIMEOUT => MailError::Unavailable(detail),
        // A redirect is not followed: Resend does not send one for this
        // endpoint, so something between is answering.
        status if status.is_server_error() || status.is_redirection() => {
            MailError::Unavailable(detail)
        }
        // Validation and other client errors: this message was refused.
        _ => MailError::Refused(detail),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn only_code_shaped_names_are_kept() {
        assert_eq!(
            error_code(
                br#"{"statusCode":422,"message":"to@x.test is bad","name":"validation_error"}"#
            )
            .as_deref(),
            Some("validation_error")
        );
        assert_eq!(error_code(br#"{"name":"Not A Code: to@x.test"}"#), None);
        assert_eq!(error_code(b"<html>bad gateway</html>"), None);
        assert_eq!(error_code(br#"{"message":"no name"}"#), None);
    }

    #[test]
    fn statuses_map_to_mail_errors() {
        assert!(matches!(
            status_error(StatusCode::UNAUTHORIZED, Some("validation_error")),
            MailError::Unavailable(_)
        ));
        assert!(matches!(
            status_error(StatusCode::TOO_MANY_REQUESTS, None),
            MailError::Unavailable(_)
        ));
        assert!(matches!(
            status_error(StatusCode::BAD_GATEWAY, None),
            MailError::Unavailable(_)
        ));
        let refused = status_error(StatusCode::UNPROCESSABLE_ENTITY, Some("validation_error"));
        assert_eq!(
            refused,
            MailError::Refused("Resend answered 422 (validation_error)".into())
        );
    }

    #[test]
    fn the_endpoint_is_the_emails_path() {
        let mailer = ResendMailer::new(ResendSettings {
            api_key: SecretString::from("re_test".to_owned()),
            from: "dash@example.test".into(),
            timeout: DEFAULT_RESEND_TIMEOUT,
            extra_roots: ExtraRoots::default(),
            api_url: url::Url::parse(RESEND_API_URL).unwrap(),
        })
        .unwrap();
        assert_eq!(mailer.endpoint.as_str(), "https://api.resend.com/emails");
    }
}
