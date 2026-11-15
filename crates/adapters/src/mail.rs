//! Sends the dashboard's own email over SMTP.
//!
//! The connection is encrypted unless the deployment explicitly allows
//! plain SMTP for local development: `smtps://` uses TLS from the first
//! byte, and `smtp://` requires STARTTLS, so a server that does not offer it
//! gets neither credentials nor a message. Certificates are checked against
//! the bundled Mozilla roots plus `SUPABASE_DASHBOARD_EXTRA_CA_FILE`; there
//! is no way to turn the check off. The SMTP password lives only in the
//! transport and never appears in errors or logs.

use std::{str::FromStr, time::Duration};

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, CertificateStore, Tls, TlsParameters},
        extension::ClientId,
    },
};
use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::mail::{MailError, Mailer, OutgoingEmail, SendFuture};

use crate::tls::ExtraRoots;

/// Longest time a whole send may take, connection included, when the
/// deployment does not choose one.
pub const DEFAULT_SMTP_TIMEOUT: Duration = Duration::from_secs(15);

/// How the connection to the mail server is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// TLS from the start (`smtps://`, port 465 by default).
    ImplicitTls,
    /// Plain connection upgraded with STARTTLS, which the server must offer
    /// (`smtp://`, port 587 by default).
    StartTls,
    /// No encryption. Only for a local test server in development.
    Plaintext,
}

/// Where the mail server is, from `SUPABASE_DASHBOARD_SMTP_URL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpEndpoint {
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
}

impl SmtpEndpoint {
    /// Reads `smtps://host[:port]` or `smtp://host[:port]`. Credentials,
    /// paths, queries, and fragments are refused: the username and password
    /// have their own settings, so the URL can be logged. With
    /// `allow_plaintext`, `smtp://` connects without STARTTLS.
    pub fn parse(raw: &str, allow_plaintext: bool) -> Result<Self, String> {
        let url =
            url::Url::parse(raw).map_err(|_| "expected smtps://host or smtp://host".to_owned())?;
        let security = match url.scheme() {
            "smtps" => SmtpSecurity::ImplicitTls,
            "smtp" if allow_plaintext => SmtpSecurity::Plaintext,
            "smtp" => SmtpSecurity::StartTls,
            _ => return Err("expected an smtps:// or smtp:// URL".to_owned()),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "must not contain credentials; use SUPABASE_DASHBOARD_SMTP_USERNAME and \
                 SUPABASE_DASHBOARD_SMTP_PASSWORD_FILE"
                    .to_owned(),
            );
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err("must be only a scheme, a host, and an optional port".to_owned());
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "needs a host".to_owned())?;
        // A bracketed IPv6 literal is kept as the url crate writes it, but
        // the socket and certificate checks want it bare.
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(match security {
            SmtpSecurity::ImplicitTls => 465,
            SmtpSecurity::StartTls | SmtpSecurity::Plaintext => 587,
        });
        Ok(Self {
            host,
            port,
            security,
        })
    }
}

/// Checks a From address such as `dashboard@example.com` or
/// `Dashboard <dashboard@example.com>`.
pub fn check_from_address(raw: &str) -> Result<(), String> {
    Mailbox::from_str(raw)
        .map(|_| ())
        .map_err(|_| "expected an email address, optionally as `Name <address>`".to_owned())
}

pub struct SmtpSettings {
    pub endpoint: SmtpEndpoint,
    /// Username and password, when the server needs them.
    pub credentials: Option<(String, SecretString)>,
    pub from: String,
    /// Bounds each send, connection included.
    pub timeout: Duration,
    /// Name sent in EHLO, normally the dashboard's public host.
    pub hello_name: Option<String>,
    pub extra_roots: ExtraRoots,
}

#[derive(Debug, thiserror::Error)]
pub enum SmtpSetupError {
    #[error("the From address is invalid")]
    From,
    #[error("could not set up TLS for the mail server: {0}")]
    Tls(String),
}

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    timeout: Duration,
}

impl SmtpMailer {
    pub fn new(settings: SmtpSettings) -> Result<Self, SmtpSetupError> {
        let from = Mailbox::from_str(&settings.from).map_err(|_| SmtpSetupError::From)?;
        let endpoint = &settings.endpoint;
        let tls = match endpoint.security {
            SmtpSecurity::Plaintext => Tls::None,
            SmtpSecurity::ImplicitTls => {
                Tls::Wrapper(tls_parameters(endpoint, &settings.extra_roots)?)
            }
            SmtpSecurity::StartTls => {
                Tls::Required(tls_parameters(endpoint, &settings.extra_roots)?)
            }
        };
        let mut builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(endpoint.host.clone())
                .port(endpoint.port)
                .tls(tls)
                .timeout(Some(settings.timeout));
        if let Some(name) = settings.hello_name {
            builder = builder.hello_name(ClientId::Domain(name));
        }
        if let Some((username, password)) = settings.credentials {
            builder = builder.credentials(Credentials::new(
                username,
                password.expose_secret().to_owned(),
            ));
        }
        Ok(Self {
            transport: builder.build(),
            from,
            timeout: settings.timeout,
        })
    }

    async fn deliver(&self, message: &OutgoingEmail) -> Result<(), MailError> {
        let to = message
            .to
            .as_str()
            .parse()
            .map(|address| Mailbox::new(None, address))
            .map_err(|_| MailError::Invalid("the recipient address".to_owned()))?;
        let email = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(message.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(message.body.clone())
            .map_err(|err| MailError::Invalid(err.to_string()))?;
        match tokio::time::timeout(self.timeout, self.transport.send(email)).await {
            Err(_) => Err(MailError::Timeout),
            Ok(Ok(_)) => Ok(()),
            Ok(Err(err)) if err.is_timeout() => Err(MailError::Timeout),
            Ok(Err(err)) if err.is_permanent() => Err(MailError::Refused(err.to_string())),
            Ok(Err(err)) => Err(MailError::Unavailable(err.to_string())),
        }
    }
}

impl Mailer for SmtpMailer {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a> {
        Box::pin(self.deliver(message))
    }
}

fn tls_parameters(
    endpoint: &SmtpEndpoint,
    extra: &ExtraRoots,
) -> Result<TlsParameters, SmtpSetupError> {
    let mut builder = TlsParameters::builder(endpoint.host.clone())
        .certificate_store(CertificateStore::WebpkiRoots);
    for der in extra.iter() {
        let cert = Certificate::from_der(der.to_vec())
            .map_err(|err| SmtpSetupError::Tls(err.to_string()))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build_rustls()
        .map_err(|err| SmtpSetupError::Tls(err.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn endpoints_require_tls_unless_plaintext_is_allowed() {
        let e = SmtpEndpoint::parse("smtps://mail.example.test", false).unwrap();
        assert_eq!((e.port, e.security), (465, SmtpSecurity::ImplicitTls));
        let e = SmtpEndpoint::parse("smtp://mail.example.test", false).unwrap();
        assert_eq!((e.port, e.security), (587, SmtpSecurity::StartTls));
        let e = SmtpEndpoint::parse("smtp://localhost:1025", true).unwrap();
        assert_eq!((e.port, e.security), (1025, SmtpSecurity::Plaintext));
        // Plaintext never weakens implicit TLS.
        let e = SmtpEndpoint::parse("smtps://mail.example.test:2465", true).unwrap();
        assert_eq!((e.port, e.security), (2465, SmtpSecurity::ImplicitTls));
        let e = SmtpEndpoint::parse("smtp://[::1]:25", true).unwrap();
        assert_eq!(e.host, "::1");
    }

    #[test]
    fn endpoints_refuse_credentials_and_extras() {
        for raw in [
            "smtp://user:hunter2@mail.example.test",
            "smtp://user@mail.example.test",
            "smtp://mail.example.test/path",
            "smtp://mail.example.test?x=1",
            "https://mail.example.test",
            "mail.example.test",
        ] {
            let err = SmtpEndpoint::parse(raw, false).unwrap_err();
            assert!(!err.contains("hunter2"), "{err}");
        }
    }

    use std::sync::{Arc, Mutex};

    use supabase_dashboard_domain::account::Email;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    fn message() -> OutgoingEmail {
        OutgoingEmail {
            to: Email::parse("invitee@example.test").unwrap(),
            subject: "Invitation".into(),
            body: "secret link".into(),
        }
    }

    fn local(port: u16, security: SmtpSecurity, timeout: Duration) -> SmtpMailer {
        SmtpMailer::new(SmtpSettings {
            endpoint: SmtpEndpoint {
                host: "127.0.0.1".into(),
                port,
                security,
            },
            credentials: Some(("dash".into(), SecretString::from("hunter2".to_owned()))),
            from: "dash@example.test".into(),
            timeout,
            hello_name: None,
            extra_roots: ExtraRoots::default(),
        })
        .unwrap()
    }

    /// An SMTP server that offers login but not STARTTLS, and records
    /// every command it receives.
    async fn server_without_starttls() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            write.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log.lock().unwrap().push(line.clone());
                let reply: &[u8] = match line.split(' ').next().unwrap_or("") {
                    "EHLO" => b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n",
                    "QUIT" => b"221 bye\r\n",
                    _ => b"250 ok\r\n",
                };
                if write.write_all(reply).await.is_err() {
                    break;
                }
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn starttls_is_required_before_login_or_mail() {
        let (port, seen) = server_without_starttls().await;
        let mailer = local(port, SmtpSecurity::StartTls, Duration::from_secs(5));
        let err = mailer.send(&message()).await.unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter()
                .all(|line| !line.starts_with("AUTH") && !line.starts_with("MAIL")),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accepts and never answers.
        let hold = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mailer = local(port, SmtpSecurity::StartTls, Duration::from_millis(300));
        let started = std::time::Instant::now();
        let err = mailer.send(&message()).await.unwrap_err();
        assert_eq!(err, MailError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        hold.abort();
    }

    #[test]
    fn from_addresses() {
        check_from_address("dash@example.test").unwrap();
        check_from_address("Dashboard <dash@example.test>").unwrap();
        check_from_address("not an address").unwrap_err();
    }
}
