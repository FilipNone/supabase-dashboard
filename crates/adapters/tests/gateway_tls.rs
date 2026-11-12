//! Health checks against an HTTPS gateway whose certificate comes from a
//! private authority, generated for each run. Nothing here is a real
//! credential: the authority and its key exist only in memory.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
    tls::{ExtraRoots, read_authorities},
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
    authority::ProjectAuthorities,
    connection::{ServiceStatus, StackService, UnreachableReason},
    project::ProjectUrl,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A private authority and a server certificate it issued for 127.0.0.1.
struct PrivatePki {
    ca_pem: String,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
}

fn private_pki() -> PrivatePki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    server_params.not_after = rcgen::date_time_ymd(2031, 5, 6);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    PrivatePki {
        ca_pem: ca_cert.pem(),
        server_cert: server_cert.der().clone(),
        server_key: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    }
}

/// An HTTPS server that answers every request with Auth's health body.
async fn serve_tls(pki: &PrivatePki) -> ProjectUrl {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![pki.server_cert.clone()], pki.server_key.clone_key())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0_u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = r#"{"version":"v2.197.0","name":"GoTrue"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    ProjectUrl::parse(&format!("https://{addr}")).unwrap()
}

fn probe(extra_roots: ExtraRoots) -> GatewayProbe {
    GatewayProbe::new(GatewaySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        extra_roots,
        ..GatewaySettings::default()
    })
    .unwrap()
}

#[tokio::test]
async fn a_private_authority_is_trusted_only_when_configured() {
    let pki = private_pki();
    let url = serve_tls(&pki).await;
    let key = SecretString::from("anon");

    let check = probe(ExtraRoots::default())
        .check(&url, StackService::Auth, &key, None)
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Tls
        }
    );

    let roots = ExtraRoots::from_pem(pki.ca_pem.as_bytes()).unwrap();
    assert_eq!(roots.len(), 1);
    let check = probe(roots)
        .check(&url, StackService::Auth, &key, None)
        .await;
    assert_eq!(check.status, ServiceStatus::Healthy);
    assert_eq!(check.version.as_deref(), Some("v2.197.0"));
    // 2031-05-06 00:00:00 UTC, the server certificate's notAfter.
    assert_eq!(
        check.certificate_expires_at.map(|t| t.unix_timestamp()),
        Some(1_935_792_000)
    );

    // Another authority does not vouch for this server.
    let other = ExtraRoots::from_pem(private_pki().ca_pem.as_bytes()).unwrap();
    let check = probe(other)
        .check(&url, StackService::Auth, &key, None)
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Tls
        }
    );
}

#[test]
fn ca_files_hold_only_usable_certificates() {
    let pki = private_pki();
    assert!(ExtraRoots::from_pem(pki.ca_pem.as_bytes()).is_ok());
    let two = format!("{}\n{}", pki.ca_pem, private_pki().ca_pem);
    assert_eq!(ExtraRoots::from_pem(two.as_bytes()).unwrap().len(), 2);

    assert!(matches!(
        ExtraRoots::from_pem(b""),
        Err(supabase_dashboard_adapters::tls::ExtraRootsError::Empty)
    ));
    assert!(matches!(
        ExtraRoots::from_pem(b"not pem at all"),
        Err(supabase_dashboard_adapters::tls::ExtraRootsError::Empty)
    ));
    let with_key = format!(
        "{}\n{}",
        pki.ca_pem,
        KeyPair::generate().unwrap().serialize_pem()
    );
    assert!(matches!(
        ExtraRoots::from_pem(with_key.as_bytes()),
        Err(supabase_dashboard_adapters::tls::ExtraRootsError::NotACertificate(_))
    ));
    let huge = vec![b'a'; supabase_dashboard_adapters::tls::MAX_EXTRA_CA_FILE_BYTES + 1];
    assert!(matches!(
        ExtraRoots::from_pem(&huge),
        Err(supabase_dashboard_adapters::tls::ExtraRootsError::TooLarge)
    ));
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert!(matches!(
        ExtraRoots::from_pem(broken.as_bytes()),
        Err(supabase_dashboard_adapters::tls::ExtraRootsError::Unusable { index: 1, .. })
    ));
}

#[tokio::test]
async fn the_studio_proxy_trusts_the_same_authorities() {
    use http::{HeaderMap, Method};
    use supabase_dashboard_adapters::studio_proxy::{
        ProxyBody, ProxyError, ProxyRequest, StudioProxy, StudioProxySettings, StudioSite,
    };
    let pki = private_pki();
    let url = serve_tls(&pki).await;
    let login = SecretString::from("supabase:a-long-enough-test-password");
    let site = StudioSite {
        host: "abc.studio.example.test",
        proto: "https",
        session_cookie: "sd-studio",
    };
    let request = || ProxyRequest {
        method: Method::GET,
        path_and_query: "/project/default".to_owned(),
        headers: HeaderMap::new(),
        body: ProxyBody::empty(),
    };
    let proxy = |extra_roots| {
        StudioProxy::new(StudioProxySettings {
            policy: TargetPolicy {
                allow_loopback: true,
            },
            extra_roots,
            ..StudioProxySettings::default()
        })
        .unwrap()
    };

    let refused = proxy(ExtraRoots::default())
        .forward(&url, &login, None, site, request())
        .await;
    assert!(matches!(refused, Err(ProxyError::Tls)), "{refused:?}");

    let roots = ExtraRoots::from_pem(pki.ca_pem.as_bytes()).unwrap();
    let response = proxy(roots)
        .forward(&url, &login, None, site, request())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // A project's own authority works without the deployment-wide file,
    // for that project's requests only.
    let own = ProjectAuthorities::from_stored(&pki.ca_pem);
    let proxy = proxy(ExtraRoots::default());
    let response = proxy
        .forward(&url, &login, Some(&own), site, request())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let refused = proxy.forward(&url, &login, None, site, request()).await;
    assert!(matches!(refused, Err(ProxyError::Tls)), "{refused:?}");
}

#[tokio::test]
async fn a_project_authority_is_trusted_for_that_project_only() {
    let pki = private_pki();
    let url = serve_tls(&pki).await;
    let key = SecretString::from("anon");
    let probe = probe(ExtraRoots::default());
    let tls_failure = ServiceStatus::Unreachable {
        reason: UnreachableReason::Tls,
    };

    let own = ProjectAuthorities::from_stored(&pki.ca_pem);
    let check = probe
        .check(&url, StackService::Auth, &key, Some(&own))
        .await;
    assert_eq!(check.status, ServiceStatus::Healthy);
    // The cached client is reused for the same bundle.
    let again = ProjectAuthorities::from_stored(&pki.ca_pem);
    let check = probe
        .check(&url, StackService::Auth, &key, Some(&again))
        .await;
    assert_eq!(check.status, ServiceStatus::Healthy);

    // A project without the bundle, or with another authority's, does not
    // trust this server.
    let check = probe.check(&url, StackService::Auth, &key, None).await;
    assert_eq!(check.status, tls_failure);
    let other = ProjectAuthorities::from_stored(&private_pki().ca_pem);
    let check = probe
        .check(&url, StackService::Auth, &key, Some(&other))
        .await;
    assert_eq!(check.status, tls_failure);

    // A stored bundle that no longer parses trusts nothing extra.
    let broken = ProjectAuthorities::from_stored("garbage");
    let check = probe
        .check(&url, StackService::Auth, &key, Some(&broken))
        .await;
    assert_eq!(check.status, tls_failure);
}

#[test]
fn project_bundles_are_summarized_and_bounded() {
    use supabase_dashboard_domain::authority::{AuthorityError, MAX_PROJECT_AUTHORITIES};

    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Synthetic Test CA");
    params.not_after = rcgen::date_time_ymd(2030, 1, 2);
    let ca = params.self_signed(&ca_key).unwrap();

    let (roots, infos) = read_authorities(&ca.pem()).unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].subject, "CN=Synthetic Test CA");
    // 2030-01-02 00:00:00 UTC.
    assert_eq!(infos[0].not_after.unix_timestamp(), 1_893_542_400);
    let fingerprint = &infos[0].sha256;
    assert_eq!(fingerprint.len(), 32 * 3 - 1);
    assert!(
        fingerprint
            .split(':')
            .all(|byte| byte.len() == 2 && byte.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')))
    );

    let too_many = vec![ca.pem(); MAX_PROJECT_AUTHORITIES + 1].join("\n");
    assert_eq!(
        read_authorities(&too_many).unwrap_err(),
        AuthorityError::TooMany
    );
    let with_key = format!("{}\n{}", ca.pem(), ca_key.serialize_pem());
    assert_eq!(
        read_authorities(&with_key).unwrap_err(),
        AuthorityError::NotACertificate
    );
    assert_eq!(read_authorities("").unwrap_err(), AuthorityError::Empty);
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert_eq!(
        read_authorities(broken).unwrap_err(),
        AuthorityError::Unusable { index: 1 }
    );
}
