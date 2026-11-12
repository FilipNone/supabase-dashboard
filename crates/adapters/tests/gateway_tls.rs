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
    tls::ExtraRoots,
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
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
    let server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
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
        .check(&url, StackService::Auth, &key)
        .await;
    assert_eq!(
        check.status,
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Tls
        }
    );

    let roots = ExtraRoots::from_pem(pki.ca_pem.as_bytes()).unwrap();
    assert_eq!(roots.len(), 1);
    let check = probe(roots).check(&url, StackService::Auth, &key).await;
    assert_eq!(check.status, ServiceStatus::Healthy);
    assert_eq!(check.version.as_deref(), Some("v2.197.0"));

    // Another authority does not vouch for this server.
    let other = ExtraRoots::from_pem(private_pki().ca_pem.as_bytes()).unwrap();
    let check = probe(other).check(&url, StackService::Auth, &key).await;
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
        .forward(&url, &login, site, request())
        .await;
    assert!(matches!(refused, Err(ProxyError::Tls)), "{refused:?}");

    let roots = ExtraRoots::from_pem(pki.ca_pem.as_bytes()).unwrap();
    let response = proxy(roots)
        .forward(&url, &login, site, request())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
