//! postgres-meta reads against an in-process HTTP server that imitates a
//! gateway. `gateway_fixture.rs` covers the real Kong and postgres-meta.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use axum::{
    Router,
    extract::RawQuery,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
};
use supabase_dashboard_application::schema::SchemaSource;
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    project::ProjectUrl,
    schema::{MetaUnavailable, SchemaName},
};

async fn serve(router: Router) -> ProjectUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    ProjectUrl::parse(&format!("http://{addr}")).unwrap()
}

fn probe(policy: TargetPolicy) -> GatewayProbe {
    GatewayProbe::new(GatewaySettings {
        policy,
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_millis(800),
    })
    .unwrap()
}

fn loopback() -> GatewayProbe {
    probe(TargetPolicy {
        allow_loopback: true,
    })
}

fn key() -> SecretString {
    SecretString::from("service-key")
}

#[tokio::test]
async fn schema_filter_is_url_encoded_and_key_sent_as_header() {
    let url = serve(Router::new().route(
        "/pg/tables",
        get(|headers: HeaderMap, RawQuery(query): RawQuery| async move {
            assert_eq!(headers.get("apikey").unwrap(), "service-key");
            assert!(headers.get("x-connection-encrypted").is_none());
            let query = query.unwrap_or_default();
            assert!(query.contains("included_schemas=my+schema%26x"), "{query}");
            assert!(query.contains("include_columns=false"), "{query}");
            assert!(!query.contains("service-key"));
            r#"[{"id":1,"schema":"my schema&x","name":"t","rls_enabled":false,"comment":null}]"#
        }),
    ))
    .await;
    let schema = SchemaName::parse("my schema&x").unwrap();
    let listing = loopback().tables(&url, &key(), &schema).await.unwrap();
    assert_eq!(listing.tables.len(), 1);
}

#[tokio::test]
async fn missing_route_is_not_exposed() {
    let url = serve(Router::new().fallback(|| async {
        (
            StatusCode::NOT_FOUND,
            r#"{"message":"no Route matched with those values"}"#,
        )
    }))
    .await;
    assert_eq!(
        loopback().schemas(&url, &key()).await.unwrap_err(),
        MetaUnavailable::NotExposed
    );
    assert_eq!(
        loopback().table(&url, &key(), 5).await.unwrap_err(),
        MetaUnavailable::NotExposed
    );
}

#[tokio::test]
async fn statuses_map_to_fixed_states() {
    let url = serve(
        Router::new()
            .route("/pg/schemas", get(|| async { StatusCode::UNAUTHORIZED }))
            .route(
                "/pg/tables",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"error":"password authentication failed for user \"postgres\""}"#,
                    )
                }),
            )
            .route(
                "/pg/tables/{id}",
                get(|| async { Redirect::temporary("http://169.254.169.254/") }),
            ),
    )
    .await;
    let probe = loopback();
    assert_eq!(
        probe.schemas(&url, &key()).await.unwrap_err(),
        MetaUnavailable::KeyRejected { http_status: 401 }
    );
    let schema = SchemaName::parse("public").unwrap();
    let err = probe.tables(&url, &key(), &schema).await.unwrap_err();
    assert_eq!(err, MetaUnavailable::ServiceError { http_status: 500 });
    assert!(!err.detail().contains("password"));
    // Redirects are not followed.
    assert_eq!(
        probe.table(&url, &key(), 1).await.unwrap_err(),
        MetaUnavailable::ServiceError { http_status: 307 }
    );
}

#[tokio::test]
async fn oversized_and_malformed_bodies_are_invalid() {
    let url = serve(
        Router::new()
            .route(
                "/pg/schemas",
                get(|| async { "x".repeat(9 * 1024 * 1024).into_response() }),
            )
            .route("/pg/tables/{id}", get(|| async { "not json" })),
    )
    .await;
    let invalid = MetaUnavailable::Unreachable {
        reason: UnreachableReason::InvalidResponse,
    };
    assert_eq!(loopback().schemas(&url, &key()).await.unwrap_err(), invalid);
    assert_eq!(
        loopback().table(&url, &key(), 1).await.unwrap_err(),
        invalid
    );
}

#[tokio::test]
async fn loopback_is_refused_by_default() {
    let url = serve(Router::new().fallback(|| async { "[]" })).await;
    assert_eq!(
        probe(TargetPolicy::default())
            .schemas(&url, &key())
            .await
            .unwrap_err(),
        MetaUnavailable::Unreachable {
            reason: UnreachableReason::DestinationNotAllowed
        }
    );
}
