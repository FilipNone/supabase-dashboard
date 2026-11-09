//! SQL editor runs against an in-process HTTP server that imitates a
//! gateway in front of postgres-meta. `gateway_fixture.rs` covers the real
//! Kong and postgres-meta.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::RawQuery,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::post,
};
use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
};
use supabase_dashboard_application::sql::SqlRunner;
use supabase_dashboard_domain::{
    connection::UnreachableReason,
    project::ProjectUrl,
    schema::MetaUnavailable,
    sql::{SqlFailure, SqlText, sql_application_name},
};
use uuid::Uuid;

async fn serve(router: Router) -> ProjectUrl {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    ProjectUrl::parse(&format!("http://{addr}")).unwrap()
}

fn probe(allow_loopback: bool) -> GatewayProbe {
    GatewayProbe::new(GatewaySettings {
        policy: TargetPolicy { allow_loopback },
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
    })
    .unwrap()
}

fn key() -> SecretString {
    SecretString::from("service-key")
}

fn sql(text: &str) -> SqlText {
    SqlText::parse(text).unwrap()
}

#[derive(Debug, Clone)]
struct Seen {
    query: String,
    application_name: Option<String>,
    body: serde_json::Value,
}

/// Records each request and answers it with `answer`.
fn recording(
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: fn(&serde_json::Value) -> (StatusCode, String),
) -> Router {
    Router::new().route(
        "/pg/query",
        post(
            move |headers: HeaderMap,
                  RawQuery(query): RawQuery,
                  Json(body): Json<serde_json::Value>| async move {
                assert_eq!(headers.get("apikey").unwrap(), "service-key");
                assert!(headers.get("x-connection-encrypted").is_none());
                let (status, text) = answer(&body);
                seen.lock().unwrap().push(Seen {
                    query: query.unwrap_or_default(),
                    application_name: headers
                        .get("x-pg-application-name")
                        .map(|v| v.to_str().unwrap().to_owned()),
                    body,
                });
                (
                    status,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    text,
                )
            },
        ),
    )
}

#[tokio::test]
async fn runs_send_the_text_with_limits_and_a_tagged_connection() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = serve(recording(seen.clone(), |_| {
        (
            StatusCode::OK,
            r#"[{"b": 2, "a": "x"}, {"b": null, "a": "y"}]"#.to_owned(),
        )
    }))
    .await;
    let run_id = Uuid::from_u128(42);
    let text = "select 2 as b, 'x' as a\nunion all select null, 'y'";
    let result = probe(true)
        .run(&url, &key(), &sql(text), run_id)
        .await
        .unwrap();
    assert_eq!(result.columns, ["b", "a"]);
    assert_eq!(result.row_count, 2);
    assert_eq!(result.rows[1][0], None);

    let seen = seen.lock().unwrap()[0].clone();
    // Sent as written, with the database-side timeout and the run's name.
    assert_eq!(seen.body, serde_json::json!({ "query": text }));
    assert!(
        seen.query.contains("statementTimeoutSecs=20"),
        "{}",
        seen.query
    );
    assert!(seen.query.contains("queryTimeoutSecs=23"), "{}", seen.query);
    assert_eq!(
        seen.application_name.as_deref(),
        Some(sql_application_name(run_id).as_str())
    );
}

#[tokio::test]
async fn cancel_targets_only_the_run_by_its_connection_name() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = serve(recording(seen.clone(), |_| {
        (StatusCode::OK, r#"[{"cancelled": 1}]"#.to_owned())
    }))
    .await;
    let run_id = Uuid::from_u128(7);
    assert_eq!(probe(true).cancel(&url, &key(), run_id).await, Ok(1));
    let seen = seen.lock().unwrap()[0].clone();
    // The name is a parameter, not part of the statement.
    assert_eq!(
        seen.body["parameters"],
        serde_json::json!([sql_application_name(run_id)])
    );
    let statement = seen.body["query"].as_str().unwrap();
    assert!(statement.contains("pg_cancel_backend"));
    assert!(statement.contains("application_name = $1"));
    assert!(!statement.contains(&run_id.simple().to_string()));
    // The cancel's own connection keeps postgres-meta's name.
    assert_eq!(seen.application_name, None);
}

#[tokio::test]
async fn database_errors_and_limits_are_told_apart() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let url = serve(recording(seen, |body| {
        let error = match body["query"].as_str().unwrap() {
            "syntax" => serde_json::json!({
                "error": "ERROR:  42601: syntax error at or near \"selec\"\nLINE 1: selec 1\n        ^\n",
                "message": "syntax error at or near \"selec\"",
                "code": "42601",
                "position": "1",
            }),
            "slow" => serde_json::json!({
                "error": "ERROR:  57014: canceling statement due to statement timeout\n",
                "code": "57014",
            }),
            "big" => serde_json::json!({
                "message": "Query result size (3000000 bytes) exceeded the configured limit",
                "code": "RESULT_SIZE_EXCEEDED",
            }),
            _ => return (StatusCode::REQUEST_TIMEOUT, r#"{"error":"Query read timeout"}"#.to_owned()),
        };
        (StatusCode::BAD_REQUEST, error.to_string())
    }))
    .await;
    let probe = probe(true);
    let run = |text: &'static str| {
        let probe = probe.clone();
        let url = url.clone();
        async move { probe.run(&url, &key(), &sql(text), Uuid::nil()).await }
    };
    match run("syntax").await {
        Err(SqlFailure::Database { code, message }) => {
            assert_eq!(code.as_deref(), Some("42601"));
            assert!(message.contains("LINE 1: selec 1"), "{message}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(run("slow").await, Err(SqlFailure::Timeout));
    assert_eq!(run("big").await, Err(SqlFailure::ResultTooLarge));
    assert_eq!(run("read timeout").await, Err(SqlFailure::Timeout));
}

#[tokio::test]
async fn oversized_answers_are_not_read() {
    let url = serve(Router::new().route(
        "/pg/query",
        post(|| async {
            let row = format!(r#"{{"v": "{}"}}"#, "x".repeat(1024));
            let rows = vec![row; 11 * 1024];
            format!("[{}]", rows.join(","))
        }),
    ))
    .await;
    assert_eq!(
        probe(true)
            .run(&url, &key(), &sql("select big"), Uuid::nil())
            .await,
        Err(SqlFailure::ResultTooLarge)
    );
}

#[tokio::test]
async fn gateway_answers_map_to_stack_states() {
    let url = serve(
        Router::new()
            .route("/pg/query", post(|| async { StatusCode::FORBIDDEN }))
            .route(
                "/other/pg/query",
                post(|| async { Redirect::temporary("http://169.254.169.254/") }),
            )
            .route(
                "/plain/pg/query",
                post(|| async { (StatusCode::BAD_REQUEST, "<html>no</html>").into_response() }),
            ),
    )
    .await;
    let probe = probe(true);
    let at = |path: &str| ProjectUrl::parse(&format!("{}{path}", url.as_str())).unwrap();
    let unavailable = |reason| Err(SqlFailure::Unavailable { reason });
    assert_eq!(
        probe.run(&url, &key(), &sql("select 1"), Uuid::nil()).await,
        unavailable(MetaUnavailable::KeyRejected { http_status: 403 })
    );
    // A redirect is not followed.
    assert_eq!(
        probe
            .run(&at("/other"), &key(), &sql("select 1"), Uuid::nil())
            .await,
        unavailable(MetaUnavailable::ServiceError { http_status: 307 })
    );
    assert_eq!(
        probe
            .run(&at("/plain"), &key(), &sql("select 1"), Uuid::nil())
            .await,
        unavailable(MetaUnavailable::ServiceError { http_status: 400 })
    );
    assert_eq!(
        probe
            .run(&at("/missing"), &key(), &sql("select 1"), Uuid::nil())
            .await,
        unavailable(MetaUnavailable::NotExposed)
    );
}

#[tokio::test]
async fn loopback_is_refused_unless_allowed() {
    let url = serve(Router::new()).await;
    assert_eq!(
        probe(false)
            .run(&url, &key(), &sql("select 1"), Uuid::nil())
            .await,
        Err(SqlFailure::Unavailable {
            reason: MetaUnavailable::Unreachable {
                reason: UnreachableReason::DestinationNotAllowed
            }
        })
    );
    assert_eq!(
        probe(false).cancel(&url, &key(), Uuid::nil()).await,
        Err(MetaUnavailable::Unreachable {
            reason: UnreachableReason::DestinationNotAllowed
        })
    );
}
