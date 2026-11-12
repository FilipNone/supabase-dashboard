//! Runs against a disposable PostgreSQL database named by
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL`. Each test creates and drops its
//! own database, so the server only needs CREATEDB permission. Without the
//! variable the tests are skipped with a message.

#![allow(clippy::unwrap_used)] // test-only crate; failures should abort the test

use std::time::Duration;

use secrecy::SecretString;
use supabase_dashboard_persistence::{Database, DatabaseSettings};

mod common;
use common::ScratchDb;

#[tokio::test]
async fn migrations_apply_to_a_fresh_database_and_are_idempotent() {
    let Some(scratch) = ScratchDb::create("fresh").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    db.migrate().await.unwrap();

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM installation")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "installation is a singleton");

    let second_insert =
        sqlx::query("INSERT INTO installation (installation_id) VALUES (gen_random_uuid())")
            .execute(db.pool())
            .await;
    assert!(second_insert.is_err(), "singleton constraint must hold");

    db.ping(Duration::from_secs(2)).await.unwrap();
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn statement_timeout_is_enforced_by_the_database() {
    let Some(scratch) = ScratchDb::create("timeout").await else {
        return;
    };
    let settings = DatabaseSettings {
        statement_timeout: Duration::from_secs(1),
        ..scratch.settings.clone()
    };
    let db = Database::connect(&settings).await.unwrap();
    let result = sqlx::query("SELECT pg_sleep(3)").execute(db.pool()).await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("statement timeout"), "{err}");
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn invalid_url_error_does_not_echo_the_url() {
    let settings = DatabaseSettings {
        url: SecretString::from("postgres://user:hunter2@[not-a-host"),
        max_connections: 1,
        acquire_timeout: Duration::from_secs(1),
        statement_timeout: Duration::from_secs(1),
    };
    let err = Database::connect_lazy(&settings).unwrap_err().to_string();
    assert!(!err.contains("hunter2"), "{err}");
}

#[tokio::test]
async fn the_dokploy_connection_is_a_singleton_that_outlives_its_author() {
    let Some(scratch) = ScratchDb::create("dokploy_row").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let account: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         VALUES (gen_random_uuid(), 'a@example.test', 'A', \
                 '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA') \
         RETURNING id",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let insert = |url: &'static str| {
        sqlx::query(
            "INSERT INTO dokploy_connection \
                 (url, key_id, nonce, ciphertext, version, connected_by) \
             VALUES ($1, 'k1', $2, $3, 'v0.31.1', $4)",
        )
        .bind(url)
        .bind(vec![0u8; 12])
        .bind(vec![0u8; 17])
        .bind(account)
        .execute(db.pool())
    };
    insert("https://one.example.test").await.unwrap();
    assert!(
        insert("https://two.example.test").await.is_err(),
        "one connection per installation"
    );
    // A short nonce or ciphertext is refused.
    assert!(
        sqlx::query("UPDATE dokploy_connection SET nonce = '\\x00'")
            .execute(db.pool())
            .await
            .is_err()
    );

    // Deleting the account that connected it keeps the connection.
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account)
        .execute(db.pool())
        .await
        .unwrap();
    let stored = db.find_dokploy_connection().await.unwrap().unwrap();
    assert_eq!(stored.url, "https://one.example.test");
    assert_eq!(stored.connected_by, None);
    assert!(!format!("{stored:?}").contains("ciphertext"));

    db.close().await;
    scratch.drop().await;
}
