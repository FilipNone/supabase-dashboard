//! Accounts, sessions, and audit storage against a scratch database. Skipped
//! unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use supabase_dashboard_domain::account::{DisplayName, Email};
use supabase_dashboard_persistence::{
    Database,
    accounts::NewAccount,
    audit::{AuditEvent, AuditOutcome},
    sessions::NewSession,
};
use time::OffsetDateTime;
use uuid::Uuid;

mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const IDLE: Duration = Duration::from_secs(3600);

fn bootstrap_event() -> AuditEvent<'static> {
    AuditEvent {
        actor_account_id: None,
        action: "account.bootstrap_owner",
        target_type: Some("account"),
        target_id: None,
        outcome: AuditOutcome::Success,
        request_id: None,
    }
}

async fn migrated(scratch: &ScratchDb) -> Database {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    db
}

async fn create_owner(db: &Database, email: &str) -> (bool, Uuid) {
    let id = Uuid::now_v7();
    let email = Email::parse(email).unwrap();
    let name = DisplayName::parse("Owner").unwrap();
    let created = db
        .create_first_account(
            &NewAccount {
                id,
                email: &email,
                display_name: &name,
                password_hash: HASH,
                is_installation_admin: true,
            },
            &bootstrap_event(),
        )
        .await
        .unwrap();
    (created, id)
}

#[tokio::test]
async fn first_account_can_be_created_only_once() {
    let Some(scratch) = ScratchDb::create("bootstrap").await else {
        return;
    };
    let db = migrated(&scratch).await;

    let (first, _) = create_owner(&db, "owner@example.test").await;
    let (second, _) = create_owner(&db, "other@example.test").await;
    assert!(first);
    assert!(!second, "a second bootstrap must be refused");
    assert_eq!(db.account_count().await.unwrap(), 1);
    assert_eq!(
        db.count_audit_events("account.bootstrap_owner")
            .await
            .unwrap(),
        1
    );

    let found = db
        .find_credentials_by_email(&Email::parse("OWNER@example.test").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.password_hash, HASH);
    assert!(found.account.is_installation_admin);
    assert!(!found.account.disabled);

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn concurrent_bootstrap_creates_a_single_owner() {
    let Some(scratch) = ScratchDb::create("bootstrap_race").await else {
        return;
    };
    let db = migrated(&scratch).await;
    let (a, b) = tokio::join!(
        create_owner(&db, "a@example.test"),
        create_owner(&db, "b@example.test")
    );
    assert!(a.0 ^ b.0, "exactly one bootstrap wins");
    assert_eq!(db.account_count().await.unwrap(), 1);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn session_lifecycle_and_revocation() {
    let Some(scratch) = ScratchDb::create("sessions").await else {
        return;
    };
    let db = migrated(&scratch).await;
    let (_, account_id) = create_owner(&db, "owner@example.test").await;

    let token_a = [1u8; 32];
    let token_b = [2u8; 32];
    let expired = [3u8; 32];
    let in_a_day = OffsetDateTime::now_utc() + time::Duration::days(1);
    let mut ids = Vec::new();
    for (token, expires_at) in [
        (&token_a, in_a_day),
        (&token_b, in_a_day),
        (
            &expired,
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
        ),
    ] {
        let id = Uuid::now_v7();
        ids.push(id);
        db.create_session(&NewSession {
            id,
            account_id,
            token_hash: token,
            expires_at,
            user_agent: Some("test-agent"),
        })
        .await
        .unwrap();
    }

    let session = db
        .find_active_session(&token_a, IDLE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.session_id, ids[0]);
    assert_eq!(session.account.id, account_id);
    assert!(
        db.find_active_session(&expired, IDLE)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_active_session(&[9u8; 32], IDLE)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.list_live_sessions(account_id, IDLE).await.unwrap().len(),
        2
    );

    // Revoking someone else's session ID fails.
    assert!(
        !db.revoke_account_session(Uuid::now_v7(), ids[1])
            .await
            .unwrap()
    );
    assert!(db.revoke_account_session(account_id, ids[1]).await.unwrap());
    assert!(
        db.find_active_session(&token_b, IDLE)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        db.revoke_session_by_token(&token_a).await.unwrap(),
        Some((ids[0], account_id))
    );
    assert_eq!(db.revoke_session_by_token(&token_a).await.unwrap(), None);
    assert!(
        db.find_active_session(&token_a, IDLE)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(db.delete_dead_sessions(IDLE).await.unwrap(), 3);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn idle_and_disabled_sessions_are_rejected() {
    let Some(scratch) = ScratchDb::create("idle").await else {
        return;
    };
    let db = migrated(&scratch).await;
    let (_, account_id) = create_owner(&db, "owner@example.test").await;
    let token = [7u8; 32];
    db.create_session(&NewSession {
        id: Uuid::now_v7(),
        account_id,
        token_hash: &token,
        expires_at: OffsetDateTime::now_utc() + time::Duration::days(1),
        user_agent: None,
    })
    .await
    .unwrap();

    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '2 hours'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        db.find_active_session(&token, IDLE)
            .await
            .unwrap()
            .is_none()
    );

    sqlx::query("UPDATE sessions SET last_seen_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        db.find_active_session(&token, IDLE)
            .await
            .unwrap()
            .is_some()
    );

    sqlx::query("UPDATE accounts SET disabled_at = now()")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        db.find_active_session(&token, IDLE)
            .await
            .unwrap()
            .is_none()
    );

    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn audit_rejects_malformed_actions() {
    let Some(scratch) = ScratchDb::create("audit").await else {
        return;
    };
    let db = migrated(&scratch).await;
    let bad = AuditEvent {
        action: "Not An Action",
        ..bootstrap_event()
    };
    assert!(db.record_audit_event(&bad).await.is_err());
    let long_request_id = "r".repeat(500);
    let ok = AuditEvent {
        request_id: Some(&long_request_id),
        ..bootstrap_event()
    };
    db.record_audit_event(&ok).await.unwrap();
    db.close().await;
    scratch.drop().await;
}
