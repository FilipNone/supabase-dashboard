//! Reading the audit log against a scratch metadata database. Skipped
//! unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    organizations::{OrganizationError, OrganizationService},
    projects::{ProjectService, Registration},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    audit::{AUDIT_PAGE, AuditEntryOutcome},
    authz::OrgRole,
};
use supabase_dashboard_persistence::{
    Database,
    accounts::AccountRecord,
    audit::{AuditEvent, AuditOutcome, AuditScope},
};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-audit"),
        user_agent: None,
    }
}

async fn account(db: &Database, name: &str) -> CurrentSession {
    let id = Uuid::now_v7();
    let email = format!("{}@example.test", name.to_lowercase());
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(&email)
    .bind(name)
    .bind(HASH)
    .execute(db.pool())
    .await
    .unwrap();
    CurrentSession {
        session_id: Uuid::now_v7(),
        account: AccountRecord {
            id,
            email: Email::parse(&email).unwrap(),
            display_name: DisplayName::parse(name).unwrap(),
            is_installation_admin: false,
            disabled: false,
        },
    }
}

async fn add_member(db: &Database, org: Uuid, who: &CurrentSession, role: OrgRole) {
    sqlx::query(
        "INSERT INTO organization_members (organization_id, account_id, role) VALUES ($1, $2, $3)",
    )
    .bind(org)
    .bind(who.account.id)
    .bind(role.as_str())
    .execute(db.pool())
    .await
    .unwrap();
}

fn registration(name: &str) -> Registration<'_> {
    Registration {
        name,
        api_url: "https://supabase.example.test/",
        allow_unencrypted: false,
    }
}

#[tokio::test]
async fn owners_and_admins_read_only_their_organizations_events() {
    let Some(scratch) = ScratchDb::create("app_audit_org").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = OrganizationService::new(db.clone());
    let projects = ProjectService::new(db.clone());
    let alice = account(&db, "Alice").await;
    let bob = account(&db, "Bob").await;
    let dev = account(&db, "Dev").await;
    let viewer = account(&db, "Viewer").await;

    let acme = orgs.create(&alice, "Acme", ctx()).await.unwrap();
    let globex = orgs.create(&bob, "Globex", ctx()).await.unwrap();
    add_member(&db, acme.id, &bob, OrgRole::Admin).await;
    add_member(&db, acme.id, &dev, OrgRole::Developer).await;
    add_member(&db, acme.id, &viewer, OrgRole::Viewer).await;

    let project = projects
        .register(&alice, acme.id, registration("Shop"), ctx())
        .await
        .unwrap();
    projects
        .rename(&bob, project.id, "Shop two", ctx())
        .await
        .unwrap();
    orgs.rename(&alice, acme.id, "Acme Inc", ctx())
        .await
        .unwrap();
    orgs.change_role(&alice, acme.id, dev.account.id, OrgRole::Viewer, ctx())
        .await
        .unwrap();
    // The project row is gone when this event is written.
    projects
        .unregister(&alice, project.id, "Shop two", ctx())
        .await
        .unwrap();
    // Bob's own organization, not Acme's.
    orgs.rename(&bob, globex.id, "Globex Corp", ctx())
        .await
        .unwrap();

    let log = orgs
        .audit_log(&bob, acme.id, None, None, ctx())
        .await
        .unwrap();
    let actions: Vec<&str> = log.entries.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "project.unregister",
            "organization.member_role_change",
            "organization.rename",
            "project.rename",
            "project.register",
            "organization.create",
        ],
        "newest first, Acme's only"
    );
    assert!(log.older.is_none());
    assert!(
        log.entries
            .iter()
            .all(|e| e.outcome == AuditEntryOutcome::Success)
    );
    let names: Vec<&str> = log
        .members
        .iter()
        .map(|m| m.display_name.as_str())
        .collect();
    assert_eq!(names, ["Alice", "Bob"]);

    // Only one member's events.
    let bobs = orgs
        .audit_log(&alice, acme.id, Some(bob.account.id), None, ctx())
        .await
        .unwrap();
    let actions: Vec<&str> = bobs.entries.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["project.rename"]);

    // Developers and viewers are refused, and the refusal is recorded in
    // the organization's log.
    for who in [&dev, &viewer] {
        assert!(matches!(
            orgs.audit_log(who, acme.id, None, None, ctx()).await,
            Err(OrganizationError::Forbidden)
        ));
    }
    let log = orgs
        .audit_log(&alice, acme.id, None, None, ctx())
        .await
        .unwrap();
    let denied: Vec<&str> = log
        .entries
        .iter()
        .filter(|e| e.outcome == AuditEntryOutcome::Denied)
        .map(|e| e.action.as_str())
        .collect();
    assert_eq!(denied, ["audit.read", "audit.read"]);

    // Another organization's log looks missing, and a cursor taken from
    // another organization's log gives nothing.
    assert!(matches!(
        orgs.audit_log(&alice, globex.id, None, None, ctx()).await,
        Err(OrganizationError::NotFound)
    ));
    let globex_event = orgs
        .audit_log(&bob, globex.id, None, None, ctx())
        .await
        .unwrap()
        .entries[0]
        .id;
    let page = orgs
        .audit_log(&alice, acme.id, None, Some(globex_event), ctx())
        .await
        .unwrap();
    assert!(page.entries.is_empty());
}

#[tokio::test]
async fn pages_neither_repeat_nor_skip_events() {
    let Some(scratch) = ScratchDb::create("app_audit_pages").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = OrganizationService::new(db.clone());
    let alice = account(&db, "Alice").await;
    let acme = orgs.create(&alice, "Acme", ctx()).await.unwrap();
    // More than two pages, all in one statement so they share a time.
    let extra = i64::from(AUDIT_PAGE) * 2 + 3;
    sqlx::query(
        "INSERT INTO audit_events (id, occurred_at, actor_account_id, action, target_type, \
             target_id, outcome, organization_id) \
         SELECT gen_random_uuid(), now(), $1, 'organization.rename', 'organization', $2, \
             'success', $3 FROM generate_series(1, $4)",
    )
    .bind(alice.account.id)
    .bind(acme.id.to_string())
    .bind(acme.id)
    .bind(extra)
    .execute(db.pool())
    .await
    .unwrap();

    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = orgs
            .audit_log(&alice, acme.id, None, before, ctx())
            .await
            .unwrap();
        assert!(page.entries.len() <= usize::from(AUDIT_PAGE));
        seen.extend(page.entries.iter().map(|e| e.id));
        match page.older {
            Some(older) => before = Some(older),
            None => break,
        }
    }
    let total = usize::try_from(extra).unwrap() + 1;
    assert_eq!(seen.len(), total);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), total, "no event listed twice");
}

#[tokio::test]
async fn an_account_log_has_its_own_events_and_those_about_it() {
    let Some(scratch) = ScratchDb::create("app_audit_account").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = OrganizationService::new(db.clone());
    let alice = account(&db, "Alice").await;
    let bob = account(&db, "Bob").await;
    orgs.create(&alice, "Acme", ctx()).await.unwrap();
    orgs.create(&bob, "Globex", ctx()).await.unwrap();
    // A failed sign-in with Alice's email, by no one.
    db.record_audit_event(&AuditEvent {
        actor_account_id: None,
        action: "session.sign_in",
        target_type: Some("account"),
        target_id: Some(alice.account.id.to_string()),
        outcome: AuditOutcome::Failure,
        request_id: None,
        organization_id: None,
    })
    .await
    .unwrap();

    let entries = db
        .list_audit_events(AuditScope::Account(alice.account.id), None, None, 10)
        .await
        .unwrap();
    let actions: Vec<(&str, AuditEntryOutcome)> = entries
        .iter()
        .map(|e| (e.action.as_str(), e.outcome))
        .collect();
    assert_eq!(
        actions,
        [
            ("session.sign_in", AuditEntryOutcome::Failure),
            ("organization.create", AuditEntryOutcome::Success),
        ]
    );
    assert!(entries[0].actor.is_none());
}

#[tokio::test]
async fn earlier_events_get_their_organization_from_the_target() {
    let Some(scratch) = ScratchDb::create("app_audit_backfill").await else {
        return;
    };
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = OrganizationService::new(db.clone());
    let alice = account(&db, "Alice").await;
    let acme = orgs.create(&alice, "Acme", ctx()).await.unwrap();
    let member = format!("{}:{}", acme.id, alice.account.id);
    let organization: Option<Uuid> =
        sqlx::query_scalar("SELECT audit_target_organization('organization_member', $1)")
            .bind(&member)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(organization, Some(acme.id));
    // Malformed or unknown targets give no organization rather than an
    // error, so they cannot fail an event's insert.
    for (kind, id) in [
        ("organization", "not-a-uuid"),
        ("project", "01a1c0a7-db5e-72a1-a5f2-6614555142e3"),
        ("organization_member", "x:y"),
        ("account", acme.id.to_string().as_str()),
    ] {
        let organization: Option<Uuid> =
            sqlx::query_scalar("SELECT audit_target_organization($1, $2)")
                .bind(kind)
                .bind(id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(organization, None, "{kind} {id}");
    }
}
