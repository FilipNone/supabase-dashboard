//! Organization authorization against a scratch metadata database. Skipped
//! unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    organizations::{OrganizationError, OrganizationService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::{MembershipError, OrgRole},
};
use supabase_dashboard_persistence::{
    Database, accounts::AccountRecord, audit::AuditEvent, audit::AuditOutcome,
    organizations::CreateOrganizationOutcome,
};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-org"),
        user_agent: None,
    }
}

async fn setup(scratch: &ScratchDb) -> (Database, OrganizationService) {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    (db.clone(), OrganizationService::new(db))
}

/// Inserts an account directly; account creation itself is tested elsewhere.
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

/// Adds a member directly, standing in for an accepted invitation.
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

async fn denied_count(db: &Database, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = 'denied'")
        .bind(action)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn organizations_are_isolated_between_non_members() {
    let Some(scratch) = ScratchDb::create("app_org_isolation").await else {
        return;
    };
    let (db, orgs) = setup(&scratch).await;
    let alice = account(&db, "Alice").await;
    let bob = account(&db, "Bob").await;

    let acme = orgs.create(&alice, "  Acme  ", ctx()).await.unwrap();
    assert_eq!(acme.name.as_str(), "Acme");
    assert_eq!(acme.role, OrgRole::Owner);
    let globex = orgs.create(&bob, "Globex", ctx()).await.unwrap();

    // Each sees only their own organization.
    assert_eq!(orgs.list(&alice).await.unwrap(), vec![acme.clone()]);
    assert_eq!(orgs.list(&bob).await.unwrap(), vec![globex.clone()]);

    // Another organization's ID behaves exactly like a guessed one.
    for org in [globex.id, Uuid::now_v7()] {
        assert!(matches!(
            orgs.get(&alice, org).await,
            Err(OrganizationError::NotFound)
        ));
        assert!(matches!(
            orgs.members(&alice, org).await,
            Err(OrganizationError::NotFound)
        ));
        assert!(matches!(
            orgs.rename(&alice, org, "Taken", ctx()).await,
            Err(OrganizationError::NotFound)
        ));
        assert!(matches!(
            orgs.change_role(&alice, org, bob.account.id, OrgRole::Viewer, ctx())
                .await,
            Err(OrganizationError::NotFound)
        ));
        assert!(matches!(
            orgs.remove_member(&alice, org, bob.account.id, ctx()).await,
            Err(OrganizationError::NotFound)
        ));
    }
    // Bob is not in Acme, so Alice cannot act on him there either.
    assert!(matches!(
        orgs.change_role(&alice, acme.id, bob.account.id, OrgRole::Owner, ctx())
            .await,
        Err(OrganizationError::MemberNotFound)
    ));

    let globex_now = orgs.get(&bob, globex.id).await.unwrap();
    assert_eq!(globex_now.name.as_str(), "Globex");
    let bob_members = orgs.members(&bob, globex.id).await.unwrap();
    assert_eq!(bob_members.len(), 1);
    assert!(bob_members[0].is_you);
    assert_eq!(
        db.count_audit_events("organization.create").await.unwrap(),
        2
    );
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn roles_are_enforced_on_every_operation() {
    let Some(scratch) = ScratchDb::create("app_org_roles").await else {
        return;
    };
    let (db, orgs) = setup(&scratch).await;
    let owner = account(&db, "Owner").await;
    let admin = account(&db, "Admin").await;
    let dev = account(&db, "Dev").await;
    let viewer = account(&db, "Viewer").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&db, org, &admin, OrgRole::Admin).await;
    add_member(&db, org, &dev, OrgRole::Developer).await;
    add_member(&db, org, &viewer, OrgRole::Viewer).await;

    // Everyone can read the organization and its members.
    for who in [&owner, &admin, &dev, &viewer] {
        assert_eq!(orgs.members(who, org).await.unwrap().len(), 4);
    }
    let roles: Vec<_> = orgs
        .members(&viewer, org)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.role)
        .collect();
    assert_eq!(
        roles,
        [
            OrgRole::Owner,
            OrgRole::Admin,
            OrgRole::Developer,
            OrgRole::Viewer
        ]
    );

    // Renaming needs OrgUpdate; refusals are audited.
    for who in [&dev, &viewer] {
        assert!(matches!(
            orgs.rename(who, org, "Mine", ctx()).await,
            Err(OrganizationError::Forbidden)
        ));
    }
    assert_eq!(denied_count(&db, "organization.rename").await, 2);
    let renamed = orgs.rename(&admin, org, "Acme Ops", ctx()).await.unwrap();
    assert_eq!(renamed.name.as_str(), "Acme Ops");
    assert_eq!(renamed.role, OrgRole::Admin);
    assert!(matches!(
        orgs.rename(&admin, org, "   ", ctx()).await,
        Err(OrganizationError::Input(_))
    ));

    // Developers and viewers cannot manage members.
    assert!(matches!(
        orgs.change_role(&dev, org, viewer.account.id, OrgRole::Developer, ctx())
            .await,
        Err(OrganizationError::Forbidden)
    ));
    assert!(matches!(
        orgs.remove_member(&viewer, org, dev.account.id, ctx())
            .await,
        Err(OrganizationError::Forbidden)
    ));
    // Nor promote themselves.
    assert!(matches!(
        orgs.change_role(&viewer, org, viewer.account.id, OrgRole::Admin, ctx())
            .await,
        Err(OrganizationError::Forbidden)
    ));

    // Admins manage non-owners but cannot touch the owner role.
    assert!(matches!(
        orgs.change_role(&admin, org, dev.account.id, OrgRole::Owner, ctx())
            .await,
        Err(OrganizationError::Membership(
            MembershipError::OwnerRoleRequiresOwner
        ))
    ));
    assert!(matches!(
        orgs.remove_member(&admin, org, owner.account.id, ctx())
            .await,
        Err(OrganizationError::Membership(
            MembershipError::OwnerRoleRequiresOwner
        ))
    ));
    orgs.change_role(&admin, org, viewer.account.id, OrgRole::Developer, ctx())
        .await
        .unwrap();
    orgs.remove_member(&admin, org, dev.account.id, ctx())
        .await
        .unwrap();

    // A removed member loses access immediately.
    assert!(matches!(
        orgs.get(&dev, org).await,
        Err(OrganizationError::NotFound)
    ));
    assert!(orgs.list(&dev).await.unwrap().is_empty());
    assert_eq!(
        db.count_audit_events("organization.member_remove")
            .await
            .unwrap(),
        3
    );
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn the_last_owner_cannot_leave_or_step_down() {
    let Some(scratch) = ScratchDb::create("app_org_last_owner").await else {
        return;
    };
    let (db, orgs) = setup(&scratch).await;
    let owner = account(&db, "Owner").await;
    let viewer = account(&db, "Viewer").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&db, org, &viewer, OrgRole::Viewer).await;

    assert!(matches!(
        orgs.remove_member(&owner, org, owner.account.id, ctx())
            .await,
        Err(OrganizationError::Membership(MembershipError::LastOwner))
    ));
    assert!(matches!(
        orgs.change_role(&owner, org, owner.account.id, OrgRole::Admin, ctx())
            .await,
        Err(OrganizationError::Membership(MembershipError::LastOwner))
    ));
    assert_eq!(denied_count(&db, "organization.leave").await, 1);

    // Any member may leave; no management permission is needed.
    orgs.remove_member(&viewer, org, viewer.account.id, ctx())
        .await
        .unwrap();
    assert_eq!(
        db.count_audit_events("organization.leave").await.unwrap(),
        2
    );

    // Once someone else owns it, the original owner can go.
    let heir = account(&db, "Heir").await;
    add_member(&db, org, &heir, OrgRole::Developer).await;
    orgs.change_role(&owner, org, heir.account.id, OrgRole::Owner, ctx())
        .await
        .unwrap();
    orgs.remove_member(&owner, org, owner.account.id, ctx())
        .await
        .unwrap();
    let members = orgs.members(&heir, org).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].role, OrgRole::Owner);
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn concurrent_demotions_keep_one_owner() {
    let Some(scratch) = ScratchDb::create("app_org_race").await else {
        return;
    };
    let (db, orgs) = setup(&scratch).await;
    let first = account(&db, "First").await;
    let second = account(&db, "Second").await;
    let org = orgs.create(&first, "Acme", ctx()).await.unwrap().id;
    add_member(&db, org, &second, OrgRole::Owner).await;

    for _ in 0..5 {
        // Each owner demotes the other at the same time. The organization
        // lock serializes them, so the second sees one owner and refuses.
        let (a, b) = tokio::join!(
            orgs.change_role(&first, org, second.account.id, OrgRole::Admin, ctx()),
            orgs.change_role(&second, org, first.account.id, OrgRole::Admin, ctx()),
        );
        assert_eq!(a.is_ok() as u8 + b.is_ok() as u8, 1, "{a:?} {b:?}");
        let owners: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_members WHERE organization_id = $1 AND role = 'owner'",
        )
        .bind(org)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(owners, 1);
        // Restore two owners for the next round.
        sqlx::query("UPDATE organization_members SET role = 'owner' WHERE organization_id = $1")
            .bind(org)
            .execute(db.pool())
            .await
            .unwrap();
    }
    db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn membership_count_is_capped() {
    let Some(scratch) = ScratchDb::create("app_org_cap").await else {
        return;
    };
    let (db, _) = setup(&scratch).await;
    let alice = account(&db, "Alice").await;
    let audit = AuditEvent {
        actor_account_id: Some(alice.account.id),
        action: "organization.create",
        target_type: None,
        target_id: None,
        outcome: AuditOutcome::Success,
        request_id: None,
    };
    let name = supabase_dashboard_domain::organization::OrganizationName::parse("Acme").unwrap();
    let mut outcomes = Vec::new();
    for _ in 0..3 {
        outcomes.push(
            db.create_organization(Uuid::now_v7(), &name, alice.account.id, 2, &audit)
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        outcomes,
        [
            CreateOrganizationOutcome::Created,
            CreateOrganizationOutcome::Created,
            CreateOrganizationOutcome::LimitReached
        ]
    );
    assert_eq!(
        db.count_audit_events("organization.create").await.unwrap(),
        2
    );
    db.close().await;
    scratch.drop().await;
}
