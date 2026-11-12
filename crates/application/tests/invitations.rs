//! Invitations against a scratch metadata database. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use secrecy::SecretString;
use supabase_dashboard_application::{
    auth::{AuthConfig, AuthService, CurrentSession, InvitationSignUpError, RequestContext},
    organizations::{OrganizationError, OrganizationService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::{MembershipError, OrgRole, Permission},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const PASSWORD: &str = "correct horse battery staple";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-invite"),
        user_agent: None,
    }
}

struct Services {
    db: Database,
    orgs: OrganizationService,
    auth: AuthService,
}

async fn setup(scratch: &ScratchDb) -> Services {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    Services {
        orgs: OrganizationService::new(db.clone()),
        auth: AuthService::new(db.clone(), AuthConfig::default())
            .await
            .unwrap(),
        db,
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

async fn role_of(db: &Database, org: Uuid, who: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND account_id = $2",
    )
    .bind(org)
    .bind(who)
    .fetch_optional(db.pool())
    .await
    .unwrap()
}

async fn audit_count(db: &Database, action: &str, outcome: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(db.pool())
        .await
        .unwrap()
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

/// Refusals recorded for `actor` doing `action`.
async fn denied_by(db: &Database, action: &str, actor: &CurrentSession) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events \
         WHERE action = $1 AND outcome = 'denied' AND actor_account_id = $2",
    )
    .bind(action)
    .bind(actor.account.id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn only_member_managers_invite_and_only_owners_invite_owners() {
    let Some(scratch) = ScratchDb::create("app_invite_roles").await else {
        return;
    };
    let s = setup(&scratch).await;
    let owner = account(&s.db, "Olivia").await;
    let admin = account(&s.db, "Adam").await;
    let viewer = account(&s.db, "Vera").await;
    let outsider = account(&s.db, "Oscar").await;
    let org = s.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    for (who, role) in [(&admin, OrgRole::Admin), (&viewer, OrgRole::Viewer)] {
        let code = s
            .orgs
            .invite(&owner, org, who.account.email.as_str(), role, ctx())
            .await
            .unwrap()
            .code;
        s.orgs
            .accept_invitation(who, code.expose(), ctx())
            .await
            .unwrap();
        assert_eq!(
            role_of(&s.db, org, who.account.id).await.as_deref(),
            Some(role.as_str())
        );
    }

    assert!(matches!(
        s.orgs
            .invite(&viewer, org, "new@example.test", OrgRole::Viewer, ctx())
            .await,
        Err(OrganizationError::Forbidden)
    ));
    assert!(matches!(
        s.orgs
            .invite(&admin, org, "new@example.test", OrgRole::Owner, ctx())
            .await,
        Err(OrganizationError::Membership(
            MembershipError::OwnerRoleRequiresOwner
        ))
    ));
    assert!(matches!(
        s.orgs
            .invite(&outsider, org, "new@example.test", OrgRole::Viewer, ctx())
            .await,
        Err(OrganizationError::NotFound)
    ));
    assert!(matches!(
        s.orgs
            .invite(&owner, org, "VERA@example.test", OrgRole::Admin, ctx())
            .await,
        Err(OrganizationError::AlreadyMember)
    ));
    assert!(matches!(
        s.orgs
            .invite(&owner, org, "not-an-email", OrgRole::Admin, ctx())
            .await,
        Err(OrganizationError::AccountInput(_))
    ));
    assert_eq!(
        audit_count(&s.db, "organization.invitation_create", "denied").await,
        3
    );

    let issued = s
        .orgs
        .invite(&admin, org, " New@Example.test ", OrgRole::Developer, ctx())
        .await
        .unwrap();
    assert_eq!(issued.invitation.email.as_str(), "new@example.test");
    assert_eq!(issued.code.expose().len(), 64);

    // The code is not stored, only its hash.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_invitations WHERE encode(token_hash, 'hex') = $1",
    )
    .bind(issued.code.expose())
    .fetch_one(s.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, 0);

    // Members can see open invitations; outsiders cannot.
    let listed = s.orgs.invitations(&viewer, org).await.unwrap();
    assert_eq!(listed, vec![issued.invitation.clone()]);
    assert!(matches!(
        s.orgs.invitations(&outsider, org).await,
        Err(OrganizationError::NotFound)
    ));

    // Only an owner withdraws an invitation to the owner role.
    let owner_invite = s
        .orgs
        .invite(&owner, org, "boss@example.test", OrgRole::Owner, ctx())
        .await
        .unwrap();
    assert!(matches!(
        s.orgs
            .revoke_invitation(&admin, org, owner_invite.invitation.id, ctx())
            .await,
        Err(OrganizationError::Membership(
            MembershipError::OwnerRoleRequiresOwner
        ))
    ));
    assert!(matches!(
        s.orgs
            .revoke_invitation(&viewer, org, issued.invitation.id, ctx())
            .await,
        Err(OrganizationError::Forbidden)
    ));
    s.orgs
        .revoke_invitation(&admin, org, issued.invitation.id, ctx())
        .await
        .unwrap();
    assert!(matches!(
        s.orgs
            .revoke_invitation(&admin, org, issued.invitation.id, ctx())
            .await,
        Err(OrganizationError::InvitationNotFound)
    ));
    assert!(
        s.auth
            .preview_invitation(issued.code.expose())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn invitations_are_single_use_bound_to_email_and_expire() {
    let Some(scratch) = ScratchDb::create("app_invite_use").await else {
        return;
    };
    let s = setup(&scratch).await;
    let owner = account(&s.db, "Olivia").await;
    let dev = account(&s.db, "Dana").await;
    let other = account(&s.db, "Eve").await;
    let org = s.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;

    let first = s
        .orgs
        .invite(&owner, org, "dana@example.test", OrgRole::Viewer, ctx())
        .await
        .unwrap();
    // Inviting again replaces the earlier code.
    let second = s
        .orgs
        .invite(&owner, org, "dana@example.test", OrgRole::Developer, ctx())
        .await
        .unwrap();
    assert!(
        s.auth
            .preview_invitation(first.code.expose())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(s.orgs.invitations(&owner, org).await.unwrap().len(), 1);

    let preview = s
        .auth
        .preview_invitation(second.code.expose())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preview.organization_name.as_str(), "Acme");
    assert_eq!(preview.role, OrgRole::Developer);
    assert!(preview.account_exists);

    // Someone else holding the link cannot use it, and the attempt does not
    // use it up.
    assert!(matches!(
        s.orgs
            .accept_invitation(&other, second.code.expose(), ctx())
            .await,
        Err(OrganizationError::InvitationEmailMismatch)
    ));
    assert_eq!(role_of(&s.db, org, other.account.id).await, None);
    assert_eq!(
        audit_count(&s.db, "organization.invitation_accept", "denied").await,
        1
    );

    assert_eq!(
        s.orgs
            .accept_invitation(&dev, second.code.expose(), ctx())
            .await
            .unwrap(),
        org
    );
    assert_eq!(
        role_of(&s.db, org, dev.account.id).await.as_deref(),
        Some("developer")
    );
    for code in [
        second.code.expose(),
        first.code.expose(),
        "zz",
        &"0".repeat(64),
    ] {
        assert!(matches!(
            s.orgs.accept_invitation(&dev, code, ctx()).await,
            Err(OrganizationError::InvitationInvalid)
        ));
    }
    let unknown: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'organization.invitation_accept' \
         AND outcome = 'denied' AND actor_account_id = $1 AND target_id IS NULL",
    )
    .bind(dev.account.id)
    .fetch_one(s.db.pool())
    .await
    .unwrap();
    assert_eq!(
        unknown, 4,
        "used and malformed codes are recorded, without the code"
    );
    assert!(s.orgs.invitations(&owner, org).await.unwrap().is_empty());

    // Expired invitations cannot be previewed, accepted, or listed.
    let late = s
        .orgs
        .invite(&owner, org, "eve@example.test", OrgRole::Viewer, ctx())
        .await
        .unwrap();
    sqlx::query("UPDATE organization_invitations SET expires_at = now() - interval '1 second'")
        .execute(s.db.pool())
        .await
        .unwrap();
    assert!(
        s.auth
            .preview_invitation(late.code.expose())
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        s.orgs
            .accept_invitation(&other, late.code.expose(), ctx())
            .await,
        Err(OrganizationError::InvitationInvalid)
    ));
    assert!(s.orgs.invitations(&owner, org).await.unwrap().is_empty());
    // A new invitation to the same address replaces the expired one.
    s.orgs
        .invite(&owner, org, "eve@example.test", OrgRole::Viewer, ctx())
        .await
        .unwrap();
}

#[tokio::test]
async fn new_accounts_are_created_once_from_an_invitation() {
    let Some(scratch) = ScratchDb::create("app_invite_signup").await else {
        return;
    };
    let s = setup(&scratch).await;
    let owner = account(&s.db, "Olivia").await;
    let org = s.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    let issued = s
        .orgs
        .invite(&owner, org, "newcomer@example.test", OrgRole::Admin, ctx())
        .await
        .unwrap();
    let code = issued.code.expose();
    let preview = s.auth.preview_invitation(code).await.unwrap().unwrap();
    assert!(!preview.account_exists);

    assert!(matches!(
        s.auth
            .accept_invitation_with_new_account(code, "New", &SecretString::from("short"), ctx())
            .await,
        Err(InvitationSignUpError::Input(_))
    ));
    assert!(matches!(
        s.auth
            .accept_invitation_with_new_account(
                &"0".repeat(64),
                "New",
                &SecretString::from(PASSWORD),
                ctx()
            )
            .await,
        Err(InvitationSignUpError::InvalidInvitation)
    ));

    // Two submissions racing with the same code: exactly one wins.
    let password = SecretString::from(PASSWORD);
    let (a, b) = tokio::join!(
        s.auth
            .accept_invitation_with_new_account(code, "First", &password, ctx()),
        s.auth
            .accept_invitation_with_new_account(code, "Second", &password, ctx()),
    );
    let wins = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(wins, 1, "{a:?} {b:?}");
    assert_eq!(a.or(b).unwrap(), org);

    let (id, admin): (Uuid, bool) = sqlx::query_as(
        "SELECT id, is_installation_admin FROM accounts WHERE email = 'newcomer@example.test'",
    )
    .fetch_one(s.db.pool())
    .await
    .unwrap();
    assert!(!admin);
    assert_eq!(role_of(&s.db, org, id).await.as_deref(), Some("admin"));
    assert_eq!(
        audit_count(&s.db, "account.create_from_invitation", "success").await,
        1
    );

    // The new account signs in like any other.
    s.auth
        .sign_in("newcomer@example.test", &password, ctx())
        .await
        .unwrap();

    // A second invitation to the same address must be accepted by signing in.
    let other_org = s.orgs.create(&owner, "Globex", ctx()).await.unwrap().id;
    let again = s
        .orgs
        .invite(
            &owner,
            other_org,
            "newcomer@example.test",
            OrgRole::Viewer,
            ctx(),
        )
        .await
        .unwrap();
    assert!(matches!(
        s.auth
            .accept_invitation_with_new_account(again.code.expose(), "Dup", &password, ctx())
            .await,
        Err(InvitationSignUpError::AccountExists)
    ));
}

/// Every role, and an operator from another organization, invites someone
/// and withdraws an invitation the owner sent. Only roles with
/// `Permission::MembersManage` succeed; refusals are audited and change no
/// invitation.
#[tokio::test]
async fn invitation_changes_follow_the_role_matrix() {
    let Some(scratch) = ScratchDb::create("app_invite_matrix").await else {
        return;
    };
    let s = setup(&scratch).await;
    let owner = account(&s.db, "Olivia").await;
    let admin = account(&s.db, "Adam").await;
    let dev = account(&s.db, "Dana").await;
    let viewer = account(&s.db, "Vera").await;
    let outsider = account(&s.db, "Oscar").await;
    let org = s.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&s.db, org, &admin, OrgRole::Admin).await;
    add_member(&s.db, org, &dev, OrgRole::Developer).await;
    add_member(&s.db, org, &viewer, OrgRole::Viewer).await;
    s.orgs.create(&outsider, "Globex", ctx()).await.unwrap();

    let cases = [
        (&owner, Some(OrgRole::Owner), true),
        (&admin, Some(OrgRole::Admin), true),
        (&dev, Some(OrgRole::Developer), false),
        (&viewer, Some(OrgRole::Viewer), false),
        (&outsider, None, false),
    ];
    for (n, (actor, role, allowed)) in cases.into_iter().enumerate() {
        let who = actor.account.display_name.as_str();
        if let Some(role) = role {
            assert_eq!(role.allows(Permission::MembersManage), allowed, "{who}");
        }
        let email = format!("invitee{n}@example.test");
        let invited = s
            .orgs
            .invite(actor, org, &email, OrgRole::Developer, ctx())
            .await;
        let pending = s
            .orgs
            .invite(
                &owner,
                org,
                &format!("pending{n}@example.test"),
                OrgRole::Developer,
                ctx(),
            )
            .await
            .unwrap()
            .invitation;
        let revoked = s
            .orgs
            .revoke_invitation(actor, org, pending.id, ctx())
            .await;

        let open = s.orgs.invitations(&owner, org).await.unwrap();
        let sent = open.iter().any(|i| i.email.as_str() == email);
        let still_pending = open.contains(&pending);
        match (role, allowed) {
            (Some(_), true) => {
                assert!(invited.is_ok(), "{who}: {invited:?}");
                assert!(revoked.is_ok(), "{who}: {revoked:?}");
                assert!(sent, "{who}");
                assert!(!still_pending, "{who}");
            }
            (Some(_), false) => {
                assert!(
                    matches!(invited, Err(OrganizationError::Forbidden)),
                    "{who}: {invited:?}"
                );
                assert!(
                    matches!(revoked, Err(OrganizationError::Forbidden)),
                    "{who}: {revoked:?}"
                );
                assert!(!sent, "{who}");
                assert!(still_pending, "{who}");
                for action in [
                    "organization.invitation_create",
                    "organization.invitation_revoke",
                ] {
                    assert_eq!(denied_by(&s.db, action, actor).await, 1, "{who} {action}");
                }
            }
            (None, _) => {
                assert!(
                    matches!(invited, Err(OrganizationError::NotFound)),
                    "{who}: {invited:?}"
                );
                assert!(
                    matches!(revoked, Err(OrganizationError::NotFound)),
                    "{who}: {revoked:?}"
                );
                assert!(!sent, "{who}");
                assert!(still_pending, "{who}");
            }
        }
    }

    // An admin refused an owner invitation's withdrawal is audited, and the
    // invitation stays open.
    let boss = s
        .orgs
        .invite(&owner, org, "boss@example.test", OrgRole::Owner, ctx())
        .await
        .unwrap()
        .invitation;
    assert!(matches!(
        s.orgs.revoke_invitation(&admin, org, boss.id, ctx()).await,
        Err(OrganizationError::Membership(
            MembershipError::OwnerRoleRequiresOwner
        ))
    ));
    assert!(
        s.orgs
            .invitations(&owner, org)
            .await
            .unwrap()
            .contains(&boss)
    );
    assert_eq!(
        denied_by(&s.db, "organization.invitation_revoke", &admin).await,
        1
    );
    s.db.close().await;
    scratch.drop().await;
}
