//! Invitation email against a scratch metadata database and a fake mailer.
//! Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    mail::{InvitationMail, MailError, Mailer, OutgoingEmail, SendFuture},
    organizations::{OrganizationError, OrganizationService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    invitation::InvitationDelivery,
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const PAGE: &str = "https://dash.example.test/dashboard/invite";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-invite-mail"),
        user_agent: None,
    }
}

/// Records what it is asked to send, and fails when told to.
#[derive(Default)]
struct FakeMailer {
    sent: Mutex<Vec<OutgoingEmail>>,
    fail: bool,
}

impl Mailer for FakeMailer {
    fn send<'a>(&'a self, message: &'a OutgoingEmail) -> SendFuture<'a> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(message.clone());
            if self.fail {
                Err(MailError::Unavailable("connection refused".into()))
            } else {
                Ok(())
            }
        })
    }
}

async fn database(scratch: &ScratchDb) -> Database {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    db
}

fn with_mail(db: &Database, mailer: &Arc<FakeMailer>) -> OrganizationService {
    OrganizationService::new(db.clone()).with_invitation_mail(InvitationMail {
        mailer: Arc::clone(mailer) as Arc<dyn Mailer>,
        invite_page_url: PAGE.into(),
    })
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

/// `organization.invitation_email` events with `outcome` for `invitation`,
/// in the invitation's organization.
async fn email_events(db: &Database, invitation: Uuid, org: Uuid, outcome: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'organization.invitation_email' \
         AND target_type = 'organization_invitation' AND target_id = $1 AND outcome = $2 \
         AND organization_id = $3",
    )
    .bind(invitation.to_string())
    .bind(outcome)
    .bind(org)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// Audit rows holding `needle` anywhere.
async fn audit_rows_containing(db: &Database, needle: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events a WHERE strpos(row_to_json(a)::text, $1) > 0",
    )
    .bind(needle)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn without_mail_nothing_is_sent() {
    let Some(scratch) = ScratchDb::create("app_invite_mail_off").await else {
        return;
    };
    let db = database(&scratch).await;
    let orgs = OrganizationService::new(db.clone());
    let owner = account(&db, "Olivia").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    let issued = orgs
        .invite(&owner, org, "new@example.test", OrgRole::Viewer, ctx())
        .await
        .unwrap();
    assert_eq!(issued.delivery, InvitationDelivery::NotConfigured);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'organization.invitation_email'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(events, 0);
}

#[tokio::test]
async fn a_new_invitation_is_emailed_to_the_invited_address() {
    let Some(scratch) = ScratchDb::create("app_invite_mail_sent").await else {
        return;
    };
    let db = database(&scratch).await;
    let mailer = Arc::new(FakeMailer::default());
    let orgs = with_mail(&db, &mailer);
    let owner = account(&db, "Olivia").await;
    let org = orgs.create(&owner, "Acme Labs", ctx()).await.unwrap().id;
    let issued = orgs
        .invite(&owner, org, "New@Example.test", OrgRole::Developer, ctx())
        .await
        .unwrap();
    assert_eq!(issued.delivery, InvitationDelivery::Sent);

    let sent = mailer.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let message = &sent[0];
    assert_eq!(message.to.as_str(), "new@example.test");
    assert_eq!(
        message.subject,
        "Invitation to join Acme Labs on the dashboard"
    );
    assert!(
        message
            .body
            .contains(&format!("{PAGE}#{}", issued.code.expose())),
        "{}",
        message.body
    );
    assert!(message.body.contains("Olivia invited you"));
    assert!(message.body.contains("as Developer"));
    assert!(
        message
            .body
            .contains(&issued.invitation.expires_at.date().to_string())
    );

    assert_eq!(
        email_events(&db, issued.invitation.id, org, "success").await,
        1
    );
    // Neither the code nor the body reaches the audit log.
    assert_eq!(audit_rows_containing(&db, issued.code.expose()).await, 0);
    assert_eq!(audit_rows_containing(&db, "invited you").await, 0);
}

#[tokio::test]
async fn a_failed_email_keeps_the_invitation_usable() {
    let Some(scratch) = ScratchDb::create("app_invite_mail_failed").await else {
        return;
    };
    let db = database(&scratch).await;
    let mailer = Arc::new(FakeMailer {
        fail: true,
        ..FakeMailer::default()
    });
    let orgs = with_mail(&db, &mailer);
    let owner = account(&db, "Olivia").await;
    let invitee = account(&db, "Nina").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    let issued = orgs
        .invite(
            &owner,
            org,
            invitee.account.email.as_str(),
            OrgRole::Viewer,
            ctx(),
        )
        .await
        .unwrap();
    assert_eq!(issued.delivery, InvitationDelivery::Failed);
    assert_eq!(mailer.sent.lock().unwrap().len(), 1);
    assert_eq!(
        email_events(&db, issued.invitation.id, org, "failure").await,
        1
    );

    let open = orgs.invitations(&owner, org).await.unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].id, issued.invitation.id);
    // The link shown to the inviter still works.
    orgs.accept_invitation(&invitee, issued.code.expose(), ctx())
        .await
        .unwrap();
}

#[tokio::test]
async fn refused_invitations_send_nothing() {
    let Some(scratch) = ScratchDb::create("app_invite_mail_refused").await else {
        return;
    };
    let db = database(&scratch).await;
    let mailer = Arc::new(FakeMailer::default());
    let orgs = with_mail(&db, &mailer);
    let owner = account(&db, "Olivia").await;
    let admin = account(&db, "Adam").await;
    let developer = account(&db, "Dana").await;
    let viewer = account(&db, "Vera").await;
    let outsider = account(&db, "Oscar").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&db, org, &admin, OrgRole::Admin).await;
    add_member(&db, org, &developer, OrgRole::Developer).await;
    add_member(&db, org, &viewer, OrgRole::Viewer).await;

    for who in [&developer, &viewer] {
        assert!(matches!(
            orgs.invite(who, org, "new@example.test", OrgRole::Viewer, ctx())
                .await,
            Err(OrganizationError::Forbidden)
        ));
    }
    assert!(matches!(
        orgs.invite(&admin, org, "new@example.test", OrgRole::Owner, ctx())
            .await,
        Err(OrganizationError::Membership(_))
    ));
    assert!(matches!(
        orgs.invite(&outsider, org, "new@example.test", OrgRole::Viewer, ctx())
            .await,
        Err(OrganizationError::NotFound)
    ));
    assert!(matches!(
        orgs.invite(&owner, org, "vera@example.test", OrgRole::Viewer, ctx())
            .await,
        Err(OrganizationError::AlreadyMember)
    ));
    assert!(mailer.sent.lock().unwrap().is_empty());
}
