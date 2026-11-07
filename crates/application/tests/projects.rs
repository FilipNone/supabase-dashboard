//! Project registry authorization against a scratch metadata database.
//! Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    organizations::OrganizationService,
    projects::{ProjectError, ProjectService, Registration},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    project::{MAX_PROJECTS_PER_ORGANIZATION, ProjectInputError},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-project"),
        user_agent: None,
    }
}

fn registration(name: &str) -> Registration<'_> {
    Registration {
        name,
        api_url: "https://supabase.example.test/",
        allow_unencrypted: false,
    }
}

struct Fixture {
    db: Database,
    orgs: OrganizationService,
    projects: ProjectService,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    Fixture {
        orgs: OrganizationService::new(db.clone()),
        projects: ProjectService::new(db.clone()),
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

async fn audit_count(db: &Database, action: &str, outcome: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = $1 AND outcome = $2")
        .bind(action)
        .bind(outcome)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn roles_decide_who_registers_renames_and_unregisters() {
    let Some(scratch) = ScratchDb::create("project_roles").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let org = f.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;

    let created = f
        .projects
        .register(&admin, org, registration(" Production "), ctx())
        .await
        .unwrap();
    assert_eq!(created.name.as_str(), "Production");
    assert_eq!(created.api_url.as_str(), "https://supabase.example.test");
    assert_eq!(created.role, OrgRole::Admin);
    assert_eq!(audit_count(&f.db, "project.register", "success").await, 1);

    for who in [&developer, &viewer] {
        assert!(matches!(
            f.projects
                .register(who, org, registration("Staging"), ctx())
                .await,
            Err(ProjectError::Forbidden)
        ));
        assert!(matches!(
            f.projects.rename(who, created.id, "Renamed", ctx()).await,
            Err(ProjectError::Forbidden)
        ));
        assert!(matches!(
            f.projects
                .unregister(who, created.id, "Production", ctx())
                .await,
            Err(ProjectError::Forbidden)
        ));
        // Every member can read.
        let listed = f.projects.list(who, org).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            f.projects.get(who, created.id).await.unwrap().role,
            who_role(who, &developer)
        );
    }
    assert_eq!(audit_count(&f.db, "project.register", "denied").await, 2);
    assert_eq!(audit_count(&f.db, "project.rename", "denied").await, 2);
    assert_eq!(audit_count(&f.db, "project.unregister", "denied").await, 2);

    let renamed = f
        .projects
        .rename(&owner, created.id, "Prod", ctx())
        .await
        .unwrap();
    assert_eq!(renamed.name.as_str(), "Prod");
    assert_eq!(renamed.role, OrgRole::Owner);
    assert_eq!(
        f.projects
            .get(&viewer, created.id)
            .await
            .unwrap()
            .name
            .as_str(),
        "Prod"
    );

    // A wrong confirmation changes nothing.
    assert!(matches!(
        f.projects
            .unregister(&admin, created.id, "Production", ctx())
            .await,
        Err(ProjectError::ConfirmationMismatch)
    ));
    assert_eq!(f.projects.list(&owner, org).await.unwrap().len(), 1);
    f.projects
        .unregister(&admin, created.id, "Prod", ctx())
        .await
        .unwrap();
    assert!(f.projects.list(&owner, org).await.unwrap().is_empty());
    assert!(matches!(
        f.projects.get(&owner, created.id).await,
        Err(ProjectError::NotFound)
    ));
    assert_eq!(audit_count(&f.db, "project.unregister", "success").await, 1);

    f.db.close().await;
    scratch.drop().await;
}

fn who_role(who: &CurrentSession, developer: &CurrentSession) -> OrgRole {
    if who.account.id == developer.account.id {
        OrgRole::Developer
    } else {
        OrgRole::Viewer
    }
}

#[tokio::test]
async fn other_organizations_projects_look_missing() {
    let Some(scratch) = ScratchDb::create("project_isolation").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let mallory = account(&f.db, "Mallory").await;
    let acme = f.orgs.create(&alice, "Acme", ctx()).await.unwrap().id;
    let evil = f.orgs.create(&mallory, "Evil", ctx()).await.unwrap().id;
    let project = f
        .projects
        .register(&alice, acme, registration("Prod"), ctx())
        .await
        .unwrap();

    let missing = Uuid::now_v7();
    for id in [project.id, missing] {
        assert!(matches!(
            f.projects.get(&mallory, id).await,
            Err(ProjectError::NotFound)
        ));
        assert!(matches!(
            f.projects.rename(&mallory, id, "Mine", ctx()).await,
            Err(ProjectError::NotFound)
        ));
        assert!(matches!(
            f.projects.unregister(&mallory, id, "Prod", ctx()).await,
            Err(ProjectError::NotFound)
        ));
    }
    for org in [acme, missing] {
        assert!(matches!(
            f.projects.list(&mallory, org).await,
            Err(ProjectError::NotFound)
        ));
        assert!(matches!(
            f.projects
                .register(&mallory, org, registration("Mine"), ctx())
                .await,
            Err(ProjectError::NotFound)
        ));
    }
    // Mallory's own organization sees nothing of Acme's.
    assert!(f.projects.list(&mallory, evil).await.unwrap().is_empty());
    assert_eq!(
        f.projects
            .get(&alice, project.id)
            .await
            .unwrap()
            .name
            .as_str(),
        "Prod"
    );

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn registration_validates_input_and_limits() {
    let Some(scratch) = ScratchDb::create("project_input").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let org = f.orgs.create(&owner, "Acme", ctx()).await.unwrap().id;

    let http = Registration {
        name: "Lab",
        api_url: "http://10.0.0.5:8000",
        allow_unencrypted: false,
    };
    assert!(matches!(
        f.projects.register(&owner, org, http, ctx()).await,
        Err(ProjectError::Input(
            ProjectInputError::UnencryptedNotConfirmed
        ))
    ));
    let confirmed = f
        .projects
        .register(
            &owner,
            org,
            Registration {
                allow_unencrypted: true,
                ..http
            },
            ctx(),
        )
        .await
        .unwrap();
    assert!(!confirmed.api_url.is_encrypted());

    let with_credentials = Registration {
        api_url: "https://user:pw@supabase.example.test",
        ..registration("Leaky")
    };
    assert!(matches!(
        f.projects
            .register(&owner, org, with_credentials, ctx())
            .await,
        Err(ProjectError::Input(ProjectInputError::UrlCredentials))
    ));
    assert!(matches!(
        f.projects
            .register(&owner, org, registration(" "), ctx())
            .await,
        Err(ProjectError::Input(ProjectInputError::EmptyName))
    ));

    // Fill the organization up to the limit directly, then try one more.
    for n in 1..MAX_PROJECTS_PER_ORGANIZATION {
        sqlx::query(
            "INSERT INTO projects (id, organization_id, name, api_url) VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .bind(format!("P{n}"))
        .bind("https://supabase.example.test")
        .execute(f.db.pool())
        .await
        .unwrap();
    }
    assert!(matches!(
        f.projects
            .register(&owner, org, registration("One more"), ctx())
            .await,
        Err(ProjectError::LimitReached)
    ));
    assert_eq!(
        f.projects.list(&owner, org).await.unwrap().len(),
        MAX_PROJECTS_PER_ORGANIZATION
    );

    f.db.close().await;
    scratch.drop().await;
}
