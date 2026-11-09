//! Saved SQL snippets against a scratch metadata database. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    snippets::{SnippetError, SnippetService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    snippet::{SNIPPETS_PER_AUTHOR, SnippetInput, SnippetVisibility},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-snippets"),
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

struct Fixture {
    db: Database,
    snippets: SnippetService,
    owner: CurrentSession,
    admin: CurrentSession,
    dev: CurrentSession,
    dev2: CurrentSession,
    viewer: CurrentSession,
    outsider: CurrentSession,
    project: Uuid,
    other_project: Uuid,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = OrganizationService::new(db.clone());
    let projects = ProjectService::new(db.clone());
    let owner = account(&db, "Owner").await;
    let admin = account(&db, "Admin").await;
    let dev = account(&db, "Dev").await;
    let dev2 = account(&db, "Devtwo").await;
    let viewer = account(&db, "Viewer").await;
    let outsider = account(&db, "Outsider").await;
    let org = orgs.create(&owner, "Acme", ctx()).await.unwrap().id;
    add_member(&db, org, &admin, OrgRole::Admin).await;
    add_member(&db, org, &dev, OrgRole::Developer).await;
    add_member(&db, org, &dev2, OrgRole::Developer).await;
    add_member(&db, org, &viewer, OrgRole::Viewer).await;
    let register = |name, url| Registration {
        name,
        api_url: url,
        allow_unencrypted: false,
    };
    let project = projects
        .register(
            &owner,
            org,
            register("Production", "https://a.example.test"),
            ctx(),
        )
        .await
        .unwrap()
        .id;
    let other_project = projects
        .register(
            &owner,
            org,
            register("Staging", "https://b.example.test"),
            ctx(),
        )
        .await
        .unwrap()
        .id;
    Fixture {
        snippets: SnippetService::new(db.clone()),
        db,
        owner,
        admin,
        dev,
        dev2,
        viewer,
        outsider,
        project,
        other_project,
    }
}

fn input(name: &str, visibility: SnippetVisibility, sql: &str) -> SnippetInput {
    SnippetInput::parse(name, visibility, sql).unwrap()
}

async fn audit_rows(db: &Database) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT action, target_id, outcome FROM audit_events \
         WHERE action LIKE 'sql_snippet.%' ORDER BY occurred_at, id",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn private_snippets_stay_with_their_author_and_shared_ones_reach_the_project() {
    let Some(scratch) = ScratchDb::create("snippets_visibility").await else {
        return;
    };
    let f = setup(&scratch).await;
    let s = &f.snippets;
    let private = s
        .create(
            &f.dev,
            f.project,
            &input("Mine", SnippetVisibility::Private, "select 'secret-marker'"),
            ctx(),
        )
        .await
        .unwrap();
    let shared = s
        .create(
            &f.dev,
            f.project,
            &input("Active users", SnippetVisibility::Project, "select 2"),
            ctx(),
        )
        .await
        .unwrap();

    let list = s.list(&f.dev, f.project).await.unwrap();
    let names: Vec<_> = list.items.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, ["Active users", "Mine"]);
    assert!(list.items.iter().all(|i| i.mine && i.author == "Dev"));
    assert!(!list.truncated);
    assert_eq!(
        s.get(&f.dev, f.project, private).await.unwrap().content,
        "select 'secret-marker'"
    );

    // Others in the project see only the shared one, and not as theirs.
    for who in [&f.owner, &f.admin, &f.dev2] {
        let list = s.list(who, f.project).await.unwrap();
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.items[0].id, shared);
        assert!(!list.items[0].mine);
        assert!(matches!(
            s.get(who, f.project, private).await,
            Err(SnippetError::NotFound)
        ));
        assert_eq!(
            s.get(who, f.project, shared).await.unwrap().content,
            "select 2"
        );
    }
    // Snippets belong to one project.
    assert!(
        s.list(&f.dev, f.other_project)
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert!(matches!(
        s.get(&f.dev, f.other_project, shared).await,
        Err(SnippetError::NotFound)
    ));
    // No SQL, no snippets; outsiders cannot tell the project exists.
    assert!(matches!(
        s.list(&f.viewer, f.project).await,
        Err(SnippetError::Forbidden)
    ));
    assert!(matches!(
        s.get(&f.viewer, f.project, shared).await,
        Err(SnippetError::Forbidden)
    ));
    assert!(matches!(
        s.list(&f.outsider, f.project).await,
        Err(SnippetError::NotFound)
    ));
    assert!(matches!(
        s.create(
            &f.viewer,
            f.project,
            &input("x", SnippetVisibility::Private, "select 1"),
            ctx()
        )
        .await,
        Err(SnippetError::Forbidden)
    ));

    // The audit log names snippets by ID only.
    let rows = audit_rows(&f.db).await;
    assert_eq!(
        rows,
        [
            (
                "sql_snippet.create".into(),
                private.to_string(),
                "success".into()
            ),
            (
                "sql_snippet.create".into(),
                shared.to_string(),
                "success".into()
            ),
            (
                "sql_snippet.create".into(),
                f.project.to_string(),
                "denied".into()
            ),
        ]
    );
    let dump: Vec<String> = sqlx::query_scalar("SELECT row_to_json(a)::text FROM audit_events a")
        .fetch_all(f.db.pool())
        .await
        .unwrap();
    assert!(
        dump.iter()
            .all(|r| !r.contains("secret-marker") && !r.contains("Mine"))
    );
}

#[tokio::test]
async fn only_authors_edit_and_managers_may_remove_shared_snippets() {
    let Some(scratch) = ScratchDb::create("snippets_ownership").await else {
        return;
    };
    let f = setup(&scratch).await;
    let s = &f.snippets;
    let shared = s
        .create(
            &f.dev,
            f.project,
            &input("Shared", SnippetVisibility::Project, "select 1"),
            ctx(),
        )
        .await
        .unwrap();
    let private = s
        .create(
            &f.dev,
            f.project,
            &input("Private", SnippetVisibility::Private, "select 1"),
            ctx(),
        )
        .await
        .unwrap();

    // Nobody else edits, owners included.
    for who in [&f.owner, &f.admin, &f.dev2] {
        assert!(matches!(
            s.update(
                who,
                f.project,
                shared,
                &input("Taken", SnippetVisibility::Private, "select 3"),
                ctx()
            )
            .await,
            Err(SnippetError::NotFound)
        ));
    }
    // The author can rename, rewrite, and make it private.
    s.update(
        &f.dev,
        f.project,
        shared,
        &input("Renamed", SnippetVisibility::Private, "select 4"),
        ctx(),
    )
    .await
    .unwrap();
    assert!(matches!(
        s.get(&f.dev2, f.project, shared).await,
        Err(SnippetError::NotFound)
    ));
    let snippet = s.get(&f.dev, f.project, shared).await.unwrap();
    assert_eq!(snippet.summary.name.as_str(), "Renamed");
    assert_eq!(snippet.content, "select 4");
    // Editing through another project does not reach it.
    assert!(matches!(
        s.update(
            &f.dev,
            f.other_project,
            shared,
            &input("x", SnippetVisibility::Private, "select 1"),
            ctx()
        )
        .await,
        Err(SnippetError::NotFound)
    ));

    // Share it again. A developer cannot delete it; an admin can. No one
    // but the author can delete a private snippet.
    s.update(
        &f.dev,
        f.project,
        shared,
        &input("Renamed", SnippetVisibility::Project, "select 4"),
        ctx(),
    )
    .await
    .unwrap();
    assert!(matches!(
        s.delete(&f.dev2, f.project, shared, ctx()).await,
        Err(SnippetError::NotFound)
    ));
    for who in [&f.owner, &f.admin] {
        assert!(matches!(
            s.delete(who, f.project, private, ctx()).await,
            Err(SnippetError::NotFound)
        ));
    }
    s.delete(&f.admin, f.project, shared, ctx()).await.unwrap();
    s.delete(&f.dev, f.project, private, ctx()).await.unwrap();
    assert!(s.list(&f.dev, f.project).await.unwrap().items.is_empty());
    assert!(matches!(
        s.delete(&f.viewer, f.project, private, ctx()).await,
        Err(SnippetError::Forbidden)
    ));

    let deletes: Vec<_> = audit_rows(&f.db)
        .await
        .into_iter()
        .filter(|(action, ..)| action == "sql_snippet.delete")
        .map(|(_, target, outcome)| (target, outcome))
        .collect();
    assert_eq!(
        deletes,
        [
            (shared.to_string(), "success".to_owned()),
            (private.to_string(), "success".to_owned()),
            (f.project.to_string(), "denied".to_owned()),
        ]
    );
}

#[tokio::test]
async fn authors_keep_a_bounded_number_and_unregistering_removes_them() {
    let Some(scratch) = ScratchDb::create("snippets_limits").await else {
        return;
    };
    let f = setup(&scratch).await;
    let s = &f.snippets;
    for n in 0..SNIPPETS_PER_AUTHOR {
        s.create(
            &f.dev,
            f.project,
            &input(&format!("n{n:03}"), SnippetVisibility::Private, "select 1"),
            ctx(),
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        s.create(
            &f.dev,
            f.project,
            &input("one more", SnippetVisibility::Private, "select 1"),
            ctx()
        )
        .await,
        Err(SnippetError::LimitReached)
    ));
    // The limit is per author and project.
    s.create(
        &f.dev2,
        f.project,
        &input("theirs", SnippetVisibility::Private, "select 1"),
        ctx(),
    )
    .await
    .unwrap();
    s.create(
        &f.dev,
        f.other_project,
        &input("elsewhere", SnippetVisibility::Private, "select 1"),
        ctx(),
    )
    .await
    .unwrap();

    sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(f.project)
        .execute(f.db.pool())
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM sql_snippets")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(left, 1);
}
