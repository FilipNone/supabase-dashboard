//! Opening Studio through the dashboard: who may, and when access ends.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::{ConnectionService, ProbeFuture, StackProbe},
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    secrets::CredentialCipher,
    studio::{STUDIO_HOME, StudioError, StudioService},
    studio_access::{StudioAccessError, StudioAccessRecorder, StudioAccessService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    connection::{CredentialKind, ServiceCheck, ServiceStatus, StackService, check_studio_login},
    project::ProjectUrl,
    studio_access::{NewStudioAccess, StudioAccessLog, loggable_path},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const PASSWORD: &str = "studio-password-for-tests";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-studio"),
        user_agent: None,
    }
}

fn cipher() -> CredentialCipher {
    CredentialCipher::from_base64(&SecretString::from(KEY)).unwrap()
}

/// Accepts every Studio login, which is all these tests need: the gateway
/// side of saving a login is covered in `connections.rs`.
struct AcceptingProbe;

impl StackProbe for AcceptingProbe {
    fn check<'a>(
        &'a self,
        _: &'a ProjectUrl,
        service: StackService,
        _: &'a SecretString,
    ) -> ProbeFuture<'a> {
        assert_eq!(
            service,
            StackService::Studio,
            "only Studio logins are checked"
        );
        Box::pin(async move {
            ServiceCheck {
                service,
                status: ServiceStatus::Healthy,
                version: None,
                latency_ms: Some(1),
            }
        })
    }
}

struct Fixture {
    db: Database,
    orgs: OrganizationService,
    projects: ProjectService,
    connections: ConnectionService,
    studio: StudioService,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    Fixture {
        orgs: OrganizationService::new(db.clone()),
        projects: ProjectService::new(db.clone()),
        connections: ConnectionService::new(db.clone(), Some(cipher()), Arc::new(AcceptingProbe)),
        studio: StudioService::new(db.clone(), Some(cipher()), Duration::from_secs(3600)),
        db,
    }
}

/// An account with a live dashboard session.
async fn account(db: &Database, name: &str) -> CurrentSession {
    let id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
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
    sqlx::query(
        "INSERT INTO sessions (id, account_id, token_hash, expires_at) \
         VALUES ($1, $2, $3, now() + interval '1 day')",
    )
    .bind(session_id)
    .bind(id)
    .bind(session_id.as_bytes().repeat(2))
    .execute(db.pool())
    .await
    .unwrap();
    CurrentSession {
        session_id,
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

async fn audit_count(db: &Database, outcome: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'studio.open' AND outcome = $1",
    )
    .bind(outcome)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// An organization with `owner` and a project with a Studio login.
async fn project(f: &Fixture, owner: &CurrentSession, name: &str) -> (Uuid, Uuid) {
    let org = f.orgs.create(owner, name, ctx()).await.unwrap().id;
    let id = f
        .projects
        .register(
            owner,
            org,
            Registration {
                name: "Production",
                api_url: "https://supabase.example.test",
                allow_unencrypted: false,
            },
            ctx(),
        )
        .await
        .unwrap()
        .id;
    let login = SecretString::from(check_studio_login("supabase", PASSWORD).unwrap());
    f.connections
        .replace_credential(owner, id, CredentialKind::StudioLogin, &login, ctx())
        .await
        .unwrap();
    (org, id)
}

/// Opens Studio and returns the Studio session token.
async fn open(f: &Fixture, who: &CurrentSession, id: Uuid) -> String {
    let handoff = f.studio.begin(who, id, None, ctx()).await.unwrap();
    let (token, path) = f
        .studio
        .redeem(id, handoff.code.expose_code())
        .await
        .unwrap();
    assert_eq!(path, STUDIO_HOME);
    token.expose_cookie_value().to_owned()
}

#[tokio::test]
async fn only_roles_with_full_access_open_studio() {
    let Some(scratch) = ScratchDb::create("studio_roles").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;

    for who in [&owner, &admin, &developer] {
        let token = open(&f, who, id).await;
        let upstream = f.studio.authorize(id, &token).await.unwrap();
        assert_eq!(upstream.account_id, who.account.id);
        assert_eq!(upstream.api_url.as_str(), "https://supabase.example.test");
        assert_eq!(
            upstream.login.expose_secret(),
            format!("supabase:{PASSWORD}")
        );
    }
    assert!(matches!(
        f.studio.begin(&viewer, id, None, ctx()).await,
        Err(StudioError::Forbidden)
    ));
    assert!(matches!(
        f.studio.begin(&outsider, id, None, ctx()).await,
        Err(StudioError::NotFound)
    ));
    assert_eq!(audit_count(&f.db, "success").await, 3);
    assert_eq!(audit_count(&f.db, "denied").await, 1);

    // Codes and sessions are stored as hashes only.
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM studio_sessions WHERE octet_length(token_hash) = 32",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, 3);
}

#[tokio::test]
async fn codes_work_once_for_their_project_and_paths_stay_on_studio() {
    let Some(scratch) = ScratchDb::create("studio_codes").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let (_, other) = project(&f, &owner, "Other").await;

    let handoff = f
        .studio
        .begin(&owner, id, Some("/project/default/sql/new"), ctx())
        .await
        .unwrap();
    let code = handoff.code.expose_code().to_owned();
    // Presented on the wrong project's host, the code is used up.
    assert!(matches!(
        f.studio.redeem(other, &code).await,
        Err(StudioError::Expired)
    ));
    assert!(matches!(
        f.studio.redeem(id, &code).await,
        Err(StudioError::Expired)
    ));

    let handoff = f
        .studio
        .begin(&owner, id, Some("/project/default/sql/new"), ctx())
        .await
        .unwrap();
    let (token, path) = f
        .studio
        .redeem(id, handoff.code.expose_code())
        .await
        .unwrap();
    assert_eq!(path, "/project/default/sql/new");
    assert!(matches!(
        f.studio.redeem(id, handoff.code.expose_code()).await,
        Err(StudioError::Expired)
    ));
    // A Studio session for one project does not open another.
    assert!(matches!(
        f.studio.authorize(other, token.expose_cookie_value()).await,
        Err(StudioError::Expired)
    ));

    // Expired codes are refused.
    let handoff = f.studio.begin(&owner, id, None, ctx()).await.unwrap();
    sqlx::query("UPDATE studio_handoffs SET expires_at = now() - interval '1 second'")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        f.studio.redeem(id, handoff.code.expose_code()).await,
        Err(StudioError::Expired)
    ));
    assert!(matches!(
        f.studio.redeem(id, "not-a-code").await,
        Err(StudioError::Expired)
    ));
}

#[tokio::test]
async fn access_ends_with_the_session_role_membership_and_login() {
    let Some(scratch) = ScratchDb::create("studio_revoke").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    let dev = account(&f.db, "Developer").await;
    add_member(&f.db, org, &dev, OrgRole::Developer).await;

    let expired = |r: Result<_, StudioError>| matches!(r, Err(StudioError::Expired));

    // Signing out of the dashboard ends Studio access.
    let token = open(&f, &dev, id).await;
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
        .bind(dev.session_id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(expired(f.studio.authorize(id, &token).await));

    // Losing the role does too.
    let dev = account(&f.db, "Developer2").await;
    add_member(&f.db, org, &dev, OrgRole::Developer).await;
    let token = open(&f, &dev, id).await;
    sqlx::query("UPDATE organization_members SET role = 'viewer' WHERE account_id = $1")
        .bind(dev.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(matches!(
        f.studio.authorize(id, &token).await,
        Err(StudioError::Forbidden)
    ));
    sqlx::query("DELETE FROM organization_members WHERE account_id = $1")
        .bind(dev.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(expired(f.studio.authorize(id, &token).await));

    // So does disabling the account.
    let token = open(&f, &owner, id).await;
    sqlx::query("UPDATE accounts SET disabled_at = now() WHERE id = $1")
        .bind(owner.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(expired(f.studio.authorize(id, &token).await));
    sqlx::query("UPDATE accounts SET disabled_at = NULL WHERE id = $1")
        .bind(owner.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();

    // Removing the Studio login closes Studio and stops new handoffs.
    let token = open(&f, &owner, id).await;
    f.connections
        .remove_credential(&owner, id, CredentialKind::StudioLogin, ctx())
        .await
        .unwrap();
    assert!(expired(f.studio.authorize(id, &token).await));
    assert!(matches!(
        f.studio.begin(&owner, id, None, ctx()).await,
        Err(StudioError::NotConfigured)
    ));

    // Unregistering the project removes its Studio sessions.
    let login = SecretString::from(check_studio_login("supabase", PASSWORD).unwrap());
    f.connections
        .replace_credential(&owner, id, CredentialKind::StudioLogin, &login, ctx())
        .await
        .unwrap();
    open(&f, &owner, id).await;
    sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(id)
        .execute(f.db.pool())
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM studio_sessions")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn studio_requests_are_logged_for_owners_and_admins_to_read() {
    let Some(scratch) = ScratchDb::create("studio_access_log").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let outsider = account(&f.db, "Outsider").await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    let (_, other) = project(&f, &outsider, "Globex").await;

    let recorder = StudioAccessRecorder::start(f.db.clone());
    let at = time::OffsetDateTime::now_utc();
    for (project_id, who, path, status) in [
        (
            id,
            &developer,
            "/api/platform/pg-meta/default/query?key=abc",
            200,
        ),
        (id, &developer, "/project/default/editor", 200),
        (other, &outsider, "/project/default", 200),
        (Uuid::now_v7(), &developer, "/unknown-project", 200),
    ] {
        recorder.record(NewStudioAccess {
            project_id,
            account_id: who.account.id,
            at,
            method: "GET".to_owned(),
            path: loggable_path(path),
            status,
        });
    }
    let log = StudioAccessService::new(f.db.clone(), Some(7));
    let entries = {
        let mut waited = 0;
        loop {
            let StudioAccessLog::On {
                entries,
                retention_days,
                older,
            } = log.read(&owner, id, None).await.unwrap()
            else {
                panic!("the log is on");
            };
            assert_eq!(retention_days, 7);
            assert_eq!(older, None);
            if entries.len() == 2 || waited > 50 {
                break entries;
            }
            waited += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(
        entries
            .iter()
            .all(|e| e.member.as_ref().unwrap().display_name == "Developer")
    );
    let paths: Vec<_> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(
        paths.contains(&"/api/platform/pg-meta/default/query"),
        "{paths:?}"
    );
    assert!(!paths.iter().any(|p| p.contains("key=")));
    assert_eq!(recorder.dropped(), 0);
    // The entry for a project that does not exist was dropped.
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM studio_access_log")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(total, 3);

    assert!(log.read(&admin, id, None).await.is_ok());
    assert!(matches!(
        log.read(&developer, id, None).await,
        Err(StudioAccessError::Forbidden)
    ));
    assert!(matches!(
        log.read(&outsider, id, None).await,
        Err(StudioAccessError::NotFound)
    ));

    // Entries past the retention period go; with the log off, all go.
    sqlx::query(
        "INSERT INTO studio_access_log (project_id, account_id, at, method, path, status) \
         VALUES ($1, $2, now() - interval '8 days', 'GET', '/old', 200)",
    )
    .bind(id)
    .bind(developer.account.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    assert_eq!(log.prune().await.unwrap(), 1);
    let off = StudioAccessService::new(f.db.clone(), None);
    assert_eq!(
        off.read(&owner, id, None).await.unwrap(),
        StudioAccessLog::Off
    );
    assert_eq!(off.prune().await.unwrap(), 3);
}

#[tokio::test]
async fn the_access_log_pages_through_entries_with_the_same_time() {
    let Some(scratch) = ScratchDb::create("studio_access_pages").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let outsider = account(&f.db, "Outsider").await;
    let (_, other) = project(&f, &outsider, "Globex").await;
    // 250 entries over 3 timestamps, so pages split entries with equal times.
    sqlx::query(
        "INSERT INTO studio_access_log (project_id, account_id, at, method, path, status) \
         SELECT $1, $2, now() - make_interval(secs => n % 3), 'GET', '/p/' || n, 200 \
         FROM generate_series(1, 250) AS n",
    )
    .bind(id)
    .bind(owner.account.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO studio_access_log (project_id, account_id, at, method, path, status) \
         VALUES ($1, $2, now(), 'GET', '/other', 200)",
    )
    .bind(other)
    .bind(outsider.account.id)
    .execute(f.db.pool())
    .await
    .unwrap();
    let log = StudioAccessService::new(f.db.clone(), Some(7));
    let page = async |before| match log.read(&owner, id, before).await.unwrap() {
        StudioAccessLog::On { entries, older, .. } => (entries, older),
        StudioAccessLog::Off => panic!("the log is on"),
    };

    let mut seen = Vec::new();
    let mut before = None;
    let mut sizes = Vec::new();
    loop {
        let (entries, older) = page(before).await;
        sizes.push(entries.len());
        assert!(
            entries
                .windows(2)
                .all(|w| (w[0].at, w[0].id) > (w[1].at, w[1].id))
        );
        seen.extend(entries.iter().map(|e| e.path.clone()));
        match older {
            Some(next) => {
                assert_eq!(Some(next), entries.last().map(|e| e.id));
                before = Some(next);
            }
            None => break,
        }
    }
    assert_eq!(sizes, vec![100, 100, 50]);
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 250, "no entry repeated or skipped");
    assert!(!seen.contains(&"/other".to_owned()));

    // Another project's entry id, or one that no longer exists, is not a
    // way into that project's log: the page is empty.
    let other_entry: i64 =
        sqlx::query_scalar("SELECT id FROM studio_access_log WHERE project_id = $1")
            .bind(other)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(page(Some(other_entry)).await, (Vec::new(), None));
    assert_eq!(page(Some(i64::MAX)).await, (Vec::new(), None));
}
