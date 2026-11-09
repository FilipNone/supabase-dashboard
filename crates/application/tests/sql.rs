//! SQL editor runs against a scratch metadata database, with a fake runner
//! in place of the network. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::ConnectionService,
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    sql::{SqlError, SqlFuture, SqlRunner, SqlService},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    connection::{CredentialKind, SkipReason},
    project::ProjectUrl,
    schema::{Cell, MetaUnavailable},
    sql::{SqlFailure, SqlOutcome, SqlResult, SqlText},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use tokio::sync::Notify;
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SERVICE: &str = "service-role-key-value-for-tests";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-sql"),
        user_agent: None,
    }
}

fn cipher() -> supabase_dashboard_application::secrets::CredentialCipher {
    supabase_dashboard_application::secrets::CredentialCipher::from_base64(&SecretString::from(KEY))
        .unwrap()
}

/// Answers `select 1` with one row. `wait` blocks until cancelled, then
/// reports what the database reports for a cancelled statement.
#[derive(Default)]
struct FakeRunner {
    keys: Mutex<Vec<String>>,
    runs: Mutex<Vec<Uuid>>,
    cancelled: Mutex<Vec<Uuid>>,
    started: Notify,
    stop: Notify,
}

impl SqlRunner for FakeRunner {
    fn run<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        key: &'a SecretString,
        sql: &'a SqlText,
        run_id: Uuid,
    ) -> SqlFuture<'a, SqlOutcome> {
        self.keys
            .lock()
            .unwrap()
            .push(key.expose_secret().to_owned());
        self.runs.lock().unwrap().push(run_id);
        Box::pin(async move {
            match sql.as_str() {
                "wait" => {
                    self.started.notify_one();
                    self.stop.notified().await;
                    Err(SqlFailure::Timeout)
                }
                "slow" => Err(SqlFailure::Timeout),
                "bad" => Err(SqlFailure::Database {
                    code: Some("42601".into()),
                    message: "syntax error".into(),
                }),
                _ => Ok(SqlResult {
                    columns: vec!["?column?".into()],
                    rows: vec![vec![Some(Cell {
                        text: "1".into(),
                        truncated: false,
                    })]],
                    row_count: 1,
                    hidden_columns: 0,
                    elapsed_ms: 0,
                }),
            }
        })
    }

    fn cancel<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        _key: &'a SecretString,
        run_id: Uuid,
    ) -> SqlFuture<'a, Result<u32, MetaUnavailable>> {
        self.cancelled.lock().unwrap().push(run_id);
        self.stop.notify_one();
        Box::pin(async { Ok(1) })
    }
}

struct Fixture {
    db: Database,
    orgs: OrganizationService,
    projects: ProjectService,
    connections: ConnectionService,
    runner: Arc<FakeRunner>,
}

impl Fixture {
    fn sql(&self) -> SqlService {
        SqlService::new(self.db.clone(), Some(cipher()), self.runner.clone())
    }
}

struct NoProbe;

impl supabase_dashboard_application::connections::StackProbe for NoProbe {
    fn check<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        _service: supabase_dashboard_domain::connection::StackService,
        _key: &'a SecretString,
    ) -> supabase_dashboard_application::connections::ProbeFuture<'a> {
        unreachable!("sql tests do not run service checks")
    }
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    Fixture {
        orgs: OrganizationService::new(db.clone()),
        projects: ProjectService::new(db.clone()),
        connections: ConnectionService::new(db.clone(), Some(cipher()), Arc::new(NoProbe)),
        runner: Arc::new(FakeRunner::default()),
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

async fn project(f: &Fixture, owner: &CurrentSession) -> (Uuid, Uuid) {
    let org = f.orgs.create(owner, "Acme", ctx()).await.unwrap().id;
    let project = f
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
    (org, project)
}

async fn store_key(f: &Fixture, owner: &CurrentSession, id: Uuid) {
    f.connections
        .replace_credential(
            owner,
            id,
            CredentialKind::ServiceRoleKey,
            &SecretString::from(SERVICE),
            ctx(),
        )
        .await
        .unwrap();
}

async fn audit_outcomes(db: &Database, project: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT outcome FROM audit_events WHERE action = 'sql.execute' AND target_id = $1 \
         ORDER BY occurred_at, id",
    )
    .bind(project.to_string())
    .fetch_all(db.pool())
    .await
    .unwrap()
}

fn text(sql: &str) -> SqlText {
    SqlText::parse(sql).unwrap()
}

#[tokio::test]
async fn sql_is_limited_to_roles_that_may_run_it() {
    let Some(scratch) = ScratchDb::create("sql_roles").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner).await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    store_key(&f, &owner, id).await;
    let sql = f.sql();

    for who in [&owner, &admin, &developer] {
        let result = sql.run(who, id, &text("select 1"), ctx()).await.unwrap();
        let result = result.unwrap();
        assert_eq!(result.columns, ["?column?"]);
        assert_eq!(result.row_count, 1);
    }
    assert!(
        f.runner
            .keys
            .lock()
            .unwrap()
            .iter()
            .all(|key| key == SERVICE)
    );

    assert!(matches!(
        sql.run(&viewer, id, &text("select 1"), ctx()).await,
        Err(SqlError::Forbidden)
    ));
    assert!(matches!(
        sql.cancel(&viewer, id, ctx()).await,
        Err(SqlError::Forbidden)
    ));
    // A non-member cannot tell the project exists.
    assert!(matches!(
        sql.run(&outsider, id, &text("select 1"), ctx()).await,
        Err(SqlError::NotFound)
    ));
    assert!(matches!(
        sql.run(&owner, Uuid::now_v7(), &text("select 1"), ctx())
            .await,
        Err(SqlError::NotFound)
    ));
    // Three runs and two refusals reached the audit log; the outsider's
    // guess did not.
    assert_eq!(
        audit_outcomes(&f.db, id).await,
        ["success", "success", "success", "denied", "denied"]
    );
    assert_eq!(f.runner.runs.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn failures_are_reported_and_audited_without_the_text() {
    let Some(scratch) = ScratchDb::create("sql_failures").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner).await;
    let sql = f.sql();

    // No key stored: nothing is sent.
    assert_eq!(
        sql.run(&owner, id, &text("select 1"), ctx()).await.unwrap(),
        Err(SqlFailure::Unavailable {
            reason: MetaUnavailable::NoKey {
                reason: SkipReason::MissingKey
            }
        })
    );
    assert!(f.runner.runs.lock().unwrap().is_empty());

    store_key(&f, &owner, id).await;
    assert_eq!(
        sql.run(&owner, id, &text("bad"), ctx()).await.unwrap(),
        Err(SqlFailure::Database {
            code: Some("42601".into()),
            message: "syntax error".into()
        })
    );
    // Without a cancel request, a stopped statement is a timeout.
    assert_eq!(
        sql.run(&owner, id, &text("slow"), ctx()).await.unwrap(),
        Err(SqlFailure::Timeout)
    );
    // Only the two runs that reached the stack are audited.
    assert_eq!(audit_outcomes(&f.db, id).await, ["failure", "failure"]);
    // Audit rows name the project and request, and carry no statement
    // text. (Matching on "bad" would also hit hex digits of a UUID.)
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT target_type, target_id, request_id FROM audit_events \
         WHERE action = 'sql.execute'",
    )
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    for (target_type, target_id, request_id) in rows {
        assert_eq!(target_type, "project");
        assert_eq!(target_id, Some(id.to_string()));
        assert_eq!(request_id.as_deref(), Some("req-sql"));
    }
}

#[tokio::test]
async fn one_run_per_member_and_project_and_cancel_stops_it() {
    let Some(scratch) = ScratchDb::create("sql_cancel").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let developer = account(&f.db, "Developer").await;
    let (org, id) = project(&f, &owner).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    store_key(&f, &owner, id).await;
    let sql = Arc::new(f.sql());

    // Nothing running: nothing to cancel, and the runner is not asked.
    assert_eq!(sql.cancel(&owner, id, ctx()).await.unwrap(), Ok(0));
    assert!(f.runner.cancelled.lock().unwrap().is_empty());

    let running = {
        let sql = sql.clone();
        let owner = owner.clone();
        tokio::spawn(async move { sql.run(&owner, id, &text("wait"), ctx()).await })
    };
    f.runner.started.notified().await;

    // A second run by the same member waits its turn; another member is
    // not held up.
    assert_eq!(
        sql.run(&owner, id, &text("select 1"), ctx()).await.unwrap(),
        Err(SqlFailure::Busy)
    );
    assert!(
        sql.run(&developer, id, &text("select 1"), ctx())
            .await
            .unwrap()
            .is_ok()
    );
    // Another member's cancel does not reach the owner's run.
    assert_eq!(sql.cancel(&developer, id, ctx()).await.unwrap(), Ok(0));
    assert!(f.runner.cancelled.lock().unwrap().is_empty());

    assert_eq!(sql.cancel(&owner, id, ctx()).await.unwrap(), Ok(1));
    let outcome = running.await.unwrap().unwrap();
    assert_eq!(outcome, Err(SqlFailure::Cancelled));
    let first_run = f.runner.runs.lock().unwrap()[0];
    assert_eq!(*f.runner.cancelled.lock().unwrap(), [first_run]);

    // The finished run no longer blocks the next one.
    assert!(
        sql.run(&owner, id, &text("select 1"), ctx())
            .await
            .unwrap()
            .is_ok()
    );
}
