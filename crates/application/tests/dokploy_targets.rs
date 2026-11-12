//! Where organizations' new stacks may go in Dokploy, against a scratch
//! metadata database, with a fake connector in place of Dokploy. Skipped
//! unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    dokploy::{
        ConnectFuture, CreateEnvironmentFuture, DokployConnector, DokployService,
        DokployServiceError, EffectiveTargets, InventoryFuture, TargetsFuture,
    },
    secrets::CredentialCipher,
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    connection::UnreachableReason,
    dokploy::{DokployError, DokployUrl, TESTED_DOKPLOY_VERSION},
    dokploy_placement::{
        DokployDomainInfo, DokployId, DokployInventory, DokployServiceInfo, DokployServiceKind,
        DokployServiceRef,
    },
    dokploy_target::{
        DefaultTarget, DokployEnvironmentInfo, DokployServerInfo, DokployTargetInventory,
        EnvironmentNameError, MAX_TARGETS_PER_ORGANIZATION, StackTarget, StackTargetNames,
        TargetLookup,
    },
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const URL: &str = "https://dokploy.example.test";
const DOKPLOY_KEY: &str = "dokploy-key-marker-targets";
const PUBLIC_HOST: &str = "dashboard.example.test";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-targets"),
        user_agent: None,
    }
}

fn id(raw: &str) -> DokployId {
    DokployId::parse(raw).unwrap()
}

#[derive(Default)]
struct FakeDokploy {
    inventory: Mutex<DokployInventory>,
    targets: Mutex<DokployTargetInventory>,
    /// Keys `targets` was called with.
    target_calls: Mutex<Vec<String>>,
    /// (project, name) of each `create_environment` call.
    created: Mutex<Vec<(String, String)>>,
    create_error: Mutex<Option<DokployError>>,
}

impl DokployConnector for FakeDokploy {
    fn connect<'a>(&'a self, _url: &'a DokployUrl, _key: &'a SecretString) -> ConnectFuture<'a> {
        Box::pin(async { Ok(TESTED_DOKPLOY_VERSION) })
    }

    fn inventory<'a>(
        &'a self,
        _url: &'a DokployUrl,
        _key: &'a SecretString,
    ) -> InventoryFuture<'a> {
        let answer = self.inventory.lock().unwrap().clone();
        Box::pin(async move { Ok(answer) })
    }

    fn targets<'a>(&'a self, _url: &'a DokployUrl, key: &'a SecretString) -> TargetsFuture<'a> {
        self.target_calls
            .lock()
            .unwrap()
            .push(key.expose_secret().to_owned());
        let answer = self.targets.lock().unwrap().clone();
        Box::pin(async move { Ok(answer) })
    }

    fn create_environment<'a>(
        &'a self,
        _url: &'a DokployUrl,
        _key: &'a SecretString,
        project_id: &'a DokployId,
        name: &'a str,
    ) -> CreateEnvironmentFuture<'a> {
        self.created
            .lock()
            .unwrap()
            .push((project_id.as_str().to_owned(), name.to_owned()));
        let answer = match self.create_error.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(id("newenv")),
        };
        Box::pin(async move { answer })
    }
}

struct Fixture {
    db: Database,
    fake: Arc<FakeDokploy>,
    service: DokployService,
    admin: CurrentSession,
}

/// A connected Dokploy whose key sees project `proj1` with environments
/// `prod` (where the dashboard runs, on Dokploy's own server) and
/// `stacks`, and the remote server `s1`.
async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let fake = Arc::new(FakeDokploy::default());
    let cipher = CredentialCipher::from_base64(&SecretString::from(KEY_A)).unwrap();
    let service = DokployService::new(db.clone(), Some(cipher), fake.clone())
        .with_public_host(Some(PUBLIC_HOST));
    let admin = account(&db, "Admin", true).await;
    service
        .connect(&admin, URL, &SecretString::from(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    let dashboard = dashboard_service("prod");
    *fake.inventory.lock().unwrap() = DokployInventory {
        domains: vec![DokployDomainInfo {
            host: PUBLIC_HOST.to_owned(),
            service: dashboard.service.clone(),
            enabled: true,
            preview: false,
        }],
        services: vec![dashboard],
    };
    *fake.targets.lock().unwrap() = DokployTargetInventory {
        environments: vec![environment("prod", true), environment("stacks", false)],
        servers: Some(vec![DokployServerInfo {
            id: id("s1"),
            name: "edge-1".to_owned(),
        }]),
    };
    Fixture {
        db,
        fake,
        service,
        admin,
    }
}

fn dashboard_service(env: &str) -> DokployServiceInfo {
    DokployServiceInfo {
        service: DokployServiceRef {
            kind: DokployServiceKind::Compose,
            id: id("dash"),
        },
        name: "dashboard".to_owned(),
        project_id: id("proj1"),
        project_name: "Infra".to_owned(),
        environment_id: id(env),
        environment_name: env.to_owned(),
        server_id: None,
        server_name: None,
    }
}

fn environment(env: &str, is_default: bool) -> DokployEnvironmentInfo {
    DokployEnvironmentInfo {
        project_id: id("proj1"),
        project_name: "Infra".to_owned(),
        environment_id: id(env),
        environment_name: env.to_owned(),
        is_default,
    }
}

async fn account(db: &Database, name: &str, admin: bool) -> CurrentSession {
    let id = Uuid::now_v7();
    let email = format!("{}@example.test", name.to_lowercase());
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash, is_installation_admin) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&email)
    .bind(name)
    .bind(HASH)
    .bind(admin)
    .execute(db.pool())
    .await
    .unwrap();
    CurrentSession {
        session_id: Uuid::now_v7(),
        account: AccountRecord {
            id,
            email: Email::parse(&email).unwrap(),
            display_name: DisplayName::parse(name).unwrap(),
            is_installation_admin: admin,
            disabled: false,
        },
    }
}

async fn organization(db: &Database, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(name)
        .execute(db.pool())
        .await
        .unwrap();
    id
}

/// Audit events for `action` with `outcome`, as (actor, target type,
/// target id).
async fn audits(
    db: &Database,
    action: &str,
    outcome: &str,
) -> Vec<(Option<Uuid>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT actor_account_id, target_type, target_id FROM audit_events \
         WHERE action = $1 AND outcome = $2 ORDER BY occurred_at, id",
    )
    .bind(action)
    .bind(outcome)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn target_rows(db: &Database) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dokploy_stack_targets")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn own(env: &str) -> StackTarget {
    StackTarget {
        environment_id: id(env),
        server_id: None,
    }
}

#[tokio::test]
async fn organizations_use_the_dashboards_environment_until_an_admin_allows_others() {
    let Some(scratch) = ScratchDb::create("dokploy_targets").await else {
        return;
    };
    let f = setup(&scratch).await;
    let bob = account(&f.db, "Bob", false).await;
    let acme = organization(&f.db, "Acme").await;
    let beta = organization(&f.db, "Beta").await;

    // Without a confirmed placement there is no default, so an
    // organization without targets of its own may use nothing.
    assert_eq!(
        f.service.organization_targets(acme).await.unwrap(),
        EffectiveTargets::Default(DefaultTarget::NoPlacement)
    );
    f.service
        .confirm_placement(&f.admin, "compose", "dash", ctx())
        .await
        .unwrap();
    let dashboard_env = DefaultTarget::Placement {
        target: own("prod"),
        names: StackTargetNames {
            project_name: "Infra".to_owned(),
            environment_name: "prod".to_owned(),
            server_name: None,
        },
    };
    assert_eq!(
        f.service.organization_targets(acme).await.unwrap(),
        EffectiveTargets::Default(dashboard_env.clone())
    );

    // The page lists every organization and what the key can see.
    let overview = f.service.stack_targets(&f.admin, ctx()).await.unwrap();
    assert_eq!(overview.default_target, dashboard_env);
    let names: Vec<&str> = overview
        .organizations
        .iter()
        .map(|org| org.organization_name.as_str())
        .collect();
    assert_eq!(names, ["Acme", "Beta"]);
    assert!(
        overview
            .organizations
            .iter()
            .all(|org| org.allowed.is_empty())
    );
    let TargetLookup::Found {
        inventory,
        truncated,
    } = overview.lookup
    else {
        panic!("Dokploy was not read");
    };
    assert_eq!(inventory.environments.len(), 2);
    assert!(!truncated);
    assert_eq!(
        f.fake.target_calls.lock().unwrap().last().unwrap(),
        DOKPLOY_KEY
    );

    // Bob can neither look nor change anything, and Dokploy is not asked
    // for him.
    let calls = f.fake.target_calls.lock().unwrap().len();
    assert!(matches!(
        f.service.stack_targets(&bob, ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .allow_stack_target(&bob, acme, "stacks", ctx())
            .await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .remove_stack_target(&bob, acme, Uuid::now_v7(), ctx())
            .await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .create_environment(&bob, "proj1", "staging", ctx())
            .await,
        Err(DokployServiceError::Forbidden)
    ));
    assert_eq!(f.fake.target_calls.lock().unwrap().len(), calls);
    assert_eq!(
        audits(&f.db, "dokploy.target_allow", "denied").await.len(),
        1
    );
    assert_eq!(
        audits(&f.db, "dokploy.target_remove", "denied").await.len(),
        1
    );
    assert_eq!(
        audits(&f.db, "dokploy.environment_create", "denied")
            .await
            .len(),
        1
    );

    // An admin allows Acme the stacks environment on edge-1.
    f.service
        .allow_stack_target(&f.admin, acme, "stacks@s1", ctx())
        .await
        .unwrap();
    let remote = StackTarget {
        environment_id: id("stacks"),
        server_id: Some(id("s1")),
    };
    let EffectiveTargets::Allowed(allowed) = f.service.organization_targets(acme).await.unwrap()
    else {
        panic!("Acme has no targets of its own");
    };
    assert_eq!(
        allowed,
        vec![(
            remote.clone(),
            StackTargetNames {
                project_name: "Infra".to_owned(),
                environment_name: "stacks".to_owned(),
                server_name: Some("edge-1".to_owned()),
            }
        )]
    );
    // Beta still has only the default.
    assert_eq!(
        f.service.organization_targets(beta).await.unwrap(),
        EffectiveTargets::Default(dashboard_env.clone())
    );
    assert_eq!(
        audits(&f.db, "dokploy.target_allow", "success").await,
        vec![(
            Some(f.admin.account.id),
            Some("organization".to_owned()),
            Some(acme.to_string())
        )]
    );

    // Allowing it again, or anything the key cannot see, stores nothing.
    for (value, expected) in [
        ("stacks@s1", "already"),
        ("gone", "not visible"),
        ("stacks@s9", "not visible"),
        ("stacks@", "not visible"),
        ("", "not visible"),
    ] {
        let err = f
            .service
            .allow_stack_target(&f.admin, acme, value, ctx())
            .await
            .unwrap_err();
        match expected {
            "already" => assert!(matches!(err, DokployServiceError::TargetAlreadyAllowed)),
            _ => assert!(
                matches!(err, DokployServiceError::TargetNotVisible),
                "{value:?}: {err}"
            ),
        }
    }
    assert!(matches!(
        f.service
            .allow_stack_target(&f.admin, Uuid::now_v7(), "stacks", ctx())
            .await,
        Err(DokployServiceError::OrganizationNotFound)
    ));
    assert_eq!(target_rows(&f.db).await, 1);
    assert_eq!(
        audits(&f.db, "dokploy.target_allow", "failure").await.len(),
        6
    );

    // The page shows the target with who added it.
    let overview = f.service.stack_targets(&f.admin, ctx()).await.unwrap();
    let acme_targets = &overview.organizations[0].allowed;
    assert_eq!(acme_targets.len(), 1);
    assert_eq!(acme_targets[0].target, remote);
    assert_eq!(
        acme_targets[0].added_by.as_ref().map(DisplayName::as_str),
        Some("Admin")
    );

    // Removing needs the right organization; then Acme is back on the
    // default.
    let target_id = acme_targets[0].id;
    assert!(matches!(
        f.service
            .remove_stack_target(&f.admin, beta, target_id, ctx())
            .await,
        Err(DokployServiceError::TargetNotFound)
    ));
    f.service
        .remove_stack_target(&f.admin, acme, target_id, ctx())
        .await
        .unwrap();
    assert_eq!(
        f.service.organization_targets(acme).await.unwrap(),
        EffectiveTargets::Default(dashboard_env)
    );
    assert_eq!(
        audits(&f.db, "dokploy.target_remove", "success")
            .await
            .len(),
        1
    );

    // A dashboard service moved in Dokploy is no default until confirmed
    // again.
    f.fake.inventory.lock().unwrap().services = vec![dashboard_service("stacks")];
    assert!(matches!(
        f.service.organization_targets(acme).await.unwrap(),
        EffectiveTargets::Default(DefaultTarget::Unavailable(_))
    ));

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn an_environment_is_created_once_in_a_project_the_key_can_see() {
    let Some(scratch) = ScratchDb::create("dokploy_targets_env").await else {
        return;
    };
    let f = setup(&scratch).await;
    let create = |project: &'static str, name: &'static str| {
        f.service.create_environment(&f.admin, project, name, ctx())
    };

    // A name the project already has, a project the key cannot see, and a
    // bad name never reach Dokploy.
    assert!(matches!(
        create("proj1", " Stacks ").await,
        Err(DokployServiceError::EnvironmentExists)
    ));
    assert!(matches!(
        create("proj2", "staging").await,
        Err(DokployServiceError::ProjectNotVisible)
    ));
    assert!(matches!(
        create("bad id", "staging").await,
        Err(DokployServiceError::ProjectNotVisible)
    ));
    assert!(matches!(
        create("proj1", "a/b").await,
        Err(DokployServiceError::EnvironmentName(
            EnvironmentNameError::InvalidCharacters
        ))
    ));
    assert!(f.fake.created.lock().unwrap().is_empty());

    // A good one is sent trimmed, and audited with both IDs.
    assert_eq!(create("proj1", " staging ").await.unwrap(), id("newenv"));
    assert_eq!(
        *f.fake.created.lock().unwrap(),
        vec![("proj1".to_owned(), "staging".to_owned())]
    );
    assert_eq!(
        audits(&f.db, "dokploy.environment_create", "success").await,
        vec![(
            Some(f.admin.account.id),
            Some("dokploy_project".to_owned()),
            Some("proj1/newenv".to_owned())
        )]
    );

    // No answer means the outcome is unknown, and it is not retried.
    *f.fake.create_error.lock().unwrap() =
        Some(DokployError::Unreachable(UnreachableReason::Timeout));
    assert!(matches!(
        create("proj1", "qa").await,
        Err(DokployServiceError::EnvironmentOutcomeUnknown)
    ));
    *f.fake.create_error.lock().unwrap() = Some(DokployError::KeyRejected);
    assert!(matches!(
        create("proj1", "qa").await,
        Err(DokployServiceError::Dokploy(DokployError::KeyRejected))
    ));
    assert_eq!(f.fake.created.lock().unwrap().len(), 3);
    // A malformed name is refused as input, before anything is audited.
    assert_eq!(
        audits(&f.db, "dokploy.environment_create", "failure")
            .await
            .len(),
        5
    );

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn targets_are_limited_and_go_with_the_connection() {
    let Some(scratch) = ScratchDb::create("dokploy_targets_limit").await else {
        return;
    };
    let f = setup(&scratch).await;
    let acme = organization(&f.db, "Acme").await;
    f.fake.targets.lock().unwrap().environments = (0..=MAX_TARGETS_PER_ORGANIZATION)
        .map(|n| environment(&format!("e{n}"), false))
        .collect();

    for n in 0..MAX_TARGETS_PER_ORGANIZATION {
        f.service
            .allow_stack_target(&f.admin, acme, &format!("e{n}"), ctx())
            .await
            .unwrap();
    }
    let last = format!("e{MAX_TARGETS_PER_ORGANIZATION}");
    assert!(matches!(
        f.service
            .allow_stack_target(&f.admin, acme, &last, ctx())
            .await,
        Err(DokployServiceError::TooManyTargets)
    ));
    // A duplicate at the limit is still reported as a duplicate.
    assert!(matches!(
        f.service
            .allow_stack_target(&f.admin, acme, "e0", ctx())
            .await,
        Err(DokployServiceError::TargetAlreadyAllowed)
    ));
    let limit = i64::try_from(MAX_TARGETS_PER_ORGANIZATION).unwrap();
    assert_eq!(target_rows(&f.db).await, limit);

    // The IDs belong to this Dokploy: removing the connection removes them.
    f.service.remove(&f.admin, ctx()).await.unwrap();
    assert_eq!(target_rows(&f.db).await, 0);

    // Nothing in the audit log names the key.
    let audit: Vec<String> = sqlx::query_scalar("SELECT row_to_json(a)::text FROM audit_events a")
        .fetch_all(f.db.pool())
        .await
        .unwrap();
    assert!(!audit.join("\n").contains(DOKPLOY_KEY));

    f.db.close().await;
    scratch.drop().await;
}
