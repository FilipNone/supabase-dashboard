//! Schema browsing against a scratch metadata database, with a fake
//! postgres-meta source in place of the network. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::ConnectionService,
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    schema::{MetaFuture, SchemaError, SchemaService, SchemaSource},
    secrets::CredentialCipher,
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    connection::{CredentialKind, SkipReason},
    project::ProjectUrl,
    schema::{
        MetaUnavailable, SchemaListing, SchemaName, SchemaSummary, TableDetail, TableListing,
        TableSummary,
    },
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B: &str = "HxwdHhscGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=";
const ANON: &str = "anon-key-value-for-tests";
const SERVICE: &str = "service-role-key-value-for-tests";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-schema"),
        user_agent: None,
    }
}

fn cipher(key: &str) -> CredentialCipher {
    CredentialCipher::from_base64(&SecretString::from(key)).unwrap()
}

fn table(id: u32, name: &str) -> TableSummary {
    TableSummary {
        id,
        schema: "public".into(),
        name: name.into(),
        rls_enabled: false,
        rls_forced: false,
        live_rows_estimate: 0,
        size: "8 kB".into(),
        comment: None,
    }
}

/// Records the key each call used. Table 7 exists; others do not.
#[derive(Default)]
struct FakeSource {
    keys: Mutex<Vec<String>>,
}

impl FakeSource {
    fn record(&self, key: &SecretString) {
        self.keys
            .lock()
            .unwrap()
            .push(key.expose_secret().to_owned());
    }
}

impl SchemaSource for FakeSource {
    fn schemas<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        key: &'a SecretString,
    ) -> MetaFuture<'a, SchemaListing> {
        self.record(key);
        Box::pin(async {
            Ok(SchemaListing {
                schemas: vec![SchemaSummary {
                    name: "public".into(),
                    owner: "postgres".into(),
                    browsable: true,
                }],
                truncated: false,
            })
        })
    }

    fn tables<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        key: &'a SecretString,
        schema: &'a SchemaName,
    ) -> MetaFuture<'a, TableListing> {
        self.record(key);
        Box::pin(async move {
            Ok(TableListing {
                schema: schema.as_str().to_owned(),
                tables: vec![table(7, "todos")],
                truncated: false,
            })
        })
    }

    fn table<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        key: &'a SecretString,
        table_id: u32,
    ) -> MetaFuture<'a, Option<TableDetail>> {
        self.record(key);
        Box::pin(async move {
            Ok((table_id == 7).then(|| TableDetail {
                table: table(7, "todos"),
                primary_key: vec!["id".into()],
                columns: Vec::new(),
            }))
        })
    }
}

struct Fixture {
    db: Database,
    orgs: OrganizationService,
    projects: ProjectService,
    connections: ConnectionService,
    source: Arc<FakeSource>,
}

impl Fixture {
    fn schema(&self, key: Option<&str>) -> SchemaService {
        SchemaService::new(self.db.clone(), key.map(cipher), self.source.clone())
    }
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    Fixture {
        orgs: OrganizationService::new(db.clone()),
        projects: ProjectService::new(db.clone()),
        connections: ConnectionService::new(db.clone(), Some(cipher(KEY_A)), Arc::new(NoProbe)),
        source: Arc::new(FakeSource::default()),
        db,
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
        unreachable!("schema tests do not run service checks")
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

async fn project(f: &Fixture, owner: &CurrentSession, org_name: &str) -> (Uuid, Uuid) {
    let org = f.orgs.create(owner, org_name, ctx()).await.unwrap().id;
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

async fn store(f: &Fixture, owner: &CurrentSession, id: Uuid, kind: CredentialKind, value: &str) {
    f.connections
        .replace_credential(owner, id, kind, &SecretString::from(value), ctx())
        .await
        .unwrap();
}

#[tokio::test]
async fn every_member_can_browse_with_the_service_role_key() {
    let Some(scratch) = ScratchDb::create("schema_roles").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let viewer = account(&f.db, "Viewer").await;
    let developer = account(&f.db, "Developer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    store(&f, &owner, id, CredentialKind::AnonKey, ANON).await;
    store(&f, &owner, id, CredentialKind::ServiceRoleKey, SERVICE).await;
    let schema = f.schema(Some(KEY_A));
    let public = SchemaName::parse("public").unwrap();

    for who in [&owner, &developer, &viewer] {
        let listing = schema.schemas(who, id).await.unwrap().unwrap();
        assert_eq!(listing.schemas[0].name, "public");
        let tables = schema.tables(who, id, &public).await.unwrap().unwrap();
        assert_eq!(tables.tables[0].id, 7);
        let detail = schema.table(who, id, 7).await.unwrap().unwrap();
        assert_eq!(detail.primary_key, ["id"]);
    }
    assert!(matches!(
        schema.table(&viewer, id, 8).await,
        Err(SchemaError::TableNotFound)
    ));
    // Only the service role key is used, never the anon key.
    assert!(f.source.keys.lock().unwrap().iter().all(|k| k == SERVICE));

    // Someone outside the organization gets the same answer as for a
    // project that does not exist, and the stack is not contacted.
    let calls = f.source.keys.lock().unwrap().len();
    assert!(matches!(
        schema.schemas(&outsider, id).await,
        Err(SchemaError::NotFound)
    ));
    assert!(matches!(
        schema.table(&outsider, id, 7).await,
        Err(SchemaError::NotFound)
    ));
    assert!(matches!(
        schema.schemas(&owner, Uuid::now_v7()).await,
        Err(SchemaError::NotFound)
    ));
    assert_eq!(f.source.keys.lock().unwrap().len(), calls);
}

#[tokio::test]
async fn missing_or_unreadable_keys_are_reported_without_contacting_the_stack() {
    let Some(scratch) = ScratchDb::create("schema_keys").await else {
        return;
    };
    let f = setup(&scratch).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let public = SchemaName::parse("public").unwrap();

    // The anon key alone is not enough.
    store(&f, &owner, id, CredentialKind::AnonKey, ANON).await;
    let missing = MetaUnavailable::NoKey {
        reason: SkipReason::MissingKey,
    };
    let schema = f.schema(Some(KEY_A));
    assert_eq!(schema.schemas(&owner, id).await.unwrap(), Err(missing));
    assert_eq!(
        schema.tables(&owner, id, &public).await.unwrap(),
        Err(missing)
    );
    assert_eq!(schema.table(&owner, id, 7).await.unwrap(), Err(missing));

    // A key sealed under another server key, or no server key at all.
    store(&f, &owner, id, CredentialKind::ServiceRoleKey, SERVICE).await;
    let unreadable = MetaUnavailable::NoKey {
        reason: SkipReason::UnreadableKey,
    };
    assert_eq!(
        f.schema(Some(KEY_B)).schemas(&owner, id).await.unwrap(),
        Err(unreadable)
    );
    assert_eq!(
        f.schema(None).schemas(&owner, id).await.unwrap(),
        Err(unreadable)
    );
    assert!(f.source.keys.lock().unwrap().is_empty());
}
