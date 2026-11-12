//! Stored API keys and service checks against a scratch metadata database,
//! with a fake probe in place of the network. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::{ConnectionError, ConnectionService, ProbeFuture, StackProbe},
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    secrets::CredentialCipher,
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authz::OrgRole,
    connection::{
        ApiKeyError, CredentialKind, CredentialState, SavedCredential, ServiceCheck, ServiceStatus,
        SkipReason, StackService, UnreachableReason, check_studio_login,
    },
    project::ProjectUrl,
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
const STUDIO_PASSWORD: &str = "studio-password-for-tests";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-connection"),
        user_agent: None,
    }
}

fn cipher(key: &str) -> CredentialCipher {
    CredentialCipher::from_base64(&SecretString::from(key)).unwrap()
}

/// Records which key each service was checked with. Reports healthy,
/// except for Studio when `studio` holds another answer.
#[derive(Default)]
struct FakeProbe {
    calls: Mutex<Vec<(StackService, String)>>,
    studio: Mutex<Option<ServiceStatus>>,
}

impl StackProbe for FakeProbe {
    fn check<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
    ) -> ProbeFuture<'a> {
        self.calls
            .lock()
            .unwrap()
            .push((service, key.expose_secret().to_owned()));
        let status = match service {
            StackService::Studio => self.studio.lock().unwrap().clone(),
            _ => None,
        }
        .unwrap_or(ServiceStatus::Healthy);
        Box::pin(async move {
            ServiceCheck {
                service,
                status,
                version: Some("v-test".into()),
                latency_ms: Some(1),
            }
        })
    }
}

struct Fixture {
    db: Database,
    orgs: OrganizationService,
    projects: ProjectService,
    probe: Arc<FakeProbe>,
    connections: ConnectionService,
}

async fn setup(scratch: &ScratchDb, key: Option<&str>) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let probe = Arc::new(FakeProbe::default());
    Fixture {
        orgs: OrganizationService::new(db.clone()),
        projects: ProjectService::new(db.clone()),
        connections: ConnectionService::new(db.clone(), key.map(cipher), probe.clone()),
        probe,
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

/// An organization with an owner and one registered project.
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

fn state(
    overview: &supabase_dashboard_domain::connection::CredentialOverview,
    kind: CredentialKind,
) -> &CredentialState {
    &overview
        .credentials
        .iter()
        .find(|c| c.kind == kind)
        .unwrap()
        .state
}

#[tokio::test]
async fn only_owners_and_admins_change_keys_and_values_stay_encrypted() {
    let Some(scratch) = ScratchDb::create("conn_roles").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;

    let anon = SecretString::from(format!("  {ANON}\n"));
    f.connections
        .replace_credential(&admin, id, CredentialKind::AnonKey, &anon, ctx())
        .await
        .unwrap();
    for who in [&developer, &viewer] {
        assert!(matches!(
            f.connections
                .replace_credential(who, id, CredentialKind::AnonKey, &anon, ctx())
                .await,
            Err(ConnectionError::Forbidden)
        ));
        assert!(matches!(
            f.connections
                .remove_credential(who, id, CredentialKind::AnonKey, ctx())
                .await,
            Err(ConnectionError::Forbidden)
        ));
        // Every member can see whether a key is set, but not its value.
        let overview = f.connections.credentials(who, id).await.unwrap();
        assert!(matches!(
            state(&overview, CredentialKind::AnonKey),
            CredentialState::Set { .. }
        ));
        assert!(!format!("{overview:?}").contains(ANON));
    }
    assert_eq!(
        audit_count(&f.db, "project.credential.replace", "success").await,
        1
    );
    assert_eq!(
        audit_count(&f.db, "project.credential.replace", "denied").await,
        2
    );

    // The stored row holds neither the value nor anything that contains it.
    let (ciphertext, key_id): (Vec<u8>, String) =
        sqlx::query_as("SELECT ciphertext, key_id FROM project_credentials WHERE project_id = $1")
            .bind(id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert!(!ciphertext.windows(ANON.len()).any(|w| w == ANON.as_bytes()));
    assert_eq!(key_id, cipher(KEY_A).key_id());
    let audit_text: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(target_id, '') FROM audit_events WHERE action LIKE 'project.credential.%'",
    )
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert!(audit_text.iter().all(|t| !t.contains(ANON)));

    // The trimmed value is what the check uses.
    f.connections.check_now(&viewer, id).await.unwrap();
    let calls = f.probe.calls.lock().unwrap().clone();
    assert!(calls.contains(&(StackService::Auth, ANON.to_owned())));

    f.connections
        .remove_credential(&owner, id, CredentialKind::AnonKey, ctx())
        .await
        .unwrap();
    assert!(matches!(
        f.connections
            .remove_credential(&owner, id, CredentialKind::AnonKey, ctx())
            .await,
        Err(ConnectionError::NotStored)
    ));
}

#[tokio::test]
async fn other_organizations_cannot_see_or_change_keys() {
    let Some(scratch) = ScratchDb::create("conn_isolation").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let alice = account(&f.db, "Alice").await;
    let mallory = account(&f.db, "Mallory").await;
    let (_, id) = project(&f, &alice, "Alice Co").await;
    project(&f, &mallory, "Mallory Co").await;
    let key = SecretString::from(SERVICE);

    assert!(matches!(
        f.connections.credentials(&mallory, id).await,
        Err(ConnectionError::NotFound)
    ));
    assert!(matches!(
        f.connections
            .replace_credential(&mallory, id, CredentialKind::ServiceRoleKey, &key, ctx())
            .await,
        Err(ConnectionError::NotFound)
    ));
    assert!(matches!(
        f.connections.check_now(&mallory, id).await,
        Err(ConnectionError::NotFound)
    ));
    assert!(matches!(
        f.connections.last_report(&mallory, id).await,
        Err(ConnectionError::NotFound)
    ));
    assert!(matches!(
        f.connections.credentials(&mallory, Uuid::now_v7()).await,
        Err(ConnectionError::NotFound)
    ));
    assert!(f.probe.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn checks_prefer_the_least_privileged_key_and_are_saved() {
    let Some(scratch) = ScratchDb::create("conn_check").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;

    // Without keys nothing is contacted.
    let report = f.connections.check_now(&owner, id).await.unwrap();
    assert!(report.checks.iter().all(|c| c.status
        == ServiceStatus::NotChecked {
            reason: SkipReason::MissingKey
        }));
    assert!(f.probe.calls.lock().unwrap().is_empty());
    assert_eq!(
        f.connections.last_report(&owner, id).await.unwrap(),
        Some(report)
    );

    // The cooldown applies to every member.
    assert!(matches!(
        f.connections.check_now(&owner, id).await,
        Err(ConnectionError::CheckTooSoon { .. })
    ));
    sqlx::query("UPDATE project_health_reports SET checked_at = now() - interval '1 minute'")
        .execute(f.db.pool())
        .await
        .unwrap();

    // A Studio login must come in its stored `user:password` form.
    assert!(matches!(
        f.connections
            .replace_credential(
                &owner,
                id,
                CredentialKind::StudioLogin,
                &SecretString::from(STUDIO_PASSWORD),
                ctx()
            )
            .await,
        Err(ConnectionError::Input(_))
    ));
    let studio = check_studio_login("supabase", STUDIO_PASSWORD).unwrap();
    for (kind, value) in [
        (CredentialKind::AnonKey, ANON),
        (CredentialKind::ServiceRoleKey, SERVICE),
        (CredentialKind::StudioLogin, studio.as_str()),
    ] {
        f.connections
            .replace_credential(&owner, id, kind, &SecretString::from(value), ctx())
            .await
            .unwrap();
    }
    // Saving the Studio login tried it once; the check below tries it again.
    assert_eq!(
        f.probe.calls.lock().unwrap().drain(..).collect::<Vec<_>>(),
        vec![(StackService::Studio, studio.clone())]
    );
    let report = f.connections.check_now(&owner, id).await.unwrap();
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.status == ServiceStatus::Healthy)
    );
    let calls = f.probe.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            (StackService::Auth, ANON.to_owned()),
            (StackService::Rest, SERVICE.to_owned()),
            (StackService::Storage, ANON.to_owned()),
            (StackService::Realtime, ANON.to_owned()),
            (StackService::Studio, studio.clone()),
        ]
    );
    // Saved reports carry statuses only.
    let saved: String =
        sqlx::query_scalar("SELECT checks::text FROM project_health_reports WHERE project_id = $1")
            .bind(id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert!(!saved.contains(ANON) && !saved.contains(SERVICE) && !saved.contains(STUDIO_PASSWORD));
}

#[tokio::test]
async fn keys_from_another_server_key_are_reported_unreadable() {
    let Some(scratch) = ScratchDb::create("conn_rotation").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    f.connections
        .replace_credential(
            &owner,
            id,
            CredentialKind::AnonKey,
            &SecretString::from(ANON),
            ctx(),
        )
        .await
        .unwrap();

    // Same database, different encryption key.
    let probe = Arc::new(FakeProbe::default());
    let other = ConnectionService::new(f.db.clone(), Some(cipher(KEY_B)), probe.clone());
    let overview = other.credentials(&owner, id).await.unwrap();
    assert!(matches!(
        state(&overview, CredentialKind::AnonKey),
        CredentialState::Unreadable { .. }
    ));
    let report = other.check_now(&owner, id).await.unwrap();
    let auth = report
        .checks
        .iter()
        .find(|c| c.service == StackService::Auth)
        .unwrap();
    assert_eq!(
        auth.status,
        ServiceStatus::NotChecked {
            reason: SkipReason::UnreadableKey
        }
    );
    assert!(probe.calls.lock().unwrap().is_empty());

    // A row copied onto another project does not decrypt there.
    let (_, second) = {
        let org = f.orgs.create(&owner, "Second", ctx()).await.unwrap().id;
        let p = f
            .projects
            .register(
                &owner,
                org,
                Registration {
                    name: "Copy",
                    api_url: "https://copy.example.test",
                    allow_unencrypted: false,
                },
                ctx(),
            )
            .await
            .unwrap();
        (org, p.id)
    };
    sqlx::query(
        "INSERT INTO project_credentials (project_id, kind, key_id, nonce, ciphertext) \
         SELECT $2, kind, key_id, nonce, ciphertext FROM project_credentials WHERE project_id = $1",
    )
    .bind(id)
    .bind(second)
    .execute(f.db.pool())
    .await
    .unwrap();
    let report = f.connections.check_now(&owner, second).await.unwrap();
    // Only API keys were copied; the Studio row reports a missing login.
    assert!(
        report
            .checks
            .iter()
            .filter(|c| c.service != StackService::Studio)
            .all(|c| matches!(
                c.status,
                ServiceStatus::NotChecked {
                    reason: SkipReason::UnreadableKey
                }
            ))
    );

    // Removing works even without a matching key.
    other
        .remove_credential(&owner, id, CredentialKind::AnonKey, ctx())
        .await
        .unwrap();
}

#[tokio::test]
async fn without_an_encryption_key_nothing_is_stored() {
    let Some(scratch) = ScratchDb::create("conn_nokey").await else {
        return;
    };
    let f = setup(&scratch, None).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let overview = f.connections.credentials(&owner, id).await.unwrap();
    assert!(!overview.storage_available);
    assert!(matches!(
        f.connections
            .replace_credential(
                &owner,
                id,
                CredentialKind::AnonKey,
                &SecretString::from(ANON),
                ctx()
            )
            .await,
        Err(ConnectionError::StorageUnavailable)
    ));
}

#[tokio::test]
async fn malformed_keys_and_unregistered_projects() {
    let Some(scratch) = ScratchDb::create("conn_input").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    assert!(matches!(
        f.connections
            .replace_credential(
                &owner,
                id,
                CredentialKind::AnonKey,
                &SecretString::from("sb_secret_abc"),
                ctx()
            )
            .await,
        Err(ConnectionError::Input(ApiKeyError::SecretInAnonSlot))
    ));
    f.connections
        .replace_credential(
            &owner,
            id,
            CredentialKind::ServiceRoleKey,
            &SecretString::from(SERVICE),
            ctx(),
        )
        .await
        .unwrap();
    f.connections.check_now(&owner, id).await.unwrap();

    // Unregistering removes keys and the saved check with the registry row.
    f.projects
        .unregister(&owner, id, "Production", ctx())
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM project_credentials) + (SELECT count(*) FROM project_health_reports)",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn studio_logins_are_tried_before_they_are_saved() {
    let Some(scratch) = ScratchDb::create("conn_studio_save").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let first = SecretString::from(check_studio_login("supabase", STUDIO_PASSWORD).unwrap());
    let save = async |login: &SecretString| {
        f.connections
            .replace_credential(&owner, id, CredentialKind::StudioLogin, login, ctx())
            .await
    };
    let stored_ciphertext = || async {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT ciphertext FROM project_credentials WHERE project_id = $1 AND kind = 'studio_login'",
        )
        .bind(id)
        .fetch_optional(f.db.pool())
        .await
        .unwrap()
    };

    // Accepted by the gateway: stored and confirmed.
    assert_eq!(save(&first).await.unwrap(), SavedCredential::Confirmed);
    let confirmed = stored_ciphertext().await.unwrap();

    // Refused by the gateway: not stored, the earlier login stays, and the
    // attempt is audited as a failure without the password.
    *f.probe.studio.lock().unwrap() = Some(ServiceStatus::KeyRejected { http_status: 401 });
    let wrong =
        SecretString::from(check_studio_login("supabase", "a-wrong-studio-password").unwrap());
    assert!(matches!(
        save(&wrong).await,
        Err(ConnectionError::StudioLoginRejected { http_status: 401 })
    ));
    assert_eq!(stored_ciphertext().await.unwrap(), confirmed);
    assert_eq!(
        audit_count(&f.db, "project.credential.replace", "failure").await,
        1
    );

    // Unreachable or unprotected gateways: stored, with the reason.
    for status in [
        ServiceStatus::Unreachable {
            reason: UnreachableReason::Connect,
        },
        ServiceStatus::Unprotected { http_status: 200 },
    ] {
        *f.probe.studio.lock().unwrap() = Some(status.clone());
        assert_eq!(
            save(&first).await.unwrap(),
            SavedCredential::Unconfirmed { status }
        );
    }
    assert_ne!(stored_ciphertext().await.unwrap(), confirmed);
    assert_eq!(
        audit_count(&f.db, "project.credential.replace", "success").await,
        3
    );

    // API keys are not sent anywhere when saved.
    f.probe.calls.lock().unwrap().clear();
    assert_eq!(
        f.connections
            .replace_credential(
                &owner,
                id,
                CredentialKind::AnonKey,
                &SecretString::from(ANON),
                ctx()
            )
            .await
            .unwrap(),
        SavedCredential::NotChecked
    );
    assert!(f.probe.calls.lock().unwrap().is_empty());

    let audit_text: Vec<String> =
        sqlx::query_scalar("SELECT coalesce(target_id, '') FROM audit_events")
            .fetch_all(f.db.pool())
            .await
            .unwrap();
    assert!(
        audit_text
            .iter()
            .all(|t| !t.contains(STUDIO_PASSWORD) && !t.contains("a-wrong-studio-password"))
    );
}

#[tokio::test]
async fn health_digests_cover_one_organization_for_its_members() {
    let Some(scratch) = ScratchDb::create("conn_digests").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    let (other_org, other_id) = project(&f, &outsider, "Globex").await;
    let unchecked = f
        .projects
        .register(
            &owner,
            org,
            Registration {
                name: "Staging",
                api_url: "https://staging.example.test",
                allow_unencrypted: false,
            },
            ctx(),
        )
        .await
        .unwrap()
        .id;

    // Only the anon key is stored: Auth, Storage, and Realtime are checked
    // with it, REST falls back to it, and Studio has no login.
    f.connections
        .replace_credential(
            &owner,
            id,
            CredentialKind::AnonKey,
            &SecretString::from(ANON),
            ctx(),
        )
        .await
        .unwrap();
    f.connections.check_now(&owner, id).await.unwrap();
    f.connections.check_now(&outsider, other_id).await.unwrap();

    let digests = f.connections.health_digests(&viewer, org).await.unwrap();
    assert_eq!(digests.len(), 1, "{digests:?}");
    let digest = &digests[0];
    assert_eq!(digest.project_id, id);
    assert!(digest.failing.is_empty());
    assert_eq!(digest.not_checked, vec![StackService::Studio]);
    assert!(!digest.stale);
    assert!(digests.iter().all(|d| d.project_id != unchecked));

    // A day later the same check is stale.
    sqlx::query("UPDATE project_health_reports SET checked_at = now() - interval '25 hours'")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(f.connections.health_digests(&owner, org).await.unwrap()[0].stale);

    // Members of one organization learn nothing about another's projects.
    assert!(matches!(
        f.connections.health_digests(&outsider, org).await,
        Err(ConnectionError::NotFound)
    ));
    assert!(matches!(
        f.connections.health_digests(&viewer, other_org).await,
        Err(ConnectionError::NotFound)
    ));
}
