//! Stored API keys and service checks against a scratch metadata database,
//! with a fake probe in place of the network. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    connections::{
        ConnectionError, ConnectionService, ProbeFuture, ScheduledChecks, ScheduledRun, StackProbe,
    },
    key_rotation::{KeyUsage, RotationSummary, key_usage, reseal_credentials},
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
    secrets::CredentialCipher,
    secrets::Sealed,
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    authority::{AuthorityError, AuthorityInfo, ProjectAuthorities},
    authz::{OrgRole, Permission},
    connection::{
        ApiKeyError, CredentialKind, CredentialState, HEALTH_HISTORY_MAX_ENTRIES,
        HEALTH_HISTORY_PAGE, HealthHour, SavedCredential, ServiceCheck, ServiceStatus, SkipReason,
        StackService, UnreachableReason, check_studio_login,
    },
    job::JobKind,
    project::ProjectUrl,
};
use supabase_dashboard_persistence::{
    Database,
    accounts::AccountRecord,
    audit::{AuditEvent, AuditOutcome},
    jobs::{NewJob, SealedJobSecrets},
};
use time::OffsetDateTime;
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

/// Records which key each service was checked with, and which bundle it
/// trusted. Reports healthy, except for Studio when `studio` holds another
/// answer, and except for every service of a stack whose API URL is in
/// `down`, which cannot be reached.
#[derive(Default)]
struct FakeProbe {
    calls: Mutex<Vec<(StackService, String)>>,
    bundles: Mutex<Vec<Option<String>>>,
    studio: Mutex<Option<ServiceStatus>>,
    down: Mutex<Vec<String>>,
}

/// A stand-in for a PEM bundle: the fake probe accepts text made of these
/// lines, one certificate per line.
const FAKE_CERT: &str = "-----BEGIN CERTIFICATE----- fake";

impl StackProbe for FakeProbe {
    fn check<'a>(
        &'a self,
        api_url: &'a ProjectUrl,
        service: StackService,
        key: &'a SecretString,
        authorities: Option<&'a ProjectAuthorities>,
    ) -> ProbeFuture<'a> {
        self.calls
            .lock()
            .unwrap()
            .push((service, key.expose_secret().to_owned()));
        self.bundles
            .lock()
            .unwrap()
            .push(authorities.map(|a| a.as_str().to_owned()));
        let down = self
            .down
            .lock()
            .unwrap()
            .iter()
            .any(|url| url == api_url.as_str());
        let status = match service {
            _ if down => Some(ServiceStatus::Unreachable {
                reason: UnreachableReason::Connect,
            }),
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
                certificate_expires_at: None,
            }
        })
    }

    fn read_authorities(&self, pem: &str) -> Result<Vec<AuthorityInfo>, AuthorityError> {
        if pem.lines().any(|line| line != FAKE_CERT) {
            return Err(AuthorityError::NotACertificate);
        }
        Ok(pem
            .lines()
            .map(|_| AuthorityInfo {
                subject: "CN=Test CA".into(),
                not_after: OffsetDateTime::UNIX_EPOCH + time::Duration::days(30_000),
                sha256: "AB:CD".into(),
            })
            .collect())
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
        // The Studio login gives full control of the project, so the same
        // roles are refused before the gateway is asked about it.
        let studio = SecretString::from(check_studio_login("supabase", STUDIO_PASSWORD).unwrap());
        assert!(matches!(
            f.connections
                .replace_credential(who, id, CredentialKind::StudioLogin, &studio, ctx())
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
        4
    );
    assert!(f.probe.calls.lock().unwrap().is_empty());

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

/// Removing a key needs `Permission::ProjectCredentialsReplace`: owners and
/// admins only. Refusals are audited and leave the key stored.
#[tokio::test]
async fn removing_keys_follows_the_role_matrix() {
    let Some(scratch) = ScratchDb::create("conn_remove_matrix").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    project(&f, &outsider, "Globex").await;
    let anon = SecretString::from(ANON);

    let cases = [
        (&owner, Some(OrgRole::Owner), true),
        (&admin, Some(OrgRole::Admin), true),
        (&developer, Some(OrgRole::Developer), false),
        (&viewer, Some(OrgRole::Viewer), false),
        (&outsider, None, false),
    ];
    for (actor, role, allowed) in cases {
        let who = actor.account.display_name.as_str();
        if let Some(role) = role {
            assert_eq!(
                role.allows(Permission::ProjectCredentialsReplace),
                allowed,
                "{who}"
            );
        }
        f.connections
            .replace_credential(&owner, id, CredentialKind::AnonKey, &anon, ctx())
            .await
            .unwrap();
        let result = f
            .connections
            .remove_credential(actor, id, CredentialKind::AnonKey, ctx())
            .await;
        let overview = f.connections.credentials(&owner, id).await.unwrap();
        let stored = state(&overview, CredentialKind::AnonKey);
        match role {
            Some(_) if allowed => {
                assert!(result.is_ok(), "{who}: {result:?}");
                assert_eq!(stored, &CredentialState::NotSet, "{who}");
            }
            Some(_) => {
                assert!(
                    matches!(result, Err(ConnectionError::Forbidden)),
                    "{who}: {result:?}"
                );
                assert!(matches!(stored, CredentialState::Set { .. }), "{who}");
                assert_eq!(
                    denied_by(&f.db, "project.credential.remove", actor).await,
                    1,
                    "{who}"
                );
            }
            None => {
                assert!(
                    matches!(result, Err(ConnectionError::NotFound)),
                    "{who}: {result:?}"
                );
                assert!(matches!(stored, CredentialState::Set { .. }), "{who}");
            }
        }
    }
    assert_eq!(
        audit_count(&f.db, "project.credential.remove", "success").await,
        2
    );
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
            (StackService::Functions, ANON.to_owned()),
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
async fn rotating_the_key_reseals_stored_values() {
    let Some(scratch) = ScratchDb::create("conn_reseal").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    for (kind, value) in [
        (CredentialKind::AnonKey, ANON),
        (CredentialKind::ServiceRoleKey, SERVICE),
    ] {
        f.connections
            .replace_credential(&owner, id, kind, &SecretString::from(value), ctx())
            .await
            .unwrap();
    }
    let before: (OffsetDateTime, Uuid) = sqlx::query_as(
        "SELECT updated_at, updated_by FROM project_credentials WHERE project_id = $1 AND kind = 'anon_key'",
    )
    .bind(id)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    // A value under a key nobody has any more, on another project.
    let (_, lost) = project(&f, &owner, "Beta").await;
    sqlx::query(
        "INSERT INTO project_credentials (project_id, kind, key_id, nonce, ciphertext) \
         VALUES ($1, 'anon_key', 'ffffffffffffffff', $2, $3)",
    )
    .bind(lost)
    .bind(vec![0u8; 12])
    .bind(vec![1u8; 32])
    .execute(f.db.pool())
    .await
    .unwrap();

    // The new key is current and the old one is kept for reading.
    let mut rotated = cipher(KEY_B);
    assert_eq!(
        rotated
            .add_previous_keys(&SecretString::from(KEY_A))
            .unwrap(),
        1
    );
    let probe = Arc::new(FakeProbe::default());
    let during = ConnectionService::new(f.db.clone(), Some(rotated.clone()), probe.clone());
    let overview = during.credentials(&owner, id).await.unwrap();
    assert!(matches!(
        state(&overview, CredentialKind::AnonKey),
        CredentialState::Set { .. }
    ));
    assert_eq!(
        key_usage(&f.db, &rotated).await.unwrap(),
        KeyUsage {
            current: 0,
            previous: 2,
            unknown: 1
        }
    );

    assert_eq!(
        reseal_credentials(&f.db, &rotated).await.unwrap(),
        RotationSummary {
            resealed: 2,
            unreadable: 1,
            changed_meanwhile: 0
        }
    );
    assert_eq!(
        key_usage(&f.db, &rotated).await.unwrap(),
        KeyUsage {
            current: 2,
            previous: 0,
            unknown: 1
        }
    );
    // Who set the key and when are unchanged.
    let after: (OffsetDateTime, Uuid) = sqlx::query_as(
        "SELECT updated_at, updated_by FROM project_credentials WHERE project_id = $1 AND kind = 'anon_key'",
    )
    .bind(id)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(after, before);

    // The new key alone now opens both values.
    let probe = Arc::new(FakeProbe::default());
    let new_only = ConnectionService::new(f.db.clone(), Some(cipher(KEY_B)), probe.clone());
    new_only.check_now(&owner, id).await.unwrap();
    let used: Vec<String> = probe
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|(_, key)| key.clone())
        .collect();
    assert!(used.iter().any(|k| k == ANON));
    assert!(used.iter().any(|k| k == SERVICE));

    // A second run has nothing left to move and leaves the lost value.
    assert_eq!(
        reseal_credentials(&f.db, &rotated).await.unwrap(),
        RotationSummary {
            resealed: 0,
            unreadable: 1,
            changed_meanwhile: 0
        }
    );
    assert_eq!(audit_count(&f.db, "credentials.reseal", "success").await, 2);

    // A row replaced since it was read is not overwritten.
    assert!(
        !f.db
            .reseal_credential(
                id,
                CredentialKind::AnonKey,
                b"stale nonce!",
                rotated.key_id(),
                &[0u8; 12],
                &[0u8; 16],
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn rotating_the_key_reseals_unfinished_jobs_secrets() {
    let Some(scratch) = ScratchDb::create("conn_reseal_jobs").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (org, _) = project(&f, &owner, "Acme").await;
    let job = Uuid::now_v7();
    let secret = SecretString::from("synthetic job secret");
    let sealed = cipher(KEY_A).seal_job_secrets(job, &secret).unwrap();
    f.db.insert_job(
        &NewJob {
            id: job,
            kind: JobKind::ProvisionStack.as_str(),
            organization_id: org,
            step: "check",
            data: "{}",
            secrets: Some(&SealedJobSecrets {
                key_id: sealed.key_id,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
            }),
            created_by: owner.account.id,
        },
        &AuditEvent {
            actor_account_id: Some(owner.account.id),
            action: "job.test",
            target_type: Some("job"),
            target_id: Some(job.to_string()),
            outcome: AuditOutcome::Success,
            request_id: None,
        },
    )
    .await
    .unwrap();

    let mut rotated = cipher(KEY_B);
    rotated
        .add_previous_keys(&SecretString::from(KEY_A))
        .unwrap();
    assert_eq!(key_usage(&f.db, &rotated).await.unwrap().previous, 1);
    assert_eq!(
        reseal_credentials(&f.db, &rotated).await.unwrap(),
        RotationSummary {
            resealed: 1,
            unreadable: 0,
            changed_meanwhile: 0
        }
    );
    assert_eq!(key_usage(&f.db, &rotated).await.unwrap().current, 1);

    // The new key alone opens them, still bound to their job.
    let stored = f.db.job_secrets(job).await.unwrap().unwrap();
    let stored = Sealed {
        key_id: stored.key_id,
        nonce: stored.nonce,
        ciphertext: stored.ciphertext,
    };
    let new_only = cipher(KEY_B);
    assert_eq!(
        new_only
            .open_job_secrets(job, &stored)
            .unwrap()
            .expose_secret(),
        "synthetic job secret"
    );
    assert!(new_only.open_job_secrets(Uuid::now_v7(), &stored).is_err());
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

    // Only the anon key is stored: Auth, Storage, Realtime, and Edge
    // Functions are checked with it, REST falls back to it, and Studio has
    // no login.
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

#[tokio::test]
async fn health_history_is_kept_for_members_within_its_limits() {
    let Some(scratch) = ScratchDb::create("conn_history").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    let (_, other_id) = project(&f, &outsider, "Globex").await;

    let empty = f.connections.health_history(&viewer, id).await.unwrap();
    assert_eq!((empty.total, empty.recent.len(), empty.since), (0, 0, None));

    // No key or login yet: every service is skipped, and nothing failed.
    f.connections.check_now(&owner, id).await.unwrap();
    f.connections.check_now(&outsider, other_id).await.unwrap();
    let one = f.connections.health_history(&viewer, id).await.unwrap();
    assert_eq!((one.total, one.with_failures), (1, 0), "{one:?}");
    assert!(one.recent[0].failing.is_empty());
    assert!(one.recent[0].not_checked.contains(&StackService::Auth));

    // An entry past the retention period is hidden at once, and more
    // entries than the cap are trimmed when the next check is saved.
    sqlx::query(
        "INSERT INTO project_health_history (project_id, checked_at, failing, checks) \
         SELECT $1, now() - make_interval(mins => g), g % 2 = 0, '[]'::jsonb \
         FROM generate_series(1, $2) g \
         UNION ALL SELECT $1, now() - interval '8 days', true, '[]'::jsonb",
    )
    .bind(id)
    .bind(i32::from(HEALTH_HISTORY_MAX_ENTRIES) + 5)
    .execute(f.db.pool())
    .await
    .unwrap();
    let before = f.connections.health_history(&owner, id).await.unwrap();
    assert_eq!(before.total, u32::from(HEALTH_HISTORY_MAX_ENTRIES) + 6);
    assert_eq!(before.recent.len(), usize::from(HEALTH_HISTORY_PAGE));
    // The hourly counts cover the same kept entries, oldest hour first,
    // each starting on the hour and none after the read.
    let sum = |pick: fn(&HealthHour) -> u32| before.hours.iter().map(pick).sum::<u32>();
    assert_eq!(sum(|h| h.checks), before.total);
    assert_eq!(sum(|h| h.failing), before.with_failures);
    assert!(before.hours.windows(2).all(|w| w[0].hour < w[1].hour));
    assert!(
        before
            .hours
            .iter()
            .all(|h| { h.hour.minute() == 0 && h.hour.second() == 0 && h.hour.nanosecond() == 0 })
    );
    assert!(before.hours.iter().all(|h| h.hour <= before.read_at));
    assert!(
        before.hours.len() >= 17 && before.hours.len() <= 19,
        "{}",
        before.hours.len()
    );

    sqlx::query("UPDATE project_health_reports SET checked_at = now() - interval '1 hour'")
        .execute(f.db.pool())
        .await
        .unwrap();
    let latest = f.connections.check_now(&owner, id).await.unwrap();
    let kept: i64 =
        sqlx::query_scalar("SELECT count(*) FROM project_health_history WHERE project_id = $1")
            .bind(id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(kept, i64::from(HEALTH_HISTORY_MAX_ENTRIES));
    let after = f.connections.health_history(&owner, id).await.unwrap();
    assert_eq!(after.total, u32::from(HEALTH_HISTORY_MAX_ENTRIES));
    let newest = after.recent[0].checked_at;
    assert!((newest - latest.checked_at).abs() < time::Duration::milliseconds(1));
    assert!(
        after
            .recent
            .windows(2)
            .all(|w| w[0].checked_at > w[1].checked_at)
    );

    // The other organization's history is untouched and out of reach.
    let other: i64 =
        sqlx::query_scalar("SELECT count(*) FROM project_health_history WHERE project_id = $1")
            .bind(other_id)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(other, 1);
    assert!(matches!(
        f.connections.health_history(&outsider, id).await,
        Err(ConnectionError::NotFound)
    ));
}

#[tokio::test]
async fn an_outage_shows_and_clears_without_touching_other_projects() {
    let Some(scratch) = ScratchDb::create("conn_outage").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (org, broken) = project(&f, &owner, "Acme").await;
    let steady = f
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
    for id in [broken, steady] {
        for (kind, value) in [
            (CredentialKind::AnonKey, ANON),
            (CredentialKind::ServiceRoleKey, SERVICE),
        ] {
            f.connections
                .replace_credential(&owner, id, kind, &SecretString::from(value), ctx())
                .await
                .unwrap();
        }
    }
    let age_reports = || async {
        sqlx::query("UPDATE project_health_reports SET checked_at = now() - interval '1 minute'")
            .execute(f.db.pool())
            .await
            .unwrap();
    };

    // One stack goes down: its services are unreachable, and the other
    // project's check is unaffected.
    let broken_url = f
        .projects
        .get(&owner, broken)
        .await
        .unwrap()
        .api_url
        .as_str()
        .to_owned();
    f.probe.down.lock().unwrap().push(broken_url);
    let outage = f.connections.check_now(&owner, broken).await.unwrap();
    assert!(outage.failing().contains(&StackService::Auth), "{outage:?}");
    assert!(outage.failing().contains(&StackService::Rest));
    let steady_report = f.connections.check_now(&owner, steady).await.unwrap();
    assert!(steady_report.failing().is_empty(), "{steady_report:?}");

    // It comes back: the next check is healthy again, the history keeps
    // the failed check, and the other project's last report is unchanged.
    f.probe.down.lock().unwrap().clear();
    age_reports().await;
    let recovered = f.connections.check_now(&owner, broken).await.unwrap();
    assert!(recovered.failing().is_empty(), "{recovered:?}");
    assert_eq!(
        f.connections.last_report(&owner, broken).await.unwrap(),
        Some(recovered)
    );
    let history = f.connections.health_history(&owner, broken).await.unwrap();
    assert_eq!((history.total, history.with_failures), (2, 1));
    assert!(history.recent[0].failing.is_empty());
    assert!(history.recent[1].failing.contains(&StackService::Auth));
    let steady_history = f.connections.health_history(&owner, steady).await.unwrap();
    assert_eq!((steady_history.total, steady_history.with_failures), (1, 0));
    let steady_last = f
        .connections
        .last_report(&owner, steady)
        .await
        .unwrap()
        .unwrap();
    assert!(steady_last.failing().is_empty());
    assert_eq!(steady_last.checks, steady_report.checks);
}

#[tokio::test]
async fn scheduled_checks_take_the_oldest_due_projects_first() {
    let Some(scratch) = ScratchDb::create("conn_scheduled").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let service = Arc::new(ConnectionService::new(
        f.db.clone(),
        Some(cipher(KEY_A)),
        f.probe.clone(),
    ));
    let owner = account(&f.db, "Owner").await;
    let (org, recent) = project(&f, &owner, "Acme").await;
    let register = async |name: &str| {
        f.projects
            .register(
                &owner,
                org,
                Registration {
                    name,
                    api_url: "https://other.example.test",
                    allow_unencrypted: false,
                },
                ctx(),
            )
            .await
            .unwrap()
            .id
    };
    let old = register("Old").await;
    let never = register("Never").await;
    for id in [recent, old] {
        f.connections.check_now(&owner, id).await.unwrap();
    }
    sqlx::query(
        "UPDATE project_health_reports SET checked_at = now() - interval '2 hours' \
         WHERE project_id = $1",
    )
    .bind(old)
    .execute(f.db.pool())
    .await
    .unwrap();
    let checked_at = |id: Uuid| {
        let db = f.db.clone();
        async move {
            sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
                "SELECT max(checked_at) FROM project_health_reports WHERE project_id = $1",
            )
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap()
        }
    };
    let recent_before = checked_at(recent).await;
    let hour = ScheduledChecks {
        older_than: std::time::Duration::from_secs(3600),
        batch: 1,
        concurrency: 2,
        lease: std::time::Duration::from_secs(600),
    };

    // A batch of one takes the project never checked.
    let run = service.check_due(hour).await.unwrap();
    assert_eq!(
        run,
        ScheduledRun {
            checked: 1,
            skipped: 0,
            failed: 0
        }
    );
    assert!(checked_at(never).await.is_some());

    // Then the one checked two hours ago; the recent one is left alone.
    let run = service
        .check_due(ScheduledChecks { batch: 10, ..hour })
        .await
        .unwrap();
    assert_eq!(run.checked, 1);
    let old_after = checked_at(old).await.unwrap();
    assert!(old_after > time::OffsetDateTime::now_utc() - time::Duration::minutes(1));
    assert_eq!(checked_at(recent).await, recent_before);

    // Nothing is due now.
    assert_eq!(
        service
            .check_due(ScheduledChecks { batch: 10, ..hour })
            .await
            .unwrap(),
        ScheduledRun::default()
    );
}

#[tokio::test]
async fn processes_sharing_the_database_split_scheduled_checks() {
    let Some(scratch) = ScratchDb::create("conn_claims").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    // Two services on one database stand for two server processes.
    let first = Arc::new(ConnectionService::new(
        f.db.clone(),
        Some(cipher(KEY_A)),
        f.probe.clone(),
    ));
    let second = Arc::new(ConnectionService::new(
        f.db.clone(),
        Some(cipher(KEY_A)),
        f.probe.clone(),
    ));
    let owner = account(&f.db, "Owner").await;
    let (org, _) = project(&f, &owner, "Acme").await;
    for n in 0..9 {
        f.projects
            .register(
                &owner,
                org,
                Registration {
                    name: &format!("Stack {n}"),
                    api_url: "https://other.example.test",
                    allow_unencrypted: false,
                },
                ctx(),
            )
            .await
            .unwrap();
    }
    let schedule = ScheduledChecks {
        older_than: std::time::Duration::from_secs(3600),
        batch: 10,
        concurrency: 3,
        lease: std::time::Duration::from_secs(600),
    };

    let (a, b) = tokio::join!(first.check_due(schedule), second.check_due(schedule));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.checked + b.checked, 10);
    assert_eq!(a.skipped + b.skipped + a.failed + b.failed, 0);
    let saved: Vec<i64> = sqlx::query_scalar(
        "SELECT count(h.checked_at) FROM projects p \
         LEFT JOIN project_health_history h ON h.project_id = p.id \
         GROUP BY p.id",
    )
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    assert_eq!(saved, vec![1; 10], "each project is checked exactly once");

    // A claim still running holds the project even once it is due again.
    sqlx::query("UPDATE project_health_reports SET checked_at = now() - interval '2 hours'")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        first.check_due(schedule).await.unwrap(),
        ScheduledRun::default()
    );

    // A lapsed claim does not: a process that stopped halfway through
    // leaves its projects to the next pass.
    sqlx::query("UPDATE project_check_claims SET claimed_until = now() - interval '1 second'")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(second.check_due(schedule).await.unwrap().checked, 10);
}

/// A JWT-shaped key with the given claims. The signature is not checked by
/// the dashboard, so any value works.
fn jwt(claims: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    format!(
        "{}.{}.not-a-real-signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims)
    )
}

#[tokio::test]
async fn jwt_keys_are_checked_for_role_and_expiry() {
    let Some(scratch) = ScratchDb::create("conn_jwt").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let (_, id) = project(&f, &owner, "Acme").await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let save = async |kind, value: String| {
        f.connections
            .replace_credential(&owner, id, kind, &SecretString::from(value), ctx())
            .await
    };

    // A key for the other role, or one already expired, is not stored.
    assert!(matches!(
        save(
            CredentialKind::AnonKey,
            jwt(&format!(
                r#"{{"role":"service_role","exp":{}}}"#,
                now + 86_400
            ))
        )
        .await,
        Err(ConnectionError::Input(ApiKeyError::SecretInAnonSlot))
    ));
    assert!(matches!(
        save(
            CredentialKind::ServiceRoleKey,
            jwt(&format!(r#"{{"role":"anon","exp":{}}}"#, now + 86_400))
        )
        .await,
        Err(ConnectionError::Input(ApiKeyError::PublishableInSecretSlot))
    ));
    assert!(matches!(
        save(
            CredentialKind::AnonKey,
            jwt(&format!(r#"{{"role":"anon","exp":{}}}"#, now - 60))
        )
        .await,
        Err(ConnectionError::Input(ApiKeyError::Expired))
    ));
    let overview = f.connections.credentials(&owner, id).await.unwrap();
    assert!(
        overview
            .credentials
            .iter()
            .all(|c| c.state == CredentialState::NotSet)
    );

    // Stored keys show their expiry; keys that are not JWTs have none.
    let anon_exp = now + 10 * 86_400 + 3600;
    save(
        CredentialKind::AnonKey,
        jwt(&format!(r#"{{"role":"anon","exp":{anon_exp}}}"#)),
    )
    .await
    .unwrap();
    save(CredentialKind::ServiceRoleKey, SERVICE.to_owned())
        .await
        .unwrap();
    let overview = f.connections.credentials(&owner, id).await.unwrap();
    let expires = |kind| {
        overview
            .credentials
            .iter()
            .find(|c| c.kind == kind)
            .and_then(|c| match c.state {
                CredentialState::Set { expires, .. } => expires,
                _ => None,
            })
    };
    let anon = expires(CredentialKind::AnonKey).unwrap();
    assert_eq!(anon.at.unix_timestamp(), anon_exp);
    assert!(!anon.expired && anon.expires_soon());
    // Ten days and an hour ahead: ten or eleven calendar days, depending
    // on whether the hour crosses midnight UTC.
    assert!((10..=11).contains(&anon.days_left), "{}", anon.days_left);
    assert_eq!(expires(CredentialKind::ServiceRoleKey), None);

    // A key that expires after it was stored shows as expired.
    let short = jwt(&format!(r#"{{"role":"anon","exp":{}}}"#, now + 2));
    save(CredentialKind::AnonKey, short).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let overview = f.connections.credentials(&owner, id).await.unwrap();
    let anon = overview
        .credentials
        .iter()
        .find(|c| c.kind == CredentialKind::AnonKey)
        .unwrap();
    assert!(matches!(
        anon.state,
        CredentialState::Set {
            expires: Some(expiry),
            ..
        } if expiry.expired && expiry.days_left == 0
    ));
}

#[tokio::test]
async fn project_authorities_are_kept_per_project_and_used_by_its_checks() {
    let Some(scratch) = ScratchDb::create("conn_authorities").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let owner = account(&f.db, "Owner").await;
    let admin = account(&f.db, "Admin").await;
    let developer = account(&f.db, "Developer").await;
    let viewer = account(&f.db, "Viewer").await;
    let outsider = account(&f.db, "Outsider").await;
    let (org, id) = project(&f, &owner, "Acme").await;
    let (_, other) = project(&f, &owner, "Other").await;
    add_member(&f.db, org, &admin, OrgRole::Admin).await;
    add_member(&f.db, org, &developer, OrgRole::Developer).await;
    add_member(&f.db, org, &viewer, OrgRole::Viewer).await;
    let bundle = format!("{FAKE_CERT}\n{FAKE_CERT}");

    // Nothing stored yet; any member may read that.
    assert_eq!(f.connections.authorities(&viewer, id).await.unwrap(), None);
    assert!(matches!(
        f.connections.authorities(&outsider, id).await,
        Err(ConnectionError::NotFound)
    ));

    // Developers and viewers cannot change it, and the refusal is audited.
    for who in [&developer, &viewer] {
        assert!(matches!(
            f.connections
                .replace_authorities(who, id, &bundle, ctx())
                .await,
            Err(ConnectionError::Forbidden)
        ));
        assert_eq!(
            denied_by(&f.db, "project.authorities.replace", who).await,
            1
        );
    }

    // Refused input is not stored.
    for (input, err) in [
        ("   ", AuthorityError::Empty),
        (
            "-----BEGIN PRIVATE KEY-----",
            AuthorityError::NotACertificate,
        ),
    ] {
        assert!(matches!(
            f.connections.replace_authorities(&admin, id, input, ctx()).await,
            Err(ConnectionError::Authority(e)) if e == err
        ));
    }
    assert_eq!(f.connections.authorities(&owner, id).await.unwrap(), None);

    // Stored trimmed, summarized, and readable by every member.
    let saved = f
        .connections
        .replace_authorities(&admin, id, &format!("\n{bundle}\n\n"), ctx())
        .await
        .unwrap();
    assert_eq!(saved.authorities.len(), 2);
    let read = f
        .connections
        .authorities(&viewer, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.authorities, saved.authorities);
    assert_eq!(read.updated_at, saved.updated_at);
    assert_eq!(
        audit_count(&f.db, "project.authorities.replace", "success").await,
        1
    );

    // Checks of this project trust the bundle; checks of the other one do not.
    for kind in [CredentialKind::AnonKey, CredentialKind::ServiceRoleKey] {
        let value = if kind == CredentialKind::AnonKey {
            ANON
        } else {
            SERVICE
        };
        for project in [id, other] {
            f.connections
                .replace_credential(&owner, project, kind, &SecretString::from(value), ctx())
                .await
                .unwrap();
        }
    }
    f.connections.check_now(&viewer, id).await.unwrap();
    let bundles: Vec<_> = f.probe.bundles.lock().unwrap().drain(..).collect();
    assert_eq!(bundles.len(), 5, "every service with a key is checked");
    assert!(
        bundles
            .iter()
            .all(|b| b.as_deref() == Some(bundle.as_str()))
    );
    f.connections.check_now(&owner, other).await.unwrap();
    assert!(
        f.probe
            .bundles
            .lock()
            .unwrap()
            .drain(..)
            .all(|b| b.is_none())
    );

    // Saving a Studio login tries it with the project's bundle too.
    let login = SecretString::from(check_studio_login("supabase", STUDIO_PASSWORD).unwrap());
    f.connections
        .replace_credential(&owner, id, CredentialKind::StudioLogin, &login, ctx())
        .await
        .unwrap();
    assert_eq!(
        f.probe
            .bundles
            .lock()
            .unwrap()
            .drain(..)
            .collect::<Vec<_>>(),
        vec![Some(bundle.clone())]
    );

    // Removing it: developers cannot; owners can, once.
    assert!(matches!(
        f.connections
            .remove_authorities(&developer, id, ctx())
            .await,
        Err(ConnectionError::Forbidden)
    ));
    f.connections
        .remove_authorities(&owner, id, ctx())
        .await
        .unwrap();
    assert!(matches!(
        f.connections.remove_authorities(&owner, id, ctx()).await,
        Err(ConnectionError::NoAuthorities)
    ));
    assert_eq!(f.connections.authorities(&owner, id).await.unwrap(), None);
    assert_eq!(
        audit_count(&f.db, "project.authorities.remove", "success").await,
        1
    );

    // A stored bundle the adapter can no longer read lists nothing, and
    // unregistering the project deletes it.
    sqlx::query("INSERT INTO project_authorities (project_id, pem) VALUES ($1, 'garbage')")
        .bind(id)
        .execute(f.db.pool())
        .await
        .unwrap();
    let unreadable = f
        .connections
        .authorities(&owner, id)
        .await
        .unwrap()
        .unwrap();
    assert!(unreadable.authorities.is_empty());
    f.projects
        .unregister(&owner, id, "Production", ctx())
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM project_authorities")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
}
