//! The installation's Dokploy connection against a scratch metadata
//! database, with a fake connector in place of Dokploy. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use secrecy::{ExposeSecret, SecretString};
use supabase_dashboard_application::{
    auth::{CurrentSession, RequestContext},
    dokploy::{ConnectFuture, DokployConnector, DokployService, DokployServiceError},
    key_rotation::{KeyUsage, RotationSummary, key_usage, reseal_credentials},
    secrets::CredentialCipher,
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    connection::UnreachableReason,
    dokploy::{DokployError, DokployKeyError, DokployUrl, DokployVersion, TESTED_DOKPLOY_VERSION},
};
use supabase_dashboard_persistence::{Database, accounts::AccountRecord};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";
const KEY_A: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const KEY_B: &str = "HxwdHhscGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=";
const URL: &str = "https://dokploy.example.test";
const HOST: &str = "dokploy.example.test";
const DOKPLOY_KEY: &str = "dokploy-key-marker-first";
const NEW_KEY: &str = "dokploy-key-marker-second";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-dokploy"),
        user_agent: None,
    }
}

fn cipher(key: &str) -> CredentialCipher {
    CredentialCipher::from_base64(&SecretString::from(key)).unwrap()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

/// Records each call and answers with `answer`, or the tested version.
#[derive(Default)]
struct FakeDokploy {
    calls: Mutex<Vec<(String, String)>>,
    answer: Mutex<Option<DokployError>>,
}

impl FakeDokploy {
    fn fail_with(&self, err: Option<DokployError>) {
        *self.answer.lock().unwrap() = err;
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl DokployConnector for FakeDokploy {
    fn connect<'a>(&'a self, url: &'a DokployUrl, key: &'a SecretString) -> ConnectFuture<'a> {
        self.calls
            .lock()
            .unwrap()
            .push((url.as_str().to_owned(), key.expose_secret().to_owned()));
        let answer = self.answer.lock().unwrap().clone();
        Box::pin(async move {
            match answer {
                Some(err) => Err(err),
                None => Ok(TESTED_DOKPLOY_VERSION),
            }
        })
    }
}

struct Fixture {
    db: Database,
    fake: Arc<FakeDokploy>,
    service: DokployService,
}

async fn setup(scratch: &ScratchDb, key: Option<&str>) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let fake = Arc::new(FakeDokploy::default());
    Fixture {
        service: DokployService::new(db.clone(), key.map(cipher), fake.clone()),
        fake,
        db,
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

/// Every column of every audit event, as text, to look for leaked keys.
async fn all_audit_text(db: &Database) -> String {
    let rows: Vec<String> = sqlx::query_scalar("SELECT row_to_json(a)::text FROM audit_events a")
        .fetch_all(db.pool())
        .await
        .unwrap();
    rows.join("\n")
}

async fn stored_rows(db: &Database) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM dokploy_connection")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn only_installation_admins_see_or_change_the_connection() {
    let Some(scratch) = ScratchDb::create("dokploy_authz").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    let bob = account(&f.db, "Bob", false).await;

    // Bob is refused everything, before the input is read or Dokploy is
    // called, and each refusal is audited without a target.
    assert!(matches!(
        f.service.overview(&bob, ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .connect(&bob, URL, &secret(DOKPLOY_KEY), ctx())
            .await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service.replace_key(&bob, &secret(NEW_KEY), ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service.remove(&bob, ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(f.fake.calls().is_empty());
    for action in [
        "dokploy.view",
        "dokploy.connect",
        "dokploy.key_replace",
        "dokploy.disconnect",
    ] {
        assert_eq!(
            audits(&f.db, action, "denied").await,
            [(Some(bob.account.id), Some("dokploy".to_owned()), None)],
            "{action}"
        );
    }

    // Once the admin has connected, Bob still cannot see, replace, or
    // remove it.
    f.service
        .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    assert!(matches!(
        f.service.overview(&bob, ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service.replace_key(&bob, &secret(NEW_KEY), ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert!(matches!(
        f.service.remove(&bob, ctx()).await,
        Err(DokployServiceError::Forbidden)
    ));
    assert_eq!(stored_rows(&f.db).await, 1);
    assert_eq!(f.fake.calls().len(), 1);

    // A stale session that still says admin after the flag was revoked
    // is the session layer's concern; this service trusts the flag the
    // session carries, which the server reads from the database on every
    // request.
    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn a_key_is_stored_encrypted_only_after_dokploy_accepts_it() {
    let Some(scratch) = ScratchDb::create("dokploy_connect").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;

    let overview = f.service.overview(&admin, ctx()).await.unwrap();
    assert!(overview.storage_available);
    assert_eq!(overview.connection, None);

    // Dokploy refuses the key: nothing is stored, the attempt is audited
    // with the host only, and the error is Dokploy's own message.
    f.fake.fail_with(Some(DokployError::KeyRejected));
    let err = f
        .service
        .connect(&admin, &format!(" {URL}/ "), &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DokployServiceError::Dokploy(DokployError::KeyRejected)
    ));
    assert_eq!(stored_rows(&f.db).await, 0);
    assert_eq!(
        audits(&f.db, "dokploy.connect", "failure").await,
        [(
            Some(admin.account.id),
            Some("dokploy".to_owned()),
            Some(HOST.to_owned())
        )]
    );
    // An unsupported release or an unreachable Dokploy stores nothing
    // either.
    for refusal in [
        DokployError::UnsupportedVersion {
            found: DokployVersion::parse("v0.32.0").unwrap(),
        },
        DokployError::Unreachable(UnreachableReason::DestinationNotAllowed),
    ] {
        f.fake.fail_with(Some(refusal.clone()));
        let err = f
            .service
            .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, DokployServiceError::Dokploy(e) if *e == refusal),
            "{err:?}"
        );
    }
    assert_eq!(stored_rows(&f.db).await, 0);
    assert_eq!(audits(&f.db, "dokploy.connect", "failure").await.len(), 3);

    // Accepted: stored with the version and who connected it. The key is
    // trimmed and sent to the parsed URL.
    f.fake.fail_with(None);
    let overview = f
        .service
        .connect(&admin, URL, &secret(&format!(" {DOKPLOY_KEY}\n")), ctx())
        .await
        .unwrap();
    assert_eq!(
        f.fake.calls().last().unwrap(),
        &(URL.to_owned(), DOKPLOY_KEY.to_owned())
    );
    let connection = overview.connection.clone().unwrap();
    assert_eq!(connection.url.as_str(), URL);
    assert_eq!(connection.version, TESTED_DOKPLOY_VERSION);
    assert_eq!(connection.connected.by.unwrap().as_str(), "Admin");
    assert_eq!(connection.key_replaced, None);
    assert!(connection.key_readable);
    assert_eq!(f.service.overview(&admin, ctx()).await.unwrap(), overview);
    assert_eq!(
        audits(&f.db, "dokploy.connect", "success").await,
        [(
            Some(admin.account.id),
            Some("dokploy".to_owned()),
            Some(HOST.to_owned())
        )]
    );

    // The key is nowhere in what the page gets, in the audit log, or in
    // the stored row; the server can still read it.
    let shown = format!("{overview:?}");
    assert!(!shown.contains("marker"), "{shown}");
    assert!(!all_audit_text(&f.db).await.contains("marker"));
    let (ciphertext, version): (Vec<u8>, String) =
        sqlx::query_as("SELECT ciphertext, version FROM dokploy_connection")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&ciphertext).contains("marker"));
    assert_eq!(version, "v0.31.1");
    let credentials = f.service.credentials().await.unwrap().unwrap();
    assert_eq!(credentials.url.as_str(), URL);
    assert_eq!(credentials.key.expose_secret(), DOKPLOY_KEY);
    assert!(!format!("{credentials:?}").contains("marker"));

    // One connection per installation: a second one is refused before
    // Dokploy is called.
    let calls = f.fake.calls().len();
    assert!(matches!(
        f.service
            .connect(
                &admin,
                "https://other.example.test",
                &secret(NEW_KEY),
                ctx()
            )
            .await,
        Err(DokployServiceError::AlreadyConnected)
    ));
    assert_eq!(f.fake.calls().len(), calls);
    assert_eq!(stored_rows(&f.db).await, 1);

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn malformed_input_is_refused_before_dokploy_is_called() {
    let Some(scratch) = ScratchDb::create("dokploy_input").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    for url in [
        "dokploy.example.test",
        "ftp://dokploy.example.test",
        "https://user:pw@dokploy.example.test",
        "https://dokploy.example.test/?key=1",
    ] {
        assert!(
            matches!(
                f.service
                    .connect(&admin, url, &secret(DOKPLOY_KEY), ctx())
                    .await,
                Err(DokployServiceError::Url(_))
            ),
            "{url}"
        );
    }
    for (key, expected) in [
        ("  ", DokployKeyError::Empty),
        ("two words", DokployKeyError::InvalidCharacters),
    ] {
        assert!(matches!(
            f.service.connect(&admin, URL, &secret(key), ctx()).await,
            Err(DokployServiceError::Key(e)) if e == expected
        ));
    }
    assert!(matches!(
        f.service.replace_key(&admin, &secret(NEW_KEY), ctx()).await,
        Err(DokployServiceError::NotConnected)
    ));
    assert!(matches!(
        f.service.remove(&admin, ctx()).await,
        Err(DokployServiceError::NotConnected)
    ));
    assert!(f.fake.calls().is_empty());
    assert_eq!(stored_rows(&f.db).await, 0);

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn replacing_the_key_checks_the_new_one_first() {
    let Some(scratch) = ScratchDb::create("dokploy_replace").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    let carol = account(&f.db, "Carol", true).await;
    f.service
        .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap();

    // Refused by Dokploy: the old key stays and the attempt is audited.
    f.fake.fail_with(Some(DokployError::KeyRejected));
    assert!(matches!(
        f.service.replace_key(&carol, &secret(NEW_KEY), ctx()).await,
        Err(DokployServiceError::Dokploy(DokployError::KeyRejected))
    ));
    assert_eq!(
        f.fake.calls().last().unwrap(),
        &(URL.to_owned(), NEW_KEY.to_owned())
    );
    let kept = f.service.credentials().await.unwrap().unwrap();
    assert_eq!(kept.key.expose_secret(), DOKPLOY_KEY);
    assert_eq!(
        audits(&f.db, "dokploy.key_replace", "failure").await,
        [(
            Some(carol.account.id),
            Some("dokploy".to_owned()),
            Some(HOST.to_owned())
        )]
    );

    // Accepted: the new key is stored against the same URL, and the page
    // says who replaced it while keeping who connected.
    f.fake.fail_with(None);
    let overview = f
        .service
        .replace_key(&carol, &secret(NEW_KEY), ctx())
        .await
        .unwrap();
    let connection = overview.connection.unwrap();
    assert_eq!(connection.connected.by.unwrap().as_str(), "Admin");
    let replaced = connection.key_replaced.unwrap();
    assert_eq!(replaced.by.unwrap().as_str(), "Carol");
    assert!(connection.verified_at >= connection.connected.at);
    let stored = f.service.credentials().await.unwrap().unwrap();
    assert_eq!(stored.key.expose_secret(), NEW_KEY);
    assert_eq!(
        audits(&f.db, "dokploy.key_replace", "success").await.len(),
        1
    );
    assert!(!all_audit_text(&f.db).await.contains("marker"));

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn removing_deletes_only_the_dashboard_record() {
    let Some(scratch) = ScratchDb::create("dokploy_remove").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    f.service
        .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    let calls = f.fake.calls().len();

    // Removal works even on a server without the encryption key, and
    // calls nothing at Dokploy.
    let keyless = DokployService::new(f.db.clone(), None, f.fake.clone());
    let overview = keyless.overview(&admin, ctx()).await.unwrap();
    assert!(!overview.storage_available);
    assert!(!overview.connection.unwrap().key_readable);
    assert!(matches!(
        keyless.credentials().await,
        Err(DokployServiceError::StorageUnavailable)
    ));
    assert!(matches!(
        keyless.replace_key(&admin, &secret(NEW_KEY), ctx()).await,
        Err(DokployServiceError::StorageUnavailable)
    ));
    keyless.remove(&admin, ctx()).await.unwrap();
    assert_eq!(f.fake.calls().len(), calls);
    assert_eq!(stored_rows(&f.db).await, 0);
    assert_eq!(
        audits(&f.db, "dokploy.disconnect", "success").await,
        [(
            Some(admin.account.id),
            Some("dokploy".to_owned()),
            Some(HOST.to_owned())
        )]
    );
    assert_eq!(
        f.service.overview(&admin, ctx()).await.unwrap().connection,
        None
    );
    assert!(f.service.credentials().await.unwrap().is_none());
    assert!(matches!(
        f.service.remove(&admin, ctx()).await,
        Err(DokployServiceError::NotConnected)
    ));

    // Without an encryption key nothing can be connected.
    assert!(matches!(
        keyless
            .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
            .await,
        Err(DokployServiceError::StorageUnavailable)
    ));
    assert_eq!(f.fake.calls().len(), calls);

    // A new connection can be made after removal.
    f.service
        .connect(&admin, URL, &secret(NEW_KEY), ctx())
        .await
        .unwrap();
    assert_eq!(stored_rows(&f.db).await, 1);

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn a_key_moved_to_another_url_is_unreadable() {
    let Some(scratch) = ScratchDb::create("dokploy_bound").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    f.service
        .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    // Someone with write access to the metadata database points the
    // connection elsewhere: the key does not decrypt for that URL.
    sqlx::query("UPDATE dokploy_connection SET url = 'https://attacker.example.test'")
        .execute(f.db.pool())
        .await
        .unwrap();
    let overview = f.service.overview(&admin, ctx()).await.unwrap();
    assert!(!overview.connection.unwrap().key_readable);
    assert!(matches!(
        f.service.credentials().await,
        Err(DokployServiceError::Cipher(_))
    ));

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn rotating_the_encryption_key_reseals_the_dokploy_key() {
    let Some(scratch) = ScratchDb::create("dokploy_reseal").await else {
        return;
    };
    let f = setup(&scratch, Some(KEY_A)).await;
    let admin = account(&f.db, "Admin", true).await;
    f.service
        .connect(&admin, URL, &secret(DOKPLOY_KEY), ctx())
        .await
        .unwrap();
    let before = f.service.overview(&admin, ctx()).await.unwrap();

    let mut rotated = cipher(KEY_B);
    rotated
        .add_previous_keys(&SecretString::from(KEY_A))
        .unwrap();
    // Before the run the key is under a previous key, and still readable.
    assert_eq!(
        key_usage(&f.db, &rotated).await.unwrap(),
        KeyUsage {
            current: 0,
            previous: 1,
            unknown: 0
        }
    );
    let during = DokployService::new(f.db.clone(), Some(rotated.clone()), f.fake.clone());
    assert!(
        during
            .overview(&admin, ctx())
            .await
            .unwrap()
            .connection
            .unwrap()
            .key_readable
    );
    assert_eq!(
        reseal_credentials(&f.db, &rotated).await.unwrap(),
        RotationSummary {
            resealed: 1,
            unreadable: 0,
            changed_meanwhile: 0
        }
    );
    assert_eq!(
        key_usage(&f.db, &rotated).await.unwrap(),
        KeyUsage {
            current: 1,
            previous: 0,
            unknown: 0
        }
    );
    // The new key alone opens it, and who connected it and when are
    // unchanged.
    let new_only = DokployService::new(f.db.clone(), Some(cipher(KEY_B)), f.fake.clone());
    assert_eq!(
        new_only
            .credentials()
            .await
            .unwrap()
            .unwrap()
            .key
            .expose_secret(),
        DOKPLOY_KEY
    );
    assert_eq!(new_only.overview(&admin, ctx()).await.unwrap(), before);
    // Nothing left to move on a second run.
    assert_eq!(
        reseal_credentials(&f.db, &rotated).await.unwrap(),
        RotationSummary::default()
    );
    // A key replaced since it was read is not overwritten.
    assert!(
        !f.db
            .reseal_dokploy_key(
                URL,
                b"stale nonce!",
                rotated.key_id(),
                &[0u8; 12],
                &[0u8; 17]
            )
            .await
            .unwrap()
    );

    // A key under an encryption key this server does not have is
    // reported, not touched.
    let stranger = cipher("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert_eq!(
        key_usage(&f.db, &stranger).await.unwrap(),
        KeyUsage {
            current: 0,
            previous: 0,
            unknown: 1
        }
    );
    assert_eq!(
        reseal_credentials(&f.db, &stranger).await.unwrap(),
        RotationSummary {
            resealed: 0,
            unreadable: 1,
            changed_meanwhile: 0
        }
    );

    f.db.close().await;
    scratch.drop().await;
}
