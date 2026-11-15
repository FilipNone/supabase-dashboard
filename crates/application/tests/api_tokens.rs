//! Dashboard API tokens against a scratch metadata database. Skipped unless
//! `SUPABASE_DASHBOARD_TEST_DATABASE_URL` is set.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use secrecy::SecretString;
use supabase_dashboard_application::{
    api_tokens::{ApiAccessError, ApiTokenError, ApiTokenService, NewToken, TokenApi},
    auth::{AuthConfig, AuthService, CurrentSession, RequestContext},
    connections::{ConnectionService, ProbeFuture, StackProbe},
    organizations::OrganizationService,
    projects::{ProjectService, Registration},
};
use supabase_dashboard_domain::{
    account::{DisplayName, Email},
    api_token::{API_TOKEN_PREFIX, ApiTokenScope, ApiTokenState, MAX_ACTIVE_API_TOKENS},
    audit::AuditEntryOutcome,
    authority::{AuthorityError, AuthorityInfo, ProjectAuthorities},
    authz::OrgRole,
    connection::{HealthReport, ServiceCheck, ServiceStatus, StackService},
    project::ProjectUrl,
};
use supabase_dashboard_persistence::{
    Database, accounts::AccountRecord, connections::HistoryRetention,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

fn ctx() -> RequestContext<'static> {
    RequestContext {
        request_id: Some("req-tokens"),
        user_agent: None,
    }
}

/// The API never runs a check, so the probe is never called.
struct NoProbe;

impl StackProbe for NoProbe {
    fn check<'a>(
        &'a self,
        _api_url: &'a ProjectUrl,
        service: StackService,
        _key: &'a SecretString,
        _authorities: Option<&'a ProjectAuthorities>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            ServiceCheck {
                service,
                status: ServiceStatus::Healthy,
                version: None,
                latency_ms: None,
                certificate_expires_at: None,
            }
        })
    }

    fn read_authorities(&self, _pem: &str) -> Result<Vec<AuthorityInfo>, AuthorityError> {
        Err(AuthorityError::NotACertificate)
    }
}

struct Fixture {
    db: Database,
    tokens: ApiTokenService,
    api: TokenApi,
    orgs: Arc<OrganizationService>,
    projects: Arc<ProjectService>,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let orgs = Arc::new(OrganizationService::new(db.clone()));
    let projects = Arc::new(ProjectService::new(db.clone()));
    let connections = Arc::new(ConnectionService::new(db.clone(), None, Arc::new(NoProbe)));
    Fixture {
        tokens: ApiTokenService::new(db.clone()),
        api: TokenApi::new(orgs.clone(), projects.clone(), connections),
        orgs,
        projects,
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

fn scopes(names: &[&str]) -> Vec<String> {
    names.iter().map(|&name| name.to_owned()).collect()
}

async fn issue(f: &Fixture, who: &CurrentSession, names: &[&str]) -> (Uuid, String) {
    let scopes = scopes(names);
    let issued = f
        .tokens
        .create(
            who,
            NewToken {
                name: "CI",
                lifetime: "30",
                scopes: &scopes,
            },
            ctx(),
        )
        .await
        .unwrap();
    (issued.token.id, issued.secret.expose().to_owned())
}

#[tokio::test]
async fn tokens_are_created_listed_and_revoked_by_their_owner() {
    let Some(scratch) = ScratchDb::create("app_tokens_lifecycle").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let bob = account(&f.db, "Bob").await;

    // Input is checked before anything is stored.
    let all = scopes(&["organizations:read", "projects:read"]);
    for (name, lifetime, scopes, expected) in [
        (" ", "30", all.clone(), "NameEmpty"),
        ("CI", "0", all.clone(), "UnknownLifetime"),
        ("CI", "never", all.clone(), "UnknownLifetime"),
        ("CI", "30", Vec::new(), "NoScopes"),
        ("CI", "30", scopes(&["projects:write"]), "UnknownScope"),
    ] {
        let err = f
            .tokens
            .create(
                &alice,
                NewToken {
                    name,
                    lifetime,
                    scopes: &scopes,
                },
                ctx(),
            )
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains(expected), "{err:?}");
    }
    assert!(f.tokens.list(&alice).await.unwrap().is_empty());

    let issued = f
        .tokens
        .create(
            &alice,
            NewToken {
                name: "  Deploy script ",
                lifetime: "7",
                scopes: &scopes(&["projects:read", "organizations:read", "projects:read"]),
            },
            ctx(),
        )
        .await
        .unwrap();
    let secret = issued.secret.expose().to_owned();
    assert!(secret.starts_with(API_TOKEN_PREFIX), "{secret}");
    assert_eq!(secret.len(), API_TOKEN_PREFIX.len() + 64);
    assert!(secret.starts_with(&issued.token.display_prefix));
    assert_eq!(issued.token.name.as_str(), "Deploy script");
    assert_eq!(
        issued.token.scopes,
        [
            ApiTokenScope::OrganizationsRead,
            ApiTokenScope::ProjectsRead
        ]
    );
    let days = (issued.token.expires_at - issued.token.created_at).whole_days();
    assert_eq!(days, 7);

    // The list shows the token without the secret; the database has only
    // its hash.
    let listed = f.tokens.list(&alice).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, issued.token.id);
    assert!(!format!("{listed:?}").contains(&secret[API_TOKEN_PREFIX.len()..]));
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE position($1 in display_prefix) > 0 \
            OR position(convert_to($1, 'UTF8') in token_hash) > 0",
    )
    .bind(&secret)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, 0);
    assert!(f.tokens.list(&bob).await.unwrap().is_empty());

    // The token works until it is revoked; Bob cannot revoke it.
    let principal = f.tokens.authenticate(&secret).await.unwrap().unwrap();
    assert_eq!(principal.account_id(), alice.account.id);
    assert_eq!(principal.token_id(), issued.token.id);
    assert!(matches!(
        f.tokens.revoke(&bob, issued.token.id, ctx()).await,
        Err(ApiTokenError::NotFound)
    ));
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_some());
    f.tokens
        .revoke(&alice, issued.token.id, ctx())
        .await
        .unwrap();
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_none());
    assert!(matches!(
        f.tokens.revoke(&alice, issued.token.id, ctx()).await,
        Err(ApiTokenError::NotFound)
    ));
    let listed = f.tokens.list(&alice).await.unwrap();
    assert_eq!(listed[0].state, ApiTokenState::Revoked);

    // Both changes are in Alice's own audit log, without the token.
    let auth = AuthService::new(f.db.clone(), AuthConfig::default())
        .await
        .unwrap();
    let log = auth.account_audit_log(&alice, None).await.unwrap();
    let actions: Vec<&str> = log.entries.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions, ["api_token.revoke", "api_token.create"]);
    assert!(
        log.entries
            .iter()
            .all(|e| e.outcome == AuditEntryOutcome::Success
                && e.target_id.as_deref() == Some(issued.token.id.to_string().as_str()))
    );
    assert!(!format!("{log:?}").contains(&secret[API_TOKEN_PREFIX.len()..]));

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn malformed_expired_and_disabled_tokens_do_not_authenticate() {
    let Some(scratch) = ScratchDb::create("app_tokens_refused").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let (id, secret) = issue(&f, &alice, &["projects:read"]).await;
    let bare = &secret[API_TOKEN_PREFIX.len()..];

    for bad in [
        "",
        bare,
        "sbd_",
        "sbd_zz",
        &secret.to_uppercase(),
        &format!("{secret}0"),
        &format!("sbd_{}", "0".repeat(64)),
    ] {
        assert!(f.tokens.authenticate(bad).await.unwrap().is_none(), "{bad}");
    }
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_some());

    // A disabled account's tokens stop working, and work again when it is
    // enabled.
    sqlx::query("UPDATE accounts SET disabled_at = now() WHERE id = $1")
        .bind(alice.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_none());
    let scopes = scopes(&["projects:read"]);
    assert!(matches!(
        f.tokens
            .create(
                &alice,
                NewToken {
                    name: "Another",
                    lifetime: "30",
                    scopes: &scopes,
                },
                ctx(),
            )
            .await,
        Err(ApiTokenError::AccountUnavailable)
    ));
    sqlx::query("UPDATE accounts SET disabled_at = NULL WHERE id = $1")
        .bind(alice.account.id)
        .execute(f.db.pool())
        .await
        .unwrap();
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_some());

    // An expired token stops working.
    sqlx::query(
        "UPDATE api_tokens SET created_at = now() - interval '2 days', \
             expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(id)
    .execute(f.db.pool())
    .await
    .unwrap();
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_none());
    let listed = f.tokens.list(&alice).await.unwrap();
    assert_eq!(listed[0].state, ApiTokenState::Expired);

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn the_number_of_working_tokens_is_capped_and_old_ones_are_deleted() {
    let Some(scratch) = ScratchDb::create("app_tokens_cap").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let mut ids = Vec::new();
    for _ in 0..MAX_ACTIVE_API_TOKENS {
        ids.push(issue(&f, &alice, &["projects:read"]).await.0);
    }
    let scopes = scopes(&["projects:read"]);
    let new = NewToken {
        name: "One too many",
        lifetime: "30",
        scopes: &scopes,
    };
    assert!(matches!(
        f.tokens.create(&alice, new, ctx()).await,
        Err(ApiTokenError::LimitReached)
    ));

    // Revoking one makes room. A token revoked over 30 days ago is deleted
    // when the next one is created; a recently revoked one stays listed.
    f.tokens.revoke(&alice, ids[0], ctx()).await.unwrap();
    f.tokens.revoke(&alice, ids[1], ctx()).await.unwrap();
    sqlx::query("UPDATE api_tokens SET revoked_at = now() - interval '31 days' WHERE id = $1")
        .bind(ids[0])
        .execute(f.db.pool())
        .await
        .unwrap();
    f.tokens.create(&alice, new, ctx()).await.unwrap();
    let listed = f.tokens.list(&alice).await.unwrap();
    assert_eq!(listed.len(), MAX_ACTIVE_API_TOKENS);
    assert!(listed.iter().all(|token| token.id != ids[0]));
    assert!(listed.iter().any(|token| token.id == ids[1]));
    // 24 work now: one more fits, and then the limit holds again.
    f.tokens.create(&alice, new, ctx()).await.unwrap();
    assert!(matches!(
        f.tokens.create(&alice, new, ctx()).await,
        Err(ApiTokenError::LimitReached)
    ));

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn tokens_read_only_what_their_scopes_and_the_account_allow() {
    let Some(scratch) = ScratchDb::create("app_tokens_api").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let bob = account(&f.db, "Bob").await;
    let acme = f.orgs.create(&alice, "Acme", ctx()).await.unwrap();
    let globex = f.orgs.create(&bob, "Globex", ctx()).await.unwrap();
    let registration = |name| Registration {
        name,
        api_url: "https://supabase.example.test/",
        allow_unencrypted: false,
    };
    let shop = f
        .projects
        .register(&alice, acme.id, registration("Shop"), ctx())
        .await
        .unwrap();
    let blog = f
        .projects
        .register(&alice, acme.id, registration("Blog"), ctx())
        .await
        .unwrap();
    let secret_project = f
        .projects
        .register(&bob, globex.id, registration("Globex secret"), ctx())
        .await
        .unwrap();
    // A saved check for the shop.
    f.db.save_health_report(
        shop.id,
        &HealthReport {
            checked_at: OffsetDateTime::now_utc(),
            checks: vec![ServiceCheck {
                service: StackService::Auth,
                status: ServiceStatus::Unhealthy { http_status: 503 },
                version: None,
                latency_ms: Some(3),
                certificate_expires_at: None,
            }],
        },
        HistoryRetention {
            max_age_days: 7,
            max_entries: 10,
        },
    )
    .await
    .unwrap();

    let (_, both) = issue(&f, &alice, &["organizations:read", "projects:read"]).await;
    let (_, orgs_only) = issue(&f, &alice, &["organizations:read"]).await;
    let (_, projects_only) = issue(&f, &alice, &["projects:read"]).await;
    let both = f.tokens.authenticate(&both).await.unwrap().unwrap();
    let orgs_only = f.tokens.authenticate(&orgs_only).await.unwrap().unwrap();
    let projects_only = f
        .tokens
        .authenticate(&projects_only)
        .await
        .unwrap()
        .unwrap();

    let orgs = f.api.organizations(&both).await.unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0].id, acme.id);
    assert_eq!(orgs[0].role, OrgRole::Owner);
    assert!(matches!(
        f.api.organizations(&projects_only).await,
        Err(ApiAccessError::MissingScope(
            ApiTokenScope::OrganizationsRead
        ))
    ));
    assert!(f.api.organizations(&orgs_only).await.is_ok());

    let projects = f.api.projects(&projects_only, acme.id).await.unwrap();
    let names: Vec<&str> = projects.iter().map(|p| p.project.name.as_str()).collect();
    assert_eq!(names, ["Blog", "Shop"]);
    let shop_entry = projects.iter().find(|p| p.project.id == shop.id).unwrap();
    assert_eq!(
        shop_entry.last_check.as_ref().unwrap().failing,
        [StackService::Auth]
    );
    assert!(
        projects
            .iter()
            .find(|p| p.project.id == blog.id)
            .unwrap()
            .last_check
            .is_none()
    );
    assert!(matches!(
        f.api.projects(&orgs_only, acme.id).await,
        Err(ApiAccessError::MissingScope(ApiTokenScope::ProjectsRead))
    ));
    let one = f.api.project(&both, shop.id).await.unwrap();
    assert_eq!(one.project.name.as_str(), "Shop");
    assert!(one.last_check.is_some());

    // Another organization and its project look like ones that do not
    // exist.
    assert!(matches!(
        f.api.projects(&both, globex.id).await,
        Err(ApiAccessError::NotFound)
    ));
    assert!(matches!(
        f.api.project(&both, secret_project.id).await,
        Err(ApiAccessError::NotFound)
    ));
    assert!(matches!(
        f.api.project(&both, Uuid::now_v7()).await,
        Err(ApiAccessError::NotFound)
    ));

    // A token follows the account's current membership.
    sqlx::query(
        "INSERT INTO organization_members (organization_id, account_id, role) VALUES ($1, $2, $3)",
    )
    .bind(globex.id)
    .bind(alice.account.id)
    .bind(OrgRole::Viewer.as_str())
    .execute(f.db.pool())
    .await
    .unwrap();
    let projects = f.api.projects(&both, globex.id).await.unwrap();
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].project.role, OrgRole::Viewer);

    f.db.close().await;
    scratch.drop().await;
}

#[tokio::test]
async fn a_password_reset_revokes_the_accounts_tokens() {
    let Some(scratch) = ScratchDb::create("app_tokens_reset").await else {
        return;
    };
    let f = setup(&scratch).await;
    let alice = account(&f.db, "Alice").await;
    let (_, secret) = issue(&f, &alice, &["projects:read"]).await;
    let auth = AuthService::new(f.db.clone(), AuthConfig::default())
        .await
        .unwrap();
    auth.reset_password(
        "alice@example.test",
        &SecretString::from("a brand new password here"),
    )
    .await
    .unwrap();
    assert!(f.tokens.authenticate(&secret).await.unwrap().is_none());

    f.db.close().await;
    scratch.drop().await;
}
