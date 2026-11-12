//! The durable job runner against a scratch metadata database, with a
//! scripted handler. Skipped unless `SUPABASE_DASHBOARD_TEST_DATABASE_URL`
//! is set.

#![allow(clippy::unwrap_used)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use supabase_dashboard_application::jobs::{
    ClaimedJob, JobHandler, JobRunner, RunResult, RunnerSettings, StepFuture, StepOutcome,
};
use supabase_dashboard_domain::job::JobKind;
use supabase_dashboard_persistence::{
    Database,
    audit::{AuditEvent, AuditOutcome},
    jobs::{NewJob, SealedJobSecrets},
};
use uuid::Uuid;

#[path = "../../persistence/tests/common/mod.rs"]
mod common;
use common::ScratchDb;

const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA";

/// Answers each step from a script, and records the steps it ran.
#[derive(Default)]
struct Scripted {
    ran: Mutex<Vec<(String, Value)>>,
    /// A step that sleeps this long before answering.
    slow: Mutex<Option<(&'static str, Duration)>>,
}

impl JobHandler for Scripted {
    fn kind(&self) -> JobKind {
        JobKind::ProvisionStack
    }

    fn run_step<'a>(&'a self, job: &'a ClaimedJob) -> StepFuture<'a> {
        Box::pin(async move {
            self.ran
                .lock()
                .unwrap()
                .push((job.step.clone(), job.data.clone()));
            let slow = *self.slow.lock().unwrap();
            if let Some((step, delay)) = slow
                && step == job.step
            {
                tokio::time::sleep(delay).await;
            }
            let mut data = job.data.clone();
            match job.step.as_str() {
                "start" => {
                    data["service"] = json!("svc-1");
                    StepOutcome::Next {
                        step: "deploy",
                        data,
                    }
                }
                "deploy" => {
                    let polls = data["polls"].as_u64().unwrap_or(0);
                    data["polls"] = json!(polls + 1);
                    if polls < 1 {
                        StepOutcome::Wait {
                            step: "deploy",
                            data,
                            after: Duration::from_millis(300),
                            message: Some("Waiting for the deployment.".to_owned()),
                        }
                    } else {
                        StepOutcome::Next {
                            step: "finish",
                            data,
                        }
                    }
                }
                "finish" => StepOutcome::Succeed {
                    data,
                    message: Some("Stack ready.".to_owned()),
                },
                "broken" => StepOutcome::Fail {
                    data,
                    message: "Dokploy refused the compose file.".to_owned(),
                },
                _ => StepOutcome::Fail {
                    data,
                    message: "unexpected step".to_owned(),
                },
            }
        })
    }
}

struct Fixture {
    db: Database,
    organization: Uuid,
    account: Uuid,
}

async fn setup(scratch: &ScratchDb) -> Fixture {
    let db = Database::connect(&scratch.settings).await.unwrap();
    db.migrate().await.unwrap();
    let account = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO accounts (id, email, display_name, password_hash) \
         VALUES ($1, 'ops@example.test', 'Ops', $2)",
    )
    .bind(account)
    .bind(HASH)
    .execute(db.pool())
    .await
    .unwrap();
    let organization = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name) VALUES ($1, 'Acme')")
        .bind(organization)
        .execute(db.pool())
        .await
        .unwrap();
    Fixture {
        db,
        organization,
        account,
    }
}

async fn enqueue(f: &Fixture, step: &str, secrets: bool) -> Uuid {
    let id = Uuid::now_v7();
    let sealed = SealedJobSecrets {
        key_id: "k1".to_owned(),
        nonce: vec![0; 12],
        ciphertext: vec![1; 32],
    };
    f.db.insert_job(
        &NewJob {
            id,
            kind: JobKind::ProvisionStack.as_str(),
            organization_id: f.organization,
            step,
            data: r#"{"name":"shop"}"#,
            secrets: secrets.then_some(&sealed),
            created_by: f.account,
        },
        &AuditEvent {
            actor_account_id: Some(f.account),
            action: "job.test",
            target_type: Some("job"),
            target_id: Some(id.to_string()),
            outcome: AuditOutcome::Success,
            request_id: None,
        },
    )
    .await
    .unwrap();
    id
}

fn runner(db: &Database, handler: Arc<Scripted>, settings: RunnerSettings) -> JobRunner {
    JobRunner::new(db.clone(), vec![handler], settings)
}

fn fast() -> RunnerSettings {
    RunnerSettings {
        lease: Duration::from_secs(10),
        step_timeout: Duration::from_secs(5),
        retry_after_timeout: Duration::from_millis(0),
        max_interruptions: 2,
        max_steps_per_claim: 10,
        idle_poll: Duration::from_millis(50),
    }
}

#[tokio::test]
async fn a_job_runs_its_steps_waits_between_polls_and_succeeds() {
    let Some(scratch) = ScratchDb::create("jobs_steps").await else {
        return;
    };
    let f = setup(&scratch).await;
    let handler = Arc::new(Scripted::default());
    let runner = runner(&f.db, handler.clone(), fast());
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Idle);

    let id = enqueue(&f, "start", true).await;
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
    // "start" saved its data and "deploy" asked to wait.
    let job = f.db.get_job(id).await.unwrap().unwrap();
    assert_eq!(job.state, "queued");
    assert_eq!(job.step, "deploy");
    assert_eq!(job.message.as_deref(), Some("Waiting for the deployment."));
    let data: Value = serde_json::from_str(&job.data).unwrap();
    assert_eq!(
        data,
        json!({"name": "shop", "service": "svc-1", "polls": 1})
    );
    // Not due yet.
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Idle);

    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
    let job = f.db.get_job(id).await.unwrap().unwrap();
    assert_eq!(job.state, "succeeded");
    assert_eq!(job.message.as_deref(), Some("Stack ready."));
    assert!(job.finished_at.is_some());
    assert_eq!(job.interruptions, 0, "waiting is not an interruption");
    // Secrets go once the job succeeds.
    assert!(f.db.job_secrets(id).await.unwrap().is_none());

    let steps: Vec<String> = handler
        .ran
        .lock()
        .unwrap()
        .iter()
        .map(|(s, _)| s.clone())
        .collect();
    assert_eq!(steps, ["start", "deploy", "deploy", "finish"]);
    // The job is created with its audit event.
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'job.test'")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    assert_eq!(audits, 1);
}

#[tokio::test]
async fn a_failed_step_keeps_the_secrets_and_says_why() {
    let Some(scratch) = ScratchDb::create("jobs_fail").await else {
        return;
    };
    let f = setup(&scratch).await;
    let runner = runner(&f.db, Arc::new(Scripted::default()), fast());
    let id = enqueue(&f, "broken", true).await;
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
    let job = f.db.get_job(id).await.unwrap().unwrap();
    assert_eq!(job.state, "failed");
    assert_eq!(
        job.message.as_deref(),
        Some("Dokploy refused the compose file.")
    );
    // Kept, because the stack may already hold them.
    assert!(f.db.job_secrets(id).await.unwrap().is_some());
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Idle);
}

#[tokio::test]
async fn a_job_whose_runner_stopped_is_resumed_by_another() {
    let Some(scratch) = ScratchDb::create("jobs_resume").await else {
        return;
    };
    let f = setup(&scratch).await;
    let id = enqueue(&f, "start", false).await;
    // A runner claims the job with a short lease and stops.
    let gone = Uuid::now_v7();
    let claimed = f.db.claim_job(gone, 0.05).await.unwrap().unwrap();
    assert_eq!(claimed.id, id);
    let handler = Arc::new(Scripted::default());
    let runner = runner(&f.db, handler.clone(), fast());
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Idle);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
    let job = f.db.get_job(id).await.unwrap().unwrap();
    assert_eq!(job.interruptions, 1);
    assert_eq!(job.step, "deploy");
    // The stopped runner can no longer change the job.
    let lost =
        f.db.update_job(
            id,
            gone,
            &supabase_dashboard_persistence::jobs::JobUpdate::Fail {
                data: "{}",
                message: "late",
            },
        )
        .await
        .unwrap();
    assert!(!lost);
    assert_eq!(f.db.get_job(id).await.unwrap().unwrap().state, "queued");
}

#[tokio::test]
async fn a_step_that_keeps_taking_too_long_fails_the_job() {
    let Some(scratch) = ScratchDb::create("jobs_timeout").await else {
        return;
    };
    let f = setup(&scratch).await;
    let handler = Arc::new(Scripted::default());
    *handler.slow.lock().unwrap() = Some(("start", Duration::from_millis(200)));
    let settings = RunnerSettings {
        step_timeout: Duration::from_millis(50),
        ..fast()
    };
    let runner = runner(&f.db, handler.clone(), settings);
    let id = enqueue(&f, "start", false).await;

    for expected in 1..=3 {
        assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
        let job = f.db.get_job(id).await.unwrap().unwrap();
        assert_eq!(job.interruptions, expected);
        assert_eq!(job.state, "queued");
        assert!(job.message.unwrap().contains("took longer than"));
    }
    // Interrupted more than twice: the next claim fails the job without
    // running the step again.
    assert_eq!(runner.run_due().await.unwrap(), RunResult::Ran(id));
    let job = f.db.get_job(id).await.unwrap().unwrap();
    assert_eq!(job.state, "failed");
    assert!(
        job.message
            .unwrap()
            .contains("interrupted 3 times at step start")
    );
    assert_eq!(handler.ran.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn the_runner_stops_on_shutdown() {
    let Some(scratch) = ScratchDb::create("jobs_shutdown").await else {
        return;
    };
    let f = setup(&scratch).await;
    let runner = runner(&f.db, Arc::new(Scripted::default()), fast());
    let id = enqueue(&f, "start", false).await;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        runner
            .run(async {
                let _ = stopped.await;
            })
            .await;
    });
    // The background loop takes the job through its wait.
    for _ in 0..40 {
        if f.db.get_job(id).await.unwrap().unwrap().state == "succeeded" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(f.db.get_job(id).await.unwrap().unwrap().state, "succeeded");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}
