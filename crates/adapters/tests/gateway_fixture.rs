//! Gateway probe against the disposable Supabase fixture's Kong gateway
//! (`tests/fixtures/supabase`). Skipped unless
//! `SUPABASE_DASHBOARD_TEST_FIXTURE_URL` is set, for example to
//! `http://127.0.0.1:54321`. Keys come from the fixture's env file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use secrecy::SecretString;
use supabase_dashboard_adapters::{
    gateway::{GatewayProbe, GatewaySettings},
    net::TargetPolicy,
};
use supabase_dashboard_application::connections::StackProbe;
use supabase_dashboard_domain::{
    connection::{ServiceStatus, StackService},
    project::ProjectUrl,
};

const ENV: &str = "SUPABASE_DASHBOARD_TEST_FIXTURE_URL";

fn fixture_value(name: &str) -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/supabase/fixture.env"
    );
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} missing from fixture.env"))
        .to_owned()
}

#[tokio::test]
async fn fixture_gateway_reports_auth_and_rest() {
    let Ok(raw) = std::env::var(ENV) else {
        eprintln!("skipping: {ENV} is not set");
        return;
    };
    let url = ProjectUrl::parse(&raw).unwrap();
    let probe = GatewayProbe::new(GatewaySettings {
        // The fixture binds to loopback.
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..GatewaySettings::default()
    })
    .unwrap();
    let anon = SecretString::from(fixture_value("ANON_KEY"));
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));

    let auth = probe.check(&url, StackService::Auth, &anon).await;
    assert_eq!(auth.status, ServiceStatus::Healthy);
    assert_eq!(auth.version.as_deref(), Some("v2.197.0"));

    // Upstream limits the PostgREST root to the service role.
    let rest = probe.check(&url, StackService::Rest, &service).await;
    assert_eq!(rest.status, ServiceStatus::Healthy);
    let rest_anon = probe.check(&url, StackService::Rest, &anon).await;
    assert_eq!(
        rest_anon.status,
        ServiceStatus::KeyRejected { http_status: 403 }
    );

    let wrong = SecretString::from("not-a-key");
    assert_eq!(
        probe.check(&url, StackService::Auth, &wrong).await.status,
        ServiceStatus::KeyRejected { http_status: 401 }
    );
}

#[tokio::test]
async fn fixture_meta_lists_structure() {
    use supabase_dashboard_application::schema::SchemaSource;
    use supabase_dashboard_domain::schema::{
        CELL_MAX_CHARS, FilterOp, ForeignKeyAction, IdentityGeneration, MetaUnavailable,
        ROW_PAGE_SIZE, RelationKind, RowFilter, RowOrder, RowPageNumber, RowSort, SchemaName,
    };

    let Ok(raw) = std::env::var(ENV) else {
        eprintln!("skipping: {ENV} is not set");
        return;
    };
    let url = ProjectUrl::parse(&raw).unwrap();
    let probe = GatewayProbe::new(GatewaySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..GatewaySettings::default()
    })
    .unwrap();
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));
    let anon = SecretString::from(fixture_value("ANON_KEY"));

    let schemas = probe.schemas(&url, &service).await.unwrap();
    let names: Vec<_> = schemas.schemas.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.contains(&"public") && names.contains(&"auth"),
        "{names:?}"
    );
    assert!(names.windows(2).all(|w| w[0] <= w[1]), "sorted: {names:?}");
    assert!(!schemas.truncated);

    // The gateway limits /pg/ to the service role.
    assert_eq!(
        probe.schemas(&url, &anon).await.unwrap_err(),
        MetaUnavailable::KeyRejected { http_status: 403 }
    );

    let public = SchemaName::parse("public").unwrap();
    let tables = probe.tables(&url, &service, &public).await.unwrap();
    let names: Vec<_> = tables.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        [
            r#"Event "Log""#,
            "open_todos",
            "remote_items",
            "tag_notes",
            "tags",
            "todo_counts",
            "todos"
        ]
    );
    let by_name = |name: &str| tables.tables.iter().find(|t| t.name == name).unwrap();
    let todos = by_name("todos");
    assert!(todos.rls_enabled);
    assert_eq!(todos.comment.as_deref(), Some("Synthetic fixture table"));

    let detail = probe
        .table(&url, &service, todos.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.primary_key, ["id"]);
    let columns: Vec<_> = detail.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        columns,
        ["id", "title", "status", "slug", "note", "created_at"]
    );
    assert_eq!(
        detail.columns[0].identity,
        Some(IdentityGeneration::ByDefault)
    );
    assert_eq!(detail.columns[1].comment.as_deref(), Some("What to do"));
    assert_eq!(detail.columns[2].enum_labels, ["open", "done"]);
    assert!(detail.columns[3].unique);
    assert!(detail.columns[4].nullable);

    let rows = probe
        .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
        .await
        .unwrap();
    assert_eq!(rows.order, RowOrder::PrimaryKey(vec!["id".into()]));
    assert!(!rows.has_more);
    let text = |row: usize, col: usize| rows.rows[row][col].as_ref().map(|cell| cell.text.as_str());
    assert_eq!(rows.rows.len(), 2);
    assert_eq!(
        (text(0, 0), text(0, 1), text(0, 2)),
        (Some("1"), Some("first"), Some("open"))
    );
    assert_eq!(text(1, 1), Some("second"));
    assert_eq!(text(0, 4), None);

    let by_title = RowSort::new("title", true).unwrap();
    let sorted = probe
        .rows(
            &url,
            &service,
            &detail,
            RowPageNumber::FIRST,
            Some(&by_title),
            &[],
        )
        .await
        .unwrap();
    assert_eq!(sorted.order.sort(), Some(by_title));
    assert!(!sorted.order.is_unstable());
    let titles: Vec<_> = sorted
        .rows
        .iter()
        .map(|row| row[1].as_ref().map(|cell| cell.text.as_str()))
        .collect();
    assert_eq!(titles, [Some("second"), Some("first")]);

    // Filters: values reach PostgreSQL only through quote_literal, so a
    // quote or a backslash is matched as itself.
    let filter = |column: &str, op, value: &str| RowFilter::new(column, op, value).unwrap();
    let matching = |filters: Vec<RowFilter>| {
        let probe = &probe;
        let (url, service, detail) = (&url, &service, &detail);
        async move {
            probe
                .rows(url, service, detail, RowPageNumber::FIRST, None, &filters)
                .await
                .map(|page| {
                    page.rows
                        .iter()
                        .map(|row| row[1].as_ref().map_or(String::new(), |c| c.text.clone()))
                        .collect::<Vec<_>>()
                })
        }
    };
    assert_eq!(
        matching(vec![filter("title", FilterOp::Ilike, "%ECO%")]).await,
        Ok(vec!["second".to_owned()])
    );
    assert_eq!(
        matching(vec![
            filter("note", FilterOp::IsNull, ""),
            filter("status", FilterOp::Eq, "open"),
            filter("id", FilterOp::Lte, "1"),
        ])
        .await,
        Ok(vec!["first".to_owned()])
    );
    for value in ["it's", r"a\b", "'; SELECT 1; --"] {
        assert_eq!(
            matching(vec![filter("title", FilterOp::Eq, value)]).await,
            Ok(vec![])
        );
    }
    for (column, value) in [
        ("id", "abc"),
        ("created_at", "not a date"),
        ("status", "bogus"),
    ] {
        assert_eq!(
            matching(vec![filter(column, FilterOp::Gt, value)]).await,
            Err(MetaUnavailable::FilterValueRejected),
            "{column}"
        );
    }

    let tags = by_name("tags");
    let detail = probe.table(&url, &service, tags.id).await.unwrap().unwrap();
    assert_eq!(detail.primary_key, ["todo_id", "label"]);
    let rows = probe
        .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
        .await
        .unwrap();
    assert!(rows.rows.is_empty() && !rows.has_more);

    // Quoted names, no primary key, several pages, and long values.
    let log = by_name(r#"Event "Log""#);
    let detail = probe.table(&url, &service, log.id).await.unwrap().unwrap();
    assert!(detail.primary_key.is_empty());
    let first = probe
        .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
        .await
        .unwrap();
    assert_eq!(first.order, RowOrder::Unordered);
    assert_eq!(first.rows.len(), ROW_PAGE_SIZE as usize);
    assert!(first.has_more);
    let columns: Vec<_> = first.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(columns, ["Kind", "payload", "body"]);
    assert_eq!(first.columns[1].type_label, "jsonb");
    let long = first.rows.iter().find_map(|row| row[2].as_ref()).unwrap();
    assert!(long.truncated);
    assert_eq!(long.text.chars().count(), CELL_MAX_CHARS);
    let third = probe
        .rows(
            &url,
            &service,
            &detail,
            RowPageNumber::new(3).unwrap(),
            None,
            &[],
        )
        .await
        .unwrap();
    assert_eq!(third.rows.len(), 20);
    assert!(!third.has_more);
    let past = probe
        .rows(
            &url,
            &service,
            &detail,
            RowPageNumber::new(9).unwrap(),
            None,
            &[],
        )
        .await
        .unwrap();
    assert!(past.rows.is_empty());

    // postgres-meta's own 404 means no such table.
    assert_eq!(probe.table(&url, &service, u32::MAX).await.unwrap(), None);

    // Foreign keys keep their column pairs in key order, whatever the
    // order the columns were declared in, and a key from a table to
    // itself shows in both directions.
    let notes = by_name("tag_notes");
    let relations = probe.relations(&url, &service, notes.id).await.unwrap();
    assert!(!relations.truncated);
    let outgoing: Vec<_> = relations
        .outgoing
        .iter()
        .map(|k| {
            (
                k.referenced_table.as_str(),
                k.columns.clone(),
                k.referenced_columns.clone(),
                k.on_update,
                k.on_delete,
            )
        })
        .collect();
    assert_eq!(
        outgoing,
        [
            (
                "tag_notes",
                vec!["parent_id".to_owned()],
                vec!["id".to_owned()],
                ForeignKeyAction::NoAction,
                ForeignKeyAction::SetNull,
            ),
            (
                "tags",
                vec!["tag_todo".to_owned(), "tag_label".to_owned()],
                vec!["todo_id".to_owned(), "label".to_owned()],
                ForeignKeyAction::Cascade,
                ForeignKeyAction::NoAction,
            ),
        ]
    );
    let incoming: Vec<_> = relations
        .incoming
        .iter()
        .map(|k| k.table.as_str())
        .collect();
    assert_eq!(incoming, ["tag_notes"]);

    let relations = probe.relations(&url, &service, todos.id).await.unwrap();
    assert!(relations.outgoing.is_empty());
    let incoming: Vec<_> = relations
        .incoming
        .iter()
        .map(|k| (k.table.as_str(), k.on_delete))
        .collect();
    assert_eq!(incoming, [("tags", ForeignKeyAction::Cascade)]);

    let none = probe.relations(&url, &service, u32::MAX).await.unwrap();
    assert!(none.outgoing.is_empty() && none.incoming.is_empty());

    // A view is found by its ID and read unordered, without row-level
    // security or statistics.
    let view = by_name("open_todos");
    assert_eq!(view.kind, RelationKind::View);
    assert!(!view.rls_enabled && view.size.is_empty());
    let detail = probe.table(&url, &service, view.id).await.unwrap().unwrap();
    assert_eq!(detail.table.kind, RelationKind::View);
    let columns: Vec<_> = detail.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(columns, ["id", "title"]);
    let rows = probe
        .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
        .await
        .unwrap();
    assert_eq!(rows.order, RowOrder::Unordered);
    assert_eq!(rows.rows.len(), 2);

    // A materialized view created WITH NO DATA, and a foreign table: both
    // have columns, and neither has its rows read.
    let counts = by_name("todo_counts");
    assert_eq!(
        counts.kind,
        RelationKind::MaterializedView { populated: false }
    );
    let detail = probe
        .table(&url, &service, counts.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.columns.len(), 2);
    assert_eq!(
        probe
            .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
            .await
            .unwrap_err(),
        MetaUnavailable::NotPopulated
    );
    let remote = by_name("remote_items");
    assert_eq!(remote.kind, RelationKind::ForeignTable);
    let detail = probe
        .table(&url, &service, remote.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.columns.len(), 2);
    assert_eq!(
        probe
            .rows(&url, &service, &detail, RowPageNumber::FIRST, None, &[])
            .await
            .unwrap_err(),
        MetaUnavailable::ForeignRows
    );
}

#[tokio::test]
async fn fixture_sql_runs_with_limits_and_can_be_cancelled() {
    use std::time::Duration;

    use supabase_dashboard_application::sql::SqlRunner;
    use supabase_dashboard_domain::sql::{
        SQL_RESULT_ROW_LIMIT, SqlFailure, SqlText, sql_application_name,
    };
    use uuid::Uuid;

    let Ok(raw) = std::env::var(ENV) else {
        eprintln!("skipping: {ENV} is not set");
        return;
    };
    let url = ProjectUrl::parse(&raw).unwrap();
    let probe = GatewayProbe::new(GatewaySettings {
        policy: TargetPolicy {
            allow_loopback: true,
        },
        ..GatewaySettings::default()
    })
    .unwrap();
    let service = SecretString::from(fixture_value("SERVICE_ROLE_KEY"));
    let sql = |text: &str| SqlText::parse(text).unwrap();
    let run_id = Uuid::new_v4();

    // Columns keep PostgreSQL's order, and the connection carries the
    // dashboard's timeout and the run's name.
    let result = probe
        .run(
            &url,
            &service,
            &sql("select current_setting('statement_timeout') as z_timeout, \
                  current_setting('application_name') as \"App\", null::text as a_null"),
            run_id,
        )
        .await
        .unwrap();
    assert_eq!(result.columns, ["z_timeout", "App", "a_null"]);
    let text = |col: usize| result.rows[0][col].as_ref().map(|c| c.text.clone());
    assert_eq!(text(0).as_deref(), Some("20s"));
    assert_eq!(text(1), Some(sql_application_name(run_id)));
    assert_eq!(text(2), None);

    // Session settings end with the request: postgres-meta opens a new
    // connection each time.
    probe
        .run(&url, &service, &sql("set work_mem = '7MB'"), Uuid::new_v4())
        .await
        .unwrap();
    let after = probe
        .run(&url, &service, &sql("show work_mem"), Uuid::new_v4())
        .await
        .unwrap();
    assert_ne!(after.rows[0][0].as_ref().unwrap().text, "7MB");

    // Statements without rows, and rows past the limit.
    let empty = probe
        .run(
            &url,
            &service,
            &sql("create temp table t (x int); insert into t values (1)"),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(empty.columns.is_empty());
    let many = probe
        .run(
            &url,
            &service,
            &sql("select g from generate_series(1, 1500) as g"),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(many.row_count, 1500);
    assert_eq!(many.rows.len(), SQL_RESULT_ROW_LIMIT);

    match probe
        .run(&url, &service, &sql("selec 1"), Uuid::new_v4())
        .await
    {
        Err(SqlFailure::Database { code, message }) => {
            assert_eq!(code.as_deref(), Some("42601"));
            assert!(message.contains("LINE 1: selec 1"), "{message}");
        }
        other => panic!("{other:?}"),
    }

    // A cancel finds the run by its connection name and stops it.
    let sleeper = Uuid::new_v4();
    let running = {
        let probe = probe.clone();
        let url = url.clone();
        let service = service.clone();
        tokio::spawn(async move {
            probe
                .run(&url, &service, &sql("select pg_sleep(15)"), sleeper)
                .await
        })
    };
    let mut cancelled = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        cancelled = probe.cancel(&url, &service, sleeper).await.unwrap();
        if cancelled > 0 {
            break;
        }
    }
    assert_eq!(cancelled, 1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("the cancelled statement should stop at once")
        .unwrap();
    assert_eq!(outcome, Err(SqlFailure::Timeout));
    // Nothing is left to cancel.
    assert_eq!(probe.cancel(&url, &service, sleeper).await.unwrap(), 0);
}
