//! `/dashboard/project/:project_id/sql`: run SQL on the project's database.
//!
//! The SQL runs on the server through the stack's postgres-meta, with a
//! database-side statement timeout. Results are cut to a fixed number of
//! rows, columns, and characters per value. Read-only members see a
//! permission notice instead of the editor.

use leptos::{ev, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::{
    authz::Permission,
    schema::{Cell, MetaUnavailable},
    sql::{
        SQL_RESULT_COLUMN_LIMIT, SQL_RESULT_ROW_LIMIT, SQL_STATEMENT_TIMEOUT_SECS, SqlFailure,
        SqlOutcome, SqlResult,
    },
};
use uuid::Uuid;

use crate::{
    components::page::{StatePanel, StateTone},
    pages::project::{ProjectContext, loaded_project, project_path},
    server_fns::{CancelSql, RunSql},
};

#[component]
pub fn SqlEditorPage() -> impl IntoView {
    let Some(ctx) = use_context::<ProjectContext>() else {
        return ().into_any();
    };
    view! {
        <Title text="SQL editor"/>
        {move || loaded_project(ctx).map(|project| {
            if project.role.allows(Permission::SqlExecute) {
                view! { <SqlEditor project_id=project.id/> }.into_any()
            } else {
                view! {
                    <StatePanel
                        tone=StateTone::Error
                        title="Your role cannot run SQL".to_string()
                        detail="Read-only members can browse tables in the table editor. SQL runs as a privileged database user, so it is limited to owners, administrators, and developers.".to_string()
                    />
                }
                .into_any()
            }
        })}
    }
    .into_any()
}

#[component]
fn SqlEditor(project_id: Uuid) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let run = ServerAction::<RunSql>::new();
    let cancel = ServerAction::<CancelSql>::new();
    let pending = run.pending();
    let start = move || {
        if pending.get_untracked() {
            return;
        }
        cancel.clear();
        run.dispatch(RunSql {
            id: project_id,
            sql: text.get_untracked(),
        });
    };
    let on_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        start();
    };
    let on_keydown = move |ev: ev::KeyboardEvent| {
        if ev.key() == "Enter" && (ev.ctrl_key() || ev.meta_key()) {
            ev.prevent_default();
            start();
        }
    };
    let stop = move |_| {
        cancel.dispatch(CancelSql { id: project_id });
    };
    let cancel_note = move || {
        cancel.value().get().map(|answer| {
            let text = match answer {
                Ok(Ok(0)) => "Nothing was running any more.".to_owned(),
                Ok(Ok(_)) => "Cancel sent; the database is stopping the query.".to_owned(),
                Ok(Err(state)) => format!("Could not cancel: {}", state.title()),
                Err(err) => format!("Could not cancel: {err}"),
            };
            view! { <p class="field-hint" role="status">{text}</p> }
        })
    };

    view! {
        <section class="panel sql-editor" aria-labelledby="sql-title">
            <h2 class="section-title" id="sql-title">"SQL editor"</h2>
            <form class="stacked-form" on:submit=on_submit>
                <label class="field">
                    <span class="field-label">"Query"</span>
                    <textarea
                        class="input sql-input"
                        name="sql"
                        rows="10"
                        spellcheck="false"
                        autocomplete="off"
                        autocapitalize="off"
                        aria-describedby="sql-hint"
                        prop:value=move || text.get()
                        on:input=move |ev| text.set(event_target_value(&ev))
                        on:keydown=on_keydown
                    ></textarea>
                    <span class="field-hint" id="sql-hint">
                        {format!(
                            "Runs as written, as the database user postgres-meta connects with, in its own connection. The database stops a statement after {SQL_STATEMENT_TIMEOUT_SECS} seconds. The rows of the last statement that returned any are shown, up to {SQL_RESULT_ROW_LIMIT}. Ctrl+Enter or ⌘+Enter runs the query."
                        )}
                    </span>
                </label>
                <div class="sql-actions">
                    <button type="submit" class="button button-primary" disabled=move || pending.get()>
                        {move || if pending.get() { "Running…" } else { "Run" }}
                    </button>
                    <Show when=move || pending.get()>
                        <button type="button" class="button button-danger" on:click=stop>
                            "Cancel"
                        </button>
                    </Show>
                </div>
            </form>
            {cancel_note}
        </section>
        <div class="sql-output" aria-live="polite" aria-busy=move || pending.get().to_string()>
            {move || {
                if pending.get() {
                    return view! { <p class="loading" role="status">"Running query…"</p> }.into_any();
                }
                match run.value().get() {
                    None => ().into_any(),
                    Some(Err(err)) => {
                        view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
                    }
                    Some(Ok(outcome)) => outcome_view(outcome, project_id).into_any(),
                }
            }}
        </div>
    }
}

fn outcome_view(outcome: SqlOutcome, project_id: Uuid) -> impl IntoView {
    match outcome {
        Ok(result) => result_view(result).into_any(),
        Err(failure) => failure_view(failure, project_id).into_any(),
    }
}

fn failure_view(failure: SqlFailure, project_id: Uuid) -> impl IntoView {
    let settings = matches!(
        failure,
        SqlFailure::Unavailable {
            reason: MetaUnavailable::NoKey { .. } | MetaUnavailable::KeyRejected { .. }
        }
    )
    .then(|| {
        view! {
            <p><a href=format!("{}/settings", project_path(project_id))>"Open project settings"</a></p>
        }
    });
    match failure {
        // The database's text keeps its line breaks and the caret under
        // the failing position, so it is shown as preformatted text.
        SqlFailure::Database { code, message } => view! {
            <div class="state-panel state-error sql-error" role="alert">
                <p class="state-title">
                    "The query failed"
                    {code.map(|code| view! { " " <code>{code}</code> })}
                </p>
                <pre class="sql-error-text">{message}</pre>
            </div>
        }
        .into_any(),
        failure => {
            let tone = match failure {
                SqlFailure::Cancelled => StateTone::Empty,
                _ => StateTone::Error,
            };
            view! {
                <StatePanel tone=tone title=failure.title().to_owned() detail=failure.detail()/>
                {settings}
            }
            .into_any()
        }
    }
}

fn result_view(result: SqlResult) -> impl IntoView {
    let timing = format!("{} ms", result.elapsed_ms);
    if result.columns.is_empty() {
        return view! {
            <div class="state-panel" role="status">
                <p class="state-title">"Success. No rows returned."</p>
                <p class="state-detail">{timing}</p>
            </div>
        }
        .into_any();
    }
    let rows_label = match result.row_count {
        1 => "1 row".to_owned(),
        n => format!("{n} rows"),
    };
    let cut_rows = result.rows_cut().then(|| {
        format!(
            "Only the first {} rows are shown. Add a LIMIT or ORDER BY to choose which.",
            result.rows.len()
        )
    });
    let cut_columns = (result.hidden_columns > 0).then(|| {
        format!(
            "Only the first {SQL_RESULT_COLUMN_LIMIT} columns are shown; {} more were returned.",
            result.hidden_columns
        )
    });
    let header = result
        .columns
        .iter()
        .map(|name| view! { <th scope="col">{name.clone()}</th> })
        .collect_view();
    let body = result
        .rows
        .iter()
        .map(|row| {
            let cells = row.iter().map(cell_view).collect_view();
            view! { <tr>{cells}</tr> }
        })
        .collect_view();
    view! {
        <p class="sql-summary" role="status">
            <span>{rows_label}</span>
            <span class="field-hint">{timing}</span>
        </p>
        {cut_rows.map(|text| view! { <p class="field-hint">{text}</p> })}
        {cut_columns.map(|text| view! { <p class="field-hint">{text}</p> })}
        <div class="table-wrap">
            <table class="data-table rows-table">
                <caption class="visually-hidden">"Query result"</caption>
                <thead><tr>{header}</tr></thead>
                <tbody>{body}</tbody>
            </table>
        </div>
    }
    .into_any()
}

fn cell_view(cell: &Option<Cell>) -> impl IntoView + use<> {
    match cell {
        None => view! { <td><span class="cell-null">"NULL"</span></td> }.into_any(),
        Some(cell) => {
            let text = if cell.truncated {
                format!("{}…", cell.text)
            } else {
                cell.text.clone()
            };
            let note = cell.truncated.then_some("Value cut for display");
            view! { <td title=note>{text}</td> }.into_any()
        }
    }
}
