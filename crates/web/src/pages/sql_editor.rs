//! `/dashboard/project/:project_id/sql`: run SQL on the project's database.
//!
//! The SQL runs on the server through the stack's postgres-meta, with a
//! database-side statement timeout. Results are cut to a fixed number of
//! rows, columns, and characters per value. Read-only members see a
//! permission notice instead of the editor.
//!
//! The side list holds saved snippets: the member's own and the ones
//! shared with the project. Snippets are stored by the dashboard, not by
//! the stack.

use leptos::{ev, prelude::*};
use leptos_meta::Title;
use supabase_dashboard_domain::{
    authz::{OrgRole, Permission},
    schema::{Cell, MetaUnavailable},
    snippet::{SNIPPET_LIST_LIMIT, SNIPPET_NAME_MAX_CHARS, SnippetList, SnippetVisibility},
    sql::{
        SQL_RESULT_COLUMN_LIMIT, SQL_RESULT_ROW_LIMIT, SQL_STATEMENT_TIMEOUT_SECS, SqlFailure,
        SqlOutcome, SqlResult,
    },
};
use uuid::Uuid;

use crate::{
    components::{
        dialog::{ConfirmDialog, DialogCancel},
        page::{StatePanel, StateTone},
    },
    pages::project::{ProjectContext, loaded_project, project_path},
    server_fns::{CancelSql, DeleteSnippet, GetSnippet, RunSql, SaveSnippet, list_snippets},
};

/// The snippet loaded into the editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenSnippet {
    id: Uuid,
    /// The caller wrote it, so saving replaces it.
    mine: bool,
    shared: bool,
}

#[component]
pub fn SqlEditorPage() -> impl IntoView {
    let Some(ctx) = use_context::<ProjectContext>() else {
        return ().into_any();
    };
    view! {
        <Title text="SQL editor"/>
        {move || loaded_project(ctx).map(|project| {
            if project.role.allows(Permission::SqlExecute) {
                view! { <SqlEditor project_id=project.id role=project.role/> }.into_any()
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
fn SqlEditor(project_id: Uuid, role: OrgRole) -> impl IntoView {
    let text = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let visibility = RwSignal::new(SnippetVisibility::Private);
    let open = RwSignal::new(None::<OpenSnippet>);
    let load = ServerAction::<GetSnippet>::new();
    let save = ServerAction::<SaveSnippet>::new();
    let remove = ServerAction::<DeleteSnippet>::new();
    let snippets = Resource::new(
        move || (save.version().get(), remove.version().get()),
        move |_| list_snippets(project_id),
    );
    Effect::new(move |_| {
        if let Some(Ok(snippet)) = load.value().get() {
            let summary = snippet.summary;
            text.set(snippet.content);
            name.set(summary.name.into());
            visibility.set(summary.visibility);
            open.set(Some(OpenSnippet {
                id: summary.id,
                mine: summary.mine,
                shared: summary.visibility == SnippetVisibility::Project,
            }));
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(id)) = save.value().get() {
            open.set(Some(OpenSnippet {
                id,
                mine: true,
                shared: visibility.get_untracked() == SnippetVisibility::Project,
            }));
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(())) = remove.value().get() {
            open.set(None);
        }
    });
    let open_snippet = move |snippet_id: Uuid| {
        save.clear();
        remove.clear();
        load.dispatch(GetSnippet {
            id: project_id,
            snippet_id,
        });
    };
    let new_query = move |_| {
        load.clear();
        save.clear();
        remove.clear();
        open.set(None);
        text.set(String::new());
        name.set(String::new());
        visibility.set(SnippetVisibility::Private);
    };
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

    let sidebar = view! {
        <aside class="panel sql-snippets" aria-labelledby="snippets-title">
            <div class="sql-snippets-head">
                <h2 class="section-title" id="snippets-title">"Snippets"</h2>
                <button type="button" class="button" on:click=new_query>"New query"</button>
            </div>
            <Transition fallback=|| view! { <p class="loading" role="status">"Loading snippets…"</p> }>
                {move || snippets.get().map(|answer| match answer {
                    Ok(list) => snippet_list(list, open, open_snippet).into_any(),
                    Err(err) => view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any(),
                })}
            </Transition>
            {move || load.value().get().and_then(Result::err).map(|err| view! {
                <p class="form-error" role="alert">{err.to_string()}</p>
            })}
        </aside>
    }
    .into_any();
    let editor = view! {
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
            <SnippetSave project_id role text name visibility open save remove/>
        </section>
    }
    .into_any();
    let output = view! {
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
    .into_any();
    view! {
        <div class="sql-layout">
            {sidebar}
            <div class="sql-main">{editor}{output}</div>
        </div>
    }
}

/// The snippet list, shared ones first, each a button that loads it.
fn snippet_list(
    list: SnippetList,
    open: RwSignal<Option<OpenSnippet>>,
    open_snippet: impl Fn(Uuid) + Copy + Send + Sync + 'static,
) -> impl IntoView {
    if list.items.is_empty() {
        return view! {
            <p class="field-hint">"No snippets yet. Save a query to keep it here."</p>
        }
        .into_any();
    }
    let (shared, private): (Vec<_>, Vec<_>) = list
        .items
        .into_iter()
        .partition(|item| item.visibility == SnippetVisibility::Project);
    let group =
        move |title: &'static str,
              items: Vec<supabase_dashboard_domain::snippet::SnippetSummary>| {
            (!items.is_empty()).then(|| {
                let entries = items
                .into_iter()
                .map(|item| {
                    let id = item.id;
                    let author = (!item.mine).then(|| {
                        view! { <span class="snippet-author">{item.author.clone()}</span> }
                    });
                    view! {
                        <li>
                            <button
                                type="button"
                                class="snippet-link"
                                aria-current=move || {
                                    (open.get().map(|o| o.id) == Some(id)).then_some("true")
                                }
                                on:click=move |_| open_snippet(id)
                            >
                                <span class="snippet-name">{item.name.as_str().to_owned()}</span>
                                {author}
                            </button>
                        </li>
                    }
                })
                .collect_view();
                view! {
                    <h3 class="snippet-group">{title}</h3>
                    <ul class="snippet-items">{entries}</ul>
                }
            })
        };
    let cut = list.truncated.then(|| {
        view! {
            <p class="field-hint">{format!("Only the first {SNIPPET_LIST_LIMIT} snippets are listed.")}</p>
        }
    });
    view! {
        {group("Shared", shared)}
        {group("Private", private)}
        {cut}
    }
    .into_any()
}

/// Saves the editor's text as a snippet, and deletes the open one.
#[component]
fn SnippetSave(
    project_id: Uuid,
    role: OrgRole,
    text: RwSignal<String>,
    name: RwSignal<String>,
    visibility: RwSignal<SnippetVisibility>,
    open: RwSignal<Option<OpenSnippet>>,
    save: ServerAction<SaveSnippet>,
    remove: ServerAction<DeleteSnippet>,
) -> impl IntoView {
    let on_save = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        remove.clear();
        // Someone else's snippet is saved as a new one of the caller's.
        let snippet_id = open.get_untracked().filter(|o| o.mine).map(|o| o.id);
        save.dispatch(SaveSnippet {
            id: project_id,
            snippet_id,
            name: name.get_untracked(),
            visibility: visibility.get_untracked(),
            sql: text.get_untracked(),
        });
    };
    let on_delete = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if let Some(snippet) = open.get_untracked() {
            save.clear();
            remove.dispatch(DeleteSnippet {
                id: project_id,
                snippet_id: snippet.id,
            });
        }
    };
    let may_delete = move || {
        open.get()
            .is_some_and(|o| o.mine || (o.shared && role.allows(Permission::SqlSnippetsManage)))
    };
    let save_label = move || match open.get() {
        Some(o) if o.mine => "Save snippet",
        Some(_) => "Save as my snippet",
        None => "Save as snippet",
    };
    let status = move || {
        if save.pending().get() || remove.pending().get() {
            return None;
        }
        let saved = save
            .value()
            .get()
            .map(|answer| answer.map(|_| "Snippet saved."));
        let deleted = remove
            .value()
            .get()
            .map(|answer| answer.map(|()| "Snippet deleted."));
        saved.or(deleted).map(|answer| match answer {
            Ok(text) => view! { <p class="form-ok" role="status">{text}</p> }.into_any(),
            Err(err) => {
                view! { <p class="form-error" role="alert">{err.to_string()}</p> }.into_any()
            }
        })
    };
    view! {
        <form class="sql-save" on:submit=on_save aria-label="Save as snippet">
            <label class="field">
                <span class="field-label">"Snippet name"</span>
                <input
                    class="input"
                    name="name"
                    required
                    maxlength=SNIPPET_NAME_MAX_CHARS.to_string()
                    autocomplete="off"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
            </label>
            <label class="field">
                <span class="field-label">"Visible to"</span>
                <select
                    class="input"
                    name="visibility"
                    prop:value=move || visibility.get().as_str()
                    on:change=move |ev| {
                        if let Some(v) = SnippetVisibility::parse(&event_target_value(&ev)) {
                            visibility.set(v);
                        }
                    }
                >
                    {[SnippetVisibility::Private, SnippetVisibility::Project]
                        .into_iter()
                        .map(|v| view! {
                            <option value=v.as_str() selected=move || visibility.get() == v>{v.label()}</option>
                        })
                        .collect_view()}
                </select>
            </label>
            <div class="sql-actions">
                <button type="submit" class="button" disabled=move || save.pending().get()>
                    {save_label}
                </button>
                <Show when=may_delete>
                    <ConfirmDialog trigger="Delete snippet" title="Delete this snippet?">
                        <form class="dialog-form" on:submit=on_delete>
                            <p>{move || format!(
                                "“{}” is removed for everyone who can see it. Nothing on the project's database changes.",
                                name.get()
                            )}</p>
                            <div class="dialog-actions">
                                <DialogCancel/>
                                <button type="submit" class="button button-danger">"Delete snippet"</button>
                            </div>
                        </form>
                    </ConfirmDialog>
                </Show>
            </div>
        </form>
        {status}
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
