//! `/dashboard/project/:project_id/editor[/:table_id]`: the project's
//! schemas, tables, and columns, read through the stack's postgres-meta.
//!
//! Read-only for now. Each view reads the stack when it opens; nothing is
//! cached, so what is shown is current as of the page load.

use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::{
    components::A,
    hooks::{use_navigate, use_params_map, use_query_map},
};
use supabase_dashboard_domain::schema::{
    ColumnSummary, DEFAULT_SCHEMA, MetaUnavailable, SchemaListing, TableDetail, TableListing,
};
use uuid::Uuid;

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::project::project_path,
    server_fns::{get_table, list_schemas, list_tables},
};

fn editor_path(project: Uuid) -> String {
    format!("{}/editor", project_path(project))
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn schema_query(schema: &str) -> String {
    if schema == DEFAULT_SCHEMA {
        String::new()
    } else {
        format!("?schema={}", encode(schema))
    }
}

fn unavailable_panel(state: MetaUnavailable, project: Uuid) -> impl IntoView {
    let settings = matches!(
        state,
        MetaUnavailable::NoKey { .. } | MetaUnavailable::KeyRejected { .. }
    )
    .then(|| {
        view! {
            <p><a href=format!("{}/settings", project_path(project))>"Open project settings"</a></p>
        }
    });
    view! {
        <StatePanel tone=StateTone::Error title=state.title().to_owned() detail=state.detail()/>
        {settings}
    }
}

#[component]
pub fn TableEditorPage() -> impl IntoView {
    let params = use_params_map();
    let query = use_query_map();
    let project_id = Memo::new(move |_| {
        params
            .read()
            .get("project_id")
            .and_then(|raw| raw.parse::<Uuid>().ok())
    });
    // `None`: no table chosen. `Some(None)`: a table ID that cannot exist.
    let table_param = Memo::new(move |_| {
        params
            .read()
            .get("table_id")
            .map(|raw| raw.parse::<u32>().ok())
    });
    let schema = Memo::new(move |_| {
        query
            .read()
            .get("schema")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_SCHEMA.to_owned())
    });

    let schemas = Resource::new(
        move || project_id.get(),
        |id| async move {
            match id {
                Some(id) => list_schemas(id).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let tables = Resource::new(
        move || (project_id.get(), schema.get()),
        |(id, schema)| async move {
            match id {
                Some(id) => list_tables(id, schema).await,
                None => Err(AppError::NotFound),
            }
        },
    );
    let detail = Resource::new(
        move || (project_id.get(), table_param.get()),
        |(id, table)| async move {
            match (id, table) {
                (Some(id), Some(Some(table))) => get_table(id, table).await.map(Some),
                (Some(_), None) => Ok(None),
                _ => Err(AppError::NotFound),
            }
        },
    );

    view! {
        <Title text="Table editor"/>
        <div class="editor">
            <aside class="editor-sidebar" aria-label="Schema and tables">
                <Transition fallback=|| view! { <p class="loading" role="status">"Loading schemas…"</p> }>
                    {move || schemas.get().map(|result| match (result, project_id.get()) {
                        (Ok(Ok(listing)), Some(project)) => {
                            schema_picker(listing, schema.get(), project).into_any()
                        }
                        // The main area explains the failure.
                        _ => ().into_any(),
                    })}
                </Transition>
                <Transition fallback=|| view! { <p class="loading" role="status">"Loading tables…"</p> }>
                    {move || tables.get().map(|result| match (result, project_id.get()) {
                        (Ok(Ok(listing)), Some(project)) => {
                            table_list(listing, project, table_param.get().flatten()).into_any()
                        }
                        (Ok(Err(_)), _) => view! {
                            <p class="field-hint">"Tables unavailable."</p>
                        }
                        .into_any(),
                        (Err(err), _) => view! {
                            <p class="form-error" role="alert">{err.to_string()}</p>
                        }
                        .into_any(),
                        (Ok(Ok(_)), None) => ().into_any(),
                    })}
                </Transition>
            </aside>
            <div class="editor-main">
                <Transition fallback=|| view! { <p class="loading" role="status">"Loading…"</p> }>
                    {move || {
                        let project = project_id.get()?;
                        // A stack that cannot list schemas cannot list
                        // anything else either; one explanation is enough.
                        if let Some(Ok(Err(state))) = schemas.get() {
                            return Some(unavailable_panel(state, project).into_any());
                        }
                        detail.get().map(|result| match result {
                            Ok(Some(Ok(detail))) => table_view(detail).into_any(),
                            Ok(Some(Err(state))) => unavailable_panel(state, project).into_any(),
                            Ok(None) => view! {
                                <StatePanel
                                    tone=StateTone::Empty
                                    title="Select a table".to_string()
                                    detail="Choose a table from the list to see its columns.".to_string()
                                />
                            }
                            .into_any(),
                            Err(err) => view! {
                                <StatePanel
                                    tone=StateTone::Error
                                    title="Table unavailable".to_string()
                                    detail=err.to_string()
                                />
                            }
                            .into_any(),
                        })
                    }}
                </Transition>
            </div>
        </div>
    }
}

/// A GET form, so it works before the WASM bundle loads; once hydrated,
/// changing the selection navigates straight away.
fn schema_picker(listing: SchemaListing, current: String, project: Uuid) -> impl IntoView {
    let navigate = use_navigate();
    let action = editor_path(project);
    let known = listing.schemas.iter().any(|s| s.name == current);
    let options = listing
        .schemas
        .into_iter()
        .map(|s| {
            let selected = s.name == current;
            let label = if s.browsable {
                s.name.clone()
            } else {
                format!("{} (cannot be browsed)", s.name)
            };
            view! {
                <option value=s.name.clone() selected=selected disabled=!s.browsable>{label}</option>
            }
        })
        .collect_view();
    let base = action.clone();
    view! {
        <form method="get" action=action class="schema-picker">
            <label class="field">
                <span class="field-label">"Schema"</span>
                <select
                    class="input"
                    name="schema"
                    on:change=move |ev| {
                        let value = event_target_value(&ev);
                        navigate(&format!("{base}{}", schema_query(&value)), Default::default());
                    }
                >
                    {(!known).then(|| view! {
                        <option value=current.clone() selected=true>{current.clone()}</option>
                    })}
                    {options}
                </select>
            </label>
            <noscript><button type="submit" class="button">"Show"</button></noscript>
        </form>
        {listing.truncated.then(|| view! {
            <p class="field-hint">"Only the first 500 schemas are listed."</p>
        })}
    }
}

fn table_list(listing: TableListing, project: Uuid, selected: Option<u32>) -> impl IntoView {
    if listing.tables.is_empty() {
        return view! {
            <p class="field-hint">{format!("No tables in {}.", listing.schema)}</p>
        }
        .into_any();
    }
    let query = schema_query(&listing.schema);
    let base = editor_path(project);
    let count = listing.tables.len();
    let items = listing
        .tables
        .into_iter()
        .map(|table| {
            let href = format!("{base}/{}{query}", table.id);
            let current = (selected == Some(table.id)).then_some("page");
            view! {
                <li>
                    <A href=href attr:class="table-link" attr:aria-current=current>
                        <span class="table-link-name">{table.name}</span>
                        {table.rls_enabled.then(|| view! {
                            <span class="badge badge-muted" title="Row-level security is enabled">"RLS"</span>
                        })}
                    </A>
                </li>
            }
        })
        .collect_view();
    view! {
        <h2 class="subsection-title" id="tables-title">
            {format!("Tables ({count}{})", if listing.truncated { "+" } else { "" })}
        </h2>
        <ul class="table-nav" aria-labelledby="tables-title">{items}</ul>
        {listing.truncated.then(|| view! {
            <p class="field-hint">"Only the first 1000 tables, by name, are listed."</p>
        })}
    }
    .into_any()
}

fn table_view(detail: TableDetail) -> impl IntoView {
    let table = detail.table;
    let rls = if table.rls_enabled {
        view! { <span class="badge badge-ok">"RLS enabled"</span> }.into_any()
    } else {
        view! { <span class="badge badge-error">"RLS disabled"</span> }.into_any()
    };
    let forced = table
        .rls_forced
        .then(|| view! { <span class="badge badge-muted">"RLS forced"</span> });
    let primary_key = if detail.primary_key.is_empty() {
        "None".to_owned()
    } else {
        detail.primary_key.join(", ")
    };
    let rows = detail
        .columns
        .iter()
        .map(|column| column_row(column, &detail.primary_key))
        .collect_view();
    let empty = detail.columns.is_empty().then(|| {
        view! {
            <StatePanel tone=StateTone::Empty title="This table has no columns".to_string()/>
        }
    });
    view! {
        <section class="panel" aria-labelledby="table-title">
            <div class="section-header">
                <h2 class="section-title" id="table-title">
                    <span class="url-text">{format!("{}.{}", table.schema, table.name)}</span>
                </h2>
                <div class="row-actions">{rls} {forced}</div>
            </div>
            {table.comment.map(|comment| view! { <p class="section-text">{comment}</p> })}
            <dl class="detail-list detail-inline">
                <div><dt>"Primary key"</dt><dd>{primary_key}</dd></div>
                <div><dt>"Estimated rows"</dt><dd>{table.live_rows_estimate.to_string()}</dd></div>
                <div><dt>"Size"</dt><dd>{table.size}</dd></div>
            </dl>
        </section>
        {empty}
        {(!detail.columns.is_empty()).then(|| view! {
            <div class="table-wrap">
                <table class="data-table columns-table">
                    <caption class="visually-hidden">"Columns"</caption>
                    <thead>
                        <tr>
                            <th scope="col">"Name"</th>
                            <th scope="col">"Type"</th>
                            <th scope="col">"Default"</th>
                            <th scope="col">"Constraints"</th>
                            <th scope="col">"Description"</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        })}
        <p class="field-hint">
            "Row estimates come from PostgreSQL's statistics and can lag behind the table. Viewing and editing rows is not available yet."
        </p>
    }
}

fn column_row(column: &ColumnSummary, primary_key: &[String]) -> impl IntoView + use<> {
    let type_name = if column.data_type == "USER-DEFINED" || column.data_type == "ARRAY" {
        column.format.clone()
    } else {
        column.data_type.clone()
    };
    let mut constraints = Vec::new();
    if primary_key.contains(&column.name) {
        constraints.push("Primary key".to_owned());
    }
    if !column.nullable {
        constraints.push("Not null".to_owned());
    }
    if column.unique {
        constraints.push("Unique".to_owned());
    }
    if let Some(identity) = column.identity {
        constraints.push(identity.label().to_owned());
    }
    if column.generated {
        constraints.push("Generated".to_owned());
    }
    let badges = constraints
        .into_iter()
        .map(|c| view! { <span class="badge badge-muted">{c}</span> " " })
        .collect_view();
    let enums = (!column.enum_labels.is_empty()).then(|| {
        view! {
            <span class="field-hint status-detail">{column.enum_labels.join(", ")}</span>
        }
    });
    view! {
        <tr>
            <th scope="row" class="cell-name"><span class="url-text">{column.name.clone()}</span></th>
            <td class="cell-type">
                <span class="url-text">{type_name}</span>
                {enums}
            </td>
            <td>
                {column.default_value.clone().map(|d| view! { <code class="url-text">{d}</code> })}
            </td>
            <td>{badges}</td>
            <td>{column.comment.clone()}</td>
        </tr>
    }
}
