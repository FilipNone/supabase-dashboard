//! `/dashboard/project/:project_id/editor[/:table_id]`: the project's
//! schemas and tables, and for the chosen table either a page of its rows
//! (`Data`, the default) or its columns and foreign keys
//! (`?view=definition`), read through the stack's postgres-meta.
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
    CELL_MAX_CHARS, Cell, ColumnSummary, DEFAULT_SCHEMA, FOREIGN_KEY_LIST_LIMIT, ForeignKey,
    MetaUnavailable, ROW_COLUMN_LIMIT, ROW_PAGE_SIZE, RowOrder, RowPage, SchemaListing,
    TableDefinition, TableListing, TableRelations, TableSummary,
};
use uuid::Uuid;

use crate::{
    components::page::{StatePanel, StateTone},
    error::AppError,
    pages::project::project_path,
    server_fns::{get_table, get_table_rows, list_schemas, list_tables},
};

/// What the main area shows for a chosen table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableView {
    Data,
    Definition,
}

impl TableView {
    fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("definition") => Self::Definition,
            _ => Self::Data,
        }
    }
}

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

/// The address of one table's view. Defaults are left out so the usual
/// address stays short.
fn table_href(project: Uuid, table: u32, schema: &str, view: TableView, page: u32) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if schema != DEFAULT_SCHEMA {
        query.append_pair("schema", schema);
    }
    if view == TableView::Definition {
        query.append_pair("view", "definition");
    }
    if page > 1 {
        query.append_pair("page", &page.to_string());
    }
    let query = query.finish();
    let base = format!("{}/{table}", editor_path(project));
    if query.is_empty() {
        base
    } else {
        format!("{base}?{query}")
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
    let view = Memo::new(move |_| TableView::parse(query.read().get("view").as_deref()));
    // Anything that is not a number asks for page 0, which the server
    // refuses with a readable message.
    let page = Memo::new(move |_| {
        query
            .read()
            .get("page")
            .map_or(1, |raw| raw.parse::<u32>().unwrap_or(0))
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
    // Only the resource for the current view reads the stack.
    let detail = Resource::new(
        move || (project_id.get(), table_param.get(), view.get()),
        |(id, table, view)| async move {
            match (id, table) {
                (Some(_), _) if view != TableView::Definition => Ok(None),
                (Some(id), Some(Some(table))) => get_table(id, table).await.map(Some),
                (Some(_), None) => Ok(None),
                _ => Err(AppError::NotFound),
            }
        },
    );
    let rows = Resource::new(
        move || (project_id.get(), table_param.get(), view.get(), page.get()),
        |(id, table, view, page)| async move {
            match (id, table) {
                (Some(_), _) if view != TableView::Data => Ok(None),
                (Some(id), Some(Some(table))) => get_table_rows(id, table, page).await.map(Some),
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
                            table_list(listing, project, table_param.get().flatten(), view.get()).into_any()
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
                        let Some(Some(table)) = table_param.get() else {
                            let missing = table_param.get().is_some();
                            return Some(no_table(missing).into_any());
                        };
                        let current = view.get();
                        let tabs = view_tabs(project, table, schema.get(), current);
                        let content = match current {
                            TableView::Definition => detail.get().map(|result| match result {
                                Ok(Some(Ok(definition))) => table_view(definition).into_any(),
                                Ok(Some(Err(state))) => unavailable_panel(state, project).into_any(),
                                Ok(None) => ().into_any(),
                                Err(err) => table_error(err).into_any(),
                            }),
                            TableView::Data => rows.get().map(|result| match result {
                                Ok(Some(Ok(page))) => {
                                    rows_view(page, project, schema.get()).into_any()
                                }
                                Ok(Some(Err(state))) => unavailable_panel(state, project).into_any(),
                                Ok(None) => ().into_any(),
                                Err(err) => table_error(err).into_any(),
                            }),
                        }?;
                        Some(view! { {tabs} {content} }.into_any())
                    }}
                </Transition>
            </div>
        </div>
    }
}

fn no_table(missing: bool) -> impl IntoView {
    if missing {
        table_error(AppError::NotFound).into_any()
    } else {
        view! {
            <StatePanel
                tone=StateTone::Empty
                title="Select a table".to_string()
                detail="Choose a table from the list to see its rows and columns.".to_string()
            />
        }
        .into_any()
    }
}

fn table_error(err: AppError) -> impl IntoView {
    view! {
        <StatePanel tone=StateTone::Error title="Table unavailable".to_string() detail=err.to_string()/>
    }
}

fn view_tabs(project: Uuid, table: u32, schema: String, current: TableView) -> impl IntoView {
    let tab = move |view: TableView, label: &'static str| {
        let current = (view == current).then_some("page");
        view! {
            // A plain link: the router's `A` marks every link to the same
            // path as current, and the two views differ only in the query.
            <a href=table_href(project, table, &schema, view, 1) class="tab" aria-current=current>
                {label}
            </a>
        }
    };
    view! {
        <nav class="tabs editor-tabs" aria-label="Table view">
            {tab(TableView::Data, "Data")}
            {tab(TableView::Definition, "Definition")}
        </nav>
    }
}

/// The table's name and row-level security state, shared by both views.
fn table_heading(table: &TableSummary) -> impl IntoView + use<> {
    let rls = if table.rls_enabled {
        view! { <span class="badge badge-ok">"RLS enabled"</span> }.into_any()
    } else {
        view! { <span class="badge badge-error">"RLS disabled"</span> }.into_any()
    };
    let forced = table
        .rls_forced
        .then(|| view! { <span class="badge badge-muted">"RLS forced"</span> });
    view! {
        <div class="section-header">
            <h2 class="section-title" id="table-title">
                <span class="url-text">{format!("{}.{}", table.schema, table.name)}</span>
            </h2>
            <div class="row-actions">{rls} {forced}</div>
        </div>
    }
}

fn rows_view(page: RowPage, project: Uuid, schema: String) -> impl IntoView {
    let number = page.page.get();
    let first_row = page.page.offset() + 1;
    let shown = u32::try_from(page.rows.len()).unwrap_or(ROW_PAGE_SIZE);
    let link = |target: u32| table_href(project, page.table.id, &schema, TableView::Data, target);
    let previous = page.page.previous().map(|p| link(p.get()));
    let next = page
        .has_more
        .then(|| page.page.next().map(|p| link(p.get())))
        .flatten();
    let status = if page.rows.is_empty() {
        format!("Page {number}")
    } else {
        format!("Rows {first_row}–{}", first_row + shown.saturating_sub(1))
    };
    // PostgreSQL's estimate is 0 until the table is first analyzed, and can
    // lag behind; it is left out when the rows on screen already prove it
    // wrong.
    let seen = i64::from(page.page.offset()) + i64::from(shown);
    let estimate = (page.table.live_rows_estimate >= seen).then(|| {
        format!(
            "About {} in total (estimate)",
            page.table.live_rows_estimate
        )
    });
    let pager = view! {
        <nav class="pager" aria-label="Pages">
            <span class="pager-status" role="status">{status}</span>
            {estimate.map(|text| view! { <span class="field-hint">{text}</span> })}
            <span class="pager-links">
                {previous.map(|href| view! { <A href=href attr:class="button">"Previous"</A> })}
                {next.map(|href| view! { <A href=href attr:class="button">"Next"</A> })}
            </span>
        </nav>
    };
    let body = if page.columns.is_empty() {
        view! { <StatePanel tone=StateTone::Empty title="This table has no columns".to_string()/> }
            .into_any()
    } else if page.rows.is_empty() && number == 1 {
        view! { <StatePanel tone=StateTone::Empty title="This table has no rows".to_string()/> }
            .into_any()
    } else if page.rows.is_empty() {
        view! {
            <StatePanel
                tone=StateTone::Empty
                title="No rows on this page".to_string()
                detail="The table has fewer rows than this page starts at.".to_string()
            />
            <p><A href=link(1)>"Go to the first page"</A></p>
        }
        .into_any()
    } else {
        rows_table(&page, first_row).into_any()
    };
    let hidden = (page.hidden_columns > 0).then(|| {
        view! {
            <p class="field-hint">
                {format!(
                    "Only the first {ROW_COLUMN_LIMIT} columns are shown; {} more are left out. The Definition tab lists all of them.",
                    page.hidden_columns
                )}
            </p>
        }
    });
    let unordered = (page.order == RowOrder::Unordered).then(|| {
        view! {
            <p class="field-hint">
                "This table has no primary key, so its rows have no fixed order and pages can overlap or skip rows while the table changes."
            </p>
        }
    });
    view! {
        <div class="editor-heading">{table_heading(&page.table)}</div>
        {pager}
        {body}
        {hidden}
        {unordered}
        <p class="field-hint">
            {format!(
                "Read-only. Values longer than {CELL_MAX_CHARS} characters are cut. Rows are read with postgres-meta's database role, which usually bypasses row-level security."
            )}
        </p>
    }
}

fn rows_table(page: &RowPage, first_row: u32) -> impl IntoView + use<> {
    let last_row = first_row
        + u32::try_from(page.rows.len())
            .unwrap_or(1)
            .saturating_sub(1);
    let headers = page
        .columns
        .iter()
        .map(|column| {
            view! {
                <th scope="col">
                    <span class="col-name">{column.name.clone()}</span>
                    <span class="col-type">{column.type_label.clone()}</span>
                </th>
            }
        })
        .collect_view();
    let rows = page
        .rows
        .iter()
        .map(|row| {
            let cells = row.iter().map(cell_view).collect_view();
            view! { <tr>{cells}</tr> }
        })
        .collect_view();
    view! {
        <div class="table-wrap">
            <table class="data-table rows-table">
                <caption class="visually-hidden">{format!("Rows {first_row} to {last_row}")}</caption>
                <thead><tr>{headers}</tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
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

fn table_list(
    listing: TableListing,
    project: Uuid,
    selected: Option<u32>,
    view: TableView,
) -> impl IntoView {
    if listing.tables.is_empty() {
        return view! {
            <p class="field-hint">{format!("No tables in {}.", listing.schema)}</p>
        }
        .into_any();
    }
    let count = listing.tables.len();
    let items = listing
        .tables
        .into_iter()
        .map(|table| {
            let href = table_href(project, table.id, &listing.schema, view, 1);
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

fn table_view(definition: TableDefinition) -> impl IntoView {
    let detail = definition.detail;
    let table = detail.table;
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
            {table_heading(&table)}
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
            "Row estimates come from PostgreSQL's statistics and can lag behind the table."
        </p>
        {relations_view(definition.relations)}
    }
}

fn relations_view(relations: Result<TableRelations, MetaUnavailable>) -> impl IntoView {
    let body = match relations {
        Err(state) => view! {
            <p class="form-error" role="alert">
                {format!("Foreign keys unavailable: {}. ", state.title())}
                {state.detail()}
            </p>
        }
        .into_any(),
        Ok(relations) => view! {
            {key_table(
                "outgoing-keys",
                "References",
                "This table has no foreign keys.",
                relations.outgoing,
                false,
            )}
            {key_table(
                "incoming-keys",
                "Referenced by",
                "No foreign keys point at this table.",
                relations.incoming,
                true,
            )}
            {relations.truncated.then(|| view! {
                <p class="field-hint">
                    {format!("Only the first {FOREIGN_KEY_LIST_LIMIT} foreign keys are listed.")}
                </p>
            })}
        }
        .into_any(),
    };
    view! {
        <section class="keys-section" aria-labelledby="keys-title">
            <h2 class="section-title" id="keys-title">"Foreign keys"</h2>
            {body}
        </section>
    }
}

/// One direction of foreign keys. `incoming` lists the table each key is
/// on; otherwise the table each key points at.
fn key_table(
    id: &'static str,
    title: &'static str,
    empty: &'static str,
    keys: Vec<ForeignKey>,
    incoming: bool,
) -> impl IntoView {
    let heading = view! { <h3 class="subsection-title" id=id>{title}</h3> };
    if keys.is_empty() {
        return view! { {heading} <p class="field-hint">{empty}</p> }.into_any();
    }
    let rows = keys
        .into_iter()
        .map(|key| {
            let (table, other) = if incoming {
                (
                    format!("{}.{}", key.schema, key.table),
                    key.columns.join(", "),
                )
            } else {
                (
                    format!("{}.{}", key.referenced_schema, key.referenced_table),
                    key.referenced_columns.join(", "),
                )
            };
            let own = if incoming {
                key.referenced_columns.join(", ")
            } else {
                key.columns.join(", ")
            };
            view! {
                <tr>
                    <th scope="row" class="cell-name"><span class="url-text">{key.name}</span></th>
                    <td><span class="url-text">{own}</span></td>
                    <td><span class="url-text">{table}</span></td>
                    <td><span class="url-text">{other}</span></td>
                    <td>{key.on_update.label()}</td>
                    <td>{key.on_delete.label()}</td>
                </tr>
            }
        })
        .collect_view();
    let (own_label, table_label, other_label) = if incoming {
        ("Columns here", "From table", "Its columns")
    } else {
        ("Columns", "Points to", "Target columns")
    };
    view! {
        {heading}
        <div class="table-wrap">
            <table class="data-table keys-table" aria-labelledby=id>
                <thead>
                    <tr>
                        <th scope="col">"Constraint"</th>
                        <th scope="col">{own_label}</th>
                        <th scope="col">{table_label}</th>
                        <th scope="col">{other_label}</th>
                        <th scope="col">"On update"</th>
                        <th scope="col">"On delete"</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    }
    .into_any()
}

fn column_row(column: &ColumnSummary, primary_key: &[String]) -> impl IntoView + use<> {
    let type_name = column.type_label().to_owned();
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
