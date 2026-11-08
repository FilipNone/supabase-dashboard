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
    CELL_MAX_CHARS, Cell, ColumnSummary, DEFAULT_SCHEMA, FILTER_VALUE_MAX_BYTES,
    FOREIGN_KEY_LIST_LIMIT, FilterOp, ForeignKey, MetaUnavailable, ROW_COLUMN_LIMIT,
    ROW_FILTER_LIMIT, ROW_PAGE_SIZE, RelationKind, RowColumn, RowFilter, RowPage, RowSort,
    SchemaListing, TableDefinition, TableListing, TableRelations, TableSummary, bounded,
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
    editor_href(project, table, schema, view, page, None, &[])
}

/// A page of the Data tab, keeping `sort` and `filters` (address values,
/// as [`RowFilter::to_param`] writes them).
fn rows_href(
    project: Uuid,
    table: u32,
    schema: &str,
    page: u32,
    sort: Option<&RowSort>,
    filters: &[String],
) -> String {
    editor_href(project, table, schema, TableView::Data, page, sort, filters)
}

fn editor_href(
    project: Uuid,
    table: u32,
    schema: &str,
    view: TableView,
    page: u32,
    sort: Option<&RowSort>,
    filters: &[String],
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if schema != DEFAULT_SCHEMA {
        query.append_pair("schema", schema);
    }
    if view == TableView::Definition {
        query.append_pair("view", "definition");
    }
    if let Some(sort) = sort {
        query.append_pair("sort", &sort.column);
        if sort.descending {
            query.append_pair("desc", "1");
        }
    }
    for filter in filters {
        query.append_pair("filter", filter);
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
    // These two are how the relation is, not something that went wrong.
    let tone = match state {
        MetaUnavailable::NotPopulated | MetaUnavailable::ForeignRows => StateTone::Empty,
        _ => StateTone::Error,
    };
    view! {
        <StatePanel tone=tone title=state.title().to_owned() detail=state.detail()/>
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

    let sort = Memo::new(move |_| query.read().get("sort").filter(|s| !s.is_empty()));
    let descending = Memo::new(move |_| query.read().get("desc").as_deref() == Some("1"));
    // The `filter` values as given; the server checks them. Without
    // JavaScript the add-filter form submits the new filter as `fc`, `fo`,
    // and `fv`, which are added here, and links on the page then carry it
    // as a `filter` value.
    let filters = Memo::new(move |_| {
        let query = query.read();
        let mut filters: Vec<String> = query
            .get_all("filter")
            .unwrap_or_default()
            .into_iter()
            .filter(|raw| !raw.is_empty())
            .collect();
        if let Some(column) = query.get("fc").filter(|c| !c.is_empty()) {
            let code = query.get("fo").unwrap_or_default();
            let value = query.get("fv").unwrap_or_default();
            filters.push(match FilterOp::from_code(&code) {
                // Not checked here, so the server reports what is wrong.
                Some(op) => RowFilter { column, op, value }.to_param(),
                None => format!("{column}:{code}:{value}"),
            });
        }
        filters
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
        move || {
            (
                project_id.get(),
                table_param.get(),
                view.get(),
                page.get(),
                sort.get(),
                descending.get(),
                filters.get(),
            )
        },
        |(id, table, view, page, sort, descending, filters)| async move {
            match (id, table) {
                (Some(_), _) if view != TableView::Data => Ok(None),
                (Some(id), Some(Some(table))) => {
                    get_table_rows(id, table, page, sort, descending, filters)
                        .await
                        .map(Some)
                }
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
                            TableView::Data => rows.get().map(|result| {
                                let columns = match &result {
                                    Ok(Some(Ok(page))) => Some(page.columns.clone()),
                                    Ok(None) => return ().into_any(),
                                    _ => None,
                                };
                                let current_sort = sort
                                    .get()
                                    .and_then(|column| RowSort::new(&column, descending.get()).ok());
                                let bar = filter_bar(FilterBar {
                                    project,
                                    table,
                                    schema: schema.get(),
                                    sort: current_sort,
                                    filters: filters.get(),
                                    columns,
                                });
                                let content = match result {
                                    Ok(Some(Ok(page))) => {
                                        rows_view(page, project, schema.get()).into_any()
                                    }
                                    Ok(Some(Err(state))) => {
                                        unavailable_panel(state, project).into_any()
                                    }
                                    Ok(None) => ().into_any(),
                                    Err(err) => table_error(err).into_any(),
                                };
                                view! { {bar} {content} }.into_any()
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
/// What the filter bar above the Data tab needs.
struct FilterBar {
    project: Uuid,
    table: u32,
    schema: String,
    sort: Option<RowSort>,
    /// The address's `filter` values, as given.
    filters: Vec<String>,
    /// The page's columns when the rows were read. Without them only the
    /// applied filters are listed, so a filter that broke the read can be
    /// removed.
    columns: Option<Vec<RowColumn>>,
}

/// Longest filter value shown in the list of applied filters.
const FILTER_LABEL_MAX_CHARS: usize = 60;

fn filter_bar(bar: FilterBar) -> impl IntoView {
    let FilterBar {
        project,
        table,
        schema,
        sort,
        filters,
        columns,
    } = bar;
    let href = |filters: &[String]| rows_href(project, table, &schema, 1, sort.as_ref(), filters);
    let applied = filters
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let label = match RowFilter::parse_param(raw) {
                Ok(filter) if filter.op.takes_value() => format!(
                    "{} {} \"{}\"",
                    filter.column,
                    filter.op.label(),
                    bounded(&filter.value, FILTER_LABEL_MAX_CHARS)
                ),
                Ok(filter) => format!("{} {}", filter.column, filter.op.label()),
                Err(_) => bounded(raw, FILTER_LABEL_MAX_CHARS),
            };
            let mut rest = filters.clone();
            rest.remove(i);
            let remove = href(&rest);
            let action = format!("Remove filter {label}");
            view! {
                <li class="filter-chip">
                    <span class="url-text">{label}</span>
                    <A href=remove attr:class="filter-remove" attr:aria-label=action>"×"</A>
                </li>
            }
        })
        .collect_view();
    let clear = (filters.len() > 1).then(|| {
        let none = href(&[]);
        view! { <A href=none attr:class="filter-clear">"Clear filters"</A> }
    });
    let list = (!filters.is_empty()).then(|| {
        view! {
            <ul class="filter-list" aria-label="Applied filters">{applied}</ul>
            {clear}
        }
    });
    let form = match columns {
        Some(columns) if !columns.is_empty() && filters.len() < ROW_FILTER_LIMIT => Some(
            add_filter_form(
                project,
                table,
                schema.clone(),
                sort.clone(),
                filters.clone(),
                columns,
            )
            .into_any(),
        ),
        Some(_) if filters.len() >= ROW_FILTER_LIMIT => Some(
            view! {
                <p class="field-hint">
                    {format!("At most {ROW_FILTER_LIMIT} filters can be applied.")}
                </p>
            }
            .into_any(),
        ),
        _ => None,
    };
    view! {
        <section class="filter-bar" aria-label="Filters">
            {list}
            {form}
        </section>
    }
}

/// Adds a filter and goes to the first page. Without JavaScript the form
/// submits as a GET with the new filter in `fc`, `fo`, and `fv`; once the
/// page is interactive it goes straight to the address with every filter
/// as a `filter` value.
fn add_filter_form(
    project: Uuid,
    table: u32,
    schema: String,
    sort: Option<RowSort>,
    filters: Vec<String>,
    columns: Vec<RowColumn>,
) -> impl IntoView {
    let navigate = use_navigate();
    let column_ref = NodeRef::<leptos::html::Select>::new();
    let op_ref = NodeRef::<leptos::html::Select>::new();
    let value_ref = NodeRef::<leptos::html::Input>::new();
    let action = format!("{}/{table}", editor_path(project));
    let hidden_schema = (schema != DEFAULT_SCHEMA)
        .then(|| view! { <input type="hidden" name="schema" value=schema.clone()/> });
    let hidden_sort = sort.as_ref().map(|sort| {
        view! {
            <input type="hidden" name="sort" value=sort.column.clone()/>
            {sort.descending.then(|| view! { <input type="hidden" name="desc" value="1"/> })}
        }
    });
    let hidden_filters = filters
        .iter()
        .map(|raw| view! { <input type="hidden" name="filter" value=raw.clone()/> })
        .collect_view();
    let column_options = columns
        .into_iter()
        .map(|column| {
            let label = column.name.clone();
            view! { <option value=column.name>{label}</option> }
        })
        .collect_view();
    let op_options = FilterOp::ALL
        .into_iter()
        .map(|op| view! { <option value=op.code()>{op.label()}</option> })
        .collect_view();
    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        let (Some(column), Some(op), Some(value)) =
            (column_ref.get(), op_ref.get(), value_ref.get())
        else {
            return;
        };
        let Some(op) = FilterOp::from_code(&op.value()) else {
            return;
        };
        ev.prevent_default();
        let mut next = filters.clone();
        // Checked by the server, which explains what is wrong.
        next.push(
            RowFilter {
                column: column.value(),
                op,
                value: value.value(),
            }
            .to_param(),
        );
        navigate(
            &rows_href(project, table, &schema, 1, sort.as_ref(), &next),
            Default::default(),
        );
    };
    view! {
        <form method="get" action=action class="filter-form" on:submit=on_submit>
            {hidden_schema}
            {hidden_sort}
            {hidden_filters}
            <label class="field">
                <span class="field-label">"Column"</span>
                <select class="input" name="fc" node_ref=column_ref>{column_options}</select>
            </label>
            <label class="field">
                <span class="field-label">"Operator"</span>
                <select class="input" name="fo" node_ref=op_ref>{op_options}</select>
            </label>
            <label class="field filter-value">
                <span class="field-label">"Value"</span>
                <input
                    class="input"
                    name="fv"
                    maxlength=FILTER_VALUE_MAX_BYTES.to_string()
                    autocomplete="off"
                    node_ref=value_ref
                />
            </label>
            <button type="submit" class="button">"Add filter"</button>
        </form>
        <p class="field-hint">
            "Filters combine with AND. like and ilike compare the value as text, where % matches any run of characters. is null and is not null take no value."
        </p>
    }
}

fn table_heading(table: &TableSummary) -> impl IntoView + use<> {
    let rls = if !table.kind.is_table() {
        view! { <span class="badge badge-muted">{table.kind.label()}</span> }.into_any()
    } else if table.rls_enabled {
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
    let sort = page.order.sort();
    let filters: Vec<String> = page.filters.iter().map(RowFilter::to_param).collect();
    let link = |target: u32| {
        rows_href(
            project,
            page.table.id,
            &schema,
            target,
            sort.as_ref(),
            &filters,
        )
    };
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
    let sorted = sort.as_ref().map(|sort| {
        let direction = if sort.descending { "descending" } else { "ascending" };
        let clear = rows_href(project, page.table.id, &schema, 1, None, &filters);
        view! {
            <span class="field-hint">
                "Sorted by " <span class="url-text">{sort.column.clone()}</span> {format!(", {direction}. ")}
                <A href=clear>"Clear sort"</A>
            </span>
        }
    });
    let pager = view! {
        <nav class="pager" aria-label="Pages">
            <span class="pager-status" role="status">{status}</span>
            {estimate.map(|text| view! { <span class="field-hint">{text}</span> })}
            {sorted}
            <span class="pager-links">
                {previous.map(|href| view! { <A href=href attr:class="button">"Previous"</A> })}
                {next.map(|href| view! { <A href=href attr:class="button">"Next"</A> })}
            </span>
        </nav>
    };
    let body = if page.columns.is_empty() {
        view! { <StatePanel tone=StateTone::Empty title="This table has no columns".to_string()/> }
            .into_any()
    } else if page.rows.is_empty() && number == 1 && !filters.is_empty() {
        view! {
            <StatePanel
                tone=StateTone::Empty
                title="No rows match the filters".to_string()
                detail="Change or remove a filter above.".to_string()
            />
        }
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
        rows_table(&page, first_row, |column, descending| {
            let sort = column.map(|column| RowSort {
                column: column.to_owned(),
                descending,
            });
            rows_href(project, page.table.id, &schema, 1, sort.as_ref(), &filters)
        })
        .into_any()
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
    let unordered = page.order.is_unstable().then(|| {
        let reason = if page.table.kind.is_table() {
            "This table has no primary key"
        } else {
            "Views have no primary key"
        };
        let rows = if sort.is_some() {
            "rows with equal values in the sorted column"
        } else {
            "the rows"
        };
        view! {
            <p class="field-hint">
                {format!("{reason}, so {rows} have no fixed order and pages can overlap or skip rows while the data changes.")}
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

/// `href(column, descending)` links to the first page sorted that way, or
/// unsorted for `None`. Each header cycles through ascending, descending,
/// and back to the default order.
fn rows_table<F: Fn(Option<&str>, bool) -> String>(
    page: &RowPage,
    first_row: u32,
    href: F,
) -> impl IntoView + use<F> {
    let last_row = first_row
        + u32::try_from(page.rows.len())
            .unwrap_or(1)
            .saturating_sub(1);
    let current = page.order.sort();
    let headers = page
        .columns
        .iter()
        .map(|column| {
            let state = current
                .as_ref()
                .filter(|sort| sort.column == column.name)
                .map(|sort| sort.descending);
            let (aria, mark, action, target) = match state {
                None => (None, "", "sort ascending", href(Some(&column.name), false)),
                Some(false) => (
                    Some("ascending"),
                    "↑",
                    "sort descending",
                    href(Some(&column.name), true),
                ),
                Some(true) => (Some("descending"), "↓", "clear sort", href(None, false)),
            };
            // The link's children are built later, so they own their text.
            let name = column.name.clone();
            let type_label = column.type_label.clone();
            let action = format!(", {action}");
            view! {
                <th scope="col" aria-sort=aria>
                    <A href=target attr:class="sort-link">
                        <span class="col-name">
                            {name}
                            <span class="sort-mark" aria-hidden="true">{mark}</span>
                        </span>
                        <span class="col-type">{type_label}</span>
                        <span class="visually-hidden">{action}</span>
                    </A>
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
                        {kind_badge(table.kind)}
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

/// A short marker for entries that are not plain tables. The full kind is
/// in the title and in the accessible name.
fn kind_badge(kind: RelationKind) -> Option<impl IntoView + use<>> {
    let short = match kind {
        RelationKind::Table => return None,
        RelationKind::View => "View",
        RelationKind::MaterializedView { .. } => "Mat. view",
        RelationKind::ForeignTable => "Foreign",
    };
    Some(view! {
        <span class="badge badge-muted" title=kind.label() aria-label=kind.label()>{short}</span>
    })
}

fn table_view(definition: TableDefinition) -> impl IntoView {
    let detail = definition.detail;
    let table = detail.table;
    let is_table = table.kind.is_table();
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
                {if table.kind.is_table() {
                    view! {
                        <div><dt>"Primary key"</dt><dd>{primary_key}</dd></div>
                        <div><dt>"Estimated rows"</dt><dd>{table.live_rows_estimate.to_string()}</dd></div>
                        <div><dt>"Size"</dt><dd>{table.size}</dd></div>
                    }
                    .into_any()
                } else {
                    let populated = match table.kind {
                        RelationKind::MaterializedView { populated } => {
                            Some(if populated { "Yes" } else { "No, never refreshed" })
                        }
                        _ => None,
                    };
                    view! {
                        <div><dt>"Kind"</dt><dd>{table.kind.label()}</dd></div>
                        {populated.map(|p| view! { <div><dt>"Populated"</dt><dd>{p}</dd></div> })}
                    }
                    .into_any()
                }}
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
        {is_table.then(|| view! {
            <p class="field-hint">
                "Row estimates come from PostgreSQL's statistics and can lag behind the table."
            </p>
        })}
        {is_table.then(|| relations_view(definition.relations))}
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
