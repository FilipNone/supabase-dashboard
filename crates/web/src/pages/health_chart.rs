//! A project's kept health checks as a grid of UTC days by hours.
//!
//! Each cell is one hour: no check, checks that all passed, or at least one
//! check with a failing service. The grid is a picture; the table under it
//! carries the same counts per day for screen readers and keyboard users.

use leptos::prelude::*;
use time::{Date, Duration, OffsetDateTime, UtcOffset};

use supabase_dashboard_domain::connection::{HEALTH_HISTORY_RETENTION_DAYS, HealthHour};

/// One hour of the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cell {
    /// Before the kept period or after the history was read.
    Outside,
    NoCheck,
    Healthy {
        checks: u32,
    },
    Failing {
        checks: u32,
        failing: u32,
    },
}

/// One UTC day of the grid, hours 00 to 23.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChartDay {
    pub date: Date,
    pub cells: [Cell; 24],
}

impl ChartDay {
    fn checks(&self) -> u32 {
        self.cells.iter().map(|cell| cell.counts().0).sum()
    }

    fn failing(&self) -> u32 {
        self.cells.iter().map(|cell| cell.counts().1).sum()
    }
}

impl Cell {
    fn counts(self) -> (u32, u32) {
        match self {
            Cell::Outside | Cell::NoCheck => (0, 0),
            Cell::Healthy { checks } => (checks, 0),
            Cell::Failing { checks, failing } => (checks, failing),
        }
    }
}

/// Lays the hourly counts out by UTC day, newest day first, covering the
/// `days` before `read_at`. Hours after `read_at` or wholly before the
/// period are `Outside`. Counts for hours outside the period are ignored.
pub(crate) fn chart_days(
    hours: &[HealthHour],
    read_at: OffsetDateTime,
    days: u16,
) -> Vec<ChartDay> {
    let read_at = read_at.to_offset(UtcOffset::UTC);
    let start = read_at - Duration::days(i64::from(days));
    let mut out = Vec::new();
    let mut date = read_at.date();
    loop {
        let midnight = date.midnight().assume_utc();
        let mut cells = [Cell::Outside; 24];
        for (hour, cell) in (0_i64..).zip(cells.iter_mut()) {
            let from = midnight + Duration::hours(hour);
            let to = from + Duration::hours(1);
            if to <= start || from > read_at {
                continue;
            }
            *cell = match hours.iter().find(|h| h.hour == from) {
                None => Cell::NoCheck,
                Some(h) if h.failing == 0 => Cell::Healthy { checks: h.checks },
                Some(h) => Cell::Failing {
                    checks: h.checks,
                    failing: h.failing,
                },
            };
        }
        out.push(ChartDay { date, cells });
        if midnight <= start {
            break;
        }
        match date.previous_day() {
            Some(previous) => date = previous,
            None => break,
        }
    }
    out
}

fn short_date(date: Date) -> String {
    let month = date.month().to_string();
    format!("{} {}", month.get(..3).unwrap_or(&month), date.day())
}

fn cell_title(date: Date, hour: usize, cell: Cell) -> String {
    let when = format!(
        "{} {hour:02}:00 to {:02}:00 UTC",
        short_date(date),
        hour + 1
    );
    match cell {
        Cell::Outside => String::new(),
        Cell::NoCheck => format!("{when}: no check"),
        Cell::Healthy { checks } => format!(
            "{when}: {checks} {}, no failures",
            if checks == 1 { "check" } else { "checks" }
        ),
        Cell::Failing { checks, failing } => {
            format!("{when}: {failing} of {checks} found a failing service")
        }
    }
}

fn cell_class(cell: Cell) -> &'static str {
    match cell {
        Cell::Outside => "hour-cell",
        Cell::NoCheck => "hour-cell hour-cell-none",
        Cell::Healthy { .. } => "hour-cell hour-cell-ok",
        Cell::Failing { .. } => "hour-cell hour-cell-fail",
    }
}

/// The grid, its legend, and a per-day table.
pub(crate) fn health_chart(hours: Vec<HealthHour>, read_at: OffsetDateTime) -> impl IntoView {
    let days = chart_days(&hours, read_at, HEALTH_HISTORY_RETENTION_DAYS);
    let failing_days = days.iter().filter(|day| day.failing() > 0).count();
    let label = format!(
        "Checks per hour over the last {HEALTH_HISTORY_RETENTION_DAYS} days, newest day first. \
         {failing_days} of {} days had a check with a failing service. \
         The table below lists the counts per day.",
        days.len()
    );
    let axis = ["00", "06", "12", "18"].map(|hour| {
        view! { <span class="health-axis-label" aria-hidden="true">{hour}</span> }
    });
    let rows = days
        .iter()
        .map(|day| {
            let date = day.date;
            let cells = day
                .cells
                .iter()
                .enumerate()
                .map(|(hour, &cell)| {
                    let title = cell_title(date, hour, cell);
                    view! { <span class=cell_class(cell) title=(!title.is_empty()).then_some(title)></span> }
                })
                .collect_view();
            view! {
                <span class="health-day">{short_date(date)}</span>
                {cells}
            }
        })
        .collect_view();
    let table_rows = days
        .iter()
        .map(|day| {
            let checks = day.checks();
            let failing = day.failing();
            view! {
                <tr>
                    <td class="nowrap">{day.date.to_string()}</td>
                    <td>{checks}</td>
                    <td>{failing}</td>
                </tr>
            }
        })
        .collect_view();
    view! {
        <div class="health-history">
        <div class="health-chart" role="img" aria-label=label>
            <span></span>
            <span class="health-axis">{axis}</span>
            {rows}
        </div>
        <ul class="health-legend">
            <li><span class="hour-cell hour-cell-ok" aria-hidden="true"></span>"No failures"</li>
            <li><span class="hour-cell hour-cell-fail" aria-hidden="true"></span>"A check found a failing service"</li>
            <li><span class="hour-cell hour-cell-none" aria-hidden="true"></span>"No check"</li>
        </ul>
        <details class="health-table">
            <summary>"Checks per day"</summary>
            <div class="table-wrap" role="region" aria-label="Checks per day" tabindex="0">
                <table class="data-table">
                    <caption class="visually-hidden">"Checks per day, newest first"</caption>
                    <thead>
                        <tr>
                            <th scope="col">"Day (UTC)"</th>
                            <th scope="col">"Checks"</th>
                            <th scope="col">"With a failing service"</th>
                        </tr>
                    </thead>
                    <tbody>{table_rows}</tbody>
                </table>
            </div>
        </details>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    // 2026-11-12 00:00:00 UTC.
    const MIDNIGHT: i64 = 1_794_441_600;

    #[test]
    fn days_cover_the_period_newest_first() {
        // Read at 10:30 on Nov 12: the period starts at 10:30 on Nov 5.
        let read_at = at(MIDNIGHT + 10 * 3600 + 1800);
        let hours = [
            HealthHour {
                hour: at(MIDNIGHT + 9 * 3600),
                checks: 4,
                failing: 0,
            },
            HealthHour {
                hour: at(MIDNIGHT + 3600),
                checks: 3,
                failing: 2,
            },
            // Past the period: ignored.
            HealthHour {
                hour: at(MIDNIGHT - 8 * 86_400),
                checks: 9,
                failing: 9,
            },
        ];
        let days = chart_days(&hours, read_at, 7);
        assert_eq!(days.len(), 8);
        assert_eq!(days[0].date.to_string(), "2026-11-12");
        assert_eq!(days[7].date.to_string(), "2026-11-05");

        let today = &days[0].cells;
        assert_eq!(today[0], Cell::NoCheck);
        assert_eq!(
            today[1],
            Cell::Failing {
                checks: 3,
                failing: 2
            }
        );
        assert_eq!(today[9], Cell::Healthy { checks: 4 });
        assert_eq!(today[10], Cell::NoCheck, "the current hour has begun");
        assert_eq!(today[11], Cell::Outside);
        assert_eq!((days[0].checks(), days[0].failing()), (7, 2));

        let first = &days[7].cells;
        assert_eq!(first[9], Cell::Outside);
        assert_eq!(first[10], Cell::NoCheck, "the hour holding the cut is kept");
        assert!(days.iter().skip(1).all(|day| day.checks() == 0));
    }

    #[test]
    fn a_read_on_the_hour_does_not_add_a_day() {
        let days = chart_days(&[], at(MIDNIGHT), 7);
        assert_eq!(days.len(), 8);
        assert_eq!(days[0].cells[0], Cell::NoCheck);
        assert_eq!(days[0].cells[1], Cell::Outside);
        assert!(days[7].cells.iter().all(|cell| *cell == Cell::NoCheck));
    }

    #[test]
    fn titles_name_the_hour_and_the_counts() {
        let date = at(MIDNIGHT).date();
        assert_eq!(
            cell_title(
                date,
                23,
                Cell::Failing {
                    checks: 4,
                    failing: 1
                }
            ),
            "Nov 12 23:00 to 24:00 UTC: 1 of 4 found a failing service"
        );
        assert_eq!(
            cell_title(date, 0, Cell::Healthy { checks: 1 }),
            "Nov 12 00:00 to 01:00 UTC: 1 check, no failures"
        );
        assert_eq!(cell_title(date, 5, Cell::Outside), "");
    }
}
