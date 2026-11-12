//! The optional Studio access log: one entry per request a member sends
//! through a project's Studio host.
//!
//! Entries hold the method, the path without its query string, the status
//! the member got, who sent it, and when. Request and response bodies,
//! query values, and headers are never recorded: Studio sends SQL and table
//! data in them.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Longest path kept, in bytes. Longer paths are cut at a character
/// boundary and end with `…`.
pub const STUDIO_ACCESS_PATH_MAX_LEN: usize = 512;

/// Longest retention an installation may configure, in days.
pub const STUDIO_ACCESS_MAX_RETENTION_DAYS: u16 = 90;

/// How many entries the project's settings page lists, newest first.
pub const STUDIO_ACCESS_PAGE: u16 = 100;

/// Most members offered in the log's member filter.
pub const STUDIO_ACCESS_MEMBER_CHOICES: u16 = 200;

/// Most entries in one CSV export, newest first.
pub const STUDIO_ACCESS_EXPORT_MAX: usize = 10_000;

/// The part of a request target that is kept: the path, without query or
/// fragment, with control characters replaced, and cut to
/// [`STUDIO_ACCESS_PATH_MAX_LEN`].
pub fn loggable_path(path_and_query: &str) -> String {
    let path = path_and_query
        .split(['?', '#'])
        .next()
        .filter(|path| !path.is_empty())
        .unwrap_or("/");
    let mut out = String::with_capacity(path.len().min(STUDIO_ACCESS_PATH_MAX_LEN));
    for c in path.chars() {
        let c = if c.is_control() { '\u{FFFD}' } else { c };
        if out.len() + c.len_utf8() > STUDIO_ACCESS_PATH_MAX_LEN - '…'.len_utf8() {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// One request to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewStudioAccess {
    pub project_id: Uuid,
    pub account_id: Uuid,
    pub at: OffsetDateTime,
    /// An HTTP method name, at most 16 bytes.
    pub method: String,
    /// Already passed through [`loggable_path`].
    pub path: String,
    pub status: u16,
}

/// One recorded request as the settings page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StudioAccessEntry {
    /// The entry's sequence number, for paging. Not a secret.
    pub id: i64,
    pub at: OffsetDateTime,
    /// `None` when the account no longer exists.
    pub member: Option<StudioAccessMember>,
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StudioAccessMember {
    /// The member's account, for filtering by member. An identifier, not a
    /// credential.
    pub account_id: Uuid,
    pub display_name: String,
    pub email: String,
}

/// What the settings page gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StudioAccessLog {
    /// The installation does not record Studio requests.
    Off,
    On {
        retention_days: u16,
        /// Newest first, at most [`STUDIO_ACCESS_PAGE`].
        entries: Vec<StudioAccessEntry>,
        /// The `id` of the last entry, when older entries follow; pass it
        /// back to read the next page.
        older: Option<i64>,
        /// Members with entries within the retention period, by name, at
        /// most [`STUDIO_ACCESS_MEMBER_CHOICES`]. Deleted accounts are not
        /// listed.
        members: Vec<StudioAccessMember>,
        /// More members have entries than `members` lists.
        more_members: bool,
    },
}

/// Entries as CSV (RFC 4180, CRLF line ends) with a header row: entry id,
/// time in UTC, member name and email (empty for a deleted account),
/// method, path, status.
///
/// A cell that a spreadsheet would read as a formula (starting with `=`,
/// `+`, `-`, `@`, tab, or carriage return) gets a leading `'`, so a display
/// name or path cannot run as one when the file is opened.
pub fn studio_access_csv(entries: &[StudioAccessEntry]) -> String {
    let mut out = String::with_capacity(64usize.saturating_mul(entries.len().saturating_add(1)));
    out.push_str("id,time_utc,member,email,method,path,status\r\n");
    for entry in entries {
        let at = entry.at.to_offset(time::UtcOffset::UTC);
        let time = format!(
            "{}T{:02}:{:02}:{:02}Z",
            at.date(),
            at.hour(),
            at.minute(),
            at.second()
        );
        let (name, email) = entry
            .member
            .as_ref()
            .map_or(("", ""), |m| (m.display_name.as_str(), m.email.as_str()));
        let cells = [
            entry.id.to_string(),
            time,
            name.to_owned(),
            email.to_owned(),
            entry.method.clone(),
            entry.path.clone(),
            entry.status.to_string(),
        ];
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_csv_cell(&mut out, cell);
        }
        out.push_str("\r\n");
    }
    out
}

fn push_csv_cell(out: &mut String, value: &str) {
    let guarded = value.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let quoted = guarded || value.contains([',', '"', '\n', '\r']);
    if quoted {
        out.push('"');
    }
    if guarded {
        out.push('\'');
    }
    for c in value.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    if quoted {
        out.push('"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_cells_and_defuses_formulas() {
        // 2026-11-12 08:05:07.25 UTC, given in UTC+1.
        let at = (time::OffsetDateTime::from_unix_timestamp(1794470707).unwrap()
            + time::Duration::milliseconds(250))
        .to_offset(time::UtcOffset::from_hms(1, 0, 0).unwrap());
        let entries = [
            StudioAccessEntry {
                id: 7,
                at,
                member: Some(StudioAccessMember {
                    account_id: Uuid::nil(),
                    display_name: "=HYPERLINK(\"x\")".to_owned(),
                    email: "a,b@example.test".to_owned(),
                }),
                method: "GET".to_owned(),
                path: "/project/default".to_owned(),
                status: 200,
            },
            StudioAccessEntry {
                id: 6,
                at,
                member: None,
                method: "POST".to_owned(),
                path: "-1+2".to_owned(),
                status: 403,
            },
        ];
        assert_eq!(
            studio_access_csv(&entries),
            "id,time_utc,member,email,method,path,status\r\n\
             7,2026-11-12T08:05:07Z,\"'=HYPERLINK(\"\"x\"\")\",\"a,b@example.test\",GET,/project/default,200\r\n\
             6,2026-11-12T08:05:07Z,,,POST,\"'-1+2\",403\r\n"
        );
        assert_eq!(
            studio_access_csv(&[]),
            "id,time_utc,member,email,method,path,status\r\n"
        );
    }

    #[test]
    fn only_the_path_is_kept() {
        assert_eq!(
            loggable_path("/api/pg-meta/default/query?key=secret"),
            "/api/pg-meta/default/query"
        );
        assert_eq!(loggable_path("/project/default#frag"), "/project/default");
        assert_eq!(loggable_path("?only=query"), "/");
        assert_eq!(loggable_path(""), "/");
        assert_eq!(loggable_path("/a\nb"), "/a\u{FFFD}b");
    }

    #[test]
    fn long_paths_are_cut_at_a_character_boundary() {
        let long = format!("/{}", "é".repeat(STUDIO_ACCESS_PATH_MAX_LEN));
        let kept = loggable_path(&long);
        assert!(kept.len() <= STUDIO_ACCESS_PATH_MAX_LEN, "{}", kept.len());
        assert!(kept.ends_with('…'));
        let exact = format!("/{}", "a".repeat(STUDIO_ACCESS_PATH_MAX_LEN - 4));
        assert_eq!(loggable_path(&exact), exact);
    }
}
