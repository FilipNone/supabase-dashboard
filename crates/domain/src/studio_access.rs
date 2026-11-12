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
    },
}

#[cfg(test)]
mod tests {
    use super::*;

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
