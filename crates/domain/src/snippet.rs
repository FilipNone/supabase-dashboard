//! SQL snippets: named SQL text saved in the dashboard for one project.
//!
//! Snippets are control-plane records. Self-hosted Studio keeps its own
//! snippets elsewhere (or not at all), and nothing here reads or writes
//! them.
//!
//! Ownership rules:
//!
//! - A snippet belongs to the member who saved it and to one project.
//! - A private snippet is visible to its author only.
//! - A shared snippet is visible to every member of the project's
//!   organization who may run SQL.
//! - Only the author renames, edits, or changes the visibility of a
//!   snippet. The author, and members with
//!   [`crate::authz::Permission::SqlSnippetsManage`], may delete a shared
//!   one.
//! - Members without [`crate::authz::Permission::SqlExecute`] see no
//!   snippets, including their own from an earlier role.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::sql::{SqlText, SqlTextError};

pub const SNIPPET_NAME_MAX_CHARS: usize = 100;
/// Snippets one member may keep in one project.
pub const SNIPPETS_PER_AUTHOR: u32 = 100;
/// Snippets listed for one project: the caller's own and the shared ones.
pub const SNIPPET_LIST_LIMIT: u32 = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SnippetName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SnippetInputError {
    #[error("enter a name for the snippet")]
    EmptyName,
    #[error("the name is longer than {SNIPPET_NAME_MAX_CHARS} characters")]
    NameTooLong,
    #[error("the name contains control characters")]
    NameControlChars,
    #[error("{0}")]
    Content(SqlTextError),
}

impl SnippetName {
    pub fn parse(raw: &str) -> Result<Self, SnippetInputError> {
        let value = raw.trim();
        if value.is_empty() {
            return Err(SnippetInputError::EmptyName);
        }
        if value.chars().count() > SNIPPET_NAME_MAX_CHARS {
            return Err(SnippetInputError::NameTooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(SnippetInputError::NameControlChars);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SnippetName {
    type Error = SnippetInputError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SnippetName> for String {
    fn from(value: SnippetName) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnippetVisibility {
    Private,
    /// Visible to the project's members who may run SQL.
    Project,
}

impl SnippetVisibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Project => "project",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::Private, Self::Project]
            .into_iter()
            .find(|v| v.as_str() == name)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Private => "Only me",
            Self::Project => "Shared with the project",
        }
    }
}

/// A validated snippet to save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetInput {
    pub name: SnippetName,
    pub visibility: SnippetVisibility,
    pub content: SqlText,
}

impl SnippetInput {
    pub fn parse(
        name: &str,
        visibility: SnippetVisibility,
        content: &str,
    ) -> Result<Self, SnippetInputError> {
        Ok(Self {
            name: SnippetName::parse(name)?,
            visibility,
            content: SqlText::parse(content).map_err(SnippetInputError::Content)?,
        })
    }
}

/// A snippet in a list, without its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnippetSummary {
    pub id: Uuid,
    pub name: SnippetName,
    pub visibility: SnippetVisibility,
    /// The author's display name.
    pub author: String,
    /// Whether the caller wrote it, and so may edit it.
    pub mine: bool,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnippetList {
    pub items: Vec<SnippetSummary>,
    /// More snippets exist than [`SNIPPET_LIST_LIMIT`].
    pub truncated: bool,
}

/// A snippet with its text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snippet {
    pub summary: SnippetSummary,
    pub content: String,
}

/// Debug output leaves the text out: it can hold data or secrets.
impl std::fmt::Debug for Snippet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snippet")
            .field("summary", &self.summary)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(
            SnippetName::parse("  Top users ").unwrap().as_str(),
            "Top users"
        );
        assert_eq!(SnippetName::parse(" "), Err(SnippetInputError::EmptyName));
        assert_eq!(
            SnippetName::parse(&"é".repeat(SNIPPET_NAME_MAX_CHARS)).map(|n| n.as_str().len()),
            Ok(SNIPPET_NAME_MAX_CHARS * 2)
        );
        assert_eq!(
            SnippetName::parse(&"a".repeat(SNIPPET_NAME_MAX_CHARS + 1)),
            Err(SnippetInputError::NameTooLong)
        );
        assert_eq!(
            SnippetName::parse("a\nb"),
            Err(SnippetInputError::NameControlChars)
        );
        assert!(serde_json::from_str::<SnippetName>("\"\"").is_err());
    }

    #[test]
    fn input_checks_the_text_like_a_run() {
        assert_eq!(
            SnippetInput::parse("x", SnippetVisibility::Private, "  "),
            Err(SnippetInputError::Content(SqlTextError::Empty))
        );
        assert!(SnippetInput::parse("x", SnippetVisibility::Project, "select 1").is_ok());
    }

    #[test]
    fn visibility_names_round_trip_and_match_serde() {
        for v in [SnippetVisibility::Private, SnippetVisibility::Project] {
            assert_eq!(SnippetVisibility::parse(v.as_str()), Some(v));
            assert_eq!(
                serde_json::to_string(&v).unwrap(),
                format!("\"{}\"", v.as_str())
            );
        }
        assert_eq!(SnippetVisibility::parse("public"), None);
    }

    #[test]
    fn debug_leaves_the_text_out() {
        let snippet = Snippet {
            summary: SnippetSummary {
                id: Uuid::nil(),
                name: SnippetName::parse("n").unwrap(),
                visibility: SnippetVisibility::Private,
                author: "Ada".into(),
                mine: true,
                updated_at: OffsetDateTime::UNIX_EPOCH,
            },
            content: "select 'hidden-marker'".into(),
        };
        assert!(!format!("{snippet:?}").contains("hidden-marker"));
    }
}
