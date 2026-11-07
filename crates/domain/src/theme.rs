//! Color theme preference.

use serde::{Deserialize, Serialize};

/// Name of the cookie that stores the theme preference. It holds no secret.
pub const THEME_COOKIE: &str = "sd-theme";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreference {
    /// Follow the operating system's `prefers-color-scheme`.
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePreference {
    pub const ALL: [Self; 3] = [Self::System, Self::Light, Self::Dark];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }

    /// Parses a stored value. Unknown values fall back to `System`.
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        }
    }

    /// Reads the preference from a raw `Cookie` header value.
    pub fn from_cookie_header(header: &str) -> Self {
        header
            .split(';')
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == THEME_COOKIE)
            .map(|(_, value)| Self::parse(value))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_values() {
        for theme in ThemePreference::ALL {
            assert_eq!(ThemePreference::parse(theme.as_str()), theme);
        }
    }

    #[test]
    fn unknown_values_fall_back_to_system() {
        assert_eq!(ThemePreference::parse("<script>"), ThemePreference::System);
    }

    #[test]
    fn reads_cookie_among_others() {
        let header = "session=abc; sd-theme=dark; other=1";
        assert_eq!(
            ThemePreference::from_cookie_header(header),
            ThemePreference::Dark
        );
        assert_eq!(
            ThemePreference::from_cookie_header("session=abc"),
            ThemePreference::System
        );
    }
}
