//! Studio hosts: one per project, named after `SUPABASE_DASHBOARD_STUDIO_DOMAIN`
//! (docs/adr/0002-studio-access.md, "Hosts").
//!
//! A project's Studio is served at `<label>.<studio domain>`, where the
//! label is the project ID as 32 lowercase hex digits. The ID is not a
//! secret. Requests are told apart by their `Host` header before any
//! dashboard route runs.
//!
//! The setting may instead be a flat pattern, `*-<suffix>.<domain>`, which
//! puts the label in the same DNS label as the suffix:
//! `<label>-<suffix>.<domain>`. Those hosts sit one level under `<domain>`,
//! so a wildcard record and certificate for `*.<domain>` cover them, which
//! matters behind proxies whose free certificates cover one level only.

use uuid::Uuid;

/// Longest host name DNS allows.
const HOST_MAX_LEN: usize = 253;
/// Longest DNS label.
const DNS_LABEL_MAX_LEN: usize = 63;
/// A project label: the project ID as 32 hex digits.
const LABEL_LEN: usize = 32;

/// Where a request goes, judged by its `Host` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRoute {
    Dashboard,
    /// A project's Studio host.
    Studio(Uuid),
    /// Under the Studio domain, or matching the flat pattern, but not a
    /// project label: 404.
    UnknownStudio,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StudioHosts {
    /// `https`, or `http` in local development.
    scheme: &'static str,
    /// Lowercase host name the project's name ends in, without a port or
    /// trailing dot: the Studio domain itself (`studio.example.com`), or for
    /// a flat pattern the domain after its first label (`example.com`).
    domain: String,
    /// For a flat pattern, the rest of the first label after the project
    /// label, starting with `-` (`-studio`). `None` for `<label>.<domain>`.
    suffix: Option<String>,
    port: Option<u16>,
}

impl StudioHosts {
    /// Validates the configured domain (`host` or `host:port`, or a flat
    /// pattern `*-suffix.domain[:port]`) against the dashboard's public URL,
    /// whose scheme Studio hosts share.
    pub fn parse(raw: &str, public_url: &url::Url) -> Result<Self, String> {
        let raw = raw.trim().trim_end_matches('.');
        let (host, port) = match raw.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or("the port must be a number from 1 to 65535")?;
                (host, Some(port))
            }
            None => (raw, None),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        // `*.studio.example.com` is the same as `studio.example.com`.
        let (suffix, domain) = match host.strip_prefix('*') {
            None => (None, host.clone()),
            Some(rest) => match rest.strip_prefix('.') {
                Some(domain) => (None, domain.to_owned()),
                None => {
                    let (first, domain) = rest
                        .split_once('.')
                        .filter(|(first, _)| first.starts_with('-'))
                        .ok_or(
                            "a flat pattern is `*-<suffix>.<domain>`, such as *-studio.example.com",
                        )?;
                    if !valid_label(&format!("x{first}"))
                        || LABEL_LEN + first.len() > DNS_LABEL_MAX_LEN
                    {
                        return Err(format!(
                            "the pattern's first label must be `*-` and at most {} letters, digits, and hyphens, not ending in a hyphen",
                            DNS_LABEL_MAX_LEN - LABEL_LEN - 1
                        ));
                    }
                    (Some(first.to_owned()), domain.to_owned())
                }
            },
        };
        let labels: Vec<&str> = domain.split('.').collect();
        // A Studio host has at least two labels either way: the nested
        // `<label>.studio.localhost` and the flat `<label>-studio.localhost`.
        let least = if suffix.is_some() { 1 } else { 2 };
        if domain.is_empty() || labels.len() < least {
            return Err(
                "expected a domain name with at least two labels, such as studio.example.com, or a flat pattern such as *-studio.example.com"
                    .into(),
            );
        }
        if !labels.iter().all(|label| valid_label(label)) {
            return Err(
                "expected a host name: letters, digits, and hyphens, without a scheme or path"
                    .into(),
            );
        }
        if labels
            .iter()
            .all(|label| label.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("expected a domain name, not an IP address".into());
        }
        let first_label = LABEL_LEN + suffix.as_ref().map_or(0, String::len);
        if domain.len() + first_label + 1 > HOST_MAX_LEN {
            return Err("the domain is too long to hold a project label".into());
        }
        let scheme = match public_url.scheme() {
            "https" => "https",
            _ => "http",
        };
        let hosts = Self {
            scheme,
            domain,
            suffix,
            port,
        };
        let dashboard = public_url
            .host_str()
            .ok_or("SUPABASE_DASHBOARD_PUBLIC_URL has no host")?;
        if hosts.route(dashboard) != HostRoute::Dashboard {
            return Err(if hosts.suffix.is_some() {
                "the dashboard's own host must not match the Studio host pattern".into()
            } else {
                "the dashboard's own host must not be the Studio domain or a name under it".into()
            });
        }
        Ok(hosts)
    }

    pub fn is_https(&self) -> bool {
        self.scheme == "https"
    }

    pub fn scheme(&self) -> &'static str {
        self.scheme
    }

    /// `label.domain[:port]` (or `label-suffix.domain[:port]` for a flat
    /// pattern), the value of `Host` on a project's Studio host.
    pub fn host(&self, project_id: Uuid) -> String {
        let label = project_id.simple();
        let suffix = self.suffix.as_deref().unwrap_or("");
        match self.port {
            Some(port) => format!("{label}{suffix}.{}:{port}", self.domain),
            None => format!("{label}{suffix}.{}", self.domain),
        }
    }

    /// `scheme://host`, without a trailing slash.
    pub fn origin(&self, project_id: Uuid) -> String {
        format!("{}://{}", self.scheme, self.host(project_id))
    }

    /// Reads a `Host` header. The port is ignored, because a reverse proxy
    /// in front may or may not pass it on.
    pub fn route(&self, host_header: &str) -> HostRoute {
        let host = strip_port(host_header.trim())
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let label = match &self.suffix {
            None => {
                if host == self.domain {
                    return HostRoute::UnknownStudio;
                }
                host.strip_suffix(&self.domain)
                    .and_then(|h| h.strip_suffix('.'))
            }
            Some(suffix) => host
                .split_once('.')
                .filter(|(_, rest)| *rest == self.domain)
                .and_then(|(first, _)| first.strip_suffix(suffix.as_str())),
        };
        let Some(label) = label else {
            return HostRoute::Dashboard;
        };
        let is_label = label.len() == LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        match is_label.then(|| Uuid::try_parse(label).ok()).flatten() {
            Some(id) => HostRoute::Studio(id),
            None => HostRoute::UnknownStudio,
        }
    }
}

fn valid_label(label: &str) -> bool {
    (1..=DNS_LABEL_MAX_LEN).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// `host:port` to `host`. IPv6 literals keep their brackets, so they never
/// match a domain.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn public(raw: &str) -> url::Url {
        url::Url::parse(raw).unwrap()
    }

    #[test]
    fn domains_are_validated() {
        let dash = public("https://dashboard.example.com");
        let hosts = StudioHosts::parse("Studio.Example.com.", &dash).unwrap();
        assert!(hosts.is_https());
        for bad in [
            "",
            "localhost",
            "https://studio.example.com",
            "studio.example.com/path",
            "studio_example.com",
            "-studio.example.com",
            "studio.example.com:0",
            "studio.example.com:http",
            "10.0.0.1",
            "user@studio.example.com",
        ] {
            assert!(StudioHosts::parse(bad, &dash).is_err(), "{bad}");
        }
        let long = format!("{}.example.com", "a".repeat(60));
        let longer = format!("{long}.{long}.{long}.{long}");
        assert!(StudioHosts::parse(&longer, &dash).is_err());
    }

    #[test]
    fn the_dashboard_host_must_stay_outside_the_studio_domain() {
        for (dashboard, studio) in [
            ("https://studio.example.com", "studio.example.com"),
            ("https://dash.studio.example.com", "studio.example.com"),
            ("https://STUDIO.example.com", "studio.example.com"),
        ] {
            assert!(
                StudioHosts::parse(studio, &public(dashboard)).is_err(),
                "{dashboard} {studio}"
            );
        }
        // A sibling or a parent of the Studio domain is fine: the
        // dashboard's cookie is host-only.
        assert!(StudioHosts::parse("studio.example.com", &public("https://example.com")).is_ok());
        assert!(
            StudioHosts::parse("studio.example.com", &public("https://dash.example.com")).is_ok()
        );
    }

    #[test]
    fn hosts_route_to_their_project() {
        let hosts =
            StudioHosts::parse("studio.example.com", &public("https://dash.example.com")).unwrap();
        let id = Uuid::parse_str("01a1c095-2170-766e-86ae-c53a0dd0bebb").unwrap();
        assert_eq!(
            hosts.host(id),
            "01a1c0952170766e86aec53a0dd0bebb.studio.example.com"
        );
        assert_eq!(
            hosts.origin(id),
            "https://01a1c0952170766e86aec53a0dd0bebb.studio.example.com"
        );
        for host in [
            "01a1c0952170766e86aec53a0dd0bebb.studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb.studio.example.com:443",
            "01A1C0952170766E86AEC53A0DD0BEBB.Studio.Example.com.",
        ] {
            assert_eq!(hosts.route(host), HostRoute::Studio(id), "{host}");
        }
        for host in [
            "studio.example.com",
            "www.studio.example.com",
            "01a1c095-2170-766e-86ae-c53a0dd0bebb.studio.example.com",
            "x.01a1c0952170766e86aec53a0dd0bebb.studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebg.studio.example.com",
        ] {
            assert_eq!(hosts.route(host), HostRoute::UnknownStudio, "{host}");
        }
        for host in [
            "dash.example.com",
            "dash.example.com:8443",
            "evilstudio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb.studio.example.com.evil.test",
            "[::1]:3000",
            "",
        ] {
            assert_eq!(hosts.route(host), HostRoute::Dashboard, "{host}");
        }
    }

    #[test]
    fn development_hosts_keep_their_port_and_scheme() {
        let hosts =
            StudioHosts::parse("studio.localhost:3000", &public("http://localhost:3000")).unwrap();
        assert!(!hosts.is_https());
        assert_eq!(
            hosts.origin(Uuid::nil()),
            "http://00000000000000000000000000000000.studio.localhost:3000"
        );
    }

    #[test]
    fn flat_patterns_are_validated() {
        let dash = public("https://dashboard.example.com");
        for good in [
            "*-studio.example.com",
            "*-Studio.Example.com.",
            "*-s.example.com",
            "*-studio.example.com:8443",
        ] {
            assert!(StudioHosts::parse(good, &dash).is_ok(), "{good}");
        }
        for bad in [
            "*",
            "*-",
            "*-studio",
            "*studio.example.com",
            "*-studio-.example.com",
            "*-stu_dio.example.com",
            "*-studio.*.example.com",
            "studio-*.example.com",
            "*-studio..example.com",
            "*-studio.10.0.0.1",
            "**-studio.example.com",
        ] {
            assert!(StudioHosts::parse(bad, &dash).is_err(), "{bad}");
        }
        // The first label holds the 32-digit project label and the suffix.
        let fits = format!(
            "*-{}.example.com",
            "a".repeat(DNS_LABEL_MAX_LEN - LABEL_LEN - 1)
        );
        assert!(StudioHosts::parse(&fits, &dash).is_ok());
        let too_long = format!(
            "*-{}.example.com",
            "a".repeat(DNS_LABEL_MAX_LEN - LABEL_LEN)
        );
        assert!(StudioHosts::parse(&too_long, &dash).is_err());
    }

    #[test]
    fn a_wildcard_label_is_the_nested_domain() {
        let dash = public("https://dash.example.com");
        assert_eq!(
            StudioHosts::parse("*.studio.example.com", &dash).unwrap(),
            StudioHosts::parse("studio.example.com", &dash).unwrap()
        );
    }

    #[test]
    fn the_dashboard_host_must_not_match_the_flat_pattern() {
        for dashboard in [
            "https://dash-studio.example.com",
            "https://01a1c0952170766e86aec53a0dd0bebb-studio.example.com",
            "https://-studio.example.com",
        ] {
            assert!(
                StudioHosts::parse("*-studio.example.com", &public(dashboard)).is_err(),
                "{dashboard}"
            );
        }
        // Siblings and the parent domain are fine: the dashboard's cookie is
        // host-only.
        for dashboard in [
            "https://dash.example.com",
            "https://example.com",
            "https://studio.example.com",
            "https://dash-studio.other.example.com",
        ] {
            assert!(
                StudioHosts::parse("*-studio.example.com", &public(dashboard)).is_ok(),
                "{dashboard}"
            );
        }
    }

    #[test]
    fn flat_hosts_route_to_their_project() {
        let hosts = StudioHosts::parse("*-studio.example.com", &public("https://dash.example.com"))
            .unwrap();
        let id = Uuid::parse_str("01a1c095-2170-766e-86ae-c53a0dd0bebb").unwrap();
        assert_eq!(
            hosts.host(id),
            "01a1c0952170766e86aec53a0dd0bebb-studio.example.com"
        );
        assert_eq!(
            hosts.origin(id),
            "https://01a1c0952170766e86aec53a0dd0bebb-studio.example.com"
        );
        for host in [
            "01a1c0952170766e86aec53a0dd0bebb-studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb-studio.example.com:443",
            "01A1C0952170766E86AEC53A0DD0BEBB-Studio.Example.com.",
        ] {
            assert_eq!(hosts.route(host), HostRoute::Studio(id), "{host}");
        }
        for host in [
            "-studio.example.com",
            "www-studio.example.com",
            "01a1c095-2170-766e-86ae-c53a0dd0bebb-studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebg-studio.example.com",
            "x01a1c0952170766e86aec53a0dd0bebb-studio.example.com",
        ] {
            assert_eq!(hosts.route(host), HostRoute::UnknownStudio, "{host}");
        }
        for host in [
            "dash.example.com",
            "example.com",
            "studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb.studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb-studio.example.com.evil.test",
            "01a1c0952170766e86aec53a0dd0bebb-studio.sub.example.com",
            "x.01a1c0952170766e86aec53a0dd0bebb-studio.example.com",
            "01a1c0952170766e86aec53a0dd0bebb-studios.example.com",
            "[::1]:3000",
            "",
        ] {
            assert_eq!(hosts.route(host), HostRoute::Dashboard, "{host}");
        }
    }

    #[test]
    fn flat_development_hosts_keep_their_port_and_scheme() {
        let hosts = StudioHosts::parse(
            "*-studio.localhost:3000",
            &public("http://dash.localhost:3000"),
        )
        .unwrap();
        assert!(!hosts.is_https());
        assert_eq!(
            hosts.origin(Uuid::nil()),
            "http://00000000000000000000000000000000-studio.localhost:3000"
        );
    }
}
