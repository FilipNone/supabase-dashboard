//! Where the dashboard itself runs in Dokploy: the service, environment,
//! and project it was deployed as.
//!
//! Dokploy tells a container nothing about its own project, environment,
//! or service, so the dashboard looks for the Dokploy domain that serves
//! its public URL. The match is only a suggestion: an installation admin
//! confirms it, or picks another service, before anything uses it. Later
//! reads compare the confirmed service with what Dokploy reports, so a
//! service that was moved or deleted in Dokploy shows up as such instead of
//! being used silently.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::account::DisplayName;

/// Longest Dokploy ID accepted. Dokploy's IDs are 21-character nanoids.
pub const DOKPLOY_ID_MAX_LEN: usize = 64;

/// Longest service, project, or environment name kept from Dokploy.
pub const DOKPLOY_NAME_MAX_CHARS: usize = 128;

/// Most services offered to choose from on the administrator page.
pub const MAX_LISTED_SERVICES: usize = 500;

/// The two kinds of Dokploy service the dashboard can run as. Databases
/// and other kinds are never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DokployServiceKind {
    Application,
    Compose,
}

impl DokployServiceKind {
    /// As Dokploy writes it (`application`, `compose`), and as stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Compose => "compose",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "application" => Some(Self::Application),
            "compose" => Some(Self::Compose),
            _ => None,
        }
    }

    /// In words, for the page.
    pub fn label(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Compose => "Compose",
        }
    }
}

/// A Dokploy ID: 1 to 64 characters of letters, digits, `_`, and `-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DokployId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a Dokploy ID")]
pub struct InvalidDokployId;

impl DokployId {
    pub fn parse(raw: &str) -> Result<Self, InvalidDokployId> {
        let valid = !raw.is_empty()
            && raw.len() <= DOKPLOY_ID_MAX_LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if valid {
            Ok(Self(raw.to_owned()))
        } else {
            Err(InvalidDokployId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DokployId {
    type Error = InvalidDokployId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DokployId> for String {
    fn from(value: DokployId) -> Self {
        value.0
    }
}

/// Which service: its kind and its ID within that kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DokployServiceRef {
    pub kind: DokployServiceKind,
    pub id: DokployId,
}

/// A service the key can see, with the project and environment it is in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployServiceInfo {
    pub service: DokployServiceRef,
    pub name: String,
    pub project_id: DokployId,
    pub project_name: String,
    pub environment_id: DokployId,
    pub environment_name: String,
    /// The remote server it is deployed on; `None` for Dokploy's own host.
    pub server_name: Option<String>,
}

/// A domain routed to a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployDomainInfo {
    /// Lowercase, without a trailing dot.
    pub host: String,
    pub service: DokployServiceRef,
    pub enabled: bool,
    /// A preview deployment's domain, which never serves the dashboard.
    pub preview: bool,
}

/// What a key can see: the application and compose services, and the
/// domains routed to them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployInventory {
    pub services: Vec<DokployServiceInfo>,
    pub domains: Vec<DokployDomainInfo>,
}

impl DokployInventory {
    pub fn service(&self, service: &DokployServiceRef) -> Option<&DokployServiceInfo> {
        self.services.iter().find(|info| &info.service == service)
    }

    /// Whether an enabled, non-preview domain of `service` is `host`.
    pub fn serves(&self, service: &DokployServiceRef, host: &str) -> bool {
        let host = normalize_host(host);
        self.domains
            .iter()
            .any(|domain| &domain.service == service && serves_host(domain, &host))
    }

    /// The services whose enabled, non-preview domains include `host`,
    /// the dashboard's public host. Each service once, in the order
    /// Dokploy listed them; only services the key can also see as services.
    pub fn services_serving(&self, host: &str) -> Vec<DokployServiceInfo> {
        let host = normalize_host(host);
        self.services
            .iter()
            .filter(|info| {
                self.domains
                    .iter()
                    .any(|domain| domain.service == info.service && serves_host(domain, &host))
            })
            .cloned()
            .collect()
    }
}

fn serves_host(domain: &DokployDomainInfo, host: &str) -> bool {
    domain.enabled && !domain.preview && !host.is_empty() && domain.host == host
}

/// Lowercase without surrounding whitespace or a trailing dot, so
/// `Dashboard.Example.com.` and `dashboard.example.com` compare equal.
pub fn normalize_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Cuts a name from Dokploy to [`DOKPLOY_NAME_MAX_CHARS`].
pub fn bounded_name(raw: &str) -> String {
    match raw.char_indices().nth(DOKPLOY_NAME_MAX_CHARS) {
        Some((index, _)) => raw[..index].to_owned(),
        None => raw.to_owned(),
    }
}

/// The confirmed placement as stored: the service, and the project and
/// environment it was in when an admin confirmed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DokployPlacement {
    pub service: DokployServiceRef,
    pub service_name: String,
    pub project_id: DokployId,
    pub project_name: String,
    pub environment_id: DokployId,
    pub environment_name: String,
}

impl From<&DokployServiceInfo> for DokployPlacement {
    fn from(info: &DokployServiceInfo) -> Self {
        Self {
            service: info.service.clone(),
            service_name: info.name.clone(),
            project_id: info.project_id.clone(),
            project_name: info.project_name.clone(),
            environment_id: info.environment_id.clone(),
            environment_name: info.environment_name.clone(),
        }
    }
}

/// How the confirmed service compares with what Dokploy reports now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementStatus {
    /// Same service, project, and environment, and one of its domains is
    /// still the dashboard's public host.
    Current,
    /// Same service, project, and environment, but none of its enabled
    /// domains is the public host any more (or the dashboard has no public
    /// URL to compare).
    DomainChanged,
    /// The service is now in another project or environment.
    Moved { now: Box<DokployServiceInfo> },
    /// The key cannot see the service: it was deleted, or the key's member
    /// lost access to it.
    Missing,
}

impl PlacementStatus {
    /// Compares `placement` with `inventory`. `public_host` is the host of
    /// the dashboard's public URL, when it has one.
    pub fn check(
        placement: &DokployPlacement,
        inventory: &DokployInventory,
        public_host: Option<&str>,
    ) -> Self {
        let Some(now) = inventory.service(&placement.service) else {
            return Self::Missing;
        };
        if now.project_id != placement.project_id || now.environment_id != placement.environment_id
        {
            return Self::Moved {
                now: Box::new(now.clone()),
            };
        }
        match public_host {
            Some(host) if inventory.serves(&placement.service, host) => Self::Current,
            _ => Self::DomainChanged,
        }
    }

    /// A sentence for the page and the startup log. Names only Dokploy
    /// names, never addresses or keys.
    pub fn message(&self) -> String {
        match self {
            Self::Current => "Dokploy still reports this service in the same project and \
                              environment, serving the dashboard's address."
                .to_owned(),
            Self::DomainChanged => "The service is still in the same project and environment, \
                                    but none of its enabled Dokploy domains is the dashboard's \
                                    public address."
                .to_owned(),
            Self::Moved { now } => format!(
                "The service has moved in Dokploy: it is now in project \"{}\", environment \
                 \"{}\". Confirm the new placement to use it.",
                now.project_name, now.environment_name
            ),
            Self::Missing => "Dokploy no longer shows this service to the key: it was deleted, \
                              or the key's member lost access to it."
                .to_owned(),
        }
    }
}

/// A confirmed placement with who confirmed it and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedPlacement {
    pub placement: DokployPlacement,
    pub confirmed_at: OffsetDateTime,
    /// `None` once that account has been deleted.
    pub confirmed_by: Option<DisplayName>,
}

/// What Dokploy reported when the page asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementLookup {
    Found {
        /// Services whose domain is the dashboard's public host. Empty
        /// when the dashboard has no public URL.
        matches: Vec<DokployServiceInfo>,
        /// Every application and compose service the key can see, up to
        /// [`MAX_LISTED_SERVICES`], for choosing by hand.
        services: Vec<DokployServiceInfo>,
        /// Whether the key can see more services than are listed.
        truncated: bool,
        /// The confirmed placement compared with Dokploy, when one is
        /// confirmed.
        status: Option<PlacementStatus>,
    },
    /// Dokploy could not be asked; the message names no address or key.
    Failed(String),
}

/// The placement section of the administrator page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementOverview {
    /// The host of the dashboard's public URL, when one is configured.
    pub public_host: Option<String>,
    pub confirmed: Option<ConfirmedPlacement>,
    pub lookup: PlacementLookup,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn id(raw: &str) -> DokployId {
        DokployId::parse(raw).unwrap()
    }

    fn service(kind: DokployServiceKind, raw_id: &str, env: &str) -> DokployServiceInfo {
        DokployServiceInfo {
            service: DokployServiceRef {
                kind,
                id: id(raw_id),
            },
            name: format!("name-{raw_id}"),
            project_id: id("proj"),
            project_name: "Infra".to_owned(),
            environment_id: id(env),
            environment_name: format!("env-{env}"),
            server_name: None,
        }
    }

    fn domain(host: &str, service: &DokployServiceInfo) -> DokployDomainInfo {
        DokployDomainInfo {
            host: host.to_owned(),
            service: service.service.clone(),
            enabled: true,
            preview: false,
        }
    }

    #[test]
    fn ids_are_dokploy_nanoids() {
        assert!(DokployId::parse("_IK3e1y1IwxNCLnlLGXEZ").is_ok());
        assert!(DokployId::parse("35--oTNsDM0g3O_k9V72j").is_ok());
        for bad in ["", "a b", "a/b", "é", "a.b", &"a".repeat(65)] {
            assert_eq!(DokployId::parse(bad), Err(InvalidDokployId), "{bad:?}");
        }
        let json = serde_json::to_string(&id("abc")).unwrap();
        assert_eq!(json, "\"abc\"");
        assert!(serde_json::from_str::<DokployId>("\"a b\"").is_err());
    }

    #[test]
    fn kinds_round_trip() {
        for kind in [DokployServiceKind::Application, DokployServiceKind::Compose] {
            assert_eq!(DokployServiceKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(DokployServiceKind::parse("postgres"), None);
    }

    #[test]
    fn the_public_host_finds_its_service() {
        let dashboard = service(DokployServiceKind::Compose, "dash", "prod");
        let other = service(DokployServiceKind::Application, "other", "prod");
        let inventory = DokployInventory {
            services: vec![other.clone(), dashboard.clone()],
            domains: vec![
                domain("other.example.test", &other),
                domain("dashboard.example.test", &dashboard),
                // A second domain of the same service is not a second match.
                domain("dashboard.example.test", &dashboard),
            ],
        };
        assert_eq!(
            inventory.services_serving("Dashboard.Example.Test."),
            vec![dashboard.clone()]
        );
        assert!(
            inventory
                .services_serving("nothing.example.test")
                .is_empty()
        );
        assert!(inventory.services_serving("").is_empty());
    }

    #[test]
    fn disabled_preview_and_unlisted_domains_do_not_match() {
        let dashboard = service(DokployServiceKind::Application, "dash", "prod");
        let hidden = service(DokployServiceKind::Compose, "hidden", "prod");
        let mut disabled = domain("dashboard.example.test", &dashboard);
        disabled.enabled = false;
        let mut preview = domain("dashboard.example.test", &dashboard);
        preview.preview = true;
        let inventory = DokployInventory {
            services: vec![dashboard],
            // `hidden` has the host, but the key cannot see it as a
            // service, so it cannot be confirmed.
            domains: vec![disabled, preview, domain("dashboard.example.test", &hidden)],
        };
        assert!(
            inventory
                .services_serving("dashboard.example.test")
                .is_empty()
        );
    }

    #[test]
    fn several_services_with_the_host_are_all_returned() {
        let a = service(DokployServiceKind::Compose, "a", "prod");
        let b = service(DokployServiceKind::Compose, "b", "staging");
        let inventory = DokployInventory {
            services: vec![a.clone(), b.clone()],
            domains: vec![
                domain("dashboard.example.test", &a),
                domain("dashboard.example.test", &b),
            ],
        };
        assert_eq!(
            inventory.services_serving("dashboard.example.test"),
            vec![a, b]
        );
    }

    #[test]
    fn the_status_reports_moves_and_deletions() {
        let dashboard = service(DokployServiceKind::Compose, "dash", "prod");
        let placement = DokployPlacement::from(&dashboard);
        let host = Some("dashboard.example.test");
        let mut inventory = DokployInventory {
            services: vec![dashboard.clone()],
            domains: vec![domain("dashboard.example.test", &dashboard)],
        };
        assert_eq!(
            PlacementStatus::check(&placement, &inventory, host),
            PlacementStatus::Current
        );
        assert_eq!(
            PlacementStatus::check(&placement, &inventory, None),
            PlacementStatus::DomainChanged
        );
        inventory.domains[0].host = "elsewhere.example.test".to_owned();
        assert_eq!(
            PlacementStatus::check(&placement, &inventory, host),
            PlacementStatus::DomainChanged
        );

        let moved = service(DokployServiceKind::Compose, "dash", "staging");
        inventory.services = vec![moved.clone()];
        let status = PlacementStatus::check(&placement, &inventory, host);
        assert_eq!(
            status,
            PlacementStatus::Moved {
                now: Box::new(moved)
            }
        );
        assert!(status.message().contains("env-staging"));

        // Same ID, other kind: a different service.
        inventory.services = vec![service(DokployServiceKind::Application, "dash", "prod")];
        assert_eq!(
            PlacementStatus::check(&placement, &inventory, host),
            PlacementStatus::Missing
        );
        inventory.services.clear();
        assert_eq!(
            PlacementStatus::check(&placement, &inventory, host),
            PlacementStatus::Missing
        );
    }

    #[test]
    fn names_are_bounded() {
        assert_eq!(bounded_name("short"), "short");
        let long = "é".repeat(DOKPLOY_NAME_MAX_CHARS + 10);
        assert_eq!(bounded_name(&long).chars().count(), DOKPLOY_NAME_MAX_CHARS);
        assert_eq!(normalize_host(" A.Example.TEST. "), "a.example.test");
    }
}
