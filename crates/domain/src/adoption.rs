//! Adopting a Supabase stack that already runs as a Dokploy compose
//! service, for example one made from Dokploy's Supabase template: what
//! members see of the candidates, and the checks on a service's compose
//! file, domains, and variables. No type here holds a secret.

use serde::{Deserialize, Serialize};

use crate::{
    dokploy_compose::ComposeDomain,
    stack_settings::{EnvFile, EnvValue},
};

/// Most compose services listed for adoption.
pub const MAX_ADOPTABLE_LISTED: usize = 200;

/// A compose service in an environment the organization may adopt from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptableService {
    pub compose_id: String,
    /// The service's name in Dokploy.
    pub name: String,
    /// `Project / environment, on server`, as the allowed target is named.
    pub location: String,
}

/// The compose services an organization's owners and admins may adopt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdoptableServices {
    /// Services in the allowed environments that no project uses yet, by
    /// name. Environments Dokploy could not list are named in
    /// `unavailable`.
    Found {
        services: Vec<AdoptableService>,
        truncated: bool,
        unavailable: Vec<String>,
    },
    /// No Dokploy connection.
    NotConnected,
    /// No environment was allowed for this organization explicitly. The
    /// default environment is shared by every organization without
    /// targets, so it is not searched.
    NoTarget,
    /// This server does not read Dokploy services.
    Unsupported,
}

/// Whether a variable the dashboard would copy is usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Found,
    Missing,
    /// Set, but refused; the reason names no value.
    Invalid(String),
}

/// One of the stack's keys, by the variable it is read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCheck {
    /// The variable name, or names for the Studio login.
    pub variable: String,
    pub state: KeyState,
}

/// What adopting a chosen service would register, before it is
/// confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptionPreview {
    pub compose_id: String,
    pub name: String,
    pub location: String,
    /// The service's name if it is a valid project name.
    pub suggested_name: Option<String>,
    /// URLs of the domains Dokploy routes to the stack's API gateway.
    pub urls: Vec<String>,
    pub keys: Vec<KeyCheck>,
    /// Why the service cannot be adopted, if it cannot.
    pub refusal: Option<AdoptionRefusal>,
}

/// Why a service cannot be adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdoptionRefusal {
    /// Its compose file runs no Supabase Studio and Auth images.
    NotSupabase,
    /// No domain routes to an API gateway service.
    NoDomain,
}

impl AdoptionRefusal {
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotSupabase => {
                "This service's compose file does not run Supabase: the dashboard looks for the supabase/studio and supabase/gotrue images."
            }
            Self::NoDomain => {
                "No Dokploy domain routes to the stack's API gateway (the kong, envoy, or api-gw service, or port 8000). Add one in Dokploy, deploy the service, then try again."
            }
        }
    }
}

/// Images a Supabase stack runs, as `image:` values start.
const STUDIO_IMAGES: [&str; 1] = ["supabase/studio"];
const AUTH_IMAGES: [&str; 2] = ["supabase/gotrue", "supabase/auth"];

/// Whether `compose_file` runs Supabase Studio and Auth. Only `image:`
/// lines count, with an optional registry such as `docker.io/` or
/// `public.ecr.aws/`.
pub fn looks_like_supabase(compose_file: &str) -> bool {
    let repositories: Vec<&str> = compose_file
        .lines()
        .filter_map(|line| line.trim().strip_prefix("image:"))
        .map(|image| repository(image.trim().trim_matches(|c| c == '"' || c == '\'')))
        .collect();
    let runs = |names: &[&str]| {
        repositories.iter().any(|repo| {
            names.iter().any(|name| {
                *repo == *name
                    || repo
                        .strip_suffix(name)
                        .is_some_and(|registry| registry.ends_with('/'))
            })
        })
    };
    runs(&STUDIO_IMAGES) && runs(&AUTH_IMAGES)
}

/// An image reference without its tag or digest.
fn repository(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    match image.rfind(':') {
        // A colon followed by a `/` is a registry port, not a tag.
        Some(colon) if !image[colon..].contains('/') => &image[..colon],
        _ => image,
    }
}

/// Service names of an API gateway in Supabase compose files: Kong in
/// older ones, Envoy in upstream's and the dashboard's own.
const GATEWAY_SERVICES: [&str; 4] = ["kong", "envoy", "api-gw", "supabase-kong"];
/// The port the gateway listens on in those files.
const GATEWAY_PORT: u16 = 8000;

/// The URLs of the domains routed to the stack's API gateway: a domain
/// for a known gateway service, or for port 8000, in Dokploy's order and
/// without duplicates. A host the dashboard would not provision (see
/// [`crate::dokploy_compose::check_stack_host`]) is left out.
pub fn gateway_urls(domains: &[ComposeDomain]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for domain in domains {
        let gateway = domain
            .service_name
            .as_deref()
            .is_some_and(|name| GATEWAY_SERVICES.contains(&name))
            || domain.port == GATEWAY_PORT;
        let Some(host) = crate::dokploy_compose::check_stack_host(&domain.host) else {
            continue;
        };
        if !gateway || host != domain.host {
            continue;
        }
        let scheme = if domain.https { "https" } else { "http" };
        let url = format!("{scheme}://{host}");
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// The variables the anon key, the service role key, and the Studio login
/// are read from, as upstream's `.env.example` and Dokploy's template name
/// them.
pub const ANON_KEY_VARIABLE: &str = "ANON_KEY";
pub const SERVICE_ROLE_KEY_VARIABLE: &str = "SERVICE_ROLE_KEY";
pub const STUDIO_USERNAME_VARIABLE: &str = "DASHBOARD_USERNAME";
pub const STUDIO_PASSWORD_VARIABLE: &str = "DASHBOARD_PASSWORD";

/// The value of `name` in `env`: `Ok(None)` when it is not set or empty,
/// and an error when the dashboard cannot read it safely.
pub fn read_value<'a>(env: &'a EnvFile, name: &str) -> Result<Option<&'a str>, KeyState> {
    match env.get(name) {
        EnvValue::Set("") | EnvValue::Missing => Ok(None),
        EnvValue::Set(value) => Ok(Some(value)),
        EnvValue::Unreadable => Err(KeyState::Invalid(
            "set more than once, or written in a form the dashboard does not read".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dokploy_placement::DokployId;

    #[test]
    fn supabase_is_recognized_by_its_images() {
        let upstream = "services:\n  studio:\n    image: supabase/studio:2026.11.02\n  auth:\n    image: supabase/gotrue:v2.197.0\n";
        assert!(looks_like_supabase(upstream));
        let registry = "  studio:\n    image: \"docker.io/supabase/studio:1\"\n  auth:\n    image: public.ecr.aws/supabase/auth@sha256:ab\n";
        assert!(looks_like_supabase(registry));
        assert!(!looks_like_supabase(
            "  studio:\n    image: supabase/studio:1\n"
        ));
        assert!(!looks_like_supabase(
            "  a:\n    image: notsupabase/studio:1\n  b:\n    image: supabase/gotrue-fork:1\n"
        ));
        // A mention outside an image line does not count.
        assert!(!looks_like_supabase(
            "# supabase/studio supabase/gotrue\n  app:\n    image: nginx:1\n"
        ));
    }

    fn domain(host: &str, service: Option<&str>, port: u16, https: bool) -> ComposeDomain {
        ComposeDomain {
            domain_id: DokployId::parse("dom1").unwrap(),
            host: host.to_owned(),
            service_name: service.map(str::to_owned),
            port,
            https,
        }
    }

    #[test]
    fn gateway_domains_give_the_urls() {
        let domains = [
            domain("studio.example.test", Some("studio"), 3000, true),
            domain("api.example.test", Some("kong"), 8000, true),
            domain("api.example.test", Some("kong"), 8000, true),
            domain("plain.example.test", Some("app"), 8000, false),
            domain("Upper.Example.test", Some("envoy"), 8000, true),
            domain("10.0.0.1", Some("envoy"), 8000, true),
        ];
        assert_eq!(
            gateway_urls(&domains),
            ["https://api.example.test", "http://plain.example.test"]
        );
    }

    #[test]
    fn values_are_read_only_when_set_once() {
        let env = EnvFile::parse("ANON_KEY=abc\nEMPTY=\nTWICE=1\nTWICE=2\n");
        assert_eq!(read_value(&env, "ANON_KEY"), Ok(Some("abc")));
        assert_eq!(read_value(&env, "EMPTY"), Ok(None));
        assert!(read_value(&env, "TWICE").is_err());
        assert_eq!(read_value(&env, "MISSING"), Ok(None));
    }

    #[test]
    fn repositories_drop_tags_and_digests() {
        assert_eq!(repository("supabase/studio:1"), "supabase/studio");
        assert_eq!(repository("supabase/studio@sha256:ab"), "supabase/studio");
        assert_eq!(
            repository("localhost:5000/supabase/studio"),
            "localhost:5000/supabase/studio"
        );
        assert!(looks_like_supabase(
            "image: localhost:5000/supabase/studio:2\nimage: supabase/gotrue\n"
        ));
    }
}
