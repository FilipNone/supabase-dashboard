//! Dokploy compose services, as a provisioned stack uses them: the
//! service, its file mounts, its deployments, and its domains.
//!
//! Dokploy returns a compose service's variables, compose file, and file
//! contents in plain text to anyone holding a key that can see the
//! service. The dashboard reads only the fields below and never keeps the
//! rest.

use crate::dokploy_placement::DokployId;

/// Longest compose service name the dashboard gives, within Dokploy's 63.
pub const COMPOSE_NAME_MAX_LEN: usize = 63;

/// A compose service the key can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeService {
    pub compose_id: DokployId,
    pub name: String,
    /// Dokploy's name for the service on disk and in Docker: the requested
    /// name with a random suffix, known only once the service exists.
    pub app_name: String,
    pub environment_id: DokployId,
}

/// A new compose service with a raw compose file.
#[derive(Debug, Clone, Copy)]
pub struct NewCompose<'a> {
    pub environment_id: &'a DokployId,
    /// `None` for Dokploy's own server.
    pub server_id: Option<&'a DokployId>,
    pub name: &'a str,
    pub description: &'a str,
    pub compose_file: &'a str,
}

/// A file Dokploy writes next to a compose service. The compose file
/// refers to it as `../files/<file_path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMount {
    pub mount_id: DokployId,
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentStatus {
    Running,
    Done,
    Error,
    Cancelled,
}

impl DeploymentStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "running" => Some(Self::Running),
            "done" => Some(Self::Done),
            "error" => Some(Self::Error),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub fn is_finished(self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// One deployment of a compose service. Dokploy queues a deployment
/// without returning an ID, and the row appears only once it starts, so a
/// deployment is recognized by the unique title it was requested with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentInfo {
    pub deployment_id: DokployId,
    pub title: Option<String>,
    pub status: DeploymentStatus,
}

/// A domain routed to one service of a compose service. Dokploy turns
/// domains into proxy labels when it deploys, so a new or removed domain
/// takes effect at the next deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeDomain {
    pub domain_id: DokployId,
    pub host: String,
    pub service_name: Option<String>,
    pub port: u16,
    pub https: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct NewComposeDomain<'a> {
    pub host: &'a str,
    /// The service in the compose file that receives the traffic.
    pub service_name: &'a str,
    pub port: u16,
    /// With a Let's Encrypt certificate when true.
    pub https: bool,
}

/// Whether `name` is a compose service name the dashboard gives: lowercase
/// letters, digits, and `-`, starting with a letter. Dokploy's search
/// treats `%` and `_` as wildcards, so these names are found exactly.
pub fn is_dashboard_compose_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= COMPOSE_NAME_MAX_LEN
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The compose service name for the stack a job provisions: `sd-` and
/// the job ID as 32 hex digits. Unique to the job, so a job that lost an
/// answer finds its own service again by name.
pub fn compose_name_for_job(job_id: uuid::Uuid) -> String {
    format!("sd-{}", job_id.simple())
}

/// Longest host name a stack may be given.
pub const STACK_HOST_MAX_LEN: usize = 253;

/// Normalizes and checks the host name a new stack is reached at: two or
/// more labels of lowercase letters, digits, and `-`, none starting or
/// ending with `-`, and not an IP address. Returns the lowercase form.
pub fn check_stack_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let valid = host.len() <= STACK_HOST_MAX_LEN
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // The last label of a domain name is never all digits, which also
        // rules out IPv4 addresses.
        && labels
            .last()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()));
    valid.then_some(host)
}

/// Whether `path` is a file mount path the dashboard writes: relative,
/// made of `[A-Za-z0-9._-]` segments separated by `/`, with no empty, `.`,
/// or `..` segment.
pub fn is_file_mount_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_names_avoid_search_wildcards() {
        assert!(is_dashboard_compose_name("sd-0192f3a4b5c6"));
        assert!(!is_dashboard_compose_name("sd_0192"));
        assert!(!is_dashboard_compose_name("sd%"));
        assert!(!is_dashboard_compose_name("Sd-1"));
        assert!(!is_dashboard_compose_name("1sd"));
        assert!(!is_dashboard_compose_name(&"a".repeat(64)));
    }

    #[test]
    fn mount_paths_stay_inside_the_files_folder() {
        assert!(is_file_mount_path("volumes/api/kong.yml"));
        assert!(is_file_mount_path("db/roles.sql"));
        assert!(!is_file_mount_path("../escape"));
        assert!(!is_file_mount_path("/etc/passwd"));
        assert!(!is_file_mount_path("a//b"));
        assert!(!is_file_mount_path("dir/"));
        assert!(!is_file_mount_path("a/./b"));
        assert!(!is_file_mount_path(""));
    }

    #[test]
    fn job_names_are_dashboard_names() {
        let name = compose_name_for_job(uuid::Uuid::from_u128(u128::MAX));
        assert_eq!(name, format!("sd-{}", "f".repeat(32)));
        assert!(is_dashboard_compose_name(&name));
    }

    #[test]
    fn stack_hosts() {
        assert_eq!(
            check_stack_host(" Shop.Example.COM. ").as_deref(),
            Some("shop.example.com")
        );
        assert!(check_stack_host("a-b.c1.example.test").is_some());
        for bad in [
            "",
            "localhost",
            "10.0.0.1",
            "-shop.example.com",
            "shop-.example.com",
            "shop..example.com",
            "shop_1.example.com",
            "shop.example.com/x",
            "shop.example.com:443",
            "*.example.com",
            &format!("{}.example.com", "a".repeat(64)),
        ] {
            assert_eq!(check_stack_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn deployment_statuses() {
        assert_eq!(
            DeploymentStatus::parse("done"),
            Some(DeploymentStatus::Done)
        );
        assert!(!DeploymentStatus::Running.is_finished());
        assert!(DeploymentStatus::Error.is_finished());
        assert_eq!(DeploymentStatus::parse("queued"), None);
    }
}
