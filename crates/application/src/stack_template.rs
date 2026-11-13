//! The pinned Supabase stack the dashboard provisions: its compose file,
//! the files Dokploy mounts next to it, and the variables it reads.
//!
//! The files live in `crates/application/stack` and are built into the
//! server, so a provisioned stack does not follow upstream's moving
//! template. The compose file refers to the mounted files as
//! `../files/<path>`, where Dokploy writes them.

use secrecy::{ExposeSecret, SecretString};

use crate::stack_secrets::{STUDIO_USERNAME, StackSecrets};

/// The compose file, as Dokploy deploys it.
pub const COMPOSE_FILE: &str = include_str!("../stack/docker-compose.yml");

/// The compose service the stack's domain routes to.
pub const GATEWAY_SERVICE: &str = "envoy";

/// The port the gateway listens on inside the stack.
pub const GATEWAY_PORT: u16 = 8000;

/// A file Dokploy writes for the stack, by its path under `../files`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackFile {
    pub path: &'static str,
    pub content: &'static str,
}

macro_rules! stack_files {
    ($($path:literal),* $(,)?) => {
        &[$(StackFile {
            path: $path,
            content: include_str!(concat!("../stack/files/", $path)),
        }),*]
    };
}

/// Every file the compose file mounts.
pub const STACK_FILES: &[StackFile] = stack_files![
    "api/envoy/envoy.yaml",
    "api/envoy/cds.yaml",
    "api/envoy/lds.template.yaml",
    "api/envoy/docker-entrypoint.sh",
    "db/roles.sql",
    "db/jwt.sql",
    "db/realtime.sql",
    "functions/main/index.ts",
    "functions/main/memory-pressure.ts",
];

/// The public URL cannot go into the stack's variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the stack's public URL must be an http or https URL of visible ASCII characters")]
pub struct PublicUrlError;

/// The stack's variables, one `NAME=value` per line, for Dokploy to write
/// to the compose service's `.env` file. `public_url` is where the stack's
/// gateway is reached, such as `https://shop.example.com`, with no
/// trailing slash.
///
/// The values hold no `$`, quote, `#`, `\`, or whitespace, so Dokploy and
/// Docker Compose read every one as written.
pub fn stack_env(secrets: &StackSecrets, public_url: &str) -> Result<SecretString, PublicUrlError> {
    if !supabase_dashboard_domain::stack_settings::is_plain_url(public_url) {
        return Err(PublicUrlError);
    }
    let variables: [(&str, &str); 11] = [
        (
            "POSTGRES_PASSWORD",
            secrets.postgres_password.expose_secret(),
        ),
        ("JWT_SECRET", secrets.jwt_secret.expose_secret()),
        ("ANON_KEY", secrets.anon_key.expose_secret()),
        ("SERVICE_ROLE_KEY", secrets.service_role_key.expose_secret()),
        ("DASHBOARD_USERNAME", STUDIO_USERNAME),
        (
            "DASHBOARD_PASSWORD",
            secrets.studio_password.expose_secret(),
        ),
        (
            "REALTIME_DB_ENC_KEY",
            secrets.realtime_db_enc_key.expose_secret(),
        ),
        ("SECRET_KEY_BASE", secrets.secret_key_base.expose_secret()),
        (
            "PG_META_CRYPTO_KEY",
            secrets.pg_meta_crypto_key.expose_secret(),
        ),
        ("SUPABASE_PUBLIC_URL", public_url),
        ("SITE_URL", public_url),
    ];
    let mut env = String::new();
    for (name, value) in variables {
        env.push_str(name);
        env.push('=');
        env.push_str(value);
        env.push('\n');
    }
    Ok(SecretString::from(env))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use supabase_dashboard_domain::dokploy_compose::is_file_mount_path;
    use time::macros::datetime;

    use super::*;

    /// The `../files/<path>` sources the compose file mounts.
    fn mounted_sources() -> BTreeSet<&'static str> {
        COMPOSE_FILE
            .lines()
            .filter_map(|line| line.trim().strip_prefix("- ../files/"))
            .filter_map(|mount| mount.split(':').next())
            .collect()
    }

    /// The `${NAME}` variables the compose file reads without a default.
    fn compose_variables() -> BTreeSet<&'static str> {
        COMPOSE_FILE
            .split("${")
            .skip(1)
            .filter_map(|rest| rest.split('}').next())
            .filter(|variable| !variable.contains(":-"))
            .collect()
    }

    /// The `${NAME:-default}` variables, with the services reading each.
    fn defaulted_variables() -> Vec<(&'static str, &'static str, &'static str)> {
        let mut service = "";
        let mut found = Vec::new();
        for line in COMPOSE_FILE.lines() {
            if let Some(name) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
                && !name.starts_with(' ')
            {
                service = name;
            }
            for rest in line.split("${").skip(1) {
                let Some(variable) = rest.split('}').next() else {
                    continue;
                };
                if let Some((name, default)) = variable.split_once(":-") {
                    found.push((name, default, service));
                }
            }
        }
        found
    }

    fn env_names(env: &str) -> BTreeSet<&str> {
        env.lines()
            .filter_map(|line| line.split('=').next())
            .collect()
    }

    #[test]
    fn every_mount_has_its_file_and_every_file_is_mounted() {
        let sources = mounted_sources();
        assert!(!sources.is_empty());
        for file in STACK_FILES {
            assert!(is_file_mount_path(file.path), "{}", file.path);
            assert!(
                sources
                    .iter()
                    .any(|s| file.path == *s || file.path.starts_with(&format!("{s}/"))),
                "{} is not mounted",
                file.path
            );
            assert!(!file.content.is_empty());
        }
        for source in sources {
            assert!(
                STACK_FILES
                    .iter()
                    .any(|f| f.path == source || f.path.starts_with(&format!("{source}/"))),
                "{source} has no file"
            );
        }
    }

    #[test]
    fn the_variables_match_what_the_compose_file_reads() {
        let secrets = StackSecrets::generate_at(datetime!(2026-01-01 0:00 UTC)).unwrap();
        let env = stack_env(&secrets, "https://shop.example.test").unwrap();
        let env = env.expose_secret();
        assert_eq!(env_names(env), compose_variables());
        for line in env.lines() {
            let (name, value) = line.split_once('=').unwrap();
            assert!(!value.is_empty(), "{name} is empty");
            assert!(
                value.bytes().all(|b| b.is_ascii_graphic()
                    && !matches!(b, b'$' | b'"' | b'\'' | b'#' | b'\\' | b'`')),
                "{name} has a character Dokploy or Compose would change"
            );
        }
        assert!(env.contains(&format!(
            "SERVICE_ROLE_KEY={}\n",
            secrets.service_role_key.expose_secret()
        )));
        assert!(env.contains("DASHBOARD_USERNAME=supabase\n"));
        assert!(env.contains("SUPABASE_PUBLIC_URL=https://shop.example.test\n"));
    }

    #[test]
    fn every_setting_is_a_defaulted_variable_of_the_services_it_names() {
        use supabase_dashboard_domain::stack_settings::STACK_SETTINGS;
        let defaulted = defaulted_variables();
        for setting in STACK_SETTINGS {
            assert!(setting.read_by(COMPOSE_FILE), "{}", setting.name);
            let uses: Vec<_> = defaulted
                .iter()
                .filter(|(name, _, _)| *name == setting.name)
                .collect();
            let mut services: Vec<&str> = uses.iter().map(|(_, _, service)| *service).collect();
            services.sort_unstable();
            services.dedup();
            match setting.default {
                Some(default) => {
                    assert!(!uses.is_empty(), "{} has no default", setting.name);
                    assert!(
                        uses.iter().all(|(_, d, _)| *d == default),
                        "{}",
                        setting.name
                    );
                    assert_eq!(services, setting.services, "{}", setting.name);
                    assert_eq!(setting.normalize(default).as_deref(), Ok(default));
                }
                None => assert!(uses.is_empty(), "{}", setting.name),
            }
        }
        for (name, _, _) in defaulted {
            assert!(
                STACK_SETTINGS.iter().any(|s| s.name == name),
                "{name} is not a setting"
            );
        }
    }

    #[test]
    fn only_plain_public_urls_are_accepted() {
        let secrets = StackSecrets::generate().unwrap();
        for url in ["https://shop.example.test", "http://10.0.0.5:8000"] {
            assert!(stack_env(&secrets, url).is_ok(), "{url}");
        }
        for url in [
            "",
            "https://",
            "ftp://shop.example.test",
            "https://shop.example.test/",
            "https://shop.example.test\nJWT_SECRET=x",
            "https://shop.example.test#x",
            "https://${JWT_SECRET}.example.test",
            "https://shop example.test",
        ] {
            assert_eq!(
                stack_env(&secrets, url).err(),
                Some(PublicUrlError),
                "{url}"
            );
        }
    }

    #[test]
    fn the_stack_has_no_host_ports_or_fixed_container_names() {
        for line in COMPOSE_FILE.lines() {
            let line = line.trim_start();
            assert!(!line.starts_with("ports:"), "{line}");
            assert!(!line.starts_with("container_name:"), "{line}");
        }
        assert!(COMPOSE_FILE.contains(&format!("\n  {GATEWAY_SERVICE}:\n")));
    }

    /// The upstream files are the ones the fixture stack runs against.
    #[test]
    fn upstream_files_match_the_fixture_copies() {
        let fixture: &[(&str, &str)] = &[
            (
                "api/envoy/envoy.yaml",
                include_str!("../../../tests/fixtures/supabase/api/envoy/envoy.yaml"),
            ),
            (
                "api/envoy/cds.yaml",
                include_str!("../../../tests/fixtures/supabase/api/envoy/cds.yaml"),
            ),
            (
                "api/envoy/lds.template.yaml",
                include_str!("../../../tests/fixtures/supabase/api/envoy/lds.template.yaml"),
            ),
            (
                "api/envoy/docker-entrypoint.sh",
                include_str!("../../../tests/fixtures/supabase/api/envoy/docker-entrypoint.sh"),
            ),
            (
                "db/jwt.sql",
                include_str!("../../../tests/fixtures/supabase/db/jwt.sql"),
            ),
            (
                "db/realtime.sql",
                include_str!("../../../tests/fixtures/supabase/db/realtime.sql"),
            ),
            (
                "functions/main/index.ts",
                include_str!("../../../tests/fixtures/supabase/functions/main/index.ts"),
            ),
            (
                "functions/main/memory-pressure.ts",
                include_str!("../../../tests/fixtures/supabase/functions/main/memory-pressure.ts"),
            ),
        ];
        for (path, expected) in fixture {
            let file = STACK_FILES.iter().find(|f| f.path == *path).unwrap();
            // The functions' first comment line says where the copy is.
            let body = |s: &'static str| {
                if path.starts_with("functions/") {
                    s.split_once('\n').unwrap().1
                } else {
                    s
                }
            };
            assert_eq!(body(file.content), body(expected), "{path}");
        }
    }
}
