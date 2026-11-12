//! Outbound connection policy for registered stacks.
//!
//! A project's API URL is the enrolled destination: the dashboard only ever
//! connects to the address an operator registered, with paths it builds
//! itself. Private network addresses are expected and allowed. Addresses
//! that should never be the target of a stack are refused at connection
//! time, after DNS resolution, so a name that later resolves somewhere else
//! cannot be used to reach them:
//!
//! - loopback, unless the deployment opts in (local development)
//! - unspecified, link-local (which includes the 169.254.169.254 metadata
//!   service of most clouds), multicast, broadcast, and reserved ranges
//! - known cloud metadata addresses outside link-local
//!
//! IPv4 addresses embedded in IPv6 (mapped or NAT64) are judged as IPv4.

use std::{
    error::Error as StdError,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TargetPolicy {
    /// Allow 127.0.0.0/8 and ::1. Only for development against a stack on
    /// the same host.
    pub allow_loopback: bool,
}

/// Metadata services that are not in a link-local range.
const METADATA_V4: [Ipv4Addr; 2] = [
    // Alibaba Cloud
    Ipv4Addr::new(100, 100, 100, 200),
    // Oracle Cloud's alternate address
    Ipv4Addr::new(192, 0, 0, 192),
];
/// AWS's IPv6 instance metadata endpoint.
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

impl TargetPolicy {
    pub fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.allows_v4(v4),
            IpAddr::V6(v6) => self.allows_v6(v6),
        }
    }

    fn allows_v4(&self, ip: Ipv4Addr) -> bool {
        let [a, ..] = ip.octets();
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        !(a == 0
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
            // 240.0.0.0/4, reserved
            || a >= 240
            || METADATA_V4.contains(&ip))
    }

    fn allows_v6(&self, ip: Ipv6Addr) -> bool {
        if let Some(v4) = embedded_v4(ip) {
            return self.allows_v4(v4);
        }
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        let first = ip.segments()[0];
        !(ip.is_unspecified()
            || ip.is_multicast()
            // fe80::/10 link-local and the deprecated fec0::/10 site-local
            || (first & 0xffc0) == 0xfe80
            || (first & 0xffc0) == 0xfec0
            || ip == METADATA_V6)
    }
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`) or NAT64
/// (`64:ff9b::a.b.c.d`) address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., a, b, c, d] = ip.octets();
        return Some(Ipv4Addr::new(a, b, c, d));
    }
    None
}

/// A resolved or literal address the policy refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationNotAllowed;

impl fmt::Display for DestinationNotAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("destination address is not allowed")
    }
}

impl StdError for DestinationNotAllowed {}

/// The host name did not resolve to any address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameNotResolved;

impl fmt::Display for NameNotResolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("host name did not resolve")
    }
}

impl StdError for NameNotResolved {}

/// Resolves with the system resolver and refuses the whole answer if any
/// address in it is not allowed. Mixing an allowed and a refused address in
/// one answer is a common rebinding trick, so it is not trimmed and used.
#[derive(Debug, Clone, Copy)]
pub struct PolicyResolver {
    pub policy: TargetPolicy,
}

impl PolicyResolver {
    pub async fn resolve_host(
        policy: TargetPolicy,
        host: &str,
    ) -> Result<Vec<SocketAddr>, Box<dyn StdError + Send + Sync>> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|_| NameNotResolved)?
            .collect();
        if addrs.is_empty() {
            return Err(Box::new(NameNotResolved));
        }
        if addrs.iter().any(|addr| !policy.allows(addr.ip())) {
            return Err(Box::new(DestinationNotAllowed));
        }
        Ok(addrs)
    }
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = Self::resolve_host(policy, &host).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Whether an error chain contains `T`.
pub(crate) fn chain_has<T: StdError + 'static>(err: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if err.is::<T>() {
            return true;
        }
        // An `io::Error` wrapping another error returns that error's source
        // from `source()`, skipping the wrapped error itself; rustls
        // certificate errors arrive this way.
        current = match err
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => Some(inner),
            None => err.source(),
        };
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn private_and_public_addresses_are_allowed() {
        let policy = TargetPolicy::default();
        for raw in [
            "10.0.0.5",
            "172.16.4.1",
            "192.168.1.20",
            "100.64.0.7",
            "203.0.113.9",
            "8.8.8.8",
            "fd00::5",
            "2001:db8::1",
            "::ffff:10.0.0.5",
        ] {
            assert!(policy.allows(ip(raw)), "{raw}");
        }
    }

    #[test]
    fn dangerous_addresses_are_refused() {
        let policy = TargetPolicy::default();
        for raw in [
            "127.0.0.1",
            "127.10.0.1",
            "::1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            "169.254.169.254",
            "169.254.0.1",
            "100.100.100.200",
            "192.0.0.192",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "240.0.0.1",
            // Embedded IPv4 is judged as IPv4.
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!policy.allows(ip(raw)), "{raw}");
        }
    }

    #[test]
    fn loopback_needs_opt_in() {
        let policy = TargetPolicy {
            allow_loopback: true,
        };
        assert!(policy.allows(ip("127.0.0.1")));
        assert!(policy.allows(ip("::1")));
        assert!(policy.allows(ip("::ffff:127.0.0.1")));
        // Opting in to loopback does not open anything else.
        assert!(!policy.allows(ip("169.254.169.254")));
        assert!(!policy.allows(ip("0.0.0.0")));
    }

    #[tokio::test]
    async fn resolver_refuses_names_pointing_at_loopback() {
        let err = PolicyResolver::resolve_host(TargetPolicy::default(), "localhost")
            .await
            .unwrap_err();
        assert!(chain_has::<DestinationNotAllowed>(err.as_ref()));
        let allowed = PolicyResolver::resolve_host(
            TargetPolicy {
                allow_loopback: true,
            },
            "localhost",
        )
        .await
        .unwrap();
        assert!(allowed.iter().all(|a| a.ip().is_loopback()));
    }

    #[tokio::test]
    async fn unresolvable_names_are_reported() {
        let err = PolicyResolver::resolve_host(TargetPolicy::default(), "does-not-exist.invalid")
            .await
            .unwrap_err();
        assert!(chain_has::<NameNotResolved>(err.as_ref()));
    }
}
