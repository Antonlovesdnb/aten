//! Userspace sockaddr parsing for the connect() probe.
//!
//! The kernel hands us the first 28 bytes of the user-space `struct sockaddr`
//! the agent's descendant passed to `connect()`. The first 2 bytes are the
//! address family — `AF_INET` (2) or `AF_INET6` (10) is what we care about;
//! AF_UNIX and friends get reported as `Other` and dropped at the collector.

#[derive(Debug, Clone)]
pub enum Endpoint {
    V4 { ip: std::net::Ipv4Addr, port: u16 },
    V6 { ip: std::net::Ipv6Addr, port: u16 },
    Other,
}

pub fn parse_sockaddr(bytes: &[u8]) -> Endpoint {
    if bytes.len() < 2 {
        return Endpoint::Other;
    }
    // sa_family is u16, native byte order (the kernel copies it from the
    // user-space struct as-is; x86_64 is little-endian).
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        // AF_INET. struct sockaddr_in:
        // u16 sin_family; u16 sin_port (BE); u32 sin_addr (BE); padding.
        2 if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Endpoint::V4 { ip, port }
        }
        // AF_INET6. struct sockaddr_in6:
        // u16 sin6_family; u16 sin6_port (BE); u32 sin6_flowinfo; u128 sin6_addr; u32 sin6_scope_id.
        10 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[8..24]);
            Endpoint::V6 {
                ip: std::net::Ipv6Addr::from(addr),
                port,
            }
        }
        _ => Endpoint::Other,
    }
}

/// True for addresses the collector should drop without emitting an event —
/// loopback, unspecified, and link-local. The post's malicious-npm scenario
/// beacons to public IPs; we don't want every localhost RPC inside the
/// agent's process tree showing up as "network egress."
pub fn is_uninteresting(ep: &Endpoint) -> bool {
    match ep {
        Endpoint::V4 { ip, .. } => ip.is_loopback() || ip.is_unspecified() || ip.is_link_local(),
        Endpoint::V6 { ip, .. } => ip.is_loopback() || ip.is_unspecified(),
        Endpoint::Other => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_sockaddr() {
        // sockaddr_in: family=2 (LE), port=443 (BE = 0x01BB), addr=1.2.3.4
        let bytes = [
            2u8, 0, // family
            0x01, 0xBB, // port = 443
            1, 2, 3, 4, // addr
            0, 0, 0, 0, 0, 0, 0, 0, // pad
        ];
        match parse_sockaddr(&bytes) {
            Endpoint::V4 { ip, port } => {
                assert_eq!(ip.to_string(), "1.2.3.4");
                assert_eq!(port, 443);
            }
            other => panic!("expected V4, got {other:?}"),
        }
    }

    #[test]
    fn loopback_is_uninteresting() {
        let ep = Endpoint::V4 {
            ip: std::net::Ipv4Addr::new(127, 0, 0, 1),
            port: 8080,
        };
        assert!(is_uninteresting(&ep));
    }

    #[test]
    fn public_ipv4_is_interesting() {
        let ep = Endpoint::V4 {
            ip: std::net::Ipv4Addr::new(203, 0, 113, 42),
            port: 443,
        };
        assert!(!is_uninteresting(&ep));
    }

    #[test]
    fn unix_socket_is_other() {
        // AF_UNIX = 1
        let bytes = [1u8, 0, b'/', b't', b'm', b'p', b'/', 0];
        assert!(matches!(parse_sockaddr(&bytes), Endpoint::Other));
    }
}
