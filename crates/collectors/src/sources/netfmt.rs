//! Shared, platform-neutral formatting for kernel-tier records.
//!
//! The Linux (eBPF) and macOS (socket-poll) connect backends observe the same
//! fact — an outbound connection's destination — but read it from different
//! kernel structures. Turning that destination into the canonical `host:port`
//! string is the one piece of genuinely identical pure logic between them, so it
//! lives here and both call it: that guarantees a `kernel_connect` record is
//! byte-identical regardless of which backend produced it, and the chain
//! verifies the same either way.
//!
//! Not a cross-platform trait — just one concrete function, tested once, compiled
//! into both backends.

use std::net::IpAddr;

/// Format a destination as `host:port`: IPv4 as `a.b.c.d:port`, IPv6 as
/// `[h:h:h:h:h:h:h:h]:port` — eight lowercase hex groups, **uncompressed** (no
/// `::`), so the string is a stable, exact function of the address bytes and
/// matches across backends. (This intentionally does not use `Ipv6Addr`'s
/// `::`-compressing `Display`.)
pub(crate) fn host_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => {
            let groups: Vec<String> = v6.segments().iter().map(|g| format!("{g:x}")).collect();
            format!("[{}]:{}", groups.join(":"), port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_is_dotted_quad_with_port() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(host_port(ip, 53), "1.1.1.1:53");
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(host_port(ip, 443), "93.184.216.34:443");
    }

    #[test]
    fn ipv6_is_bracketed_uncompressed_lowercase_hex() {
        // Deliberately an address that Ipv6Addr::Display WOULD compress to
        // `2001:db8::1` — we must keep all eight groups so both backends match.
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(host_port(ip, 443), "[2001:db8:0:0:0:0:0:1]:443");
    }

    #[test]
    fn ipv6_loopback_stays_uncompressed() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(host_port(ip, 80), "[0:0:0:0:0:0:0:1]:80");
    }
}
