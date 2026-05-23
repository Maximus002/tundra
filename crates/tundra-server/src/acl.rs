use std::net::IpAddr;

pub fn is_upstream_allowed(host: &str, port: u16) -> bool {
    if port == 0 {
        return false;
    }

    let Ok(addr) = host.parse::<IpAddr>() else {
        return true;
    };

    !is_private_ip(addr)
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 127
                || octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254)
                || octets[0] == 0
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || is_ipv6_unique_local(&v6)
                || is_ipv6_link_local(&v6)
        }
    }
}

fn is_ipv6_unique_local(addr: &std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments[0] == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_loopback() {
        assert!(!is_upstream_allowed("127.0.0.1", 80));
    }

    #[test]
    fn blocks_private_10() {
        assert!(!is_upstream_allowed("10.0.0.1", 443));
    }

    #[test]
    fn blocks_private_192_168() {
        assert!(!is_upstream_allowed("192.168.1.1", 80));
    }

    #[test]
    fn blocks_link_local() {
        assert!(!is_upstream_allowed("169.254.1.1", 80));
    }

    #[test]
    fn allows_public() {
        assert!(is_upstream_allowed("1.1.1.1", 443));
    }

    #[test]
    fn allows_domain() {
        assert!(is_upstream_allowed("example.com", 443));
    }

    #[test]
    fn blocks_port_zero() {
        assert!(!is_upstream_allowed("1.1.1.1", 0));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(!is_upstream_allowed("::1", 80));
    }

    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(!is_upstream_allowed("::ffff:127.0.0.1", 80));
    }

    #[test]
    fn blocks_ipv4_mapped_private() {
        assert!(!is_upstream_allowed("::ffff:192.168.1.1", 80));
    }

    #[test]
    fn allows_ipv4_mapped_public() {
        assert!(is_upstream_allowed("::ffff:1.1.1.1", 443));
    }
}
