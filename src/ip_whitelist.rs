use ipnetwork::Ipv6Network;
use std::net::IpAddr;

use log::debug;

use super::{Error, Result};

pub struct IpWhitelist {
    whitelist_networks: Vec<Ipv6Network>,
}

impl IpWhitelist {
    pub fn empty() -> Self {
        IpWhitelist {
            whitelist_networks: vec![],
        }
    }

    pub fn new<S: AsRef<str>>(vs: Vec<S>) -> Result<Self> {
        let parsed: Vec<Ipv6Network> = {
            let p_i: Result<Vec<Ipv6Network>> = vs
                .into_iter()
                .map(|item| {
                    let item = item.as_ref();
                    let (base, bits) = if item.contains('/') {
                        let parts: Vec<&str> = item.split('/').collect();
                        if parts.len() != 2 {
                            return Err(Error::InvalidWhitelistEntry("wrong number of slashes"));
                        }
                        let (base, bits_offset) = match parts[0].parse()? {
                            IpAddr::V4(v4_addr) => (v4_addr.to_ipv6_mapped(), 96),
                            IpAddr::V6(v6_addr) => (v6_addr, 0),
                        };
                        let bits: u8 = parts[1]
                            .parse::<u8>()
                            .map_err(|_| Error::InvalidWhitelistEntry("bad bit suffix"))?
                            + bits_offset;
                        (base, bits)
                    } else {
                        let base = match item.parse()? {
                            IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
                            IpAddr::V6(v6_addr) => v6_addr,
                        };
                        (base, 128)
                    };
                    Ipv6Network::new(base, bits)
                        .map_err(|_| Error::InvalidWhitelistEntry("invalid whitelisted network"))
                })
                .collect();
            p_i?
        };
        debug!("whitelisted networks: {:?}", parsed);
        Ok(IpWhitelist {
            whitelist_networks: parsed,
        })
    }

    pub fn contains<I: Into<IpAddr>>(&self, addr: I) -> bool {
        let addr = match addr.into() {
            IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
            IpAddr::V6(v6_addr) => v6_addr,
        };
        self.whitelist_networks.iter().any(|n| n.contains(addr))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::IpWhitelist;

    #[test]
    fn test_empty() {
        let wl = IpWhitelist::empty();
        assert_eq!(wl.contains("127.0.0.1".parse::<IpAddr>().unwrap()), false);
    }

    #[test]
    fn test_basic() {
        let wl = IpWhitelist::new(vec!["127.0.0.0/8", "fd00:eeee::/32"]).expect("should construct");
        assert_eq!(wl.contains("127.0.0.1".parse::<IpAddr>().unwrap()), true);
        assert_eq!(wl.contains("126.0.0.1".parse::<IpAddr>().unwrap()), false);
        assert_eq!(wl.contains("fd00:eeee::1".parse::<IpAddr>().unwrap()), true);
        assert_eq!(
            wl.contains("fd00:eee1::1".parse::<IpAddr>().unwrap()),
            false
        );
    }
}
