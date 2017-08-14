use std::net::IpAddr;
use ipnetwork::Ipv6Network;

use super::errors::*;


pub struct IpWhitelist {
    whitelist_networks: Vec<Ipv6Network>
}

impl IpWhitelist {
    pub fn from_vec(vs: Option<Vec<String>>) -> Result<Self> {
        let parsed: Vec<Ipv6Network> = if let Some(vs) = vs {
            let p_i: Result<Vec<Ipv6Network>> = vs.into_iter().map(|item| {
                let (base, bits) = if item.contains('/') {
                    let parts: Vec<&str> = item.split('/').collect();
                    if parts.len() != 2 {
                        bail!("wrong number of slashes in a whitelist");
                    }
                    let (base, bits_offset) =  match parts[0].parse()? {
                        IpAddr::V4(v4_addr) => (v4_addr.to_ipv6_mapped(), 96),
                        IpAddr::V6(v6_addr) => (v6_addr, 0)
                    };
                    let bits: u8 = parts[1].parse::<u8>().chain_err(|| "bad bit suffix")? + bits_offset;
                    (base, bits)
                } else {
                    let base = match item.parse()? {
                        IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
                        IpAddr::V6(v6_addr) => v6_addr
                    };
                    (base, 128)
                };
                Ipv6Network::new(base, bits).chain_err(|| format!("invalid whitelisted network: {:?}", item))
            }).collect();
            p_i?
        } else {
            vec![]
        };
        debug!("whitelisted networks: {:?}", parsed);
        Ok(IpWhitelist {
            whitelist_networks: parsed
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
