use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde_derive::Deserialize;

use super::{Error, Result};
use crate::ip_whitelist::IpWhitelist;
use crate::recent_ip::RecentIp;

#[derive(Deserialize, Debug)]
struct RawConfig {
    pub ikey: String,
    pub skey: String,
    pub base: String,
    pub request_timeout_ms: Option<u64>,
    pub recent_ip_file: Option<String>,
    pub recent_ip_duration_s: Option<u64>,
    pub whitelisted_networks: Option<Vec<String>>,
    pub mask_ipv6: Option<bool>,
}

pub(crate) struct Config {
    pub ikey: String,
    pub skey: String,
    pub base: String,
    pub request_timeout: Duration,
    pub recent_ip_file: Option<PathBuf>,
    pub recent_ip_duration: Duration,
    pub whitelist: IpWhitelist,
    pub mask_ipv6: bool,
}

impl Config {
    fn from_raw_config(r: RawConfig) -> Result<Self> {
        let whitelist = if let Some(networks) = r.whitelisted_networks {
            IpWhitelist::new(networks)?
        } else {
            IpWhitelist::empty()
        };
        Ok(Config {
            ikey: r.ikey,
            skey: r.skey,
            base: r.base,
            request_timeout: Duration::from_millis(r.request_timeout_ms.unwrap_or(60_000)),
            recent_ip_file: r.recent_ip_file.map(|f| f.into()),
            recent_ip_duration: Duration::from_secs(r.recent_ip_duration_s.unwrap_or(28_800)),
            whitelist,
            mask_ipv6: r.mask_ipv6.unwrap_or(false),
        })
    }

    pub fn from_path(p: &Path) -> Result<Self> {
        let f = File::open(p).map_err(Error::ConfigIOError)?;
        let config: RawConfig = serde_json::from_reader(f)?;
        Ok(Config::from_raw_config(config)?)
    }

    pub(crate) fn make_recent_ip(&self) -> Result<Option<RecentIp>> {
        self.recent_ip_file
            .as_ref()
            .map(|path| RecentIp::try_new(path, self.recent_ip_duration, self.mask_ipv6))
            .transpose()
            .map_err(Error::from)
    }
}
