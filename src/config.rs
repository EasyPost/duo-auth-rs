use std::path::Path;
use std::fs::File;
use std::time::Duration;

use serde_json;

use super::errors::*;
use ip_whitelist::IpWhitelist;


#[derive(Deserialize, Debug)]
struct RawConfig {
    pub ikey: String,
    pub skey: String,
    pub base: String,
    pub request_timeout_ms: Option<u64>,
    pub recent_ip_file: Option<String>,
    pub recent_ip_duration_s: Option<u64>,
    pub whitelisted_networks: Option<Vec<String>>
}

pub(crate) struct Config {
    pub ikey: String,
    pub skey: String,
    pub base: String,
    pub request_timeout: Duration,
    pub recent_ip_file: Option<String>,
    pub recent_ip_duration: Duration,
    pub whitelist: IpWhitelist,
}


impl Config {
    fn from_raw_config(r: RawConfig) -> Result<Self> {
        let whitelist = IpWhitelist::from_vec(r.whitelisted_networks)?;
        Ok(Config {
            ikey: r.ikey,
            skey: r.skey,
            base: r.base,
            request_timeout: Duration::from_millis(r.request_timeout_ms.unwrap_or(60_000)),
            recent_ip_file: r.recent_ip_file,
            recent_ip_duration: Duration::from_secs(r.recent_ip_duration_s.unwrap_or(28_800)),
            whitelist: whitelist
        })

    }

    pub fn from_path(p: &Path) -> Result<Self> {
        let f = File::open(p).chain_err(|| format!("unable to open config file at {:?}", p))?;
        let config: RawConfig = serde_json::from_reader(f)?;
        Ok(Config::from_raw_config(config)?)
    }

    pub fn has_recent_ip(&self) -> bool {
        self.recent_ip_file.is_some()
    }
}

