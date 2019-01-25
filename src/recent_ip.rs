use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::Ipv6Addr;

use rusqlite;

use config;


pub(crate) mod errors {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        errors {
            NoDbInConfig {
                description("no db in config")
                display("no db in config")
            }
        }

        foreign_links {
            Db(::rusqlite::Error);
        }
    }
}

use self::errors::*;

pub(crate) struct RecentIp {
    conn: rusqlite::Connection,
    expiration: Duration,
    mask_ipv6: bool,
}


fn now() -> i64 {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).expect("it should not be before 1970");
    duration.as_secs() as i64
}


impl RecentIp {
    pub(crate) fn from_config(c: &config::Config) -> Result<RecentIp> {
        let path = if let Some(ref path) = c.recent_ip_file {
            Path::new(path)
        } else {
            return Err(ErrorKind::NoDbInConfig.into());
        };
        let mut conn = rusqlite::Connection::open(path)?;
        {
            let xact = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            xact.execute("CREATE TABLE IF NOT EXISTS logins (user STRING NOT NULL, rhost STRING NOT NULL, last_success_at INTEGER, UNIQUE (user, rhost));", &[])?;
            xact.commit()?;
        }
        Ok(RecentIp {
            conn,
            expiration: c.recent_ip_duration,
            mask_ipv6: c.mask_ipv6,
        })
    }

    /// Potentially normalize an address. This masks V6 addresses to the closest /64 to make
    /// rotating ephemeral addresses less annoying
    fn normalize_addr(&self, a: &Ipv6Addr) -> Ipv6Addr {
        if self.mask_ipv6 {
            if a.to_ipv4().is_some() {
                *a
            } else {
                let segs = a.segments();
                Ipv6Addr::new(
                    segs[0],
                    segs[1],
                    segs[2],
                    segs[3],
                    0,
                    0,
                    0,
                    0
                )
            }
        } else {
            *a
        }
    }

    pub fn check_for(&self, user: &str, rhost: &Ipv6Addr) -> Result<bool> {
        let rhost = self.normalize_addr(rhost).to_string();
        match self.conn.query_row("SELECT last_success_at FROM logins WHERE user = ? AND rhost = ?", &[&user, &rhost], |row| {
            let ts: i64 = row.get(0);
            let now = now();
            if ts > now {
                warn!("warning: login from the FUTURE! user={:?}, rhost={:?}, ts={:?}, now={:?}", user, rhost, ts, now);
                Duration::from_secs(0)
            } else {
                Duration::from_secs((now - ts) as u64)
            }
        }) {
            Ok(time_delta) => {
                debug!("recent_ip match was {:?} ago; expiration is {:?}", time_delta, self.expiration);
                Ok(time_delta < self.expiration)
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn set_inner(&mut self, user: &str, rhost: &str) -> rusqlite::Result<()> {
        let now = now();
        let old_time = now - (2 * self.expiration.as_secs()) as i64;
        let xact = self.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        xact.execute("INSERT OR REPLACE INTO logins VALUES (?, ?, ?)", &[&user, &rhost, &now])?;
        // prune old dead stuff here, too
        xact.execute("DELETE FROM logins WHERE last_success_at < ?", &[&old_time])?;
        xact.commit()?;
        Ok(())
    }

    pub fn set_for(&mut self, user: &str, rhost: &Ipv6Addr) {
        let rhost = self.normalize_addr(rhost).to_string();
        if let Err(e) = self.set_inner(user, &rhost) {
            error!("Error updating DB: {:?}", e);
        }
    }
}
