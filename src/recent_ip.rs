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
            FailureBackoff {
                description("too many consecutive failures")
                display("too many consecutive failures")
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
    backoff_window: Duration,
    consecutive_failures: u16,
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
            xact.execute("CREATE TABLE IF NOT EXISTS logins (user STRING NOT NULL, rhost STRING NOT NULL, timestamp INTEGER, failure_count INTEGER default 0, UNIQUE (user, rhost));", &[])?;
            xact.commit()?;
        }
        Ok(RecentIp {
            conn: conn,
            expiration: c.recent_ip_duration,
            backoff_window: c.backoff_window,
            consecutive_failures: c.consecutive_failures,
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
        let norm_rhost = self.normalize_addr(rhost).to_string();
        match self.conn.query_row("SELECT timestamp, failure_count FROM logins WHERE user = ? AND rhost = ?", &[&user, &norm_rhost], |row| {
            let ts: i64 = row.get(0);
            let fails: u16 = row.get(1);
            let now = now();
            if ts > now {
                warn!("warning: login from the FUTURE! user={:?}, rhost={:?}, ts={:?}, now={:?}", user, rhost, ts, now);
                (Duration::from_secs(0), fails)
            } else {
                (Duration::from_secs((now - ts) as u64), fails)
            }
        }) {
            Ok((time_delta, fails)) => {
                debug!("recent_ip match was {:?} ago; expiration is {:?}, fail count is {:?}", time_delta, self.expiration, fails);
                if (fails < self.consecutive_failures) || (time_delta > self.backoff_window) {
                    Ok(time_delta < self.expiration)
                } else {
                    Err(ErrorKind::FailureBackoff.into())
                }
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn set_inner(&mut self, user: &str, rhost: &str, success: bool) -> rusqlite::Result<()> {
        let now = now();
        let old_time = now - (2 * self.expiration.as_secs()) as i64;
        let xact = self.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if success {
            xact.execute("INSERT OR REPLACE INTO logins (user, rhost, timestamp, failure_count) \
            VALUES (?, ?, ?, 0)", &[&user, &rhost, &now])?;
        } else {
            let rows_updated = xact.execute("UPDATE logins \
                                            SET timestamp = ?, failure_count = failure_count + 1 \
                                            WHERE user = ? and rhost = ?", &[&now, &user, &rhost])?;
            if rows_updated != 1 {
                xact.execute("INSERT INTO logins (user, rhost, timestamp, failure_count) VALUES (?, ?, ?, 1):", &[&user, &rhost, &now])?;
            }
        }
        // prune old dead stuff here, too
        xact.execute("DELETE FROM logins WHERE timestamp < ?", &[&old_time])?;
        xact.commit()?;
        Ok(())
    }

    pub fn set_for(&mut self, user: &str, rhost: &Ipv6Addr, success: bool) -> () {
        let rhost = self.normalize_addr(rhost).to_string();
        if let Err(e) = self.set_inner(user, &rhost, success) {
            error!("Error updating DB: {:?}", e);
        }
    }
}
