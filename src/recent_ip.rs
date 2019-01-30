use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use std::net::Ipv6Addr;

use rusqlite::{self, NO_PARAMS};
use rusqlite::types::ToSql;


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
    let duration = UNIX_EPOCH.elapsed().expect("it should not be before 1970");
    duration.as_secs() as i64
}


// Fun fact: the to_ipv5() method on Ipv6Addr now accepts IPv4-compatible addresses,
// which are impossible to distinguish from loopback addresses
trait IsIpv4Mapped {
    fn is_ipv4_mapped(&self) -> bool;
}

impl IsIpv4Mapped for Ipv6Addr {
    fn is_ipv4_mapped(&self) -> bool {
        let segs = self.segments();
        segs[0] == 0 &&
            segs[1] == 0 &&
            segs[2] == 0 &&
            segs[3] == 0 &&
            segs[4] == 0 &&
            segs[5] == 0xffff
    }
}


impl RecentIp {
    pub(crate) fn try_new(path: &Path, expiration: Duration, mask_ipv6: bool) -> Result<Self> {
        let mut conn = rusqlite::Connection::open(path)?;
        {
            let xact = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            xact.execute("CREATE TABLE IF NOT EXISTS logins (user STRING NOT NULL, rhost STRING NOT NULL, last_success_at INTEGER, UNIQUE (user, rhost));", NO_PARAMS)?;
            xact.commit()?;
        }
        Ok(Self {
            conn,
            expiration,
            mask_ipv6,
        })
    }

    /// Potentially normalize an address. This masks V6 addresses to the closest /64 to make
    /// rotating ephemeral addresses less annoying
    fn normalize_addr(&self, a: &Ipv6Addr) -> Ipv6Addr {
        if self.mask_ipv6 {
            if a.is_ipv4_mapped() {
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
        match self.conn.query_row("SELECT last_success_at FROM logins WHERE user = ? AND rhost = ?", &[user, rhost.as_str()], |row| {
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
        xact.execute("INSERT OR REPLACE INTO logins VALUES (?, ?, ?)", &[&user, &rhost, &now as &ToSql])?;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::net::{Ipv6Addr, Ipv4Addr};

    use super::RecentIp;
    use super::IsIpv4Mapped;

    use tempfile;

    #[test]
    fn test_is_ipv4_mapped() {
        let native_ipv6_loopback = "::1".parse::<Ipv6Addr>().unwrap();
        let mapped_loopback = "127.0.0.1".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped();

        assert_eq!(native_ipv6_loopback.is_ipv4_mapped(), false);
        assert_eq!(mapped_loopback.is_ipv4_mapped(), true);
    }

    #[test]
    fn test_basic() {
        let tf = tempfile::NamedTempFile::new().unwrap();
        let mut db = RecentIp::try_new(tf.path(), Duration::from_secs(60), false).unwrap();
        let good_source_address = "::1".parse::<Ipv6Addr>().unwrap();
        let bad_source_address = "::2".parse::<Ipv6Addr>().unwrap();
        let good_ipv4_address = "127.0.0.1".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped();
        let bad_ipv4_address = "127.0.0.2".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped();
        assert_eq!(db.check_for("foobar", &good_source_address).unwrap(), false);
        db.set_for("foobar", &good_source_address);
        assert_eq!(db.check_for("foobar", &good_source_address).unwrap(), true);
        assert_eq!(db.check_for("foobar", &bad_source_address).unwrap(), false);
        assert_eq!(db.check_for("foobar", &good_ipv4_address).unwrap(), false);
        assert_eq!(db.check_for("foobar", &bad_ipv4_address).unwrap(), false);

        // check v4
        assert_eq!(db.check_for("ipv4", &good_ipv4_address).unwrap(), false);
        db.set_for("ipv4", &good_ipv4_address);
        assert_eq!(db.check_for("ipv4", &good_ipv4_address).unwrap(), true);
        assert_eq!(db.check_for("ipv4", &bad_ipv4_address).unwrap(), false);
    }

    #[test]
    fn test_masking() {
        let tf = tempfile::NamedTempFile::new().unwrap();
        let mut db = RecentIp::try_new(tf.path(), Duration::from_secs(60), true).unwrap();
        let good_source_address = "::1".parse::<Ipv6Addr>().unwrap();
        let other_good_source_address = "::2".parse::<Ipv6Addr>().unwrap();
        let bad_source_address = "1234::2".parse::<Ipv6Addr>().unwrap();
        let good_ipv4_address = "127.0.0.1".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped();
        let bad_ipv4_address = "127.0.0.2".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped();

        assert_eq!(db.check_for("foobar", &good_source_address).unwrap(), false);
        db.set_for("foobar", &good_source_address);
        assert_eq!(db.check_for("foobar", &good_source_address).unwrap(), true);
        assert_eq!(db.check_for("foobar", &other_good_source_address).unwrap(), true);
        assert_eq!(db.check_for("foobar", &bad_source_address).unwrap(), false);
        assert_eq!(db.check_for("foobar", &good_ipv4_address).unwrap(), false);
        assert_eq!(db.check_for("foobar", &bad_ipv4_address).unwrap(), false);

        // check v4
        assert_eq!(db.check_for("ipv4", &good_ipv4_address).unwrap(), false);
        db.set_for("ipv4", &good_ipv4_address);
        assert_eq!(db.check_for("ipv4", &good_ipv4_address).unwrap(), true);
        assert_eq!(db.check_for("ipv4", &bad_ipv4_address).unwrap(), false);
    }
}
