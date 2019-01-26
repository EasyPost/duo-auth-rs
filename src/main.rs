#[macro_use] extern crate log;
#[macro_use] extern crate error_chain;

use std::env;
use std::str::FromStr;
use std::path::Path;
use std::net::IpAddr;

use clap::{self, Arg};
use env_logger;
use log_panics;

mod config;
mod duo_client;
mod recent_ip;
mod ip_whitelist;

mod errors {
    error_chain!{
        links {
            DuoClient(crate::duo_client::errors::Error, crate::duo_client::errors::ErrorKind);
            Db(crate::recent_ip::errors::Error, crate::recent_ip::errors::ErrorKind);
        }

        foreign_links {
            Serialization(::serde_json::error::Error);
            MissingVar(::std::env::VarError);
            BadRhost(::std::net::AddrParseError);
        }

        errors {
            InvalidLogLevel(t: String) {
                description("invalid log level")
                display("invalid log level: '{}'", t)
            }

            MissingEnvironmentVariable(t: String) {
                description("missing environment variable")
                display("missing environment variable: '{}'", t)
            }
        }
    }
}

use crate::errors::*;


fn get_env_var(s: String) -> Result<String> {
    env::var(&s).map_err(|_| ErrorKind::MissingEnvironmentVariable(s).into())
}



fn main_r() -> errors::Result<i32> {
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
                            .version(env!("CARGO_PKG_VERSION"))
                            .about(env!("CARGO_PKG_DESCRIPTION"))
                            .author("James Brown <jbrown@easypost.com>")
                            .arg(Arg::with_name("stderr")
                                     .short("e")
                                     .long("stderr")
                                     .takes_value(false)
                                     .help("Log to stderr instead of syslog"))
                            .arg(Arg::with_name("config_file")
                                     .short("c")
                                     .long("config-file")
                                     .takes_value(true)
                                     .value_name("PATH")
                                     .default_value("/etc/duo-auth-rs.json")
                                     .help("Path to config file"))
                            .arg(Arg::with_name("username_env")
                                     .long("username-env")
                                     .takes_value(true)
                                     .value_name("VAR")
                                     .default_value("PAM_USER")
                                     .help("Name of environment variable containing username"))
                            .arg(Arg::with_name("ip_env")
                                     .long("ip-env")
                                     .takes_value(true)
                                     .value_name("VAR")
                                     .default_value("PAM_RHOST")
                                     .help("Name of environment variable containing remote IP"))
                            .arg(Arg::with_name("check")
                                     .long("check-duo")
                                     .takes_value(false)
                                     .help("Run check method on Duo before authing"))
                            .arg(Arg::with_name("never_duo")
                                     .long("never-duo")
                                     .takes_value(false)
                                     .help("If passed, will never call Duo and will just fail of no whitelists match"))
                            .get_matches();
    
    // set up logging
    if matches.is_present("stderr") {
        env_logger::init();
    } else {
        let log_level = match env::var("RUST_LOG") {
            Ok(level) => log::LevelFilter::from_str(&level).map_err(|_| ErrorKind::InvalidLogLevel(level.to_owned()))?,
            _ => log::LevelFilter::Info
        };
        syslog::init_unix(syslog::Facility::LOG_AUTH, log_level).chain_err(|| "cannot initialize syslog")?;
    }
    log_panics::init();

    let config = config::Config::from_path(Path::new(matches.value_of("config_file").unwrap()))?;

    let mut client = duo_client::DuoClient::from_config(&config)?;

    if matches.is_present("check") {
        client.check()?;
    }

    let user = get_env_var(matches.value_of("username_env").unwrap().to_owned())?;
    let rhost = get_env_var(matches.value_of("ip_env").unwrap().to_owned())?;

    let rhost_raw = IpAddr::from_str(&rhost)?;
    let rhost = match rhost_raw {
        IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
        IpAddr::V6(v6_addr) => v6_addr,
    };

    if config.whitelist.contains(rhost_raw) {
        info!("whitelist match for {}@{}", user, rhost);
        return Ok(0);
    }

    let mut recent_ip = config.make_recent_ip()?;

    if let Some(ref recent_ip) = recent_ip {
        if recent_ip.check_for(&user, &rhost)? {
            info!("recent_ip match for {}@{}", user, rhost);
            return Ok(0);
        }
    }

    if matches.is_present("never_duo") {
        warn!("bailing instead of calling duo");
        return Ok(1);
    }

    if client.auth_for(&user, rhost.to_string().as_str())? {
        info!("successful duo auth for {}@{}", user, rhost);
        if let Some(ref mut recent_ip) = recent_ip {
            recent_ip.set_for(&user, &rhost);
        }
        Ok(0)
    } else {
        info!("auth failed via duo for {}@{}", user, rhost);
        Ok(1)
    }
}

fn main() {
    match main_r() {
        Ok(i) => {
            ::std::process::exit(i);
        },
        Err(ref e) => {
            error!("error: {}", e);
            eprintln!("error: {}", e);

            for e in e.iter().skip(1) {
                error!("caused by: {}", e);
                eprintln!("caused by: {}", e);
            }

            if let Some(backtrace) = e.backtrace() {
                eprintln!("backtrace: {:?}", backtrace);
            }

            ::std::process::exit(1);
        }
    }
}
