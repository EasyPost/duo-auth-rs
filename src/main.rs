extern crate reqwest;
extern crate clap;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate log_panics;
extern crate syslog;
#[macro_use] extern crate error_chain;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate rusqlite;
extern crate url;
extern crate crypto;
extern crate itertools;

use clap::Arg;
use std::env;
use std::str::FromStr;
use std::path::Path;
use std::net::IpAddr;

mod config;
mod duo_client;
mod recent_ip;

mod errors {
    error_chain!{
        links {
            DuoClient(::duo_client::errors::Error, ::duo_client::errors::ErrorKind);
            Db(::recent_ip::errors::Error, ::recent_ip::errors::ErrorKind);
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

use errors::*;


fn get_env_var(s: String) -> Result<String> {
    env::var(&s).map_err(|_| ErrorKind::MissingEnvironmentVariable(s).into())
}



fn main_r() -> errors::Result<i32> {
    let matches = clap::App::new("duo-auth-rs")
                            .version("0.1.0")
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
                                     .default_value("/usr/local/etc/duo-auth-rs.json")
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
                            .get_matches();
    
    // set up logging
    if matches.is_present("stderr") {
        env_logger::init().chain_err(|| "cannot initialize env_logger")?;
    } else {
        let log_level = match env::var("RUST_LOG") {
            Ok(level) => log::LogLevelFilter::from_str(&level).map_err(|_| ErrorKind::InvalidLogLevel(level.to_owned()))?,
            _ => log::LogLevelFilter::Warn
        };
        syslog::init_unix(syslog::Facility::LOG_AUTH, log_level).chain_err(|| "cannot initialize syslog")?;
    }

    let config = config::Config::from_path(Path::new(matches.value_of("config_file").unwrap()))?;

    let user = get_env_var(matches.value_of("username_env").unwrap().to_owned())?;
    let rhost = get_env_var(matches.value_of("ip_env").unwrap().to_owned())?;

    let rhost = match IpAddr::from_str(&rhost)? {
        IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
        IpAddr::V6(v6_addr) => v6_addr,
    }.to_string();

    let mut recent_ip = if config.has_recent_ip() {
        Some(recent_ip::RecentIp::from_config(&config)?)
    } else {
        None
    };

    if let Some(ref recent_ip) = recent_ip {
        if recent_ip.check_for(&user, &rhost)? {
            debug!("recent_ip match for {} {}", user, rhost);
            return Ok(0);
        }
    }

    let mut client = duo_client::DuoClient::from_config(&config)?;

    if matches.is_present("check") {
        client.check()?;
    }

    if client.auth_for(&user, &rhost)? {
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
            eprintln!("error: {}", e);

            for e in e.iter().skip(1) {
                eprintln!("caused by: {}", e);
            }

            if let Some(backtrace) = e.backtrace() {
                eprintln!("backtrace: {:?}", backtrace);
            }

            ::std::process::exit(1);
        }
    }
}
