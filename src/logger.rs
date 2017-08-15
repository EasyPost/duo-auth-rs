use std::io;

use log::{self, Log,LogRecord,LogMetadata,LogLevel,SetLoggerError};
use syslog::{self, Facility};


struct SyslogLogger {
    l: syslog::Logger
}

impl SyslogLogger {
    fn unix(facility: Facility) -> Result<Box<Self>, io::Error> {
        Ok(Box::new(SyslogLogger {
            l: *syslog::unix(facility)?
        }))

    }
}

impl Log for SyslogLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        self.l.enabled(metadata)
    }

    #[allow(unused_must_use)]
    fn log(&self, record: &LogRecord) {
        // XXX: hyper and reqwest log responses at INFO even though they're pretty un-arguably
        // debug information. turn them into debug level logs.
        if record.metadata().level() == LogLevel::Info {
            let tgt = record.metadata().target();
            if (tgt == "hyper::http::response") || (tgt == "reqwest::async_impl::response") {
                let message = &(format!("{}", record.args()));
                self.l.debug(message);
                return;
            }
        }
        self.l.log(record)
    }
}

pub fn init_unix(facility: Facility, log_level: log::LogLevelFilter) -> Result<(), SetLoggerError> {
  log::set_logger(|max_level| {
    max_level.set(log_level);
    SyslogLogger::unix(facility).unwrap()
  })

}

