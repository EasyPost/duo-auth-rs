use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac, NewMac};
use log::warn;
use reqwest::{self, Method, Url};
use serde_json::Value;
use sha1::Sha1;
use thiserror::Error;
use url::form_urlencoded::Serializer;

use crate::config;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid response from duo; status {status:?}")]
    InvalidResponse { status: DuoResponseStatus },
    #[error("other I/O error: {0:?}")]
    Io(#[from] ::std::io::Error),
    #[error("JSON ser/de error: {0:?}")]
    Serialization(#[from] ::serde_json::error::Error),
    #[error("Invalid URL: {0:?}")]
    Url(#[from] ::url::ParseError),
    #[error("HTTP error: {0:?}")]
    Request(#[from] ::reqwest::Error),
    #[error("malformed response body structure {0}")]
    MalformedResponseBody(&'static str),
}

type Result<T> = ::std::result::Result<T, Error>;

struct DuoRequest<'a> {
    method: Method,
    path: &'a str,
    date: DateTime<Utc>,
    params: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum DuoResponseStatus {
    Ok,
    Fail {
        code: i64,
        message: String,
        message_detail: Option<String>,
    },
    NoStat,
    Other(String),
}

#[derive(Debug)]
struct OkDuoResponse {
    stat: DuoResponseStatus,
    json: Value,
}

impl OkDuoResponse {
    fn response_json(&self) -> &Value {
        &self.json
    }
}

#[derive(Debug)]
struct DuoResponse {
    status: reqwest::StatusCode,
    stat: DuoResponseStatus,
    json: Option<Value>,
}

impl DuoResponse {
    fn status(&self) -> reqwest::StatusCode {
        self.status
    }

    /// Consume this response body and raise a Result. In the Ok case, we are
    /// guaranteed to have an "OK" stat and a valid response body
    fn consume(self) -> Result<OkDuoResponse> {
        match self.stat {
            DuoResponseStatus::Ok => {
                if let Some(json) = self.json {
                    Ok(OkDuoResponse {
                        stat: DuoResponseStatus::Ok,
                        json,
                    })
                } else {
                    Err(Error::InvalidResponse { status: self.stat })
                }
            }
            v => Err(Error::InvalidResponse { status: v }),
        }
    }

    fn from_response(r: reqwest::blocking::Response) -> Result<Self> {
        let status = r.status();
        let data: Value = r.json()?;
        let stat = match data["stat"].as_str() {
            Some("OK") => DuoResponseStatus::Ok,
            Some("FAIL") => {
                let message = data["message"].as_str().unwrap_or("unknown").to_owned();
                let message_detail = data["message_detail"].as_str().map(|o| o.to_owned());
                let code = data["code"].as_i64().unwrap_or(0);
                DuoResponseStatus::Fail {
                    code,
                    message,
                    message_detail,
                }
            }
            Some(s) => DuoResponseStatus::Other(s.to_owned()),
            None => DuoResponseStatus::NoStat,
        };
        Ok(DuoResponse {
            status,
            json: match stat {
                DuoResponseStatus::Ok => data.get("response").map(|i| i.to_owned()),
                _ => None,
            },
            stat,
        })
    }
}

type HmacSha1 = Hmac<Sha1>;

impl<'a> DuoRequest<'a> {
    fn new(method: Method, path: &'a str) -> DuoRequest<'a> {
        DuoRequest {
            method,
            path,
            date: Utc::now(),
            params: BTreeMap::new(),
        }
    }

    fn sign(&self, body: &str, client: &DuoClient) -> String {
        let to_sign = &[
            self.date.to_rfc2822(),
            self.method.to_string().to_uppercase(),
            client
                .base_url
                .host_str()
                .expect("URL must have a host...")
                .to_owned(),
            self.path.to_owned(),
            body.to_owned(),
        ];
        let to_sign = to_sign.join("\n");
        let mut signer =
            HmacSha1::new_varkey(&client.skey.as_bytes()).expect("skey must be the right size");
        signer.update(to_sign.as_bytes());
        hex::encode(signer.finalize().into_bytes())
    }

    fn run(self, client: &DuoClient) -> Result<DuoResponse> {
        let mut ser = Serializer::new(String::new());
        for (key, value) in self.params.iter() {
            ser.append_pair(&key, &value);
        }
        let body = ser.finish();
        let signature = self.sign(&body, client);
        let mut url = client.base_url.clone();
        url.set_path(self.path);
        let can_have_body = match self.method {
            Method::GET | Method::HEAD => false,
            _ => true,
        };
        if !can_have_body {
            url.set_query(Some(&body));
        }
        let rb = client
            .client
            .request(self.method, url)
            .basic_auth(client.ikey.clone(), Some(signature))
            .header("Date", self.date.to_rfc2822())
            .header(
                "User-Agent",
                concat!("duo-auth-rs/", env!("CARGO_PKG_VERSION")),
            );
        let rb = if can_have_body {
            rb.header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
        } else {
            rb
        };
        let resp = rb.send()?;
        DuoResponse::from_response(resp)
    }

    fn set_param<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.params.insert(key.into(), value.into());
    }
}

#[derive(Debug)]
pub struct DuoClient {
    ikey: String,
    skey: String,
    base_url: Url,
    client: reqwest::blocking::Client,
}

impl DuoClient {
    pub(crate) fn from_config(config: &config::Config) -> Result<DuoClient> {
        Ok(DuoClient {
            ikey: config.ikey.clone(),
            skey: config.skey.clone(),
            base_url: Url::parse(&config.base)?,
            client: reqwest::blocking::Client::builder()
                .timeout(config.request_timeout)
                .build()?,
        })
    }

    pub fn check(&mut self) -> Result<bool> {
        let req = DuoRequest::new(Method::GET, "/auth/v2/check");
        let resp = req.run(&self)?;
        Ok(resp.status().is_success())
    }

    pub fn auth_for(&mut self, user: &str, rhost: &str) -> Result<bool> {
        let mut req = DuoRequest::new(Method::POST, "/auth/v2/auth");
        req.set_param("username", user);
        req.set_param("ipaddr", rhost);
        req.set_param("factor", "push");
        req.set_param("device", "auto");
        let resp = req.run(&self)?.consume()?;
        let result = resp.response_json()["result"]
            .as_str()
            .ok_or(Error::MalformedResponseBody("missing result"))?
            .to_owned();
        Ok(match result.as_str() {
            "allow" => true,
            "deny" => false,
            other => {
                warn!("unexpected duo auth_status result: {:?}", other);
                false
            }
        })
    }
}
