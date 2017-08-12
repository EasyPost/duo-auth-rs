use std::collections::BTreeMap;
use std::time::SystemTime;
use std::io::Read;

use reqwest::{self, Url, Method};
use reqwest::header;
use url::form_urlencoded::Serializer;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use crypto::mac::{Mac, MacResult};
use itertools::Itertools;

use config;

pub(crate) mod errors {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Io(::std::io::Error);
            Serialization(::serde_json::error::Error);
            Url(::reqwest::UrlError);
            Request(::reqwest::Error);
        }
    }
}

use self::errors::*;

trait Hexlify {
    fn hexlify(&self) -> String;
}

impl Hexlify for MacResult {
    fn hexlify(&self) -> String {
        // This does not feel like an efficient way to do this
        format!("{:02x}", self.code().iter().format(""))
    }
}

struct DuoRequest<'a> {
    method: Method,
    path: &'a str,
    date: header::HttpDate,
    params: BTreeMap<String, String>
}


impl<'a> DuoRequest<'a> {
    fn new(method: Method, path: &'a str) -> DuoRequest<'a> {
        DuoRequest {
            method: method,
            path: path,
            date: header::HttpDate::from(SystemTime::now()),
            params: BTreeMap::new()
        }
    }


    fn sign(&self, body: &str, client: &DuoClient) -> String {
        let to_sign = &[
            self.date.to_string(),
            self.method.to_string().to_uppercase(),
            client.base_url.host_str().expect("URL must have a host...").to_owned(),
            self.path.to_owned(),
            body.to_owned(),
        ];
        let to_sign = to_sign.join("\n");
        let mut signer = Hmac::new(Sha1::new(), &client.skey.as_bytes());
        signer.input(to_sign.as_bytes());
        signer.result().hexlify().into()
    }

    fn run(self, client: &DuoClient) -> Result<reqwest::Response> {
        let mut ser = Serializer::new(String::new());
        for (key, value) in self.params.iter() {
            ser.append_pair(&key, &value);
        }
        let body = ser.finish();
        let signature = self.sign(&body, client);
        let mut url = client.base_url.clone();
        url.set_path(self.path);
        let can_have_body = match &self.method {
            &Method::Get | &Method::Head => false,
            _ => true
        };
        if !can_have_body {
            url.set_query(Some(&body));
        }
        let mut rb = client.client.request(self.method, url)?;
        rb.basic_auth(client.ikey.clone(), Some(signature));
        rb.header(header::Date(self.date));
        if can_have_body {
            rb.header(header::ContentType::form_url_encoded());
            rb.body(body);
        }
        let resp = rb.send()?;
        Ok(resp)
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
    client: reqwest::Client,
}


impl DuoClient {
    pub(crate) fn from_config(config: &config::Config) -> Result<DuoClient> {
        Ok(DuoClient {
            ikey: config.ikey.clone(),
            skey: config.skey.clone(),
            base_url: Url::parse(&config.base)?,
            client: reqwest::Client::builder()?
                .timeout(config.request_timeout)
                .build()?
        })
    }

    pub fn check(&mut self) -> Result<bool> {
        let req = DuoRequest::new(Method::Get, "/auth/v2/check");
        let resp = req.run(&self)?;
        Ok(resp.status().is_success())
    }

    pub fn auth_for(&mut self, user: &str, rhost: &str) -> Result<bool> {
        let mut req = DuoRequest::new(Method::Post, "/auth/v2/auth");
        req.set_param("username", user);
        req.set_param("ipaddr", rhost);
        req.set_param("factor", "push");
        req.set_param("device", "auto");
        let mut resp = req.run(&self)?.error_for_status()?;
        // read the whole body
        let mut body = Vec::new();
        resp.read_to_end(&mut body)?;
        Ok(true)
    }
}
